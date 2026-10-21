"""Assignment 5.6: a small tamper-evident encrypted log (design in docs/ch05.md, prototype here).

Requirements: confidentiality of log lines, detection of modification, reordering, deletion and replay,
safe nonce management, and key separation. Choices:
  * Mode: AES-256-GCM. Authenticated, fast, one primitive for confidentiality + integrity.
  * Keys: a master key never touches log files; each segment gets its own key via HKDF(master, "enc|segment").
  * Nonce: the 96-bit record sequence number. Safe because every segment has a unique key and a single writer holds
    a file lock, so a (key, nonce) pair can never repeat. (Multiple writers or no per-segment key -> use random
    nonces with a message cap, or a nonce-misuse-resistant mode such as AES-GCM-SIV.)
  * Order/deletion: each record's associated data = segment id | sequence | SHA-256 of the previous record line.
    Reordering, deleting or replaying a record breaks the chain and fails authentication of the next record.
  * Tail truncation cannot be seen from inside the file (no later record exists to notice). A MAC'd checkpoint
    (count + chain head) stored OUTSIDE the file (another host, a ticket, a blockchain anchor) detects it.
Line format:  <seq>:<base64(ciphertext||tag)>
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ZERO = bytes(32)


class LogTamperError(Exception):
    pass


def _derive(master: bytes, label: str, segment: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=f"{label}|{segment}".encode()).derive(master)


def _aad(segment: str, seq: int, prev: bytes) -> bytes:
    return segment.encode() + b"|" + seq.to_bytes(8, "big") + prev


def _lines(path: str) -> list[bytes]:
    if not os.path.exists(path):
        return []
    with open(path, "rb") as f:
        return [l.rstrip(b"\n") for l in f if l.strip()]


class SecureLog:
    def __init__(self, path: str, master_key: bytes, segment: str):
        if len(master_key) < 32:
            raise ValueError("master key must be at least 32 bytes")
        self.path, self.segment = path, segment
        self._aead = AESGCM(_derive(master_key, "log-enc", segment))
        self._ckpt_key = _derive(master_key, "log-ckpt", segment)
        # Single writer: the exclusive lock is what makes the sequence-number nonce safe.
        self._fh = open(path, "ab")
        fcntl.flock(self._fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        existing = _lines(path)
        self.seq = len(existing)
        self.head = hashlib.sha256(existing[-1]).digest() if existing else ZERO

    def append(self, message: str | bytes) -> None:
        data = message.encode() if isinstance(message, str) else message
        ct = self._aead.encrypt(self.seq.to_bytes(12, "big"), data, _aad(self.segment, self.seq, self.head))
        line = f"{self.seq}:{base64.b64encode(ct).decode()}".encode()
        self._fh.write(line + b"\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self.head, self.seq = hashlib.sha256(line).digest(), self.seq + 1

    def checkpoint(self) -> bytes:
        """MAC over (record count, chain head). Store it somewhere the log writer cannot rewrite."""
        return hmac.new(self._ckpt_key, self.seq.to_bytes(8, "big") + self.head, hashlib.sha256).digest()

    def close(self) -> None:
        fcntl.flock(self._fh, fcntl.LOCK_UN)
        self._fh.close()


def read_verified(path: str, master_key: bytes, segment: str, checkpoint: tuple[int, bytes] | None = None) -> list[bytes]:
    """Decrypt every record, raising LogTamperError on any inconsistency.

    `checkpoint` is (count, mac) from SecureLog.checkpoint() taken when the log had `count` records.
    """
    aead = AESGCM(_derive(master_key, "log-enc", segment))
    prev, out, lines = ZERO, [], _lines(path)
    for i, line in enumerate(lines):
        try:
            seq_s, b64 = line.split(b":", 1)
            if int(seq_s) != i:
                raise LogTamperError(f"record {i}: sequence number {int(seq_s)} out of order (reordered, deleted or replayed)")
            out.append(aead.decrypt(i.to_bytes(12, "big"), base64.b64decode(b64, validate=True), _aad(segment, i, prev)))
        except InvalidTag as e:
            raise LogTamperError(f"record {i}: authentication failed (modified, or earlier record missing/reordered)") from e
        except (ValueError, TypeError) as e:
            raise LogTamperError(f"record {i}: malformed") from e
        prev = hashlib.sha256(line).digest()
    if checkpoint:
        count, mac = checkpoint
        if len(lines) < count:
            raise LogTamperError(f"log has {len(lines)} records but a checkpoint vouches for {count}: tail truncated")
        # Recompute the head at `count` records and compare in constant time.
        head = ZERO if count == 0 else hashlib.sha256(lines[count - 1]).digest()
        expect = hmac.new(_derive(master_key, "log-ckpt", segment), count.to_bytes(8, "big") + head, hashlib.sha256).digest()
        if not hmac.compare_digest(expect, mac):
            raise LogTamperError("checkpoint MAC mismatch: history before the checkpoint was altered")
    return out


def demo() -> None:
    import tempfile
    master, path = os.urandom(32), os.path.join(tempfile.mkdtemp(), "app.log")
    log = SecureLog(path, master, "2026-10-22")
    for m in ("service started", "login ok user=alice", "transfer 100 alice->bob", "logout user=alice"):
        log.append(m)
    ckpt = (log.seq, log.checkpoint())
    log.close()
    print("verified:", [m.decode() for m in read_verified(path, master, "2026-10-22", ckpt)])
    ls = open(path, "rb").read().split(b"\n")
    open(path, "wb").write(b"\n".join(ls[:2] + ls[3:]))             # attacker deletes record 2
    try:
        read_verified(path, master, "2026-10-22", ckpt)
    except LogTamperError as e:
        print("tamper detected:", e)


if __name__ == "__main__":
    demo()
