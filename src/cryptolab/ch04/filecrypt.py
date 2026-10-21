"""Assignment 4.5: file-encryption CLI using AES-256-GCM.

Design (one decision per line, because each is a classic way to get this wrong):
  * Key: scrypt(password, random 16-byte salt) -> 32 bytes. Cost parameter is stored in the header.
  * Cipher: AES-256-GCM from the `cryptography` package. Never hand-roll the cipher; this repo's own AES is for study.
  * Nonce: 8 random bytes per file + a 4-byte chunk counter, so every (key, nonce) pair is used exactly once.
  * Big files: encrypted in 64 KiB chunks (STREAM-style). Each chunk is authenticated, so tampering is caught
    per chunk, and nothing is held in memory beyond a chunk.
  * Truncation/reordering: the header and a "final chunk" flag are authenticated data (AAD) of every chunk, and the
    counter is in the nonce, so dropping, reordering, or appending chunks fails authentication.
  * Failure: decryption writes to a temp file and only renames it into place once every chunk verified.
File format: MAGIC(4) | log2(n)(1) | chunk_size(4) | salt(16) | nonce_prefix(8) | chunk_1 | ... | chunk_k (each + 16-byte tag)
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"CGF1"
HEADER_LEN = 4 + 1 + 4 + 16 + 8
TAG = 16
MAX_LOG2_N, MAX_CHUNK = 20, 16 * 1024 * 1024     # refuse absurd header values from an untrusted file


class TamperError(Exception):
    """Wrong password, corrupted file, or modified file (GCM cannot tell these apart, by design)."""


def _key(password: str, salt: bytes, log2_n: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=1 << log2_n, r=8, p=1).derive(password.encode())


def encrypt_file(src: str, dst: str, password: str, chunk_size: int = 64 * 1024, log2_n: int = 15) -> None:
    salt, prefix = os.urandom(16), os.urandom(8)
    header = MAGIC + bytes([log2_n]) + chunk_size.to_bytes(4, "big") + salt + prefix
    aead, tmp = AESGCM(_key(password, salt, log2_n)), dst + ".tmp"
    try:
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            fout.write(header)
            chunk, counter = fin.read(chunk_size), 0
            while True:
                nxt = fin.read(chunk_size)
                final = not nxt
                if counter >= 2 ** 32:
                    raise ValueError("file too large for one nonce prefix")
                fout.write(aead.encrypt(prefix + counter.to_bytes(4, "big"), chunk, header + (b"\x01" if final else b"\x00")))
                if final:
                    break
                chunk, counter = nxt, counter + 1
        os.replace(tmp, dst)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)
        raise


def decrypt_file(src: str, dst: str, password: str) -> None:
    tmp = dst + ".tmp"
    try:
        with open(src, "rb") as fin:
            header = fin.read(HEADER_LEN)
            if len(header) != HEADER_LEN or header[:4] != MAGIC:
                raise TamperError("not a CGF1 file (or header damaged)")
            log2_n, chunk_size = header[4], int.from_bytes(header[5:9], "big")
            salt, prefix = header[9:25], header[25:33]
            if log2_n > MAX_LOG2_N or not 0 < chunk_size <= MAX_CHUNK:
                raise TamperError("implausible header values")
            aead = AESGCM(_key(password, salt, log2_n))
            with open(tmp, "wb") as fout:
                block, counter = fin.read(chunk_size + TAG), 0
                while True:
                    nxt = fin.read(chunk_size + TAG)
                    final = not nxt
                    if len(block) < TAG:
                        raise TamperError("truncated file")
                    try:
                        fout.write(aead.decrypt(prefix + counter.to_bytes(4, "big"), block,
                                                header + (b"\x01" if final else b"\x00")))
                    except InvalidTag as e:
                        raise TamperError("authentication failed: wrong password or file was modified") from e
                    if final:
                        break
                    block, counter = nxt, counter + 1
        os.replace(tmp, dst)
    except BaseException:
        if os.path.exists(tmp):
            os.remove(tmp)   # never leave unverified plaintext behind
        raise


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="AES-256-GCM file encryption (scrypt key derivation)")
    ap.add_argument("mode", choices=["encrypt", "decrypt"])
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--password-env", help="read the password from this environment variable instead of prompting")
    args = ap.parse_args(argv)
    password = os.environ[args.password_env] if args.password_env else getpass.getpass("Password: ")
    try:
        (encrypt_file if args.mode == "encrypt" else decrypt_file)(args.src, args.dst, password)
    except TamperError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"{args.mode}ed {args.src} -> {args.dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
