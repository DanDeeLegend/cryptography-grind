"""Assignment 7.2: RSA with proper padding (OAEP), and why "textbook" RSA must never be used.

Part 1 implements RSAES-OAEP (RFC 8017 s7.1, SHA-256, MGF1) from scratch on top of the raw RSA operation, and
checks it against a reference library in BOTH directions: our padding decrypted by the library, and the library's
ciphertexts decrypted by our code. Part 2 shows three concrete breaks of unpadded RSA that OAEP prevents.
"""
from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

H_LEN = 32


class DecryptionError(Exception):
    """One generic error for every failure: distinguishing causes enables Manger's chosen-ciphertext attack."""


def mgf1(seed: bytes, length: int) -> bytes:
    out, counter = b"", 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def oaep_encode(message: bytes, k: int, label: bytes = b"", seed: bytes | None = None) -> bytes:
    if len(message) > k - 2 * H_LEN - 2:
        raise ValueError("message too long for this key")
    l_hash = hashlib.sha256(label).digest()
    db = l_hash + bytes(k - len(message) - 2 * H_LEN - 2) + b"\x01" + message
    seed = seed or os.urandom(H_LEN)
    masked_db = _xor(db, mgf1(seed, k - H_LEN - 1))
    masked_seed = _xor(seed, mgf1(masked_db, H_LEN))
    return b"\x00" + masked_seed + masked_db


def oaep_decode(em: bytes, label: bytes = b"") -> bytes:
    k = len(em)
    masked_seed, masked_db = em[1:1 + H_LEN], em[1 + H_LEN:]
    seed = _xor(masked_seed, mgf1(masked_db, H_LEN))
    db = _xor(masked_db, mgf1(seed, k - H_LEN - 1))
    rest = db[H_LEN:]
    sep = rest.find(b"\x01")
    ok = (em[0] == 0 and db[:H_LEN] == hashlib.sha256(label).digest()
          and sep >= 0 and rest[:sep].count(0) == sep)           # padding string must be all zeros
    if not ok:
        raise DecryptionError("decryption error")
    return rest[sep + 1:]


def _numbers(key: rsa.RSAPrivateKey):
    pn = key.private_numbers()
    return pn.public_numbers.n, pn.public_numbers.e, pn.d


def encrypt(key: rsa.RSAPrivateKey, message: bytes, label: bytes = b"") -> bytes:
    n, e, _ = _numbers(key)
    k = (n.bit_length() + 7) // 8
    return pow(int.from_bytes(oaep_encode(message, k, label), "big"), e, n).to_bytes(k, "big")


def decrypt(key: rsa.RSAPrivateKey, ciphertext: bytes, label: bytes = b"") -> bytes:
    n, _, d = _numbers(key)
    k = (n.bit_length() + 7) // 8
    c = int.from_bytes(ciphertext, "big")
    if len(ciphertext) != k or c >= n:
        raise DecryptionError("decryption error")
    return oaep_decode(pow(c, d, n).to_bytes(k, "big"), label)


LIB_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


# ---------------- why padding exists: three breaks of textbook RSA ----------------
def textbook_demos() -> list[str]:
    key = rsa.generate_private_key(3, 1024)                   # e = 3 is legal and was common
    n, e, d = _numbers(key)
    out = []

    m = int.from_bytes(b"attack at dawn", "big")
    c = pow(m, e, n)
    out.append(f"1. Deterministic: encrypting the same message twice gives the same ciphertext: {pow(m, e, n) == c}"
               " (an eavesdropper can test guesses).")

    m1, m2 = 6, 7
    c1, c2 = pow(m1, e, n), pow(m2, e, n)
    out.append(f"2. Malleable: c1*c2 mod n decrypts to m1*m2 = {pow(c1 * c2 % n, d, n)}"
               " (an attacker edits plaintexts without the key, e.g. doubling an amount).")

    # Small message, small e: m^e < n, so no modular reduction happened and an integer e-th root recovers m.
    c_small = pow(m, e, n)
    lo, hi = 0, 1 << (n.bit_length() // e + 1)
    while lo < hi:
        mid = (lo + hi) // 2
        lo, hi = (mid + 1, hi) if mid ** e < c_small else (lo, mid)
    out.append(f"3. Small message + e = 3: integer cube root of the ciphertext = {lo.to_bytes(14, 'big')!r}"
               " (no private key needed).")
    return out


def demo() -> None:
    key = rsa.generate_private_key(65537, 2048)
    msg = b"padding matters"
    ours = encrypt(key, msg)
    print("our OAEP ciphertext decrypted by the library:", key.decrypt(ours, LIB_OAEP))
    theirs = key.public_key().encrypt(msg, LIB_OAEP)
    print("library ciphertext decrypted by our OAEP    :", decrypt(key, theirs))
    print("\nTextbook RSA, three breaks that OAEP prevents:")
    print("\n".join("  " + line for line in textbook_demos()))


if __name__ == "__main__":
    demo()
