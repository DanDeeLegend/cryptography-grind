"""Assignment 10.1: RSA signatures (PKCS#1 v1.5, SHA-256) built from scratch and checked byte-for-byte against OpenSSL.

PKCS#1 v1.5 signing is deterministic, so for the same key and message our signature must equal the library's exactly.
"""
from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# DER prefix of DigestInfo for SHA-256 (RFC 8017 s9.2 note 1)
SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def emsa_pkcs1_v15(message: bytes, em_len: int) -> bytes:
    t = SHA256_PREFIX + hashlib.sha256(message).digest()
    if em_len < len(t) + 11:
        raise ValueError("key too short")
    return b"\x00\x01" + b"\xff" * (em_len - len(t) - 3) + b"\x00" + t


def sign(message: bytes, d: int, n: int) -> bytes:
    k = (n.bit_length() + 7) // 8
    m = int.from_bytes(emsa_pkcs1_v15(message, k), "big")
    return pow(m, d, n).to_bytes(k, "big")


def verify(message: bytes, signature: bytes, e: int, n: int) -> bool:
    """Rebuild the expected encoding and compare the whole thing (never parse the padding: that is how Bleichenbacher's
    e=3 forgery worked against lenient verifiers)."""
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    return pow(s, e, n).to_bytes(k, "big") == emsa_pkcs1_v15(message, k)


def demo() -> dict:
    key = rsa.generate_private_key(65537, 2048)
    nums = key.private_numbers()
    n, e, d = nums.public_numbers.n, nums.public_numbers.e, nums.d
    msg = b"pay Daniel 100 USD"
    ours = sign(msg, d, n)
    lib = key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    out = {
        "byte_identical_to_openssl": ours == lib,
        "ours_verifies": verify(msg, ours, e, n),
        "library_signature_verifies_in_ours": verify(msg, lib, e, n),
        "tampered_message_rejected": not verify(b"pay Daniel 900 USD", ours, e, n),
        "tampered_signature_rejected": not verify(msg, ours[:-1] + bytes([ours[-1] ^ 1]), e, n),
    }
    key.public_key().verify(ours, msg, padding.PKCS1v15(), hashes.SHA256())  # raises if OpenSSL disagrees
    out["openssl_accepts_ours"] = True
    return out


if __name__ == "__main__":
    for k, v in demo().items():
        print(f"{k}: {v}")
