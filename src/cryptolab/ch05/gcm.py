"""Assignment 5.3: AES-GCM from primitives, and a demo of why authentication matters.

GCM = CTR-mode encryption + GHASH, a polynomial MAC over GF(2^128). This file builds it on the from-scratch
AES-128 from chapter 4, checks it against the published GCM test cases and against a library, and then shows
the difference between an authenticated mode (a flipped bit is rejected) and an unauthenticated one (CTR
silently decrypts to attacker-chosen plaintext). Educational only: not constant-time.
"""
from __future__ import annotations

from cryptolab.ch04 import aes

R = 0xE1 << 120   # GCM's bit-reflected reduction constant for x^128 + x^7 + x^2 + x + 1


class AuthenticationError(Exception):
    """The tag did not verify: the ciphertext, tag or associated data was modified."""


def gf128_mul(x: int, y: int) -> int:
    z, v = 0, y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ R if v & 1 else v >> 1
    return z


def _blocks(data: bytes):
    for i in range(0, len(data), 16):
        yield int.from_bytes(data[i:i + 16].ljust(16, b"\0"), "big")


def ghash(h: int, aad: bytes, ct: bytes) -> int:
    y = 0
    for b in list(_blocks(aad)) + list(_blocks(ct)):
        y = gf128_mul(y ^ b, h)
    return gf128_mul(y ^ ((len(aad) * 8) << 64 | len(ct) * 8), h)


def _encryptor(key: bytes):
    rks = aes.expand_key(key)          # expand once; the chapter-4 helper would redo it for every block
    def enc(block: bytes) -> bytes:
        s = aes.add_round_key(list(block), rks[0])
        for r in range(1, 10):
            s = aes.add_round_key(aes.mix_columns(aes.shift_rows(aes.sub_bytes(s))), rks[r])
        return bytes(aes.add_round_key(aes.shift_rows(aes.sub_bytes(s)), rks[10]))
    return enc


def _ctr(enc, j0: bytes, data: bytes) -> bytes:
    out, ctr = bytearray(), int.from_bytes(j0[12:], "big")
    for i in range(0, len(data), 16):
        ctr = (ctr + 1) & 0xFFFFFFFF
        ks = enc(j0[:12] + ctr.to_bytes(4, "big"))
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], ks))
    return bytes(out)


def encrypt(key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Return (ciphertext, 16-byte tag). IV must be 12 bytes and never reused with the same key."""
    if len(iv) != 12:
        raise ValueError("this implementation uses 96-bit IVs")
    enc = _encryptor(key)
    h = int.from_bytes(enc(bytes(16)), "big")
    j0 = iv + b"\x00\x00\x00\x01"
    ct = _ctr(enc, j0, plaintext)
    tag = ghash(h, aad, ct) ^ int.from_bytes(enc(j0), "big")
    return ct, tag.to_bytes(16, "big")


def decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """Verify first, decrypt second; raises AuthenticationError and never returns unverified plaintext."""
    enc = _encryptor(key)
    h = int.from_bytes(enc(bytes(16)), "big")
    j0 = iv + b"\x00\x00\x00\x01"
    expected = (ghash(h, aad, ciphertext) ^ int.from_bytes(enc(j0), "big")).to_bytes(16, "big")
    diff = 0
    for a, b in zip(expected, tag):       # compare without an early exit
        diff |= a ^ b
    if diff or len(tag) != 16:
        raise AuthenticationError("tag mismatch: message was modified")
    return _ctr(enc, j0, ciphertext)


def ctr_only(key: bytes, nonce12: bytes, data: bytes) -> bytes:
    """Unauthenticated CTR (the keystream half of GCM) for the contrast demo."""
    return _ctr(_encryptor(key), nonce12 + b"\x00\x00\x00\x01", data)


def demo() -> None:
    key, iv = bytes(range(16)), bytes(range(12))
    msg = b"PAY ALICE $100.00"
    ct, tag = encrypt(key, iv, msg, aad=b"txn-42")
    print("GCM round-trip:", decrypt(key, iv, ct, tag, aad=b"txn-42"))
    forged = bytearray(ct); forged[11] ^= ord("1") ^ ord("9")          # '1' -> '9' without the key
    try:
        decrypt(key, iv, bytes(forged), tag, aad=b"txn-42")
    except AuthenticationError as e:
        print("GCM, bit flipped in ciphertext ->", type(e).__name__, "-", e)
    c = ctr_only(key, iv, msg)
    forged = bytearray(c); forged[11] ^= ord("1") ^ ord("9")
    print("CTR (no MAC), same flip -> silently decrypts to:", ctr_only(key, iv, bytes(forged)))


if __name__ == "__main__":
    demo()
