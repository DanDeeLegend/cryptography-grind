"""Assignment 2.1: the one-time pad, and what happens when the pad is reused.

OTP: ciphertext = plaintext XOR key, with a truly random key as long as the message, used once. It is
perfectly secret: for ANY plaintext of the same length there is a key that produces the observed
ciphertext, so the ciphertext tells an attacker nothing. Reuse the key and that guarantee collapses:
c1 XOR c2 = p1 XOR p2, the key cancels out.
"""
from __future__ import annotations

import os


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def keygen(n: int) -> bytes:
    return os.urandom(n)


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(key) != len(plaintext):
        raise ValueError("OTP key must be exactly as long as the message")
    return xor(plaintext, key)


decrypt = encrypt  # XOR is its own inverse


def key_for(ciphertext: bytes, claimed_plaintext: bytes) -> bytes:
    """The key that would make `ciphertext` decrypt to `claimed_plaintext`: the heart of perfect secrecy."""
    return xor(ciphertext, claimed_plaintext)


def crib_drag(x: bytes, crib: bytes) -> list[tuple[int, bytes]]:
    """Slide `crib` along x = p1 XOR p2. At the right offset, crib XOR x reveals the other plaintext."""
    return [(i, xor(x[i:i + len(crib)], crib)) for i in range(len(x) - len(crib) + 1)]


def demo() -> None:
    p1, p2 = b"ATTACK AT DAWN ON THE EASTERN BRIDGE", b"RETREAT TO THE HILLS BEFORE NIGHTFALL"
    n = min(len(p1), len(p2))
    p1, p2 = p1[:n], p2[:n]

    key = keygen(n)
    c = encrypt(p1, key)
    print("1) Perfect secrecy: the same ciphertext 'decrypts' to any message under a suitable key")
    for guess in (p1, b"HOLD POSITION, SEND SUPPLIES TO CAMP"[:n].ljust(n)):
        print(f"   key guess -> {decrypt(c, key_for(c, guess))!r}")

    c1, c2 = encrypt(p1, key), encrypt(p2, key)  # the mistake: same key twice
    leak = xor(c1, c2)
    print("\n2) Two-time pad: c1 XOR c2 == p1 XOR p2 ->", leak == xor(p1, p2))
    print("3) Crib dragging ' THE ' over p1 XOR p2 (printable hits reveal the OTHER message):")
    for off, frag in crib_drag(leak, b" THE "):
        if all(65 <= ch <= 90 or ch == 32 for ch in frag):
            print(f"   offset {off:2d}: {frag!r}")


if __name__ == "__main__":
    demo()
