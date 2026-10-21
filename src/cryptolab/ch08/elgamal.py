"""Assignment 8.3: ElGamal encryption.

Key: secret x, public y = g^x. Encrypt m with a FRESH random k: c1 = g^k, c2 = m * y^k (mod p). Decrypt: m = c2 / c1^x.
It is a Diffie-Hellman exchange in disguise: y^k is the shared secret and it masks the message like a one-time pad.
Two properties worth knowing are demonstrated: it is malleable, and reusing k is catastrophic.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass

from cryptolab.numtheory import modinv


@dataclass(frozen=True)
class PublicKey:
    p: int
    g: int
    y: int


def keygen(p: int, g: int, x: int | None = None) -> tuple[PublicKey, int]:
    x = x if x is not None else secrets.randbelow(p - 3) + 2
    return PublicKey(p, g, pow(g, x, p)), x


def encrypt(pk: PublicKey, m: int, k: int | None = None) -> tuple[int, int]:
    if not 0 < m < pk.p:
        raise ValueError("message must be in [1, p-1]")
    k = k if k is not None else secrets.randbelow(pk.p - 3) + 2
    return pow(pk.g, k, pk.p), m * pow(pk.y, k, pk.p) % pk.p


def decrypt(pk: PublicKey, x: int, c: tuple[int, int]) -> int:
    c1, c2 = c
    return c2 * modinv(pow(c1, x, pk.p), pk.p) % pk.p


def demo() -> None:
    pk, x = keygen(2579, 2, 765)                      # a textbook-sized example
    c = encrypt(pk, 1299, k=853)
    print(f"p=2579 g=2 x=765 -> y={pk.y};  encrypt m=1299 with k=853: (c1, c2) = {c};  decrypt -> {decrypt(pk, x, c)}")
    print("fresh randomness -> different ciphertexts for the same message:", encrypt(pk, 1299) != encrypt(pk, 1299))

    c1, c2 = c
    print(f"\nMalleability: doubling c2 decrypts to 2m mod p = {decrypt(pk, x, (c1, 2 * c2 % pk.p))}"
          f" (2 * 1299 = 2598 = 19 mod {pk.p}); an attacker edits the plaintext without the key")

    m1, m2 = 1000, 777
    ca, cb = encrypt(pk, m1, k=1234), encrypt(pk, m2, k=1234)        # the mistake: same k twice
    recovered = cb[1] * modinv(ca[1], pk.p) * m1 % pk.p
    print(f"Nonce reuse: knowing m1={m1}, c2_b / c2_a * m1 = {recovered} == m2: {recovered == m2}"
          "  (the same flaw broke Sony's ECDSA signatures)")


if __name__ == "__main__":
    demo()
