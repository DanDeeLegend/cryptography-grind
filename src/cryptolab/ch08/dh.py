"""Assignment 8.1: Diffie-Hellman key exchange.

Alice and Bob agree on a public group (prime p, generator g). Alice picks secret a and sends A = g^a mod p; Bob
picks b and sends B = g^b mod p. Each computes the same secret: B^a = g^(ab) = A^b (mod p). An eavesdropper sees
p, g, A, B and would need the discrete logarithm of A or B, which is infeasible in a large group (and trivial in a
small one, shown below with baby-step giant-step).
"""
from __future__ import annotations

import math
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptolab.numtheory import gen_safe_prime
from . import groups


@dataclass(frozen=True)
class Group:
    name: str
    p: int
    g: int
    prime_order_subgroup: bool = False       # True for the RFC 7919 groups: g = 2 generates the subgroup of order (p-1)/2

    @property
    def q(self) -> int:
        return (self.p - 1) // 2


TEXTBOOK = Group("textbook p=23", 23, 5)
FFDHE2048 = Group("ffdhe2048", groups.FFDHE2048_P, 2, True)
FFDHE3072 = Group("ffdhe3072", groups.FFDHE3072_P, 2, True)
FFDHE4096 = Group("ffdhe4096", groups.FFDHE4096_P, 2, True)


def private_key(group: Group) -> int:
    return secrets.randbelow(group.p - 3) + 2          # in [2, p-2]


def public_key(group: Group, a: int) -> int:
    return pow(group.g, a, group.p)


def validate_public(group: Group, y: int) -> None:
    """Reject values that force the shared secret into a tiny set (0, 1, p-1) or leave the intended subgroup."""
    if not 2 <= y <= group.p - 2:
        raise ValueError("invalid DH public value")
    if group.prime_order_subgroup and pow(y, group.q, group.p) != 1:
        raise ValueError("DH public value is not in the prime-order subgroup")


def shared_secret(group: Group, my_private: int, peer_public: int) -> int:
    validate_public(group, peer_public)
    return pow(peer_public, my_private, group.p)


def derive_key(secret: int, group: Group, info: bytes = b"dh-demo", length: int = 32) -> bytes:
    """Never use the raw shared secret as a key: run it through a KDF."""
    raw = secret.to_bytes((group.p.bit_length() + 7) // 8, "big")
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(raw)


def discrete_log(g: int, h: int, p: int, order: int) -> int:
    """Baby-step giant-step: solve g^x = h (mod p) in about sqrt(order) steps and sqrt(order) memory."""
    m = math.isqrt(order) + 1
    baby = {pow(g, j, p): j for j in range(m)}
    step = pow(g, -m, p)
    y = h
    for i in range(m + 1):
        if y in baby:
            return i * m + baby[y]
        y = y * step % p
    raise ValueError("no solution in this subgroup")


def demo() -> None:
    g = TEXTBOOK
    a, b = 6, 15
    A, B = public_key(g, a), public_key(g, b)
    print(f"textbook group p={g.p}, g={g.g}: Alice a={a} -> A={A};  Bob b={b} -> B={B}")
    print(f"  Alice computes B^a = {shared_secret(g, a, B)};  Bob computes A^b = {shared_secret(g, b, A)}")

    g = FFDHE2048
    a, b = private_key(g), private_key(g)
    A, B = public_key(g, a), public_key(g, b)
    ka, kb = derive_key(shared_secret(g, a, B), g), derive_key(shared_secret(g, b, A), g)
    print(f"\n{g.name}: keys equal: {ka == kb}  key = {ka.hex()[:32]}...")

    print("\nWhy group size matters: recover the private key from the public value with baby-step giant-step")
    p = gen_safe_prime(40)
    gen = pow(secrets.randbelow(p - 3) + 2, 2, p)       # a square generates the prime-order subgroup
    secret = secrets.randbelow(p // 2 - 2) + 1
    import time
    t0 = time.perf_counter()
    found = discrete_log(gen, pow(gen, secret, p), p, (p - 1) // 2)
    print(f"  40-bit prime: recovered exponent in {time.perf_counter() - t0:.2f}s, correct: {pow(gen, found, p) == pow(gen, secret, p)}"
          f"  (work ~ sqrt(2^39) = 2^20; a 2048-bit group needs ~2^1023 even for this generic attack)")


if __name__ == "__main__":
    demo()
