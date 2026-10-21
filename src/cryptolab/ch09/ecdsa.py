"""Assignment 9.6: ECDSA from scratch, and recovering the private key when a nonce is reused.

Sign:   r = x(kG) mod n,   s = k^-1 (z + r*d) mod n.        Verify: x(u1*G + u2*Q) = r with u1 = z/s, u2 = r/s.
The per-signature secret k MUST be unique and unpredictable. If two signatures share k (they then share r), the
algebra collapses:  s1 - s2 = k^-1 (z1 - z2)  =>  k = (z1 - z2)/(s1 - s2)  =>  d = (s1*k - z1)/r.
This is the flaw that exposed the PlayStation 3's firmware-signing key (2010): its signatures used a constant k.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

from . import ec
from .ec import Curve, Point


def hash_to_int(msg: bytes, n: int) -> int:
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    if n.bit_length() < 256:
        e >>= 256 - n.bit_length()                       # keep the leftmost bits, as the standard says
    return e % n


def keygen(c: Curve, d: int | None = None) -> tuple[int, Point]:
    d = d if d is not None else secrets.randbelow(c.n - 1) + 1
    return d, ec.scalar_mult(c, d, c.g)


def sign(c: Curve, d: int, msg: bytes, k: int | None = None) -> tuple[int, int]:
    z = hash_to_int(msg, c.n)
    while True:
        kk = k if k is not None else secrets.randbelow(c.n - 1) + 1
        r = ec.scalar_mult(c, kk, c.g)[0] % c.n
        s = pow(kk, -1, c.n) * (z + r * d) % c.n
        if r and s:
            return r, s
        if k is not None:
            raise ValueError("this nonce gives a degenerate signature")


def verify(c: Curve, q: Point, msg: bytes, sig: tuple[int, int]) -> bool:
    r, s = sig
    if not (0 < r < c.n and 0 < s < c.n):
        return False
    z, w = hash_to_int(msg, c.n), pow(s, -1, c.n)
    x = ec.add(c, ec.scalar_mult(c, z * w % c.n, c.g), ec.scalar_mult(c, r * w % c.n, q))
    return x is not None and x[0] % c.n == r


def recover_key_from_nonce_reuse(c: Curve, m1: bytes, sig1, m2: bytes, sig2) -> int:
    (r1, s1), (r2, s2) = sig1, sig2
    if r1 != r2:
        raise ValueError("different r: these signatures did not reuse a nonce")
    z1, z2 = hash_to_int(m1, c.n), hash_to_int(m2, c.n)
    if (s1 - s2) % c.n == 0 or (z1 - z2) % c.n == 0:
        raise ValueError("degenerate pair (identical messages or signatures)")
    k = (z1 - z2) * pow(s1 - s2, -1, c.n) % c.n
    return (s1 * k - z1) * pow(r1, -1, c.n) % c.n


def deterministic_k(c: Curve, d: int, msg: bytes) -> int:
    """The fix, in the spirit of RFC 6979: derive k from (private key, message) with HMAC, so it needs no RNG, never
    repeats for different messages and never leaks through a bad RNG. (Simplified: the real RFC uses an HMAC-DRBG loop.)"""
    key, z, counter = d.to_bytes((c.n.bit_length() + 7) // 8, "big"), hash_to_int(msg, c.n).to_bytes(32, "big"), 0
    while True:
        k = int.from_bytes(hmac.new(key, z + bytes([counter]), hashlib.sha256).digest(), "big") % c.n
        if k:
            return k
        counter += 1


def demo() -> None:
    for c in (ec.TOY, ec.P256):
        d, q = keygen(c)
        m1, m2 = b"firmware v1.0 (signed)", b"firmware v1.1 (signed)"
        k = secrets.randbelow(c.n - 1) + 1                 # the bug: the same nonce for both signatures
        s1, s2 = sign(c, d, m1, k), sign(c, d, m2, k)
        ok = verify(c, q, m1, s1) and verify(c, q, m2, s2)
        got = recover_key_from_nonce_reuse(c, m1, s1, m2, s2)
        print(f"{c.name}: signatures valid: {ok}; r1 == r2: {s1[0] == s2[0]}; private key recovered: {got == d}")
        forged = sign(c, got, b"malicious firmware", None)
        print(f"   attacker now signs new code that verifies: {verify(c, q, b'malicious firmware', forged)}")
    d = ec.TOY.n // 3
    print("deterministic nonces differ per message:", deterministic_k(ec.TOY, d, b"a") != deterministic_k(ec.TOY, d, b"b"))


if __name__ == "__main__":
    demo()
