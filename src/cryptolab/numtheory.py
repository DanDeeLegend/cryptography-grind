"""Number theory helpers shared by the public-key chapters (educational; not constant-time)."""
from __future__ import annotations

import secrets

_SMALL_PRIMES = [p for p in range(2, 200) if all(p % q for q in range(2, int(p ** 0.5) + 1))]


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclid: returns (g, x, y) with a*x + b*y = g = gcd(a, b)."""
    x0, y0, x1, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("no modular inverse: gcd(a, m) != 1")
    return x % m


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin. Error probability at most 4^-rounds for any composite."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int) -> int:
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1     # force the top bit and oddness
        if is_probable_prime(c):
            return c


def gen_safe_prime(bits: int) -> int:
    """p = 2q + 1 with q prime. Slow beyond a few hundred bits; real systems use standardised groups."""
    while True:
        q = gen_prime(bits - 1)
        if is_probable_prime(2 * q + 1):
            return 2 * q + 1
