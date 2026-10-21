"""Assignment 7.6: recover RSA private keys from public moduli that share a prime factor.

If two moduli n1 = p*q1 and n2 = p*q2 share a prime p, then gcd(n1, n2) = p, and both are factored instantly
(no hard problem solved). This happened at internet scale when devices with too little randomness at first
boot generated keys from the same pools of primes. Here: pairwise GCD, and Bernstein's batch-GCD (product tree +
remainder tree) which handles many keys at once, run on a toy "device fleet" with a weak random generator.
"""
from __future__ import annotations

import random
from math import gcd

from cryptolab.numtheory import gen_prime, is_probable_prime, modinv


def recover_private_key(n: int, p: int, e: int = 65537) -> int:
    q = n // p
    return modinv(e, (p - 1) * (q - 1))


def pairwise(moduli: list[int]) -> dict[int, int]:
    """index -> a shared prime factor, for every modulus that shares one with any other. O(n^2) gcds."""
    found: dict[int, int] = {}
    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            g = gcd(moduli[i], moduli[j])
            if 1 < g < moduli[i]:
                found.setdefault(i, g)
                found.setdefault(j, g)
    return found


def batch_gcd(moduli: list[int]) -> dict[int, int]:
    """Same answer as `pairwise`, in quasi-linear time: gcd(n_i, (prod of all) / n_i) via a remainder tree."""
    tree = [moduli[:]]
    while len(tree[-1]) > 1:
        lvl = tree[-1]
        tree.append([lvl[i] * lvl[i + 1] if i + 1 < len(lvl) else lvl[i] for i in range(0, len(lvl), 2)])
    rem = tree[-1]
    for lvl in reversed(tree[:-1]):                       # push P mod (node^2) down to the leaves
        rem = [rem[i // 2] % (lvl[i] ** 2) for i in range(len(lvl))]
    out = {}
    for i, n in enumerate(moduli):
        g = gcd(rem[i] // n, n)
        if g == n:
            # Both primes of n appear elsewhere (possibly in different moduli): the tree only says "n is
            # fully covered", so split it by gcd-ing against the others. Exact duplicates share the whole key
            # and cannot be factored this way (they are reported separately by `duplicates`).
            g = next((h for m in moduli if m != n and 1 < (h := gcd(n, m)) < n), 1)
        if 1 < g < n:
            out[i] = g
    return out


def duplicates(moduli: list[int]) -> list[int]:
    """Indices of moduli that appear more than once: identical keys, a failure of its own."""
    seen: dict[int, int] = {}
    for n in moduli:
        seen[n] = seen.get(n, 0) + 1
    return [i for i, n in enumerate(moduli) if seen[n] > 1]


def weak_fleet(devices: int, prime_bits: int = 48, pool_size: int = 40, seed: int = 7) -> tuple[list[int], list[tuple[int, int]]]:
    """Devices that draw primes from a small pool (a stand-in for a low-entropy RNG), some from a good one."""
    rng = random.Random(seed)
    pool = [gen_prime(prime_bits) for _ in range(pool_size)]
    moduli, factors = [], []
    for _ in range(devices):
        if rng.random() < 0.5:                            # weak boot: both primes come from the shared pool
            p, q = rng.sample(pool, 2)
        else:                                             # healthy device: fresh random primes
            p, q = gen_prime(prime_bits), gen_prime(prime_bits)
        moduli.append(p * q)
        factors.append((p, q))
    return moduli, factors


def demo() -> None:
    p, q1, q2 = gen_prime(64), gen_prime(64), gen_prime(64)
    n1, n2 = p * q1, p * q2
    g = gcd(n1, n2)
    print(f"two 128-bit moduli sharing a prime: gcd(n1, n2) = {g}  (== p: {g == p})")
    print(f"  n1 = {g} * {n1 // g};  n2 = {g} * {n2 // g}  -> both private keys recovered without factoring anything hard")
    m = 123456789
    c = pow(m, 65537, n1)
    print(f"  intercepted ciphertext for n1 decrypts to {pow(c, recover_private_key(n1, g), n1)}")

    import time
    moduli, _ = weak_fleet(600)
    t0 = time.perf_counter(); a = pairwise(moduli); t_pair = time.perf_counter() - t0
    t0 = time.perf_counter(); b = batch_gcd(moduli); t_batch = time.perf_counter() - t0
    print(f"\nfleet of {len(moduli)} devices: {len(a)} keys share a prime ({len(a) / len(moduli):.0%}); "
          f"pairwise {t_pair * 1e3:.0f} ms vs batch GCD {t_batch * 1e3:.0f} ms; same set: {set(a) == set(b)}")


if __name__ == "__main__":
    demo()
