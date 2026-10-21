"""Assignment 7.4: naive repeated multiplication vs square-and-multiply for RSA-sized numbers.

Naive: multiply `base` into an accumulator e-1 times (mod n). Square-and-multiply: about 1.5 * bits(e). Both
are timed with a 2048-bit modulus. Naive cannot even be run for a 2048-bit private exponent, so its time is
extrapolated from the measured per-multiplication cost.
"""
from __future__ import annotations

import math
import random
import time


def naive_pow(base: int, exp: int, mod: int) -> int:
    result = 1
    for _ in range(exp):
        result = result * base % mod
    return result


def square_and_multiply(base: int, exp: int, mod: int) -> int:
    result = 1
    for bit in bin(exp)[2:]:
        result = result * result % mod
        if bit == "1":
            result = result * base % mod
    return result


def _time(fn, *args, repeats: int = 1) -> float:
    t0 = time.perf_counter()
    for _ in range(repeats):
        fn(*args)
    return (time.perf_counter() - t0) / repeats


def run(exp_bits=(8, 12, 16, 17, 20, 22), mod_bits: int = 2048, seed: int = 1) -> dict:
    rng = random.Random(seed)
    n = rng.getrandbits(mod_bits) | (1 << (mod_bits - 1)) | 1
    base = rng.getrandbits(mod_bits - 8)
    rows = []
    for bits in exp_bits:
        e = 65537 if bits == 17 else (1 << (bits - 1)) | rng.getrandbits(bits - 1) | 1
        t_naive = _time(naive_pow, base, e, n)
        t_sm = _time(square_and_multiply, base, e, n, repeats=50)
        assert naive_pow(base, e, n) == square_and_multiply(base, e, n) == pow(base, e, n)
        rows.append({"exp_bits": bits, "exp": e, "naive_s": t_naive, "sm_s": t_sm, "naive_mults": e})
    per_mult = rows[-1]["naive_s"] / rows[-1]["naive_mults"]
    d = rng.getrandbits(mod_bits) | (1 << (mod_bits - 1)) | 1
    sm_private = _time(square_and_multiply, base, d, n, repeats=3)
    log10_years = 2047 * math.log10(2) + math.log10(per_mult) - math.log10(365.25 * 24 * 3600)
    return {"rows": rows, "per_mult_us": per_mult * 1e6, "sm_private_ms": sm_private * 1e3, "naive_private_log10_years": log10_years}


def markdown(r: dict) -> str:
    out = ["| Exponent bits | exponent | naive mults | naive time | square-and-multiply | speed-up |", "|---:|---:|---:|---:|---:|---:|"]
    for x in r["rows"]:
        out.append(f"| {x['exp_bits']} | {x['exp']:,} | {x['naive_mults']:,} | {x['naive_s'] * 1e3:,.1f} ms | "
                   f"{x['sm_s'] * 1e6:,.0f} us | {x['naive_s'] / x['sm_s']:,.0f}x |")
    out.append(f"\n2048-bit modulus; one modular multiplication = {r['per_mult_us']:.2f} us.")
    out.append(f"Square-and-multiply with a **2048-bit private exponent**: {r['sm_private_ms']:.1f} ms.")
    out.append(f"Naive with the same exponent: about 2^2047 multiplications = ~10^{r['naive_private_log10_years']:.0f} years.")
    return "\n".join(out)


if __name__ == "__main__":
    print(markdown(run()))
