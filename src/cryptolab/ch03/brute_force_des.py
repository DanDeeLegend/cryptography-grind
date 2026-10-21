"""Assignment 3.4: brute-force a reduced-key cipher, time it, extrapolate to full DES.

Real DES (PyCryptodome) with all but `unknown_bits` of the 56 effective key bits fixed. Searching that
reduced space is exactly the DES attack on a smaller scale, so the measured keys/second extrapolates
directly: full DES needs 2^55 trials on average. Python is far slower than hardware; the *scaling* is
the point, not the absolute speed.
"""
from __future__ import annotations

import os
import time

from Crypto.Cipher import DES


def key_from_index(base_key: bytes, index: int, unknown_bits: int) -> bytes:
    """Place the `unknown_bits` low bits of `index` into the key's non-parity bits (7 per byte)."""
    key = bytearray(base_key)
    for i in range(unknown_bits):
        byte, bit = divmod(i, 7)
        if (index >> i) & 1:
            key[byte] |= 1 << (bit + 1)        # bit 0 of each DES key byte is a parity bit: skip it
        else:
            key[byte] &= ~(1 << (bit + 1)) & 0xFF
    return bytes(key)


def crack(plaintext: bytes, ciphertext: bytes, base_key: bytes, unknown_bits: int) -> tuple[bytes, int]:
    """Try every candidate; return (key, number_of_trials)."""
    for i in range(1 << unknown_bits):
        key = key_from_index(base_key, i, unknown_bits)
        if DES.new(key, DES.MODE_ECB).encrypt(plaintext) == ciphertext:
            return key, i + 1
    raise ValueError("key not found")


def measure(unknown_bits: int, seed_index: int | None = None) -> dict:
    base = os.urandom(8)
    secret_index = (1 << unknown_bits) - 1 if seed_index is None else seed_index   # worst case: last key
    secret = key_from_index(base, secret_index, unknown_bits)
    pt = b"ATTACK!!"
    ct = DES.new(secret, DES.MODE_ECB).encrypt(pt)
    t0 = time.perf_counter()
    key, trials = crack(pt, ct, base, unknown_bits)
    dt = time.perf_counter() - t0
    assert DES.new(key, DES.MODE_ECB).encrypt(pt) == ct
    return {"bits": unknown_bits, "trials": trials, "seconds": dt, "keys_per_sec": trials / dt}


def extrapolate(keys_per_sec: float, bits: int = 56) -> str:
    seconds = (2 ** (bits - 1)) / keys_per_sec
    years = seconds / (365.25 * 24 * 3600)
    return f"{years:,.0f} years" if years >= 1 else f"{seconds / 86400:,.1f} days"


def demo() -> None:
    print("bits  trials        seconds   keys/s")
    last = None
    for bits in (12, 16, 20, 22):
        m = measure(bits)
        last = m
        print(f"{bits:>4}  {m['trials']:>9,}  {m['seconds']:>9.2f}  {m['keys_per_sec']:>9,.0f}")
    print(f"\nExtrapolation to 56-bit DES at {last['keys_per_sec']:,.0f} keys/s (single Python process):")
    print(f"  average (2^55 trials): {extrapolate(last['keys_per_sec'])}")
    print(f"  doubling per bit: 22 -> 56 bits multiplies the 22-bit time by 2^34 = {2 ** 34:,}")


if __name__ == "__main__":
    demo()
