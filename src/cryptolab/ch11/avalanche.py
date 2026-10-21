"""Assignment 11.1: the avalanche effect. Flip one input bit; a good hash flips about half of the output bits.

CRC32 and a byte-sum checksum are included as contrast: fine for accidents, useless as cryptographic hashes.
"""
from __future__ import annotations

import hashlib
import random
import zlib


def _sum32(data: bytes) -> bytes:
    return (sum(data) & 0xFFFFFFFF).to_bytes(4, "big")


HASHES = {
    "SHA-256": lambda b: hashlib.sha256(b).digest(),
    "SHA-1": lambda b: hashlib.sha1(b).digest(),
    "MD5": lambda b: hashlib.md5(b).digest(),
    "CRC32": lambda b: zlib.crc32(b).to_bytes(4, "big"),
    "byte-sum": _sum32,
}


def hamming(a: bytes, b: bytes) -> int:
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).bit_count()


def measure(name: str, trials: int = 2000, msg_len: int = 64, seed: int = 1) -> dict:
    h, rng = HASHES[name], random.Random(seed)
    ratios = []
    for _ in range(trials):
        m = bytearray(rng.randbytes(msg_len))
        base = h(bytes(m))
        bit = rng.randrange(msg_len * 8)
        m[bit // 8] ^= 1 << (bit % 8)
        ratios.append(hamming(base, h(bytes(m))) / (len(base) * 8))
    return {"hash": name, "mean": sum(ratios) / trials, "min": min(ratios), "max": max(ratios)}


def markdown(trials: int = 2000) -> str:
    rows = ["| Hash | Mean bits flipped | Min | Max |", "|---|---|---|---|"]
    for n in HASHES:
        r = measure(n, trials)
        rows.append(f"| {n} | {r['mean']:.1%} | {r['min']:.1%} | {r['max']:.1%} |")
    return "\n".join(rows)


if __name__ == "__main__":
    print(markdown())
