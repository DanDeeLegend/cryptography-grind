"""Assignment 11.2: birthday collisions on a truncated hash, two ways.

Table method: remember every hash seen (memory ~ 2^(k/2)). Floyd/Pollard-rho method: iterate x -> H(x) and detect the
cycle with two pointers (memory O(1)). Both need on the order of 2^(k/2) evaluations, not 2^k.
"""
from __future__ import annotations

import hashlib
import statistics


def trunc_hash(data: bytes, bits: int) -> int:
    return int.from_bytes(hashlib.sha256(data).digest(), "big") >> (256 - bits)


def table_collision(bits: int, seed: int) -> tuple[bytes, bytes, int]:
    seen: dict[int, bytes] = {}
    i = 0
    while True:
        m = f"{seed}:{i}".encode()
        h = trunc_hash(m, bits)
        if h in seen:
            return seen[h], m, i + 1
        seen[h] = m
        i += 1


def floyd_collision(bits: int, seed: int) -> tuple[bytes, bytes, int]:
    """Collision on f(x) = H(x) restricted to bits-bit strings; inputs are the byte encodings of k-bit values."""
    nbytes = (bits + 7) // 8

    def f(x: int) -> int:
        return trunc_hash(x.to_bytes(nbytes, "big"), bits)

    evals = 0
    x0 = seed % (1 << bits)
    tort, hare = f(x0), f(f(x0))
    evals += 3
    while tort != hare:
        tort, hare = f(tort), f(f(hare))
        evals += 3
    # find the cycle entry: the two predecessors there are the colliding inputs
    tort = x0
    prev_t = prev_h = None
    while tort != hare:
        prev_t, prev_h = tort, hare
        tort, hare = f(tort), f(hare)
        evals += 2
    if prev_t is None:  # x0 itself is on the cycle: no tail, so no collision found from this start
        raise ValueError("start point is on the cycle")
    return prev_t.to_bytes(nbytes, "big"), prev_h.to_bytes(nbytes, "big"), evals


def experiment(bits_list=(16, 20, 24, 28, 32), trials: int = 20) -> list[dict]:
    out = []
    for bits in bits_list:
        t = [table_collision(bits, s)[2] for s in range(trials)]
        f, s = [], 0
        while len(f) < trials:
            s += 1
            try:
                f.append(floyd_collision(bits, s)[2])
            except ValueError:
                continue
        out.append({"bits": bits, "table_mean": statistics.mean(t), "floyd_mean": statistics.mean(f), "sqrt_2k": 2 ** (bits / 2)})
    return out


def markdown() -> str:
    rows = ["| Hash bits | 2^(k/2) | Table method (mean evals) | Floyd method (mean evals) |", "|---|---|---|---|"]
    for r in experiment():
        rows.append(f"| {r['bits']} | {r['sqrt_2k']:,.0f} | {r['table_mean']:,.0f} | {r['floyd_mean']:,.0f} |")
    return "\n".join(rows)


if __name__ == "__main__":
    print(markdown())
