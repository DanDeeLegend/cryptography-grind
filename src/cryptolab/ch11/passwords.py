"""Assignment 11.4: password storage. Naive SHA-256 vs salted Argon2id, and what each costs an attacker.

Measured on ONE CPU thread. Real attackers use GPUs/ASICs: unsalted fast hashes get 10^9-10^10 guesses/s there. That is
not measured here; the ratio between fast and memory-hard hashing is the point.
"""
from __future__ import annotations

import hashlib
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# OWASP-style minimum: 19 MiB, t=2, p=1
ARGON = PasswordHasher(time_cost=2, memory_cost=19 * 1024, parallelism=1)


def naive_store(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def naive_check(password: str, stored: str) -> bool:
    return naive_store(password) == stored


def argon_store(password: str) -> str:
    return ARGON.hash(password)  # random salt + parameters are embedded in the encoded string


def argon_check(password: str, stored: str) -> bool:
    try:
        return ARGON.verify(stored, password)
    except VerifyMismatchError:
        return False


def rate(fn, seconds: float = 1.0) -> float:
    """Guesses per second on one thread."""
    n, end = 0, time.perf_counter() + seconds
    while time.perf_counter() < end:
        fn(n)
        n += 1
    return n / seconds


def crack_wordlist(stored: str, words: list[str], check) -> tuple[str | None, int]:
    for i, w in enumerate(words, 1):
        if check(w, stored):
            return w, i
    return None, len(words)


def comparison() -> dict:
    sha = rate(lambda i: hashlib.sha256(f"pw{i}".encode()).digest())
    arg = rate(lambda i: ARGON.hash(f"pw{i}"), 2.0)
    spaces = {"100,000-word list": 1e5, "8 chars, a-z0-9 (36^8)": 36.0**8, "8 chars, all printable (95^8)": 95.0**8}
    return {"sha256_per_s": sha, "argon2id_per_s": arg,
            "times": {k: (v / sha, v / arg) for k, v in spaces.items()}, "salt_demo": argon_store("x") != argon_store("x")}


def human(seconds: float) -> str:
    for unit, size in (("years", 31_557_600), ("days", 86_400), ("hours", 3600), ("min", 60)):
        if seconds >= size:
            return f"{seconds / size:,.1f} {unit}"
    return f"{seconds:,.2f} s"


def markdown() -> str:
    c = comparison()
    rows = [f"SHA-256: {c['sha256_per_s']:,.0f} guesses/s per thread; Argon2id (19 MiB, t=2): {c['argon2id_per_s']:,.0f}/s.\n",
            "| Search space | Naive SHA-256 | Argon2id |", "|---|---|---|"]
    for k, (a, b) in c["times"].items():
        rows.append(f"| {k} | {human(a)} | {human(b)} |")
    return "\n".join(rows)


if __name__ == "__main__":
    print(markdown())
