"""Assignment 1.4: brute-force feasibility calculator.

Time to search a key space of 2^bits keys given an attacker's guesses per second. Worst case tries
every key; on average the key is found halfway through (2^(bits-1) guesses).

The attacker rates are ILLUSTRATIVE ROUND NUMBERS chosen to span orders of magnitude, not measurements
of any real system. Change them to model a specific adversary.
"""
from __future__ import annotations

import math

ATTACKERS = {
    "1 GPU (1e9 keys/s)": 1e9,
    "Cloud cluster (1e12 keys/s)": 1e12,
    "Nation-state (1e18 keys/s)": 1e18,
}
KEY_SIZES = (40, 56, 64, 80, 128, 256)
YEAR = 365.25 * 24 * 3600
AGE_OF_UNIVERSE = 13.8e9 * YEAR


def brute_force_seconds(bits: int, guesses_per_second: float) -> tuple[float, float]:
    """Return (worst_case_seconds, average_seconds)."""
    worst = 2.0 ** bits / guesses_per_second
    return worst, worst / 2


def human(seconds: float) -> str:
    if seconds < 1:
        return "<1 second"
    for unit, size in (("seconds", 1), ("minutes", 60), ("hours", 3600), ("days", 86400)):
        nxt = {"seconds": 60, "minutes": 3600, "hours": 86400, "days": YEAR}[unit]
        if seconds < nxt:
            return f"{seconds / size:,.1f} {unit}"
    years = seconds / YEAR
    if seconds > AGE_OF_UNIVERSE:
        return f"{seconds / AGE_OF_UNIVERSE:.1e} x age of universe"
    return f"{years:,.1f} years" if years < 1e6 else f"{years:.1e} years"


def table() -> str:
    lines = ["| Key bits | " + " | ".join(f"{a} (avg)" for a in ATTACKERS) + " |",
             "|---|" + "---|" * len(ATTACKERS)]
    for bits in KEY_SIZES:
        cells = [human(brute_force_seconds(bits, rate)[1]) for rate in ATTACKERS.values()]
        lines.append(f"| {bits} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def chart(rate: float = 1e12) -> str:
    """ASCII bar chart of log10(average seconds) for one attacker."""
    out = []
    for bits in KEY_SIZES:
        log_s = math.log10(brute_force_seconds(bits, rate)[1])
        bar = "#" * max(int(log_s + 10), 0)  # shift so sub-second bars are visible
        out.append(f"{bits:>3} bits  10^{log_s:+6.1f} s  {bar}")
    return "\n".join(out)


if __name__ == "__main__":
    print(table())
    print("\nlog10(average seconds) at 1e12 keys/s:")
    print(chart())
