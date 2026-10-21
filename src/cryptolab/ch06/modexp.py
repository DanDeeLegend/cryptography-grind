"""Assignment 6.2: modular exponentiation by square-and-multiply.

Computing a^e mod n by multiplying a by itself e times is hopeless for the exponents public-key crypto uses
(e has hundreds of bits). Square-and-multiply walks the *bits* of e from the top: square the running result for
every bit, and multiply by `a` when the bit is 1. That is about 1.5 * bits(e) multiplications instead of e.
"""
from __future__ import annotations


def square_and_multiply(base: int, exp: int, mod: int, trace: list | None = None) -> int:
    """Left-to-right binary exponentiation. If `trace` is a list, each step is appended as a row."""
    if mod == 1:
        return 0
    result, base = 1, base % mod
    for bit in bin(exp)[2:]:
        result = result * result % mod
        row = [bit, result]
        if bit == "1":
            result = result * base % mod
        row.append(result)
        if trace is not None:
            trace.append(tuple(row))
    return result


def operation_count(exp: int) -> int:
    """Modular multiplications used: one squaring per bit (the first is trivial) plus one per set bit."""
    return exp.bit_length() + bin(exp).count("1")


def worked_example(base: int = 7, exp: int = 13, mod: int = 11) -> str:
    trace: list = []
    result = square_and_multiply(base, exp, mod, trace)
    lines = [f"{base}^{exp} mod {mod}   (exponent {exp} = {bin(exp)[2:]} in binary)",
             "  bit | square | then multiply by base if bit = 1"]
    lines += [f"   {b}  | {sq:>6} | {after:>6}" for b, sq, after in trace]
    lines.append(f"result {result}   (library pow: {pow(base, exp, mod)}); "
                 f"{operation_count(exp)} multiplications instead of {exp - 1}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(worked_example())
    print()
    print(worked_example(5, 117, 19))
