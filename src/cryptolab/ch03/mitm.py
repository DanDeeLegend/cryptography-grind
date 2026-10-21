"""Assignment 3.2: meet-in-the-middle attack on double encryption.

Double encryption C = E_k2(E_k1(P)) with two independent n-bit keys *looks* like a 2n-bit key. The
meet-in-the-middle attack shows it is not: encrypt P under every k1 and decrypt C under every k2,
and look for the same middle value. That costs about 2 * 2^n operations (plus 2^n memory), not 2^(2n).
Here the cipher is MiniDES (16-bit keys), so brute force is 2^32 and MITM is ~2^17.
"""
from __future__ import annotations

from . import mini_des as des

KEY_BITS = 16


def double_encrypt(p: int, k1: int, k2: int) -> int:
    return des.encrypt(des.encrypt(p, k1), k2)


def mitm_attack(pairs: list[tuple[int, int]]) -> tuple[list[tuple[int, int]], int]:
    """Return (candidate (k1, k2) pairs consistent with every known pair, number of cipher operations).

    A 16-bit block means one plaintext/ciphertext pair leaves ~2^16 false candidates (32-bit key space
    mapped onto a 16-bit check), so extra pairs filter them out.
    """
    p0, c0 = pairs[0]
    middle: dict[int, list[int]] = {}
    ops = 0
    for k1 in range(1 << KEY_BITS):                 # forward half: encrypt under every k1
        middle.setdefault(des.encrypt(p0, k1), []).append(k1)
        ops += 1
    found = []
    for k2 in range(1 << KEY_BITS):                 # backward half: decrypt under every k2
        ops += 1
        for k1 in middle.get(des.decrypt(c0, k2), ()):
            if all(double_encrypt(p, k1, k2) == c for p, c in pairs[1:]):
                found.append((k1, k2))
    return found, ops


def demo() -> None:
    k1, k2 = 0x3A5C, 0xB17E
    plaintexts = [0x1234, 0xBEEF, 0x0F0F, 0xA5A5]
    pairs = [(p, double_encrypt(p, k1, k2)) for p in plaintexts]
    found, ops = mitm_attack(pairs)
    print(f"true keys: k1={k1:#06x} k2={k2:#06x}")
    print(f"MITM with {len(pairs)} known pairs: {found}  after {ops:,} cipher operations (2^{ops.bit_length() - 1})")
    print(f"brute force over both keys would need up to {2 ** 32:,} double-encryptions (2^32)")
    print("Scaling to 2DES (56-bit keys): MITM ~ 2^57 operations, not 2^112; 3DES (3-key) ~ 2^112, not 2^168.")


if __name__ == "__main__":
    demo()
