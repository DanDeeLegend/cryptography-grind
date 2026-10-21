"""Assignment 3.1: a toy DES-style Feistel cipher and a step-by-step trace of one round.

MiniDES keeps DES's round structure at a size you can follow by hand: a 16-bit block split into two
8-bit halves, 4 rounds, 12-bit round keys. Each round does what DES does:
    expansion (8 -> 12 bits) -> key mixing (XOR) -> S-boxes (2 x 6 -> 4 bits) -> permutation (8 bits)
and then the Feistel step  L', R' = R, L XOR F(R, K).
The two S-boxes are DES's real S1 and S2 (the toy only shrinks the sizes around them).
"""
from __future__ import annotations

SBOX1 = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]
SBOX2 = [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]]
EXPANSION = [8, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 1]      # 1-indexed bit positions of the 8-bit input, MSB first
PERMUTATION = [2, 6, 3, 1, 4, 8, 5, 7]
ROUNDS = 4


def _pick(value: int, width: int, positions: list[int]) -> int:
    """Build a number from the listed 1-indexed bit positions (MSB first) of `value`."""
    out = 0
    for p in positions:
        out = (out << 1) | ((value >> (width - p)) & 1)
    return out


def sbox(box: list[list[int]], six: int) -> int:
    row = ((six >> 5) << 1) | (six & 1)            # outer bits choose the row
    col = (six >> 1) & 0xF                        # middle four bits choose the column
    return box[row][col]


def expand(r: int) -> int:
    return _pick(r, 8, EXPANSION)


# Precomputed tables so bulk attacks are fast: SP[x] = P(S1(x_hi6) || S2(x_lo6)) for a 12-bit x.
_EXP = [expand(r) for r in range(256)]
_SP = [_pick((sbox(SBOX1, x >> 6) << 4) | sbox(SBOX2, x & 0x3F), 8, PERMUTATION) for x in range(4096)]


def round_keys(key: int, rounds: int = ROUNDS) -> list[int]:
    """12-bit round keys: rotate the 16-bit key left by 3 bits per round and keep the top 12 bits."""
    keys = []
    for i in range(rounds):
        rot = ((key << (3 * i)) | (key >> (16 - 3 * i))) & 0xFFFF if i else key
        keys.append(rot >> 4)
    return keys


def f(r: int, k: int) -> int:
    return _SP[_EXP[r] ^ k]


def encrypt(block: int, key: int, rounds: int = ROUNDS) -> int:
    left, right = block >> 8, block & 0xFF
    for k in round_keys(key, rounds):
        left, right = right, left ^ f(right, k)
    return (right << 8) | left                      # final swap, as in DES


def decrypt(block: int, key: int, rounds: int = ROUNDS) -> int:
    left, right = block >> 8, block & 0xFF
    for k in reversed(round_keys(key, rounds)):
        left, right = right, left ^ f(right, k)
    return (right << 8) | left


def trace_round(left: int, right: int, k: int) -> list[tuple[str, str]]:
    """Every intermediate value of one Feistel round, as (step, value) lines."""
    e = expand(right)
    x = e ^ k
    s1_in, s2_in = x >> 6, x & 0x3F
    s1, s2 = sbox(SBOX1, s1_in), sbox(SBOX2, s2_in)
    s_out = (s1 << 4) | s2
    p_out = _pick(s_out, 8, PERMUTATION)
    return [
        ("L (8 bits)", f"{left:08b}"), ("R (8 bits)", f"{right:08b}"), ("round key K (12 bits)", f"{k:012b}"),
        ("1. expansion E(R) (12 bits)", f"{e:012b}"), ("2. key mixing E(R) XOR K", f"{x:012b}"),
        ("3. S1 input / row,col", f"{s1_in:06b}  row {((s1_in >> 5) << 1) | (s1_in & 1)} col {(s1_in >> 1) & 15}"),
        ("   S1 output (4 bits)", f"{s1:04b}"),
        ("3. S2 input / row,col", f"{s2_in:06b}  row {((s2_in >> 5) << 1) | (s2_in & 1)} col {(s2_in >> 1) & 15}"),
        ("   S2 output (4 bits)", f"{s2:04b}"), ("4. permutation P(S1||S2) = F(R,K)", f"{p_out:08b}"),
        ("5. new R = L XOR F(R,K)", f"{left ^ p_out:08b}"), ("   new L = old R", f"{right:08b}"),
    ]


def demo() -> None:
    key, block = 0b1010_0110_1100_0011, 0b1101_0010_0111_1001
    l, r = block >> 8, block & 0xFF
    print(f"plaintext {block:016b}  key {key:016b}  round-1 key {round_keys(key)[0]:012b}\n")
    for step, value in trace_round(l, r, round_keys(key)[0]):
        print(f"  {step:38s} {value}")
    c = encrypt(block, key)
    print(f"\nfull {ROUNDS}-round ciphertext {c:016b}; decrypts back: {decrypt(c, key) == block}")


if __name__ == "__main__":
    demo()
