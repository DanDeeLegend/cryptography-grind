"""Assignments 4.1 / 4.2 (from-scratch half): AES-128, written to be read.

State layout follows FIPS-197: 16 bytes, filled column by column, so state[r + 4*c] is row r, column c.
The S-box is *computed* (multiplicative inverse in GF(2^8), then an affine map) instead of typed in, which
shows where it comes from and removes the risk of a mistyped table.
Educational only: table lookups with secret indices leak through cache timing. Use a vetted library.
"""
from __future__ import annotations

from collections.abc import Callable

# ---- GF(2^8) arithmetic, modulus x^8 + x^4 + x^3 + x + 1 (0x11B) ----
def xtime(a: int) -> int:
    """Multiply by x (i.e. by 2) in GF(2^8)."""
    a <<= 1
    return (a ^ 0x11B) & 0xFF if a & 0x100 else a


_EXP, _LOG = [0] * 512, [0] * 256
_x = 1
for _i in range(255):                    # powers of the generator 3 cover every non-zero element
    _EXP[_i], _LOG[_x] = _x, _i
    _x ^= xtime(_x)
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def gmul(a: int, b: int) -> int:
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _rotl8(b: int, n: int) -> int:
    return ((b << n) | (b >> (8 - n))) & 0xFF


def _sbox_entry(a: int) -> int:
    inv = 0 if a == 0 else _EXP[255 - _LOG[a]]
    return inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63


SBOX = [_sbox_entry(a) for a in range(256)]
INV_SBOX = [0] * 256
for _a, _s in enumerate(SBOX):
    INV_SBOX[_s] = _a
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

State = list[int]


# ---- the four round transformations ----
def sub_bytes(s: State) -> State:
    return [SBOX[b] for b in s]


def inv_sub_bytes(s: State) -> State:
    return [INV_SBOX[b] for b in s]


def shift_rows(s: State) -> State:
    """Row r rotates left by r positions."""
    return [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]


def inv_shift_rows(s: State) -> State:
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[r + 4 * ((c + r) % 4)] = s[r + 4 * c]
    return out


def mix_columns(s: State) -> State:
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out += [gmul(2, a0) ^ gmul(3, a1) ^ a2 ^ a3, a0 ^ gmul(2, a1) ^ gmul(3, a2) ^ a3,
                a0 ^ a1 ^ gmul(2, a2) ^ gmul(3, a3), gmul(3, a0) ^ a1 ^ a2 ^ gmul(2, a3)]
    return out


def inv_mix_columns(s: State) -> State:
    out = []
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        out += [gmul(14, a0) ^ gmul(11, a1) ^ gmul(13, a2) ^ gmul(9, a3),
                gmul(9, a0) ^ gmul(14, a1) ^ gmul(11, a2) ^ gmul(13, a3),
                gmul(13, a0) ^ gmul(9, a1) ^ gmul(14, a2) ^ gmul(11, a3),
                gmul(11, a0) ^ gmul(13, a1) ^ gmul(9, a2) ^ gmul(14, a3)]
    return out


def add_round_key(s: State, rk: State) -> State:
    return [a ^ b for a, b in zip(s, rk)]


def expand_key(key: bytes) -> list[State]:
    """11 round keys (16 bytes each) for AES-128."""
    if len(key) != 16:
        raise ValueError("this implementation is AES-128: key must be 16 bytes")
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = w[i - 1][:]
        if i % 4 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]          # RotWord then SubWord
            t[0] ^= RCON[i // 4 - 1]
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(11)]


Step = Callable[[str, State], None]


def encrypt_block(block: bytes, key: bytes, on_step: Step | None = None) -> bytes:
    """Encrypt one 16-byte block. `on_step(label, state)` is called after every transformation."""
    note = on_step or (lambda *_: None)
    rks = expand_key(key)
    s = list(block)
    note("input", s)
    s = add_round_key(s, rks[0])
    note("round 0 add_round_key", s)
    for r in range(1, 10):
        s = sub_bytes(s); note(f"round {r} sub_bytes", s)
        s = shift_rows(s); note(f"round {r} shift_rows", s)
        s = mix_columns(s); note(f"round {r} mix_columns", s)
        s = add_round_key(s, rks[r]); note(f"round {r} add_round_key", s)
    s = sub_bytes(s); note("round 10 sub_bytes", s)
    s = shift_rows(s); note("round 10 shift_rows", s)
    s = add_round_key(s, rks[10]); note("round 10 add_round_key (ciphertext)", s)
    return bytes(s)


def decrypt_block(block: bytes, key: bytes) -> bytes:
    rks = expand_key(key)
    s = add_round_key(list(block), rks[10])
    for r in range(9, 0, -1):
        s = inv_sub_bytes(inv_shift_rows(s))
        s = inv_mix_columns(add_round_key(s, rks[r]))
    s = add_round_key(inv_sub_bytes(inv_shift_rows(s)), rks[0])
    return bytes(s)


def ecb_encrypt(data: bytes, key: bytes) -> bytes:
    if len(data) % 16:
        raise ValueError("ECB needs whole 16-byte blocks")
    return b"".join(encrypt_block(data[i:i + 16], key) for i in range(0, len(data), 16))


# ---- Assignment 4.1: the worked round (FIPS-197 Appendix B example) ----
def trace_first_round(plaintext: bytes, key: bytes) -> list[tuple[str, str]]:
    """Return (step, state-as-hex) for the input, the initial key addition and all of round 1."""
    steps: list[tuple[str, str]] = []
    wanted = ("input", "round 0", "round 1")
    encrypt_block(plaintext, key, lambda label, s: steps.append((label, bytes(s).hex()))
                  if label.startswith(wanted) else None)
    return steps


def grid(hexstate: str) -> str:
    """Render a state as the 4x4 matrix FIPS-197 draws (rows = r, columns = c)."""
    b = bytes.fromhex(hexstate)
    return "\n".join("  " + " ".join(f"{b[r + 4 * c]:02x}" for c in range(4)) for r in range(4))


def demo() -> None:
    pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    print("FIPS-197 Appendix B example. States shown as 4x4 matrices (columns are the input bytes in order).\n")
    for label, st in trace_first_round(pt, key):
        print(f"{label}: {st}\n{grid(st)}")
    print("\nround-1 key:", bytes(expand_key(key)[1]).hex())
    print("full ciphertext:", encrypt_block(pt, key).hex())


if __name__ == "__main__":
    demo()
