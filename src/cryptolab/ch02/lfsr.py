"""Assignment 2.2: an LFSR keystream generator, and recovering it from a few keystream bits.

An LFSR with a linear recurrence s[n] = XOR of s[n-i] for i in `taps` is linear over GF(2), so it is
only as strong as its size: the Berlekamp-Massey algorithm finds the shortest LFSR that produces ANY
observed bit sequence from just 2L bits (L = register length). Known plaintext gives the attacker
keystream bits (keystream = ciphertext XOR plaintext), so the rest of the message falls.
"""
from __future__ import annotations

# Lags for x^16 + x^5 + x^3 + x^2 + 1, a primitive polynomial: period 2^16 - 1 = 65535.
TAPS16 = (16, 14, 13, 11)


class LFSR:
    def __init__(self, taps: tuple[int, ...], seed: list[int]):
        if len(seed) != max(taps) or not any(seed):
            raise ValueError("seed must have max(taps) bits and not be all zero")
        self.taps, self.s = taps, list(seed)

    def bits(self, n: int) -> list[int]:
        s, out = self.s, []
        for _ in range(n):
            out.append(s[0])
            fb = 0
            for t in self.taps:
                fb ^= s[len(s) - t]
            s.pop(0)
            s.append(fb)
        return out


def bits_to_bytes(bits: list[int]) -> bytes:
    return bytes(sum(b << (7 - i) for i, b in enumerate(bits[j:j + 8])) for j in range(0, len(bits) - 7, 8))


def bytes_to_bits(data: bytes) -> list[int]:
    return [(byte >> (7 - i)) & 1 for byte in data for i in range(8)]


def encrypt(plaintext: bytes, taps: tuple[int, ...], seed: list[int]) -> bytes:
    ks = bits_to_bytes(LFSR(taps, seed).bits(8 * len(plaintext)))
    return bytes(p ^ k for p, k in zip(plaintext, ks))


def berlekamp_massey(s: list[int]) -> tuple[int, list[int]]:
    """Shortest LFSR for bit sequence s. Returns (L, c) with s[n] = XOR_{i=1..L} c[i]*s[n-i]."""
    c, b, L, m = [1], [1], 0, 1
    for n in range(len(s)):
        d = s[n]
        for i in range(1, L + 1):
            if i < len(c):
                d ^= c[i] & s[n - i]
        if d == 0:
            m += 1
            continue
        t = c[:]
        c = c + [0] * max(0, len(b) + m - len(c))
        for i, bi in enumerate(b):
            c[i + m] ^= bi
        if 2 * L <= n:
            L, b, m = n + 1 - L, t, 1
        else:
            m += 1
    return L, (c + [0] * (L + 1))[:L + 1]


def predict(known: list[int], c: list[int], count: int) -> list[int]:
    """Continue a sequence using the recovered recurrence."""
    L, out = len(c) - 1, list(known)
    for _ in range(count):
        n = len(out)
        out.append(sum(c[i] & out[n - i] for i in range(1, L + 1)) & 1)
    return out[len(known):]


def known_plaintext_attack(ciphertext: bytes, known_plaintext: bytes) -> tuple[bytes, int, list[int]]:
    """Given a ciphertext and its first bytes of plaintext, decrypt the whole message."""
    ks = [c ^ p for c, p in zip(bytes_to_bits(ciphertext), bytes_to_bits(known_plaintext))]
    L, c = berlekamp_massey(ks)
    rest = predict(ks, c, 8 * len(ciphertext) - len(ks))
    keystream = bits_to_bytes(ks + rest)
    return bytes(a ^ b for a, b in zip(ciphertext, keystream)), L, c


def demo() -> None:
    seed = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1]
    msg = b"Stream ciphers built from one LFSR are not secure!"
    ct = encrypt(msg, TAPS16, seed)
    known = msg[:6]  # 48 known bits >= 2L = 32
    plain, L, c = known_plaintext_attack(ct, known)
    print(f"Attacker knows only the first {len(known)} plaintext bytes ({8 * len(known)} keystream bits).")
    print(f"Berlekamp-Massey: register length L = {L}, taps (lags) = {[i for i in range(1, L + 1) if c[i]]}")
    print("Recovered plaintext:", plain)


if __name__ == "__main__":
    demo()
