"""Assignment 1.1: break Caesar and general monoalphabetic substitution ciphers with letter statistics.

Caesar has only 26 keys, so a chi-squared test against English letter frequencies is enough.
Substitution has 26! keys (~2^88), far too many to try, but the cipher preserves the statistics of the
language, so hill-climbing on a trigram score recovers the key from the ciphertext alone.
"""
from __future__ import annotations

import math
import random
import string
from collections import Counter

from .corpus import TRAIN

A = string.ascii_lowercase
# Standard English letter frequencies (percent), a-z.
ENGLISH_FREQ = [8.17, 1.49, 2.78, 4.25, 12.70, 2.23, 2.02, 6.09, 6.97, 0.15, 0.77, 4.03, 2.41,
                6.75, 7.51, 1.93, 0.10, 5.99, 6.33, 9.06, 2.76, 0.98, 2.36, 0.15, 1.97, 0.07]


def clean(text: str) -> str:
    """Lower-case letters only; the attacks work on the letter stream."""
    return "".join(c for c in text.lower() if c in A)


# ---------- Caesar ----------
def caesar(text: str, shift: int) -> str:
    return "".join(A[(A.index(c) + shift) % 26] for c in clean(text))


def caesar_break(ciphertext: str) -> tuple[int, str]:
    """Return (key, plaintext). Picks the shift whose letter counts best match English (chi-squared)."""
    ct = clean(ciphertext)
    n = len(ct)
    counts = Counter(ct)
    best_shift, best_chi = 0, math.inf
    for shift in range(26):
        # Undoing `shift` maps ciphertext letter (i + shift) back to plaintext letter i.
        chi = sum((counts[A[(i + shift) % 26]] - n * ENGLISH_FREQ[i] / 100) ** 2 / (n * ENGLISH_FREQ[i] / 100)
                  for i in range(26))
        if chi < best_chi:
            best_shift, best_chi = shift, chi
    return best_shift, caesar(ct, -best_shift)


# ---------- Monoalphabetic substitution ----------
def substitute(text: str, key: str) -> str:
    """key[i] is the cipher letter that replaces plaintext letter A[i]."""
    table = {p: c for p, c in zip(A, key)}
    return "".join(table[c] for c in clean(text))


def random_key(rng: random.Random) -> str:
    letters = list(A)
    rng.shuffle(letters)
    return "".join(letters)


class TrigramModel:
    """Log-probability of letter triples, learned from the training corpus.

    A small corpus makes trigram counts sparse, so each probability blends three estimates
    (interpolation): trigram, bigram and single-letter frequency. Dense low-order statistics rescue the
    sparse high-order ones.
    """

    def __init__(self, text: str = TRAIN, weights=(0.55, 0.35, 0.10)):
        t = clean(text)
        n = len(t)
        uni, bi, tri = Counter(t), Counter(zip(t, t[1:])), Counter(zip(t, t[1:], t[2:]))
        w3, w2, w1 = weights
        idx = {c: i for i, c in enumerate(A)}
        self.table = [0.0] * 26 ** 3
        for a in A:
            for b in A:
                for c in A:
                    p3 = tri[(a, b, c)] / bi[(a, b)] if bi[(a, b)] else 0.0
                    p2 = bi[(b, c)] / uni[b] if uni[b] else 0.0
                    p1 = uni[c] / n
                    p = max(w3 * p3 + w2 * p2 + w1 * p1, 1e-7)
                    self.table[(idx[a] * 26 + idx[b]) * 26 + idx[c]] = math.log(p)

    def score(self, nums: list[int]) -> float:
        t = self.table
        return sum(t[(a * 26 + b) * 26 + c] for a, b, c in zip(nums, nums[1:], nums[2:]))


_MODEL: TrigramModel | None = None


def _model() -> TrigramModel:
    global _MODEL
    if _MODEL is None:
        _MODEL = TrigramModel()
    return _MODEL


def _initial_key(ct_nums: list[int]) -> list[int]:
    """Guess by frequency rank: most common cipher letter -> most common English letter, and so on."""
    ranked_cipher = [c for c, _ in Counter(ct_nums).most_common()] + [c for c in range(26) if c not in ct_nums]
    ranked_plain = sorted(range(26), key=lambda i: -ENGLISH_FREQ[i])
    dec = [0] * 26
    for c, p in zip(ranked_cipher, ranked_plain):
        dec[c] = p
    return dec


def substitution_break(ciphertext: str, restarts: int = 6, seed: int = 0) -> tuple[str, str]:
    """Return (decryption_alphabet, plaintext): dec[i] is the plaintext letter for cipher letter A[i]."""
    ct = [A.index(c) for c in clean(ciphertext)]
    model, rng = _model(), random.Random(seed)
    best_dec, best_score = None, -math.inf
    for r in range(restarts):
        dec = _initial_key(ct)
        if r:  # later restarts start from a perturbed key to escape local optima
            for _ in range(8 + 2 * r):
                i, j = rng.sample(range(26), 2)
                dec[i], dec[j] = dec[j], dec[i]
        score = model.score([dec[c] for c in ct])
        improved = True
        while improved:
            improved = False
            for i in range(25):
                for j in range(i + 1, 26):
                    dec[i], dec[j] = dec[j], dec[i]
                    s = model.score([dec[c] for c in ct])
                    if s > score:
                        score, improved = s, True
                    else:
                        dec[i], dec[j] = dec[j], dec[i]
        if score > best_score:
            best_dec, best_score = dec[:], score
    return "".join(A[d] for d in best_dec), "".join(A[best_dec[c]] for c in ct)


def accuracy(guess: str, truth: str) -> float:
    return sum(a == b for a, b in zip(guess, truth)) / max(len(truth), 1)


def characters_needed(plaintext: str, lengths=(50, 100, 150, 200, 300, 400, 600), trials: int = 5,
                      threshold: float = 0.95) -> list[tuple[int, float, float]]:
    """Experiment: for each ciphertext length, attack `trials` random keys and report success.

    Returns (length, mean letter accuracy, fraction of trials with accuracy >= threshold).
    """
    pt = clean(plaintext)
    rows = []
    for n in lengths:
        accs = []
        for t in range(trials):
            key = random_key(random.Random(1000 * n + t))
            _, guess = substitution_break(substitute(pt[:n], key), restarts=4, seed=t)
            accs.append(accuracy(guess, pt[:n]))
        rows.append((n, sum(accs) / trials, sum(a >= threshold for a in accs) / trials))
    return rows


def demo() -> None:
    from .corpus import TEST_PASSAGES
    pt = clean(TEST_PASSAGES[0])
    shift, plain = caesar_break(caesar(pt, 11)[:120])
    print(f"Caesar: recovered shift {shift} from 120 characters -> {plain[:60]}...")
    print("\nSubstitution attack (mean accuracy, fraction of runs >= 95% correct):")
    for n, acc, ok in characters_needed(pt):
        print(f"  {n:4d} chars   accuracy {acc:6.1%}   success {ok:4.0%}")


if __name__ == "__main__":
    demo()
