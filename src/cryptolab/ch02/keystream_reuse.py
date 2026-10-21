"""Assignment 2.4: detect keystream reuse and recover plaintext fragments by crib dragging.

If two messages were encrypted under the same stream-cipher key and nonce, c1 XOR c2 = p1 XOR p2.
Both plaintexts are text, so the XOR has recognisable structure (every byte < 0x80, many letter-XOR-
letter and letter-XOR-space values). Guessing a common word (a "crib") and sliding it along the XOR
exposes the other message's text wherever the guess is right.
"""
from __future__ import annotations

import math
import re
from collections import Counter

from Crypto.Cipher import ChaCha20

from cryptolab.ch01.corpus import TRAIN

COMMON_WORDS = [b" the ", b" and ", b" that ", b" with ", b" will ", b" this ", b" from ", b" you ", b" for ",
                b" before ", b" are ", b" have ", b" not ", b" was ", b" but "]


def _bigram_model():
    """Character bigrams (a-z plus space) from the ch01 corpus, used to judge whether text looks English."""
    text = re.sub(r"[^a-z]+", " ", TRAIN.lower())
    return Counter(zip(text, text[1:])), Counter(text)


_BI, _UNI = _bigram_model()


def plausibility(frag: bytes) -> float:
    """Mean log-probability per character pair under the English bigram model (higher = more English)."""
    s = frag.decode("latin1").lower()
    lp = [math.log((_BI[(a, b)] + 0.5) / (_UNI[a] + 13.5)) for a, b in zip(s, s[1:])]
    return sum(lp) / max(len(lp), 1)


def sample_pair(reuse: bool = True) -> tuple[bytes, bytes]:
    """Two ciphertexts as a careless system would produce them (ChaCha20 with a repeated nonce)."""
    p1 = b"Meet me at the station at noon and bring the documents with you for the review."
    p2 = b"The package will arrive on friday and the team is going to check it before the weekend."
    key = bytes(range(32))
    n2 = b"\x00" * 8 if reuse else b"\x01" * 8
    return (ChaCha20.new(key=key, nonce=b"\x00" * 8).encrypt(p1),
            ChaCha20.new(key=key, nonce=n2).encrypt(p2))


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def reuse_score(c1: bytes, c2: bytes) -> float:
    """Fraction of XOR bytes with the high bit clear.

    ASCII text XOR ASCII text never sets bit 7, so reused keystream scores ~1.0. Independent keystreams
    make each XOR byte uniformly random, so about half have the high bit clear.
    """
    x = _xor(c1, c2)
    return sum(b < 0x80 for b in x) / max(len(x), 1)


def looks_reused(c1: bytes, c2: bytes, threshold: float = 0.95) -> bool:
    return reuse_score(c1, c2) >= threshold


def crib_drag(c1: bytes, c2: bytes, cribs=COMMON_WORDS) -> list[tuple[float, int, bytes, bytes]]:
    """Candidate (plausibility, offset, crib, revealed_fragment), best first.

    The crib may sit in either message; the revealed fragment is then the other message at that offset.
    """
    x, hits = _xor(c1, c2), []
    for crib in cribs:
        for off in range(len(x) - len(crib) + 1):
            frag = _xor(x[off:off + len(crib)], crib)
            if all(chr(b).isalpha() or b == 0x20 for b in frag):
                hits.append((plausibility(frag), off, crib, frag))
    return sorted(hits, reverse=True)


def confident(hits, min_crib: int = 5, min_plausibility: float = -2.8):
    """Auto-accept long cribs whose revealed text looks English. Thresholds are heuristics calibrated on
    the sample pair: on real data an analyst reviews the ranked list instead of trusting them."""
    return [h for h in hits if len(h[2]) >= min_crib and h[0] >= min_plausibility]


def reconstruct(c1: bytes, c2: bytes, hits, crib_in: dict[int, int] | None = None) -> tuple[str, str]:
    """Overlay hits on two '_' templates. crib_in[offset] says which message (1 or 2) holds the crib."""
    n = min(len(c1), len(c2))
    t = {1: ["_"] * n, 2: ["_"] * n}
    for _, off, crib, frag in hits:
        mine = (crib_in or {}).get(off, 1)
        for i, (a, b) in enumerate(zip(crib, frag)):
            t[mine][off + i], t[3 - mine][off + i] = chr(a), chr(b)
    return "".join(t[1]), "".join(t[2])


def demo() -> None:
    c1, c2 = sample_pair()
    print(f"reuse score (same keystream)      : {reuse_score(c1, c2):.2f} -> reused? {looks_reused(c1, c2)}")
    d1, d2 = sample_pair(reuse=False)
    print(f"reuse score (different keystreams): {reuse_score(d1, d2):.2f} -> reused? {looks_reused(d1, d2)}")
    hits = crib_drag(c1, c2)
    sure = confident(hits)
    print(f"\n{len(hits)} candidate hits; {len(sure)} pass the confidence filter (crib <-> revealed text):")
    for score, off, crib, frag in sure:
        print(f"  offset {off:2d}  {crib!r:10} <-> {frag!r:10}  plausibility {score:.2f}")
    print("\nEach pair is (word guessed in one message) <-> (text it reveals in the OTHER message).")
    print("Which message holds the crib is a judgement call; extend promising fragments by guessing")
    print("the next word, then use reconstruct(..., crib_in={offset: 1 or 2}) to build up each message.")


if __name__ == "__main__":
    demo()
