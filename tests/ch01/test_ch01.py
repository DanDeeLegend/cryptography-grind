import math
from cryptolab.ch01 import brute_force as bf
from cryptolab.ch01.corpus import TEST_PASSAGES
from cryptolab.ch01.frequency_attack import (accuracy, caesar, caesar_break, clean, random_key,
                                             substitute, substitution_break)
import random


def test_caesar_roundtrip_and_break():
    pt = clean(TEST_PASSAGES[1])
    for shift in (0, 3, 13, 25):
        key, plain = caesar_break(caesar(pt, shift)[:150])
        assert key == shift and plain == pt[:150]


def test_substitution_break_on_unseen_text():
    pt = clean(TEST_PASSAGES[0])[:500]
    ct = substitute(pt, random_key(random.Random(7)))
    _, guess = substitution_break(ct, restarts=4)
    assert accuracy(guess, pt) > 0.95


def test_substitution_is_a_permutation_of_letters():
    key = random_key(random.Random(1))
    assert sorted(key) == list("abcdefghijklmnopqrstuvwxyz")


def test_brute_force_math():
    worst, avg = bf.brute_force_seconds(40, 1e9)
    assert math.isclose(worst, 2 ** 40 / 1e9) and math.isclose(avg, worst / 2)
    assert bf.brute_force_seconds(128, 1e18)[1] > bf.AGE_OF_UNIVERSE  # 128-bit stays out of reach
    assert bf.brute_force_seconds(56, 1e12)[0] < 3600 * 24 * 365      # 56-bit is within reach


def test_human_formatting():
    assert bf.human(0.2) == "<1 second"
    assert bf.human(7200) == "2.0 hours"
    assert "universe" in bf.human(1e30)
