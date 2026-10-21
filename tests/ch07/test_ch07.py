import math
import random

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptolab import numtheory as nt
from cryptolab.ch07 import bench_modexp, common_factor, rsa_oaep, rsa_toy


def test_numtheory():
    rng = random.Random(0)
    for _ in range(200):
        m, a = rng.randrange(2, 10 ** 12), rng.randrange(1, 10 ** 12)
        if math.gcd(a, m) == 1:
            assert nt.modinv(a, m) == pow(a, -1, m)
    with pytest.raises(ValueError):
        nt.modinv(6, 9)
    assert all(nt.is_probable_prime(p) for p in (2, 3, 97, 7919, 2 ** 61 - 1, 2 ** 127 - 1))
    assert not any(nt.is_probable_prime(c) for c in (1, 4, 561, 1105, 6601, 2 ** 61 + 1))   # incl. Carmichael numbers
    p = nt.gen_prime(96)
    assert p.bit_length() == 96 and nt.is_probable_prime(p)
    sp = nt.gen_safe_prime(64)
    assert nt.is_probable_prime((sp - 1) // 2)


def test_textbook_rsa_example():
    k = rsa_toy.make_key()
    assert (k.n, k.phi, k.e, k.d) == (3233, 3120, 17, 2753)
    assert k.encrypt(65) == 2790 and k.decrypt(2790) == 65
    assert all(k.decrypt(k.encrypt(m)) == m for m in range(k.n))        # every message in range, not just one
    with pytest.raises(ValueError):
        rsa_toy.make_key(61, 53, 15)                                      # e shares a factor with phi


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(65537, 2048)


def test_oaep_interoperates_with_the_library_both_ways(key):
    for i in range(10):
        msg = bytes(random.Random(i).randrange(256) for _ in range(i * 17))
        assert key.decrypt(rsa_oaep.encrypt(key, msg), rsa_oaep.LIB_OAEP) == msg
        assert rsa_oaep.decrypt(key, key.public_key().encrypt(msg, rsa_oaep.LIB_OAEP)) == msg


def test_oaep_label_randomisation_limits_and_uniform_errors(key):
    c = rsa_oaep.encrypt(key, b"hello", label=b"ctx")
    assert c != rsa_oaep.encrypt(key, b"hello", label=b"ctx")             # randomised
    assert rsa_oaep.decrypt(key, c, label=b"ctx") == b"hello"
    with pytest.raises(rsa_oaep.DecryptionError):
        rsa_oaep.decrypt(key, c, label=b"other")
    with pytest.raises(ValueError):
        rsa_oaep.encrypt(key, bytes(191))                                 # 190 is the maximum for 2048-bit OAEP-SHA256
    bad = bytearray(c); bad[10] ^= 1
    with pytest.raises(rsa_oaep.DecryptionError, match="^decryption error$"):
        rsa_oaep.decrypt(key, bytes(bad), label=b"ctx")


def test_oaep_encoding_is_deterministic_given_a_seed():
    a = rsa_oaep.oaep_encode(b"x", 256, seed=bytes(32))
    assert a == rsa_oaep.oaep_encode(b"x", 256, seed=bytes(32)) and a[0] == 0 and len(a) == 256


def test_textbook_demos_show_all_three_breaks():
    lines = rsa_oaep.textbook_demos()
    assert "True" in lines[0] and "42" in lines[1] and "attack at dawn" in lines[2]


def test_square_and_multiply_vs_naive():
    r = bench_modexp.run(exp_bits=(8, 12, 17), mod_bits=512)
    assert all(x["naive_s"] > x["sm_s"] for x in r["rows"][1:])
    assert r["naive_private_log10_years"] > 500


def test_common_factor_pairwise_and_batch_agree_and_recover_keys():
    moduli, factors = common_factor.weak_fleet(120, prime_bits=40, pool_size=15)
    a, b = common_factor.pairwise(moduli), common_factor.batch_gcd(moduli)
    assert a and set(a) == set(b)
    for i, p in a.items():
        assert moduli[i] % p == 0 and p in factors[i]
        d = common_factor.recover_private_key(moduli[i], p)
        assert pow(pow(4242, 65537, moduli[i]), d, moduli[i]) == 4242
    healthy = [i for i, (p, q) in enumerate(factors) if i not in a]
    assert healthy                                                          # unaffected devices stay safe
