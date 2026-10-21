import random

import pytest

from cryptolab.ch06 import bench_sym_vs_pk, hybrid, mitm_sim, modexp


def test_modexp_matches_pow_and_counts_operations():
    rng = random.Random(3)
    for _ in range(300):
        b, e, m = rng.randrange(1, 10 ** 30), rng.randrange(0, 10 ** 30), rng.randrange(2, 10 ** 30)
        assert modexp.square_and_multiply(b, e, m) == pow(b, e, m)
    assert modexp.square_and_multiply(5, 0, 7) == 1 and modexp.square_and_multiply(5, 3, 1) == 0
    assert modexp.operation_count(65537) == 17 + 2          # 17 squarings + 2 set bits
    assert modexp.square_and_multiply(7, 13, 11) == 2


def test_modexp_hand_example_trace():
    trace: list = []
    modexp.square_and_multiply(7, 13, 11, trace)
    assert trace == [("1", 1, 7), ("1", 5, 2), ("0", 4, 4), ("1", 5, 2)]


def test_rsa_is_orders_of_magnitude_slower_than_aes():
    aes = bench_sym_vs_pk.aes_mb_s(256 * 1024)
    row = bench_sym_vs_pk.rsa_rows((2048,))[0]
    assert aes > 100 * row["dec_mb_s"] and row["dec_ops"] < row["enc_ops"]   # private op is the slow one


@pytest.fixture(scope="module")
def keypair():
    return hybrid.generate_keypair(2048)


def test_hybrid_roundtrip_large_and_randomised(keypair):
    msg = bytes(range(256)) * 4096                         # 1 MiB, far beyond what RSA alone could encrypt
    a, b = hybrid.encrypt(keypair.public_key(), msg), hybrid.encrypt(keypair.public_key(), msg)
    assert a != b and hybrid.decrypt(keypair, a) == msg
    assert hybrid.decrypt(keypair, hybrid.encrypt(keypair.public_key(), b"")) == b""


def test_hybrid_rejects_wrong_key_tampering_and_wrong_context(keypair):
    blob = hybrid.encrypt(keypair.public_key(), b"secret", aad=b"user-7")
    with pytest.raises(hybrid.HybridError):
        hybrid.decrypt(hybrid.generate_keypair(2048), blob, aad=b"user-7")
    for i in (0, 8, len(blob) // 2, len(blob) - 1):
        bad = bytearray(blob); bad[i] ^= 1
        with pytest.raises(hybrid.HybridError):
            hybrid.decrypt(keypair, bytes(bad), aad=b"user-7")
    with pytest.raises(hybrid.HybridError):
        hybrid.decrypt(keypair, blob, aad=b"user-8")
    with pytest.raises(hybrid.HybridError):
        hybrid.decrypt(keypair, blob[:-5], aad=b"user-7")


def test_mitm_is_invisible_without_the_check_and_visible_with_it():
    honest = mitm_sim.run(False)
    assert honest["bob_reads"] == "meet at noon" and honest["alice_code"] == honest["bob_code"]
    attack = mitm_sim.run(True)
    assert attack["mallory_reads"] == "meet at noon"            # Mallory reads everything
    assert attack["bob_reads"] == "meet at midnight"            # ...and edits it, and Bob's decryption succeeds
    assert attack["alice_code"] != attack["bob_code"]           # only the out-of-band code comparison exposes it
