import random

from cryptolab.ch03 import bench_3des_aes as bench
from cryptolab.ch03 import brute_force_des as bf
from cryptolab.ch03 import mini_des as des
from cryptolab.ch03 import mitm


def test_sboxes_rows_are_permutations():
    for box in (des.SBOX1, des.SBOX2):
        assert len(box) == 4
        for row in box:
            assert sorted(row) == list(range(16))     # guards against a mistyped S-box entry


def test_encrypt_decrypt_roundtrip_all_keys_sample():
    rng = random.Random(1)
    for _ in range(500):
        block, key = rng.randrange(65536), rng.randrange(65536)
        assert des.decrypt(des.encrypt(block, key), key) == block


def test_trace_matches_round_function():
    left, right, k = 0b11010010, 0b01111001, 0b101001101100
    lines = dict(des.trace_round(left, right, k))
    assert lines["5. new R = L XOR F(R,K)"] == f"{left ^ des.f(right, k):08b}"
    assert lines["4. permutation P(S1||S2) = F(R,K)"] == f"{des.f(right, k):08b}"


def test_mitm_recovers_double_key_far_below_brute_force():
    k1, k2 = 0x3A5C, 0xB17E
    pairs = [(p, mitm.double_encrypt(p, k1, k2)) for p in (0x1234, 0xBEEF, 0x0F0F, 0xA5A5)]
    found, ops = mitm.mitm_attack(pairs)
    assert (k1, k2) in found
    assert ops == 2 * 65536 and ops < 2 ** 32 // 10_000


def test_reduced_key_des_brute_force_finds_key():
    m = bf.measure(10)
    assert m["trials"] == 1 << 10 and m["keys_per_sec"] > 0


def test_key_placement_ignores_parity_bits():
    base = bytes(8)
    keys = {bf.key_from_index(base, i, 12) for i in range(1 << 12)}
    assert len(keys) == 1 << 12


def test_aes_is_faster_than_3des():
    rows = bench.run(sizes=(256 * 1024,))
    assert rows[0]["AES-128 (software)"] > rows[0]["3DES"]
