import pytest
from cryptolab.ch02 import keystream_reuse as kr
from cryptolab.ch02 import lfsr, otp


def test_otp_roundtrip_and_length_check():
    key = otp.keygen(20)
    assert otp.decrypt(otp.encrypt(b"twenty bytes of data", key), key) == b"twenty bytes of data"
    with pytest.raises(ValueError):
        otp.encrypt(b"short", otp.keygen(10))


def test_otp_perfect_secrecy_any_plaintext_is_consistent():
    c = otp.encrypt(b"HELLO", otp.keygen(5))
    for guess in (b"HELLO", b"WORLD", b"ZZZZZ"):
        assert otp.decrypt(c, otp.key_for(c, guess)) == guess


def test_two_time_pad_leaks_xor_of_plaintexts():
    p1, p2, key = b"first message", b"other message", otp.keygen(13)
    assert otp.xor(otp.encrypt(p1, key), otp.encrypt(p2, key)) == otp.xor(p1, p2)


def test_lfsr_is_maximal_length():
    seed = [1] + [0] * 15
    bits = lfsr.LFSR(lfsr.TAPS16, seed).bits(2 * 65535)
    assert bits[:65535] == bits[65535:]            # repeats after the period
    assert bits[:65535] != bits[1:65536]           # and not earlier than that (sanity)
    assert sum(bits[:65535]) == 2 ** 15            # a maximal LFSR emits 2^(L-1) ones per period


def test_berlekamp_massey_recovers_register_and_plaintext():
    seed = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1]
    msg = b"A message long enough to need the whole keystream, not just the start."
    ct = lfsr.encrypt(msg, lfsr.TAPS16, seed)
    plain, L, c = lfsr.known_plaintext_attack(ct, msg[:4])   # 32 bits = 2L, the minimum
    assert L == 16 and plain == msg
    assert [i for i in range(1, 17) if c[i]] == sorted(lfsr.TAPS16)


def test_keystream_reuse_detected_only_when_reused():
    assert kr.looks_reused(*kr.sample_pair(reuse=True))
    assert not kr.looks_reused(*kr.sample_pair(reuse=False))


def test_crib_dragging_hits_are_true_plaintext_fragments():
    p1 = b"Meet me at the station at noon and bring the documents with you for the review."
    p2 = b"The package will arrive on friday and the team is going to check it before the weekend."
    c1, c2 = kr.sample_pair()
    sure = kr.confident(kr.crib_drag(c1, c2))
    assert len(sure) >= 3
    for _, off, crib, frag in sure:           # the crib may be in either message
        n = len(crib)
        assert (p1[off:off + n], p2[off:off + n]) in ((crib, frag), (frag, crib))


def test_best_ranked_hit_is_a_real_one():
    p1 = b"Meet me at the station at noon and bring the documents with you for the review."
    p2 = b"The package will arrive on friday and the team is going to check it before the weekend."
    c1, c2 = kr.sample_pair()
    _, off, crib, frag = kr.crib_drag(c1, c2)[0]
    n = len(crib)
    assert (p1[off:off + n], p2[off:off + n]) in ((crib, frag), (frag, crib))
