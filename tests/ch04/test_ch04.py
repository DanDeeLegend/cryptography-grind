import os
import random

import pytest
from Crypto.Cipher import AES

from cryptolab.ch04 import aes, bench_aesni, filecrypt, nist_vectors

PT = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")


def test_nist_vectors_pass_for_library_and_from_scratch():
    assert all(ok for _, ok in nist_vectors.check(nist_vectors.library_encrypt))
    assert all(ok for _, ok in nist_vectors.check(nist_vectors.scratch_encrypt))


def test_matches_library_on_random_blocks_and_decrypts():
    rng = random.Random(0)
    for _ in range(200):
        key, block = rng.randbytes(16), rng.randbytes(16)
        ct = aes.encrypt_block(block, key)
        assert ct == AES.new(key, AES.MODE_ECB).encrypt(block)
        assert aes.decrypt_block(ct, key) == block


def test_sbox_is_computed_correctly():
    assert aes.SBOX[0x00] == 0x63 and aes.SBOX[0x53] == 0xED and aes.SBOX[0xFF] == 0x16
    assert sorted(aes.SBOX) == list(range(256))


def test_round_one_trace_matches_fips197_appendix_b():
    steps = dict(aes.trace_first_round(PT, KEY))
    assert steps["round 0 add_round_key"] == "193de3bea0f4e22b9ac68d2ae9f84808"
    assert steps["round 1 sub_bytes"] == "d42711aee0bf98f1b8b45de51e415230"
    assert steps["round 1 shift_rows"] == "d4bf5d30e0b452aeb84111f11e2798e5"
    assert steps["round 1 mix_columns"] == "046681e5e0cb199a48f8d37a2806264c"
    assert steps["round 1 add_round_key"] == "a49c7ff2689f352b6b5bea43026a5049"
    assert bytes(aes.expand_key(KEY)[1]).hex() == "a0fafe1788542cb123a339392a6c7605"


def test_benchmark_runs_and_hardware_beats_pure_python():
    rows = bench_aesni.run(sizes=(256 * 1024,))
    assert rows[0]["AES-NI (PyCryptodome)"] > bench_aesni.pure_python_mb_s(512)


# ---- 4.5 file encryption ----
FAST = dict(log2_n=10)  # cheap scrypt for tests; the default (15) is what users get


@pytest.mark.parametrize("size", [0, 1, 100, 65535, 65536, 65537, 200_000])
def test_roundtrip_various_sizes(tmp_path, size):
    src, enc, dec = tmp_path / "a", tmp_path / "a.enc", tmp_path / "a.dec"
    src.write_bytes(os.urandom(size))
    filecrypt.encrypt_file(str(src), str(enc), "pw", **FAST)
    filecrypt.decrypt_file(str(enc), str(dec), "pw")
    assert dec.read_bytes() == src.read_bytes()


def test_text_file_roundtrip_and_ciphertext_is_randomised(tmp_path):
    src = tmp_path / "t.txt"
    src.write_text("hello hello hello\n" * 1000)
    e1, e2 = tmp_path / "1", tmp_path / "2"
    filecrypt.encrypt_file(str(src), str(e1), "pw", **FAST)
    filecrypt.encrypt_file(str(src), str(e2), "pw", **FAST)
    assert e1.read_bytes() != e2.read_bytes()           # fresh salt + nonce every time
    assert b"hello" not in e1.read_bytes()


def _enc(tmp_path, data=b"x" * 150_000):
    src, enc = tmp_path / "s", tmp_path / "s.enc"
    src.write_bytes(data)
    filecrypt.encrypt_file(str(src), str(enc), "pw", chunk_size=65536, **FAST)
    return enc


def _fails(tmp_path, enc, password="pw"):
    out = tmp_path / "out"
    with pytest.raises(filecrypt.TamperError):
        filecrypt.decrypt_file(str(enc), str(out), password)
    assert not out.exists() and not (tmp_path / "out.tmp").exists()    # no plaintext left behind


def test_tamper_flipped_bit_in_body(tmp_path):
    enc = _enc(tmp_path)
    b = bytearray(enc.read_bytes()); b[100] ^= 1; enc.write_bytes(b)
    _fails(tmp_path, enc)


def test_tamper_flipped_bit_in_header(tmp_path):
    enc = _enc(tmp_path)
    b = bytearray(enc.read_bytes()); b[27] ^= 1; enc.write_bytes(b)    # nonce prefix
    _fails(tmp_path, enc)


def test_tamper_truncation_and_extension(tmp_path):
    enc = _enc(tmp_path)
    data = enc.read_bytes()
    chunk = 65536 + 16
    enc.write_bytes(data[:filecrypt.HEADER_LEN + chunk])              # drop trailing chunks cleanly
    _fails(tmp_path, enc)
    enc.write_bytes(data + data[filecrypt.HEADER_LEN:filecrypt.HEADER_LEN + chunk])   # append a chunk
    _fails(tmp_path, enc)


def test_tamper_chunk_reordering(tmp_path):
    enc = _enc(tmp_path)
    d, c, h = enc.read_bytes(), 65536 + 16, filecrypt.HEADER_LEN
    enc.write_bytes(d[:h] + d[h + c:h + 2 * c] + d[h:h + c] + d[h + 2 * c:])
    _fails(tmp_path, enc)


def test_wrong_password_and_garbage_input(tmp_path):
    enc = _enc(tmp_path)
    _fails(tmp_path, enc, password="not-the-password")
    junk = tmp_path / "junk"
    junk.write_bytes(b"this is not an encrypted file at all")
    _fails(tmp_path, junk)
