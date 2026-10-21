import secrets

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec as lib_ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

from cryptolab import numtheory as nt
from cryptolab.ch09 import bench_ecc_vs_rsa, ecdh, ecdsa
from cryptolab.ch09 import ec


def test_textbook_curve_multiples_and_order():
    c, g = ec.TEXTBOOK, ec.TEXTBOOK.g
    expected = [(5, 1), (6, 3), (10, 6), (3, 1), (9, 16), (16, 13), (0, 6), (13, 7), (7, 6), (7, 11)]
    assert [ec.scalar_mult(c, k, g) for k in range(1, 11)] == expected
    assert ec.scalar_mult(c, 19, g) is None and ec.scalar_mult(c, 20, g) == g          # the group has order 19
    acc = None
    for k in range(1, 20):                                                              # repeated addition == double-and-add
        acc = ec.add(c, acc, g)
        assert acc == ec.scalar_mult(c, k, g) and ec.on_curve(c, acc)


def test_worked_example_text_contains_the_steps():
    text = ec.worked_example()
    assert "2P (point doubling)" in text and "(6, 3)" in text and "(10, 6)" in text


def test_group_law_properties():
    c = ec.TOY
    a, b = secrets.randbelow(c.n), secrets.randbelow(c.n)
    pa, pb = ec.scalar_mult(c, a, c.g), ec.scalar_mult(c, b, c.g)
    assert ec.add(c, pa, pb) == ec.add(c, pb, pa) == ec.scalar_mult(c, (a + b) % c.n, c.g)   # commutative, a*G + b*G = (a+b)*G
    assert ec.add(c, pa, ec.neg(c, pa)) is None and ec.add(c, pa, None) == pa


def test_p256_matches_openssl_public_keys_and_ecdh():
    c = ec.P256
    assert ec.on_curve(c, c.g) and ec.scalar_mult(c, c.n, c.g) is None
    for _ in range(4):
        k = secrets.randbelow(c.n - 1) + 1
        n = lib_ec.derive_private_key(k, lib_ec.SECP256R1()).public_key().public_numbers()
        assert ec.scalar_mult(c, k, c.g) == (n.x, n.y)
    assert ecdh.scratch_matches_openssl()


def test_toy_curve_parameters_are_independently_valid():
    c = ec.TOY
    assert nt.is_probable_prime(c.p) and nt.is_probable_prime(c.n)
    assert (4 * c.a ** 3 + 27 * c.b ** 2) % c.p != 0                       # non-singular
    assert ec.on_curve(c, c.g) and ec.scalar_mult(c, c.n, c.g) is None
    # Hasse: the group order N satisfies |N - (p+1)| <= 2*sqrt(p). n divides N and n > 4*sqrt(p) forces N == n.
    assert c.n > 4 * c.p ** 0.5 and abs(c.n - (c.p + 1)) <= 2 * c.p ** 0.5


@pytest.mark.parametrize("c", [ec.TOY, ec.P256], ids=lambda c: c.name)
def test_ecdsa_roundtrip_and_tamper(c):
    d, q = ecdsa.keygen(c)
    sig = ecdsa.sign(c, d, b"hello")
    assert ecdsa.verify(c, q, b"hello", sig) and not ecdsa.verify(c, q, b"hellO", sig)
    assert not ecdsa.verify(c, q, b"hello", (sig[0], (sig[1] + 1) % c.n)) and not ecdsa.verify(c, q, b"hello", (0, sig[1]))


def test_ecdsa_interoperates_with_openssl_both_ways():
    c = ec.P256
    d, q = ecdsa.keygen(c)
    pub = lib_ec.EllipticCurvePublicNumbers(q[0], q[1], lib_ec.SECP256R1()).public_key()
    r, s = ecdsa.sign(c, d, b"interop")
    pub.verify(encode_dss_signature(r, s), b"interop", lib_ec.ECDSA(hashes.SHA256()))      # raises if invalid
    key = lib_ec.derive_private_key(d, lib_ec.SECP256R1())
    assert ecdsa.verify(c, q, b"interop2", decode_dss_signature(key.sign(b"interop2", lib_ec.ECDSA(hashes.SHA256()))))


@pytest.mark.parametrize("c", [ec.TOY, ec.P256], ids=lambda c: c.name)
def test_nonce_reuse_recovers_the_private_key(c):
    recovered = 0
    for i in range(12 if c is ec.TOY else 3):
        d, q = ecdsa.keygen(c)
        k = secrets.randbelow(c.n - 1) + 1
        m1, m2 = f"message A {i}".encode(), f"message B {i}".encode()
        try:
            s1, s2 = ecdsa.sign(c, d, m1, k), ecdsa.sign(c, d, m2, k)
        except ValueError:
            continue                                                         # degenerate toy nonce, skip
        assert s1[0] == s2[0]
        assert ecdsa.recover_key_from_nonce_reuse(c, m1, s1, m2, s2) == d
        recovered += 1
    assert recovered >= 2


def test_no_nonce_reuse_no_recovery_and_deterministic_k_fix():
    c = ec.TOY
    d, _ = ecdsa.keygen(c)
    s1, s2 = ecdsa.sign(c, d, b"one"), ecdsa.sign(c, d, b"two")
    with pytest.raises(ValueError):
        ecdsa.recover_key_from_nonce_reuse(c, b"one", s1, b"two", s2)
    assert ecdsa.deterministic_k(c, d, b"one") == ecdsa.deterministic_k(c, d, b"one")
    assert ecdsa.deterministic_k(c, d, b"one") != ecdsa.deterministic_k(c, d, b"two")
    ks = {ecdsa.deterministic_k(c, d, f"m{i}".encode()) for i in range(50)}
    assert len(ks) == 50


def test_comparison_and_benchmark_shape():
    rows = {r["scheme"]: r for r in ecdh.compare(rounds=2)}
    assert rows["X25519"]["public_bytes"] == 32 and rows["ECDH P-256"]["public_bytes"] == 65
    assert rows["RSA-3072 key transport"]["ms"] > 5 * rows["X25519"]["ms"]
    b = {r["scheme"]: r for r in bench_ecc_vs_rsa.run()}
    assert b["Ed25519"]["sig_bytes"] == 64 and b["RSA-2048 PSS"]["sig_bytes"] == 256
    assert b["RSA-2048 PSS"]["sign_us"] > 5 * b["ECDSA P-256"]["sign_us"]       # ECC signing is far cheaper
