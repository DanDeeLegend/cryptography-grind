import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from cryptolab.ch10 import forgery, rsa_sign
from cryptolab.ch10.cert_chain import signed_by, describe


@pytest.fixture(scope="module")
def key():
    k = rsa.generate_private_key(65537, 2048)
    nums = k.private_numbers()
    return k, nums.public_numbers.n, nums.public_numbers.e, nums.d


def test_signature_byte_identical_to_openssl(key):
    k, n, e, d = key
    for msg in (b"", b"a", b"hello world" * 50):
        assert rsa_sign.sign(msg, d, n) == k.sign(msg, padding.PKCS1v15(), hashes.SHA256())


def test_verify_accepts_library_signature_and_rejects_tampering(key):
    k, n, e, d = key
    sig = k.sign(b"msg", padding.PKCS1v15(), hashes.SHA256())
    assert rsa_sign.verify(b"msg", sig, e, n)
    assert not rsa_sign.verify(b"msG", sig, e, n)
    assert not rsa_sign.verify(b"msg", sig[:-1] + bytes([sig[-1] ^ 1]), e, n)
    assert not rsa_sign.verify(b"msg", sig[1:], e, n)  # wrong length
    assert not rsa_sign.verify(b"msg", (n + 1).to_bytes(256, "big"), e, n)  # s >= n


def test_verify_rejects_garbage_padding_even_with_valid_digest(key):
    """A lenient verifier that only looks for the digest at the end would accept this; ours compares the whole encoding."""
    _, n, e, d = key
    import hashlib
    t = rsa_sign.SHA256_PREFIX + hashlib.sha256(b"x").digest()
    bad = b"\x00\x01" + b"\xff" * 8 + b"\x00" + t + b"\x00" * (256 - 3 - 8 - len(t))
    sig = pow(int.from_bytes(bad, "big"), d, n).to_bytes(256, "big")
    assert not rsa_sign.verify(b"x", sig, e, n)


def test_forgeries_work_on_textbook_and_fail_on_padded(key):
    _, n, e, d = key
    fm, fs = forgery.existential_forgery(e, n)
    assert forgery.textbook_verify(fm, fs, e, n)
    s1, s2 = pow(11, d, n), pow(13, d, n)
    pm, ps = forgery.product_forgery(11, s1, 13, s2, n)
    assert pm == 143 and forgery.textbook_verify(pm, ps, e, n)
    target = 424242
    blocked = lambda x: pow(x, d, n)
    sig = forgery.blinding_attack(target, blocked, e, n)
    assert forgery.textbook_verify(target, sig, e, n)
    assert forgery.padded_scheme_rejects(e, n, b"x") == {"random_signature_accepted": False}


def test_cert_signed_by_detects_wrong_issuer():
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    def make(name, issuer_key, issuer_name, pub):
        now = datetime.datetime.now(datetime.timezone.utc)
        return (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])).public_key(pub)
                .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
                .sign(issuer_key, hashes.SHA256()))

    ca, other, leaf_key = (rsa.generate_private_key(65537, 2048) for _ in range(3))
    leaf = make("leaf", ca, "ca", leaf_key.public_key())
    ca_cert = make("ca", ca, "ca", ca.public_key())
    other_cert = make("ca", other, "ca", other.public_key())  # same name, different key
    assert signed_by(leaf, ca_cert) and not signed_by(leaf, other_cert)
    assert describe(leaf)["key"] == "RSA-2048"
