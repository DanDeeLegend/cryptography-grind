"""A tiny in-memory PKI for tests and demos: make a CA, issue intermediates and leaves. ECDSA P-256 throughout."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@dataclass
class Ca:
    key: ec.EllipticCurvePrivateKey
    cert: x509.Certificate


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _build(subject_cn, issuer_cert, issuer_key, pub, *, ca, path_length=None, san=None, days=30, start=None,
           key_cert_sign=None, ocsp_url=None):
    now = start or dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(_name(subject_cn))
         .issuer_name(issuer_cert.subject if issuer_cert else _name(subject_cn)).public_key(pub)
         .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=1))
         .not_valid_after(now + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True))
    if key_cert_sign is None:
        key_cert_sign = ca
    b = b.add_extension(x509.KeyUsage(digital_signature=not ca, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=key_cert_sign,
                                      crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
    if san:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in san]), critical=False)
    if ocsp_url:
        b = b.add_extension(x509.AuthorityInformationAccess([x509.AccessDescription(
            x509.oid.AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp_url))]), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


def make_root(cn="Test Root CA", **kw) -> Ca:
    key = ec.generate_private_key(ec.SECP256R1())
    return Ca(key, _build(cn, None, key, key.public_key(), ca=True, **kw))


def make_intermediate(parent: Ca, cn="Test Intermediate CA", path_length=None, **kw) -> Ca:
    key = ec.generate_private_key(ec.SECP256R1())
    return Ca(key, _build(cn, parent.cert, parent.key, key.public_key(), ca=True, path_length=path_length, **kw))


def make_leaf(parent: Ca, hostname: str, **kw) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    san = kw.pop("san", [hostname])
    return key, _build(hostname, parent.cert, parent.key, key.public_key(), ca=False, san=san, **kw)
