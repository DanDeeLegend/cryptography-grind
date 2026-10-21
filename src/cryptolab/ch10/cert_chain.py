"""Assignment 10.6: fetch and inspect the certificate chain a server presents.

Only run this against hosts you own or are allowed to test. Uses the same CONNECT-proxy-aware socket as the chapter 5 audit.
The chain is fetched *unverified* (we want to look at it, not trust it), then each link is checked: does the issuer's
public key actually validate the child's signature?
"""
from __future__ import annotations

import ssl
import sys

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID

from cryptolab.ch05.tls_audit import _connect


def fetch_chain(host: str, port: int = 443) -> list[x509.Certificate]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with ctx.wrap_socket(_connect(host, port), server_hostname=host) as tls:
        return [x509.load_der_x509_certificate(c) for c in tls.get_unverified_chain()]


def signed_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    pub = parent.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        else:
            return False
        return True
    except Exception:
        return False


def describe(cert: x509.Certificate) -> dict:
    pub = cert.public_key()
    kind = f"RSA-{pub.key_size}" if isinstance(pub, rsa.RSAPublicKey) else f"EC-{pub.curve.name}" if isinstance(pub, ec.EllipticCurvePublicKey) else type(pub).__name__
    try:
        is_ca = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(), "key": kind,
            "sig_hash": cert.signature_hash_algorithm.name, "not_after": cert.not_valid_after_utc.date().isoformat(), "ca": is_ca}


def inspect(host: str) -> str:
    chain = fetch_chain(host)
    lines = [f"{host}: {len(chain)} certificate(s) sent"]
    for i, c in enumerate(chain):
        d = describe(c)
        link = ""
        if i + 1 < len(chain):
            link = f" | signed by next cert: {signed_by(c, chain[i + 1])}"
        elif c.subject == c.issuer:
            link = f" | self-signed root, self-check: {signed_by(c, c)}"
        else:
            link = " | top of sent chain (issuer root is expected in the client trust store, not sent)"
        lines.append(f"  [{i}] {d['subject']} <- {d['issuer']} | {d['key']}, {d['sig_hash']}, CA={d['ca']}, expires {d['not_after']}{link}")
    return "\n".join(lines)


if __name__ == "__main__":
    for h in sys.argv[1:] or ["ncf-website-ten.vercel.app", "signalmap-8117.onrender.com"]:
        print(inspect(h))
