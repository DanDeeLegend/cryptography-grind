"""Assignment 13.2: certificate path validation, written out so each check is visible.

Checks (RFC 5280 s6, simplified): every certificate is inside its validity window; each certificate's signature verifies
under its issuer's key and issuer name matches; every issuer is a CA (basicConstraints) allowed to sign certificates
(keyUsage keyCertSign) and respects pathLenConstraint; the path ends at a trust anchor, matched by subject AND public key
(not by fingerprint, since cross-signed roots share a key but not a certificate); the leaf's SAN matches the hostname.
NOT done: revocation (OCSP/CRL), name constraints, policy mapping, EKU. Don't use this in place of the TLS library.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID


@dataclass
class Result:
    ok: bool
    errors: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    anchor: str | None = None


def _spki(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def sig_ok(child: x509.Certificate, issuer_pub) -> bool:
    try:
        if isinstance(issuer_pub, rsa.RSAPublicKey):
            issuer_pub.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(issuer_pub, ec.EllipticCurvePublicKey):
            issuer_pub.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        else:
            return False
        return True
    except Exception:
        return False


def hostname_matches(cert: x509.Certificate, host: str) -> bool:
    try:
        names = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return False  # CN fallback is deprecated (RFC 9110/6125): SAN is required
    host = host.lower().rstrip(".")
    for n in names:
        n = n.lower()
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") == n.count(".") and host.split(".", 1)[1] == n[2:]:
            return True  # wildcard covers exactly one label
    return False


def revocation_pointers(cert: x509.Certificate) -> dict:
    out: dict = {"ocsp": [], "crl": []}
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        out["ocsp"] = [d.access_location.value for d in aia if d.access_method == AuthorityInformationAccessOID.OCSP]
    except x509.ExtensionNotFound:
        pass
    try:
        crl = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        out["crl"] = [n.value for dp in crl for n in (dp.full_name or [])]
    except x509.ExtensionNotFound:
        pass
    return out


def validate(chain: list[x509.Certificate], anchors: list[x509.Certificate], hostname: str, now: dt.datetime | None = None) -> Result:
    now = now or dt.datetime.now(dt.timezone.utc)
    r = Result(ok=False)
    if not chain:
        r.errors.append("empty chain")
        return r
    if not hostname_matches(chain[0], hostname):
        r.errors.append(f"hostname {hostname!r} not in leaf SAN")
    else:
        r.steps.append("leaf SAN matches hostname")
    anchor_by_key = {_spki(a): a for a in anchors}
    for i, cert in enumerate(chain):
        name = cert.subject.rfc4514_string()
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            r.errors.append(f"[{i}] {name}: outside validity window")
        else:
            r.steps.append(f"[{i}] {name}: within validity")
        anchor = anchor_by_key.get(_spki(cert))
        if anchor is not None and anchor.subject == cert.subject:
            r.anchor, r.steps = name, r.steps + [f"[{i}] {name}: key + name match a trust anchor; path complete"]
            break
        if i + 1 < len(chain):
            issuer = chain[i + 1]
        else:  # end of the sent chain: the issuer must be a trust anchor we already hold
            issuer = next((a for a in anchors if a.subject == cert.issuer and sig_ok(cert, a.public_key())), None)
            if issuer is None:
                r.errors.append(f"[{i}] {name}: issuer is not a trusted anchor")
                break
            r.anchor = issuer.subject.rfc4514_string()
            r.steps.append(f"[{i}] {name}: issued by trust anchor {r.anchor}")
        if cert.issuer != issuer.subject:
            r.errors.append(f"[{i}] {name}: issuer name does not match next certificate")
        if not sig_ok(cert, issuer.public_key()):
            r.errors.append(f"[{i}] {name}: signature does not verify under issuer key")
        else:
            r.steps.append(f"[{i}] {name}: signature verified by {issuer.subject.rfc4514_string()}")
        try:
            bc = issuer.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
            ku = issuer.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value
        except x509.ExtensionNotFound:
            r.errors.append(f"issuer {issuer.subject.rfc4514_string()}: missing basicConstraints/keyUsage")
            continue
        if not bc.ca or not ku.key_cert_sign:
            r.errors.append(f"issuer {issuer.subject.rfc4514_string()}: not allowed to sign certificates")
        elif bc.path_length is not None and i > bc.path_length:  # i = CAs already below this issuer on the path
            r.errors.append(f"issuer {issuer.subject.rfc4514_string()}: pathLenConstraint {bc.path_length} exceeded")
        if i + 1 >= len(chain) and r.anchor:
            break
    else:
        if r.anchor is None:
            r.errors.append("path did not end at a trust anchor")
    r.ok = not r.errors and r.anchor is not None
    return r


def system_anchors() -> list[x509.Certificate]:
    import ssl
    import warnings
    ctx = ssl.create_default_context()
    with warnings.catch_warnings():  # a few legacy roots have non-positive serial numbers
        warnings.simplefilter("ignore")
        return [x509.load_der_x509_certificate(c) for c in ctx.get_ca_certs(binary_form=True)]


if __name__ == "__main__":
    import sys
    from cryptolab.ch10.cert_chain import fetch_chain
    anchors = system_anchors()
    print(f"{len(anchors)} trust anchors loaded")
    for h in sys.argv[1:] or ["ncf-website-ten.vercel.app", "signalmap-8117.onrender.com"]:
        res = validate(fetch_chain(h), anchors, h)
        print(f"{h}: {'VALID' if res.ok else 'INVALID'} (anchor: {res.anchor})")
        for s in res.steps + res.errors:
            print("   ", s)
        print("    revocation pointers on leaf:", revocation_pointers(fetch_chain(h)[0]))
