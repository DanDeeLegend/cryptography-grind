"""Assignment 5.5: audit a TLS endpoint for weak protocol versions, cipher suites and settings.

Pure Python (ssl + cryptography). Connects directly, or through an HTTP CONNECT proxy when HTTPS_PROXY is set,
and reports: which protocol versions the server accepts; which TLS 1.2 cipher suites it accepts (each tried
separately); the certificate (issuer, key, signature, expiry); and security headers. Only point this at hosts
you own or have permission to test. Limits: it only sees what the local OpenSSL can offer (TLS 1.3 suites cannot
be enumerated this way), so treat it as a quick first pass and confirm with testssl.sh or SSL Labs.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import urllib.parse
import warnings
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

warnings.filterwarnings("ignore", category=DeprecationWarning, message="ssl.TLSVersion")  # we probe old TLS on purpose
VERSIONS = {"TLS 1.0": ssl.TLSVersion.TLSv1, "TLS 1.1": ssl.TLSVersion.TLSv1_1,
            "TLS 1.2": ssl.TLSVersion.TLSv1_2, "TLS 1.3": ssl.TLSVersion.TLSv1_3}
WEAK_PROTOCOLS = {"TLS 1.0", "TLS 1.1"}


def classify_cipher(name: str) -> list[str]:
    """Reasons a TLS 1.2 (OpenSSL-named) cipher suite is weak or dated; an empty list means no concerns."""
    n, why = name.upper(), []
    for token, reason in (("NULL", "no encryption"), ("EXPORT", "export-grade 40/56-bit crypto"), ("ANON", "no authentication"),
                          ("RC4", "RC4 is broken"), ("DES-CBC3", "3DES: 64-bit block (Sweet32)"), ("MD5", "MD5 MAC"),
                          ("-DES-", "single DES: 56-bit key")):
        if token in n:
            why.append(reason)
    if not n.startswith(("ECDHE", "DHE", "TLS_")):
        why.append("no forward secrecy (static RSA key exchange)")
    if "CBC" in n and not why:
        why.append("CBC mode (legacy; AEAD suites preferred)")
    return why


def _connect(host: str, port: int, timeout: float = 10.0) -> socket.socket:
    proxy = urllib.parse.urlparse(os.environ.get("HTTPS_PROXY", ""))
    if proxy.hostname and host not in ("localhost", "127.0.0.1"):
        s = socket.create_connection((proxy.hostname, proxy.port), timeout=timeout)
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        reply = s.recv(4096)
        if b" 200 " not in reply.split(b"\r\n")[0]:
            raise ConnectionError(reply.split(b"\r\n")[0].decode(errors="replace"))
        return s
    return socket.create_connection((host, port), timeout=timeout)


def _context(min_v, max_v, ciphers: str | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE   # we are probing, not authenticating
    ctx.set_ciphers(ciphers or "ALL:@SECLEVEL=0")
    try:
        ctx.minimum_version, ctx.maximum_version = min_v, max_v
    except ValueError:
        raise
    return ctx


def handshake(host: str, port: int, min_v, max_v, ciphers: str | None = None):
    """Return (negotiated version, cipher name, peer cert DER) or None if the server refuses / we cannot offer it."""
    try:
        ctx = _context(min_v, max_v, ciphers)
        with _connect(host, port) as raw, ctx.wrap_socket(raw, server_hostname=host) as tls:
            return tls.version(), tls.cipher()[0], tls.getpeercert(binary_form=True)
    except (ssl.SSLError, OSError, ValueError):
        return None


def probe_protocol(host: str, port: int, version) -> str:
    """'supported', 'refused by server', or 'cannot test' (the local OpenSSL will not offer this version)."""
    try:
        ctx = _context(version, version)
        with _connect(host, port) as raw, ctx.wrap_socket(raw, server_hostname=host):
            return "supported"
    except ssl.SSLError as e:
        reason = (getattr(e, "reason", "") or str(e)).upper()
        if any(k in reason for k in ("NO_PROTOCOLS_AVAILABLE", "UNSUPPORTED_PROTOCOL", "NO_CIPHERS", "INAPPROPRIATE_FALLBACK")):
            return "cannot test (local OpenSSL does not offer it)"
        return "refused by server"
    except ValueError:
        return "cannot test (local OpenSSL does not offer it)"
    except OSError:
        return "unreachable"


def cert_info(der: bytes) -> dict:
    c = x509.load_der_x509_certificate(der)
    pub = c.public_key()
    key = (f"RSA {pub.key_size}" if isinstance(pub, rsa.RSAPublicKey) else
           f"EC {pub.curve.name}" if isinstance(pub, ec.EllipticCurvePublicKey) else type(pub).__name__)
    left = (c.not_valid_after_utc - datetime.now(timezone.utc)).days
    try:
        san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []
    return {"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(), "key": key,
            "signature": c.signature_algorithm_oid._name, "days_left": left, "san": san[:6],
            "self_signed": c.issuer == c.subject}


def http_headers(host: str, port: int) -> dict[str, str]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        with _connect(host, port) as raw, ctx.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
        lines = data.split(b"\r\n\r\n")[0].decode(errors="replace").split("\r\n")[1:]
        return {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in lines if ":" in l)}
    except OSError:
        return {}


def audit(host: str, port: int = 443) -> dict:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    offered = [c["name"] for c in ctx.get_ciphers() if c["protocol"] != "TLSv1.3"]

    protocols = {}
    for label, v in VERSIONS.items():
        protocols[label] = probe_protocol(host, port, v)
    first = handshake(host, port, ssl.TLSVersion.MINIMUM_SUPPORTED, ssl.TLSVersion.MAXIMUM_SUPPORTED)
    with ThreadPoolExecutor(8) as pool:    # try every TLS 1.2 suite individually
        tried = list(pool.map(lambda c: (c, handshake(host, port, VERSIONS["TLS 1.2"], VERSIONS["TLS 1.2"], c)), offered))
    accepted = sorted({c for c, r in tried if r})
    return {"host": host, "negotiated_by_default": first[:2] if first else None, "protocols": protocols,
            "tls12_suites_accepted": accepted, "tls12_suites_tested": len(offered),
            "certificate": cert_info(first[2]) if first else None, "headers": http_headers(host, port)}


def findings(report: dict) -> list[tuple[str, str, str]]:
    """(severity, finding, remediation) tuples derived from an audit report."""
    out = []
    for p in WEAK_PROTOCOLS:
        if report["protocols"].get(p) == "supported":
            out.append(("HIGH", f"{p} is enabled", f"Disable {p}; require TLS 1.2 or newer (PCI DSS and NIST SP 800-52 ask for this)."))
    for p in WEAK_PROTOCOLS:
        if report["protocols"].get(p, "").startswith("cannot test"):
            out.append(("INFO", f"{p} could not be tested from this machine", "Confirm with testssl.sh or SSL Labs from a machine whose OpenSSL still offers legacy protocols."))
    if report["protocols"].get("TLS 1.3") != "supported":
        out.append(("MEDIUM", "TLS 1.3 not available", "Enable TLS 1.3: fewer round trips and no legacy cipher suites."))
    for suite in report["tls12_suites_accepted"]:
        why = classify_cipher(suite)
        if why:
            sev = "LOW" if all(w.startswith(("CBC", "no forward")) for w in why) and "forward" not in " ".join(why) else "HIGH"
            out.append((sev, f"weak TLS 1.2 suite {suite}: {', '.join(why)}", f"Remove {suite}; keep ECDHE + AES-GCM/ChaCha20-Poly1305 suites."))
    cert = report.get("certificate")
    if cert:
        if cert["days_left"] < 21:
            out.append(("HIGH" if cert["days_left"] < 0 else "MEDIUM", f"certificate expires in {cert['days_left']} days", "Automate renewal (ACME)."))
        if cert["self_signed"]:
            out.append(("HIGH", "self-signed certificate", "Use a certificate from a publicly trusted CA."))
        if cert["key"].startswith("RSA") and int(cert["key"].split()[1]) < 2048:
            out.append(("HIGH", f"short key ({cert['key']})", "Use RSA 2048+ or an EC P-256 key."))
    h = report.get("headers", {})
    if "strict-transport-security" not in h:
        out.append(("MEDIUM", "no Strict-Transport-Security header", "Send HSTS: max-age=63072000; includeSubDomains."))
    return out


def render(report: dict) -> str:
    lines = [f"TLS audit: {report['host']}", f"default negotiation: {report['negotiated_by_default']}"]
    lines += [f"  {k}: {v}" for k, v in report["protocols"].items()]
    n, t = len(report["tls12_suites_accepted"]), report["tls12_suites_tested"]
    lines.append(f"TLS 1.2 suites accepted: {n} of {t} tested")
    lines += [f"  {s}" for s in report["tls12_suites_accepted"]]
    if report["certificate"]:
        lines.append("certificate: " + json.dumps(report["certificate"]))
    lines.append("security headers present: " + ", ".join(k for k in report["headers"] if k in (
        "strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy")) or "none")
    lines.append("\nFINDINGS")
    fs = findings(report)
    lines += [f"  [{sev}] {f}\n         fix: {fix}" for sev, f, fix in fs] or ["  none"]
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Audit a TLS endpoint you own or may test")
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    rep = audit(a.host, a.port)
    print(json.dumps(rep, indent=2) if a.json else render(rep))
