"""Assignment 9.2: ECDH, and its size/speed against RSA and finite-field DH at equivalent security.

Everything here goes through OpenSSL (the `cryptography` package) so the comparison is fair; the from-scratch curve
code is cross-checked against it. Equivalent strengths are the NIST SP 800-57 correspondences.
"""
from __future__ import annotations

import os
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, ec, padding, rsa, x25519

from cryptolab.ch08.groups import FFDHE2048_P, FFDHE3072_P
from . import ec as myec

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
PUB = dict(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)
RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
DER = dict(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)


def _t(fn, n: int) -> float:
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - t0) / n * 1e3          # ms


def scratch_matches_openssl() -> bool:
    """Our P-256 ECDH produces the same shared secret as OpenSSL's."""
    a, b = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    qn = b.public_key().public_numbers()
    mine = myec.scalar_mult(myec.P256, a.private_numbers().private_value, (qn.x, qn.y))
    return mine[0].to_bytes(32, "big") == a.exchange(ec.ECDH(), b.public_key())


def compare(rounds: int = 20) -> list[dict]:
    rows = []
    # elliptic-curve ECDH: each side does keygen + one exchange
    for name, sec, gen, size, pubfmt in (
            ("X25519", 128, lambda: x25519.X25519PrivateKey.generate(), 32, RAW),
            ("ECDH P-256", 128, lambda: ec.generate_private_key(ec.SECP256R1()), 32, PUB),
            ("ECDH P-384", 192, lambda: ec.generate_private_key(ec.SECP384R1()), 48, PUB)):
        a, b = gen(), gen()
        ex = (lambda: a.exchange(b.public_key())) if name == "X25519" else (lambda: a.exchange(ec.ECDH(), b.public_key()))
        ms = _t(gen, rounds * 5) + _t(ex, rounds * 5)
        rows.append({"scheme": name, "security": sec, "private_bytes": size, "public_bytes": len(b.public_key().public_bytes(**pubfmt)), "ms": ms})
    # finite-field DH
    for name, sec, p in (("DH ffdhe2048", 112, FFDHE2048_P), ("DH ffdhe3072", 128, FFDHE3072_P)):
        params = dh.DHParameterNumbers(p, 2).parameters()
        a, b = params.generate_private_key(), params.generate_private_key()
        ms = _t(params.generate_private_key, rounds) + _t(lambda: a.exchange(b.public_key()), rounds)
        rows.append({"scheme": name, "security": sec, "private_bytes": (p.bit_length() + 7) // 8,
                     "public_bytes": (p.bit_length() + 7) // 8, "ms": ms})
    # RSA key transport: the client encrypts a 32-byte secret, the server decrypts it
    for bits, sec in ((2048, 112), (3072, 128)):
        k = rsa.generate_private_key(65537, bits)
        secret = os.urandom(32)
        ct = k.public_key().encrypt(secret, OAEP)
        ms = _t(lambda: k.public_key().encrypt(secret, OAEP), rounds * 5) + _t(lambda: k.decrypt(ct, OAEP), rounds)
        rows.append({"scheme": f"RSA-{bits} key transport", "security": sec, "private_bytes": len(k.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
            "public_bytes": len(k.public_key().public_bytes(**DER)), "ms": ms})
    return rows


def markdown(rows: list[dict]) -> str:
    base = next(r["ms"] for r in rows if r["scheme"] == "X25519")
    out = ["| Scheme | Security (bits) | Private key (bytes) | Public key (bytes) | Time, both sides (ms) | vs X25519 |", "|---|---:|---:|---:|---:|---:|"]
    for r in rows:
        out.append(f"| {r['scheme']} | {r['security']} | {r['private_bytes']} | {r['public_bytes']} | {r['ms']:.3f} | {r['ms'] / base:,.0f}x |")
    return "\n".join(out)


def demo() -> None:
    print("from-scratch P-256 ECDH matches OpenSSL:", scratch_matches_openssl())
    print(markdown(compare()))


if __name__ == "__main__":
    demo()
