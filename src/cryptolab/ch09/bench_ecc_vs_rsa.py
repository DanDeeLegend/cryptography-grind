"""Assignment 9.5: signing/verification benchmark for a constrained device (memo in docs/ch09.md).

Measured as wall-clock time per operation on this (server-class) machine: a proxy for relative CPU work, NOT a
measurement of a microcontroller's energy. Multiply by your device's clock ratio, and measure on target hardware.
"""
from __future__ import annotations

import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
MSG = os.urandom(256)                                   # a typical small telemetry/command message


def _us(fn, n: int) -> float:
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - t0) / n * 1e6


def run() -> list[dict]:
    rows = []
    k = ed25519.Ed25519PrivateKey.generate(); s = k.sign(MSG); q = k.public_key()
    rows.append(("Ed25519", 128, _us(ed25519.Ed25519PrivateKey.generate, 200), _us(lambda: k.sign(MSG), 500), _us(lambda: q.verify(s, MSG), 500), len(s), 32))
    k = ec.generate_private_key(ec.SECP256R1()); s = k.sign(MSG, ec.ECDSA(hashes.SHA256())); q = k.public_key()
    rows.append(("ECDSA P-256", 128, _us(lambda: ec.generate_private_key(ec.SECP256R1()), 200), _us(lambda: k.sign(MSG, ec.ECDSA(hashes.SHA256())), 500),
                 _us(lambda: q.verify(s, MSG, ec.ECDSA(hashes.SHA256())), 500), len(s), 65))
    for bits, sec, reps in ((2048, 112, 3), (3072, 128, 2)):
        t0 = time.perf_counter(); k = rsa.generate_private_key(65537, bits); gen = (time.perf_counter() - t0) * 1e6
        s = k.sign(MSG, PSS, hashes.SHA256()); q = k.public_key()
        rows.append((f"RSA-{bits} PSS", sec, gen, _us(lambda: k.sign(MSG, PSS, hashes.SHA256()), 50 if bits == 2048 else 20),
                     _us(lambda: q.verify(s, MSG, PSS, hashes.SHA256()), 1000), len(s), bits // 8))
    return [dict(zip(("scheme", "security", "keygen_us", "sign_us", "verify_us", "sig_bytes", "pub_bytes"), r)) for r in rows]


def markdown(rows: list[dict]) -> str:
    out = ["| Scheme | Security | Keygen | Sign | Verify | Signatures/s | Verifies/s | Signature (B) | Public key (B) |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    fmt = lambda us: f"{us / 1e6:.2f} s" if us >= 1e6 else f"{us / 1e3:.1f} ms" if us >= 1e3 else f"{us:.0f} us"
    for r in rows:
        out.append(f"| {r['scheme']} | {r['security']} | {fmt(r['keygen_us'])} | {fmt(r['sign_us'])} | {fmt(r['verify_us'])} | "
                   f"{1e6 / r['sign_us']:,.0f} | {1e6 / r['verify_us']:,.0f} | {r['sig_bytes']} | {r['pub_bytes']} |")
    return "\n".join(out)


if __name__ == "__main__":
    print(markdown(run()))
