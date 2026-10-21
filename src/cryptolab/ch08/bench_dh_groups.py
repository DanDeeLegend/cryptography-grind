"""Assignment 8.5: cost and security of standardised finite-field DH groups, versus elliptic-curve DH.

Times one DH key generation (g^a mod p) and one shared-secret computation (peer^a mod p) for RFC 7919 groups. A full
handshake costs each side one of each. Security levels are the NIST SP 800-57 estimates for finite-field DH.
"""
from __future__ import annotations

import time

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import dh

SECURITY_BITS = {"ffdhe2048": 112, "ffdhe3072": 128, "ffdhe4096": 152}


def _ms(fn, n: int) -> float:
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    return (time.perf_counter() - t0) / n * 1e3


def run(repeats: int = 30) -> list[dict]:
    rows = []
    for g in (dh.FFDHE2048, dh.FFDHE3072, dh.FFDHE4096):
        a = dh.private_key(g)
        peer = dh.public_key(g, dh.private_key(g))
        rows.append({"group": g.name, "bits": g.p.bit_length(), "security": SECURITY_BITS[g.name],
                     "keygen_ms": _ms(lambda: dh.public_key(g, a), repeats),
                     "shared_ms": _ms(lambda: dh.shared_secret(g, a, peer), repeats),
                     "public_bytes": (g.p.bit_length() + 7) // 8})
    k, peer = X25519PrivateKey.generate(), X25519PrivateKey.generate().public_key()
    rows.append({"group": "X25519 (ECDH)", "bits": 255, "security": 128, "keygen_ms": _ms(X25519PrivateKey.generate, 300),
                 "shared_ms": _ms(lambda: k.exchange(peer), 300), "public_bytes": 32})
    return rows


def markdown(rows: list[dict]) -> str:
    base = rows[-1]["keygen_ms"] + rows[-1]["shared_ms"]
    out = ["| Group | Size (bits) | Security (bits) | Keygen ms | Shared-secret ms | Per-side handshake ms | Public value (bytes) | Cost vs X25519 |",
           "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for r in rows:
        tot = r["keygen_ms"] + r["shared_ms"]
        out.append(f"| {r['group']} | {r['bits']} | {r['security']} | {r['keygen_ms']:.3f} | {r['shared_ms']:.3f} | {tot:.3f} | "
                   f"{r['public_bytes']} | {tot / base:,.0f}x |")
    return "\n".join(out)


if __name__ == "__main__":
    print(markdown(run()))
