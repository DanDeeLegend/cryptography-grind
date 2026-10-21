"""Assignment 12.6: AES-128-CBC + HMAC-SHA256 (encrypt-then-MAC) vs AES-128-GCM, throughput by message size.

Both are correct constructions; GCM is one primitive, one key, parallelisable and usually hardware-accelerated.
"""
from __future__ import annotations

import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptolab.ch12.compose import etm_decrypt, etm_encrypt

SIZES = [64, 1024, 64 * 1024, 1024 * 1024]


def _time(fn, min_s: float = 0.4) -> float:
    n, start = 0, time.perf_counter()
    while time.perf_counter() - start < min_s:
        fn()
        n += 1
    return (time.perf_counter() - start) / n


def run() -> list[dict]:
    ke, km, gk = os.urandom(16), os.urandom(32), AESGCM.generate_key(128)
    g, rows = AESGCM(gk), []
    for size in SIZES:
        pt = os.urandom(size)
        nonce = os.urandom(12)
        iv, ct, tag = etm_encrypt(ke, km, pt)
        gct = g.encrypt(nonce, pt, None)
        assert etm_decrypt(ke, km, iv, ct, tag) == pt and g.decrypt(nonce, gct, None) == pt
        e = _time(lambda: etm_decrypt(ke, km, *etm_encrypt(ke, km, pt)))
        c = _time(lambda: g.decrypt(nonce, g.encrypt(nonce, pt, None), None))
        rows.append({"size": size, "etm_mbps": size / e / 1e6, "gcm_mbps": size / c / 1e6})
    return rows


def markdown() -> str:
    out = ["| Message size | AES-CBC + HMAC (MB/s) | AES-GCM (MB/s) | GCM speed-up |", "|---|---|---|---|"]
    for r in run():
        label = f"{r['size']} B" if r["size"] < 1024 else f"{r['size'] // 1024} KiB"
        out.append(f"| {label} | {r['etm_mbps']:,.0f} | {r['gcm_mbps']:,.0f} | {r['gcm_mbps'] / r['etm_mbps']:.1f}x |")
    return "\n".join(out)


if __name__ == "__main__":
    print(markdown())
