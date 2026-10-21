"""Assignment 4.4: AES throughput with and without hardware acceleration.

Compares, on the same machine and data: AES-NI (PyCryptodome and OpenSSL), portable software AES in C
(PyCryptodome with AES-NI disabled) and a pure-Python AES (ours) as the extreme "no tricks" fallback.
"""
from __future__ import annotations

import os
import time

from Crypto.Cipher import AES

from . import aes as scratch
from cryptolab.ch03.bench_3des_aes import cpu_has_aesni, _ossl, throughput


def pure_python_mb_s(size: int = 4096) -> float:
    key, data = os.urandom(16), os.urandom(size)
    t0 = time.perf_counter()
    scratch.ecb_encrypt(data, key)
    return size / (time.perf_counter() - t0) / 1e6


def run(sizes=(64 * 1024, 1024 * 1024, 16 * 1024 * 1024)) -> list[dict]:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key, iv = os.urandom(16), os.urandom(16)
    rows = []
    for size in sizes:
        data = os.urandom(size)
        rows.append({
            "size": size,
            "AES-NI (PyCryptodome)": throughput(lambda: AES.new(key, AES.MODE_CBC, iv), data),
            "AES-NI (OpenSSL)": _ossl(lambda: Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor(), data),
            "software C (AES-NI off)": throughput(lambda: AES.new(key, AES.MODE_CBC, iv, use_aesni=False), data),
        })
    return rows


def markdown(rows: list[dict], pure: float) -> str:
    cols = ["AES-NI (PyCryptodome)", "AES-NI (OpenSSL)", "software C (AES-NI off)"]
    out = ["| Data size | " + " | ".join(f"{c} MB/s" for c in cols) + " | AES-NI / software |", "|---:|" + "---:|" * 4]
    for r in rows:
        out.append(f"| {r['size'] // 1024:,} KiB | " + " | ".join(f"{r[c]:,.0f}" for c in cols)
                   + f" | {r[cols[0]] / r[cols[2]]:.1f}x |")
    out.append(f"\nPure-Python AES (this repo, 4 KiB): {pure:.3f} MB/s "
               f"= {rows[-1][cols[2]] / pure:,.0f}x slower than software C.")
    return "\n".join(out)


def demo() -> None:
    print(f"AES-NI flag in /proc/cpuinfo: {cpu_has_aesni()}")
    print(markdown(run(), pure_python_mb_s()))


if __name__ == "__main__":
    demo()
