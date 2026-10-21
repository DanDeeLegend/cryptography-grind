"""Assignment 3.5: 3DES vs AES-128 throughput on the same machine and data.

Uses PyCryptodome in CBC mode. AES is measured twice: with hardware acceleration (AES-NI, when the
CPU has it) and with the portable software implementation, so the structural gap between the two
ciphers is separable from the "AES has a CPU instruction" effect.
"""
from __future__ import annotations

import os
import platform
import time

from Crypto.Cipher import AES, DES3
from Crypto.Random import get_random_bytes


def _des3_key() -> bytes:
    while True:
        try:
            return DES3.adjust_key_parity(get_random_bytes(24))
        except ValueError:   # PyCryptodome rejects degenerate (repeated) subkeys
            continue


def throughput(make_cipher, data: bytes, repeats: int = 5) -> float:
    """Best-of-N MB/s encrypting `data` once per run (a fresh cipher each time, as CBC state is consumed)."""
    best = float("inf")
    for _ in range(repeats):
        cipher = make_cipher()
        t0 = time.perf_counter()
        cipher.encrypt(data)
        best = min(best, time.perf_counter() - t0)
    return len(data) / best / 1e6


def openssl_rows(sizes):
    """Same measurement through OpenSSL (the `cryptography` package) as a second, independent library."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:  # older cryptography versions kept it in the main namespace
        TripleDES = algorithms.TripleDES  # type: ignore[attr-defined]
    k3, k16, iv8, iv16 = os.urandom(24), os.urandom(16), os.urandom(8), os.urandom(16)
    rows = []
    for size in sizes:
        data = os.urandom(size)
        rows.append({
            "size": size,
            "3DES": _ossl(lambda: Cipher(TripleDES(k3), modes.CBC(iv8)).encryptor(), data),
            "AES-128 (AES-NI)": _ossl(lambda: Cipher(algorithms.AES(k16), modes.CBC(iv16)).encryptor(), data),
        })
    return rows


def _ossl(make_encryptor, data: bytes, repeats: int = 5) -> float:
    best = float("inf")
    for _ in range(repeats):
        enc = make_encryptor()
        t0 = time.perf_counter()
        enc.update(data)
        best = min(best, time.perf_counter() - t0)
    return len(data) / best / 1e6


def cpu_has_aesni() -> bool:
    try:
        return " aes" in open("/proc/cpuinfo").read().split("flags")[1].split("\n")[0] + " "
    except (OSError, IndexError):
        return False


def run(sizes=(64 * 1024, 1024 * 1024, 16 * 1024 * 1024)) -> list[dict]:
    k3, k16, iv8, iv16 = _des3_key(), get_random_bytes(16), get_random_bytes(8), get_random_bytes(16)
    rows = []
    for size in sizes:
        data = os.urandom(size)
        rows.append({
            "size": size,
            "3DES": throughput(lambda: DES3.new(k3, DES3.MODE_CBC, iv8), data),
            "AES-128 (software)": throughput(lambda: AES.new(k16, AES.MODE_CBC, iv16, use_aesni=False), data),
            "AES-128 (AES-NI)": throughput(lambda: AES.new(k16, AES.MODE_CBC, iv16), data),
        })
    return rows


def markdown(rows: list[dict]) -> str:
    out = ["| Data size | 3DES MB/s | AES-128 software MB/s | AES-128 AES-NI MB/s | AES(sw)/3DES | AES-NI/3DES |",
           "|---:|---:|---:|---:|---:|---:|"]
    for r in rows:
        d, s, n = r["3DES"], r["AES-128 (software)"], r["AES-128 (AES-NI)"]
        out.append(f"| {r['size'] // 1024:,} KiB | {d:,.0f} | {s:,.0f} | {n:,.0f} | {s / d:.1f}x | {n / d:.1f}x |")
    return "\n".join(out)


def markdown_openssl(rows: list[dict]) -> str:
    out = ["| Data size | 3DES MB/s | AES-128 AES-NI MB/s | AES-NI/3DES |", "|---:|---:|---:|---:|"]
    for r in rows:
        out.append(f"| {r['size'] // 1024:,} KiB | {r['3DES']:,.0f} | {r['AES-128 (AES-NI)']:,.0f} | "
                   f"{r['AES-128 (AES-NI)'] / r['3DES']:.1f}x |")
    return "\n".join(out)


def demo() -> None:
    sizes = (64 * 1024, 1024 * 1024, 16 * 1024 * 1024)
    print(f"machine: {platform.processor() or platform.machine()}, AES-NI flag present: {cpu_has_aesni()}")
    print("\nPyCryptodome:")
    print(markdown(run(sizes)))
    print("\nOpenSSL (cryptography package):")
    print(markdown_openssl(openssl_rows(sizes)))


if __name__ == "__main__":
    demo()
