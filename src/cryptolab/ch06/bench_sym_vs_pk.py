"""Assignment 6.4: AES-GCM throughput vs RSA encryption/decryption throughput.

RSA can only encrypt a small block per operation (190 bytes for a 2048-bit key with OAEP-SHA256), so its
throughput is (bytes per operation) x (operations per second), measured on the same kind of data as AES.
"""
from __future__ import annotations

import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def _best(fn, repeats: int, runs: int = 3) -> float:
    best = float("inf")
    for _ in range(runs):
        t0 = time.perf_counter()
        for _ in range(repeats):
            fn()
        best = min(best, time.perf_counter() - t0)
    return best / repeats        # seconds per call


def aes_mb_s(size: int = 1024 * 1024) -> float:
    aead, data = AESGCM(AESGCM.generate_key(256)), os.urandom(size)
    return size / _best(lambda: aead.encrypt(os.urandom(12), data, None), 5) / 1e6


def rsa_rows(bits_list=(2048, 3072, 4096)) -> list[dict]:
    rows = []
    for bits in bits_list:
        key = rsa.generate_private_key(65537, bits)
        chunk = os.urandom(bits // 8 - 2 * 32 - 2)               # OAEP-SHA256 capacity
        ct = key.public_key().encrypt(chunk, OAEP)
        enc_s = _best(lambda: key.public_key().encrypt(chunk, OAEP), 200)
        dec_s = _best(lambda: key.decrypt(ct, OAEP), 20)
        rows.append({"bits": bits, "chunk": len(chunk), "enc_ops": 1 / enc_s, "dec_ops": 1 / dec_s,
                     "enc_mb_s": len(chunk) / enc_s / 1e6, "dec_mb_s": len(chunk) / dec_s / 1e6})
    return rows


def markdown(aes: float, rows: list[dict]) -> str:
    out = [f"AES-256-GCM: **{aes:,.0f} MB/s**", "",
           "| RSA key | bytes per op | encrypt ops/s | decrypt ops/s | encrypt MB/s | decrypt MB/s | AES / RSA-decrypt |",
           "|---:|---:|---:|---:|---:|---:|---:|"]
    for r in rows:
        out.append(f"| {r['bits']} | {r['chunk']} | {r['enc_ops']:,.0f} | {r['dec_ops']:,.0f} | {r['enc_mb_s']:.2f} | "
                   f"{r['dec_mb_s']:.3f} | {aes / r['dec_mb_s']:,.0f}x |")
    return "\n".join(out)


def demo() -> None:
    print(markdown(aes_mb_s(), rsa_rows()))


if __name__ == "__main__":
    demo()
