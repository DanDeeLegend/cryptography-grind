"""Assignment 12.4: MAC-then-encrypt (MtE) vs encrypt-then-MAC (EtM) with AES-CBC + HMAC-SHA256, and a Vaudenay padding oracle.

MtE: tag = HMAC(plaintext); CBC(pad(plaintext || tag)). The receiver must decrypt BEFORE it can check anything, so
unpadding errors happen on attacker-controlled data, and if the error for bad padding differs from the error for bad MAC
(message, status code, or even timing) the attacker learns plaintext one byte at a time.
EtM: CBC(pad(plaintext)); tag = HMAC(iv || ciphertext). The receiver checks the tag first and rejects anything modified
before touching the cipher, so there is no padding oracle to query.

Lucky 13 (2013) showed that even MtE with identical error *messages* leaked through timing differences. It is described in
the write-up, not reproduced here.
"""
from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.hazmat.primitives import padding as pkcs7
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BS = 16


class BadPadding(Exception): ...
class BadMac(Exception): ...


def _cbc(key: bytes, iv: bytes, data: bytes, enc: bool) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    x = c.encryptor() if enc else c.decryptor()
    return x.update(data) + x.finalize()


def _pad(b: bytes) -> bytes:
    p = pkcs7.PKCS7(128).padder()
    return p.update(b) + p.finalize()


def _unpad(b: bytes) -> bytes:
    u = pkcs7.PKCS7(128).unpadder()
    try:
        return u.update(b) + u.finalize()
    except ValueError:
        raise BadPadding from None


def _mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


# ---- MAC-then-encrypt (the flawed composition) ----
def mte_encrypt(ke: bytes, km: bytes, pt: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(BS)
    return iv, _cbc(ke, iv, _pad(pt + _mac(km, pt)), True)


def mte_decrypt(ke: bytes, km: bytes, iv: bytes, ct: bytes) -> bytes:
    body = _unpad(_cbc(ke, iv, ct, False))  # raises BadPadding: the leak
    pt, tag = body[:-32], body[-32:]
    if not hmac.compare_digest(tag, _mac(km, pt)):
        raise BadMac
    return pt


# ---- encrypt-then-MAC (the recommended composition) ----
def etm_encrypt(ke: bytes, km: bytes, pt: bytes) -> tuple[bytes, bytes, bytes]:
    iv = os.urandom(BS)
    ct = _cbc(ke, iv, _pad(pt), True)
    return iv, ct, _mac(km, iv + ct)


class Invalid(Exception):
    """The only error EtM ever reports."""


def etm_decrypt(ke: bytes, km: bytes, iv: bytes, ct: bytes, tag: bytes) -> bytes:
    if not hmac.compare_digest(tag, _mac(km, iv + ct)):
        raise Invalid
    try:
        return _unpad(_cbc(ke, iv, ct, False))
    except BadPadding:
        raise Invalid from None


# ---- the attack ----
def _recover_block(oracle, prev: bytes, block: bytes) -> bytes:
    """Return D_K(block) (the intermediate value) using only `oracle(forged_prev, block) -> padding_ok`."""
    inter = bytearray(BS)
    for pos in range(BS - 1, -1, -1):
        pad = BS - pos
        found = False
        for g in range(256):
            forged = bytearray(BS)
            for j in range(pos + 1, BS):
                forged[j] = inter[j] ^ pad
            forged[pos] = g
            if not oracle(bytes(forged), block):
                continue
            if pos == BS - 1:  # rule out accidental "...02 02" style valid padding
                check = bytearray(forged)
                check[pos - 1] ^= 1
                if not oracle(bytes(check), block):
                    continue
            inter[pos] = g ^ pad
            found = True
            break
        if not found:
            raise RuntimeError("no padding signal: oracle gives nothing away")
    return bytes(inter)


def padding_oracle_attack(oracle, iv: bytes, ct: bytes) -> tuple[bytes, int]:
    """Recover the full padded plaintext. `oracle(iv, ct) -> bool`. Returns (padded_plaintext, queries)."""
    n = 0

    def counted(i, c):
        nonlocal n
        n += 1
        return oracle(i, c)

    blocks = [iv] + [ct[i:i + BS] for i in range(0, len(ct), BS)]
    out = b""
    for prev, blk in zip(blocks, blocks[1:]):
        inter = _recover_block(counted, prev, blk)
        out += bytes(a ^ b for a, b in zip(inter, prev))
    return out, n


def mte_oracle(ke: bytes, km: bytes):
    """What a careless server reveals: 'bad padding' vs anything else."""
    def oracle(iv: bytes, ct: bytes) -> bool:
        try:
            mte_decrypt(ke, km, iv, ct)
        except BadPadding:
            return False
        except BadMac:
            return True
        return True
    return oracle


def etm_oracle(ke: bytes, km: bytes, tag: bytes):
    """Same attacker, same forged inputs, against EtM: every modified ciphertext is rejected identically."""
    def oracle(iv: bytes, ct: bytes) -> bool:
        try:
            etm_decrypt(ke, km, iv, ct, tag)
        except Invalid:
            return False
        return True
    return oracle


def demo() -> dict:
    ke, km = os.urandom(16), os.urandom(32)
    secret = b"session=9f8e7d6c5b4a; user=daniel"
    iv, ct = mte_encrypt(ke, km, secret)
    padded, queries = padding_oracle_attack(mte_oracle(ke, km), iv, ct)
    # the attacker recovers pt || tag || padding; strip PKCS#7 padding and the 32-byte tag
    body = padded[:-padded[-1]]
    pt = body[:-32]
    eiv, ect, etag = etm_encrypt(ke, km, secret)
    try:
        padding_oracle_attack(etm_oracle(ke, km, etag), eiv, ect)
        etm_leaks = True
    except RuntimeError:
        etm_leaks = False
    return {"mte_plaintext_recovered": pt == secret, "queries": queries, "etm_leaks": etm_leaks}


if __name__ == "__main__":
    for k, v in demo().items():
        print(f"{k}: {v}")
