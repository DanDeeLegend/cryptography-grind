"""Assignment 6.5: hybrid encryption, the pattern behind TLS, PGP, S/MIME and every "envelope" scheme.

    sender                                              receiver
    ------                                              --------
    random 256-bit AES key K
    ciphertext = AES-GCM(K, message)    --------->      K = RSA-OAEP-decrypt(wrapped_key, private key)
    wrapped_key = RSA-OAEP(public key, K) ------>       message = AES-GCM-decrypt(K, ciphertext)

Public-key operations are slow and size-limited, so RSA only protects the short key; the bulk data goes through
fast AES-GCM. The wrapped key is bound into the AES-GCM associated data, so a ciphertext cannot be re-attached
to a different wrapped key.
Format: "HYB1" | len(wrapped)(2) | wrapped | nonce(12) | AES-GCM ciphertext+tag
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .bench_sym_vs_pk import OAEP

MAGIC = b"HYB1"


class HybridError(Exception):
    pass


def generate_keypair(bits: int = 3072) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(65537, bits)


def encrypt(public_key: rsa.RSAPublicKey, message: bytes, aad: bytes = b"") -> bytes:
    key = AESGCM.generate_key(256)
    wrapped = public_key.encrypt(key, OAEP)
    header = MAGIC + len(wrapped).to_bytes(2, "big") + wrapped
    nonce = os.urandom(12)                                   # fresh key per message, so a random nonce is safe
    return header + nonce + AESGCM(key).encrypt(nonce, message, header + aad)


def decrypt(private_key: rsa.RSAPrivateKey, blob: bytes, aad: bytes = b"") -> bytes:
    try:
        if blob[:4] != MAGIC:
            raise HybridError("not a HYB1 message")
        n = int.from_bytes(blob[4:6], "big")
        header, wrapped = blob[:6 + n], blob[6:6 + n]
        nonce, body = blob[6 + n:18 + n], blob[18 + n:]
        key = private_key.decrypt(wrapped, OAEP)
        return AESGCM(key).decrypt(nonce, body, header + aad)
    except HybridError:
        raise
    except Exception as e:                                   # wrong key, tampering, truncation: one generic error
        raise HybridError("decryption failed") from e


def demo() -> None:
    priv = generate_keypair()
    msg = b"hybrid encryption: RSA wraps a 32-byte key, AES encrypts the rest " * 20_000
    blob = encrypt(priv.public_key(), msg)
    print(f"message {len(msg):,} bytes -> blob {len(blob):,} bytes (overhead {len(blob) - len(msg)} bytes)")
    print("round-trip OK:", decrypt(priv, blob) == msg)


if __name__ == "__main__":
    demo()
