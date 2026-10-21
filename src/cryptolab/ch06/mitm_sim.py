"""Assignment 6.6: man-in-the-middle on an unauthenticated key exchange, and a fix that makes it detectable.

Alice and Bob run an ephemeral X25519 exchange over a channel an attacker (Mallory) controls. Nothing in the
exchange says WHOSE public key it is, so Mallory can swap in her own keys, share one secret with Alice and another
with Bob, and silently decrypt, read and re-encrypt every message. The fix here is a short authentication string
(SAS): each side hashes the two public keys it saw, and the people compare that code over a channel Mallory does not
control (a phone call, in person). Under attack the codes differ. (Chapter 8.2 closes the gap with signatures.)
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def _pub(k: X25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(**RAW)


def _session_key(priv: X25519PrivateKey, peer_pub: bytes) -> bytes:
    shared = priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"mitm-demo").derive(shared)


def sas(pub_a: bytes, pub_b: bytes) -> str:
    """Short code both humans read aloud. Order-independent so each side can compute it from its own view."""
    d = hashlib.sha256(b"".join(sorted((pub_a, pub_b)))).digest()
    return "-".join(f"{d[i]:02X}{d[i + 1]:02X}" for i in (0, 2, 4))


def seal(key: bytes, text: str) -> bytes:
    n = os.urandom(12)
    return n + AESGCM(key).encrypt(n, text.encode(), None)


def open_(key: bytes, blob: bytes) -> str:
    return AESGCM(key).decrypt(blob[:12], blob[12:], None).decode()


@dataclass
class Party:
    name: str
    priv: X25519PrivateKey
    peer_pub: bytes = b""
    key: bytes = b""

    @classmethod
    def new(cls, name: str) -> "Party":
        return cls(name, X25519PrivateKey.generate())

    @property
    def pub(self) -> bytes:
        return _pub(self.priv)

    def accept(self, peer_pub: bytes) -> None:
        self.peer_pub, self.key = peer_pub, _session_key(self.priv, peer_pub)

    def code(self) -> str:
        return sas(self.pub, self.peer_pub)


def run(mallory_present: bool) -> dict:
    alice, bob = Party.new("Alice"), Party.new("Bob")
    if not mallory_present:
        alice.accept(bob.pub); bob.accept(alice.pub)
        wire = seal(alice.key, "meet at noon")
        return {"bob_reads": open_(bob.key, wire), "mallory_reads": None, "alice_code": alice.code(), "bob_code": bob.code()}

    m_to_a, m_to_b = Party.new("Mallory-as-Bob"), Party.new("Mallory-as-Alice")
    alice.accept(m_to_a.pub)              # Alice thinks this is Bob's key
    bob.accept(m_to_b.pub)                # Bob thinks this is Alice's key
    m_to_a.accept(alice.pub); m_to_b.accept(bob.pub)
    wire = seal(alice.key, "meet at noon")                       # Alice -> (Mallory) -> Bob
    seen = open_(m_to_a.key, wire)                               # Mallory decrypts with her key shared with Alice
    forged = seal(m_to_b.key, seen.replace("noon", "midnight"))  # ...edits it, re-encrypts for Bob
    return {"bob_reads": open_(bob.key, forged), "mallory_reads": seen, "alice_code": alice.code(), "bob_code": bob.code()}


def demo() -> None:
    for label, present in (("no attacker", False), ("MALLORY IN THE MIDDLE", True)):
        r = run(present)
        print(f"\n[{label}] Alice's code {r['alice_code']}  Bob's code {r['bob_code']}  -> "
              f"{'match' if r['alice_code'] == r['bob_code'] else 'MISMATCH: attack detected'}")
        print(f"  Bob reads: {r['bob_reads']!r}   Mallory read: {r['mallory_reads']!r}")


if __name__ == "__main__":
    demo()
