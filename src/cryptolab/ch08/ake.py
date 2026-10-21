"""Assignment 8.6: an authenticated key exchange for a hypothetical chat app (design in docs/ch08.md).

Protocol (a signed-DH "SIGMA-lite", all messages in `Handshake`):
    1. A -> B : A_eph, A_id
    2. B -> A : B_eph, B_id, Sig_B(transcript), MAC_B          # B proves identity AND that it derived the same keys
    3. A -> B : Sig_A(transcript), MAC_A
  transcript = H("AKE1" | A_eph | A_id | B_eph | B_id). Both signatures cover both ephemerals and both identities, so a
  man-in-the-middle cannot splice sessions, and a signature cannot be replayed into a different session.
  Session keys = HKDF(X25519(A_eph, B_eph), salt = transcript): fresh keys per session (forward secrecy: ephemeral
  secrets are deleted after the handshake, so later theft of long-term keys does not reveal recorded traffic).
Identity: each user has a long-term Ed25519 key; peers are remembered on first use and a changed key raises IdentityChanged
until the user re-verifies the safety number out of band.
"""
from __future__ import annotations

import hashlib
import hmac

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


class HandshakeError(Exception):
    pass


class IdentityChanged(HandshakeError):
    pass


class ReplayError(Exception):
    pass


def _raw(pub) -> bytes:
    return pub.public_bytes(**RAW)


class Identity:
    def __init__(self, name: str):
        self.name, self.sk = name, Ed25519PrivateKey.generate()
        self.pub = _raw(self.sk.public_key())

    def safety_number(self) -> str:
        """What two users read to each other once over a trusted channel (a call, in person)."""
        d = hashlib.sha256(self.pub).hexdigest()[:30]
        return " ".join(d[i:i + 5] for i in range(0, 30, 5))


class PeerStore:
    """Trust on first use, with an explicit alarm if a known contact's key changes."""

    def __init__(self):
        self.known: dict[str, bytes] = {}

    def check(self, name: str, pub: bytes) -> str:
        if name not in self.known:
            self.known[name] = pub
            return "new contact (verify the safety number to be sure)"
        if self.known[name] != pub:
            raise IdentityChanged(f"{name}'s identity key changed: possible impersonation, or they reinstalled")
        return "known contact"

    def accept_change(self, name: str, pub: bytes) -> None:   # only after out-of-band verification
        self.known[name] = pub


class Session:
    """Directional AES-GCM keys with strictly increasing counters (rejects replay, reordering and tampering)."""

    def __init__(self, send_key: bytes, recv_key: bytes, transcript: bytes, initiator: bool):
        self._send, self._recv = AESGCM(send_key), AESGCM(recv_key)
        self._aad, self._n_send, self._last_recv = transcript, 0, -1
        self._dir_send, self._dir_recv = (b"\x01", b"\x02") if initiator else (b"\x02", b"\x01")

    def _nonce(self, direction: bytes, counter: int) -> bytes:
        return direction * 4 + counter.to_bytes(8, "big")

    def seal(self, plaintext: bytes) -> bytes:
        c, self._n_send = self._n_send, self._n_send + 1
        return c.to_bytes(8, "big") + self._send.encrypt(self._nonce(self._dir_send, c), plaintext, self._aad)

    def open(self, blob: bytes) -> bytes:
        c = int.from_bytes(blob[:8], "big")
        if c <= self._last_recv:
            raise ReplayError("old or repeated message counter")
        try:
            pt = self._recv.decrypt(self._nonce(self._dir_recv, c), blob[8:], self._aad)
        except InvalidTag as e:
            raise ReplayError("message failed authentication") from e
        self._last_recv = c                                  # advance only after authentication succeeds
        return pt


class Handshake:
    def __init__(self, me: Identity, store: PeerStore, peer_name: str, initiator: bool):
        self.me, self.store, self.peer_name, self.initiator = me, store, peer_name, initiator
        self._eph: X25519PrivateKey | None = X25519PrivateKey.generate()
        self.eph_pub = _raw(self._eph.public_key())
        self._peer_eph = self._peer_id = self._transcript = self._keys = None

    # --- transcript and keys ---
    def _derive(self, peer_eph: bytes, peer_id: bytes) -> None:
        a_eph, a_id, b_eph, b_id = ((self.eph_pub, self.me.pub, peer_eph, peer_id) if self.initiator
                                    else (peer_eph, peer_id, self.eph_pub, self.me.pub))
        self._transcript = hashlib.sha256(b"AKE1" + a_eph + a_id + b_eph + b_id).digest()
        shared = self._eph.exchange(X25519PublicKey.from_public_bytes(peer_eph))
        okm = HKDF(algorithm=hashes.SHA256(), length=96, salt=self._transcript, info=b"AKE1 keys").derive(shared)
        self._keys = (okm[:32], okm[32:64], okm[64:])         # initiator->responder, responder->initiator, confirmation
        self._peer_eph, self._peer_id = peer_eph, peer_id

    def _sig_input(self, role: bytes) -> bytes:
        return b"AKE1|" + role + b"|" + self._transcript

    def _mac(self, role: bytes) -> bytes:
        return hmac.new(self._keys[2], b"confirm|" + role + self._transcript, hashlib.sha256).digest()

    def _verify(self, role: bytes, sig: bytes, mac: bytes) -> None:
        try:
            Ed25519PublicKey.from_public_bytes(self._peer_id).verify(sig, self._sig_input(role))
        except InvalidSignature as e:
            raise HandshakeError("peer signature invalid: the exchange was tampered with or the peer is not who it claims") from e
        if not hmac.compare_digest(mac, self._mac(role)):
            raise HandshakeError("key confirmation failed: peers derived different keys")

    def _finish(self) -> Session:
        k_ab, k_ba, _ = self._keys
        self._eph = None                                      # forward secrecy: the ephemeral secret is gone
        return Session(k_ab if self.initiator else k_ba, k_ba if self.initiator else k_ab, self._transcript, self.initiator)

    # --- messages ---
    def msg1(self) -> dict:                                   # initiator
        return {"eph": self.eph_pub, "id": self.me.pub}

    def on_msg1(self, m: dict) -> dict:                       # responder
        self.store.check(self.peer_name, m["id"])
        self._derive(m["eph"], m["id"])
        return {"eph": self.eph_pub, "id": self.me.pub,
                "sig": self.me.sk.sign(self._sig_input(b"B")), "mac": self._mac(b"B")}

    def on_msg2(self, m: dict) -> dict:                       # initiator
        self.store.check(self.peer_name, m["id"])
        self._derive(m["eph"], m["id"])
        self._verify(b"B", m["sig"], m["mac"])
        return {"sig": self.me.sk.sign(self._sig_input(b"A")), "mac": self._mac(b"A")}

    def initiator_session(self) -> Session:
        return self._finish()

    def on_msg3(self, m: dict) -> Session:                    # responder
        self._verify(b"A", m["sig"], m["mac"])
        return self._finish()


def connect(alice: Identity, bob: Identity, alice_store: PeerStore | None = None, bob_store: PeerStore | None = None):
    a_store, b_store = alice_store or PeerStore(), bob_store or PeerStore()
    ha, hb = Handshake(alice, a_store, bob.name, True), Handshake(bob, b_store, alice.name, False)
    m2 = hb.on_msg1(ha.msg1())
    m3 = ha.on_msg2(m2)
    sb = hb.on_msg3(m3)
    return ha.initiator_session(), sb


def demo() -> None:
    alice, bob = Identity("alice"), Identity("bob")
    sa, sb = connect(alice, bob)
    print("safety numbers to compare out of band:\n  alice:", alice.safety_number(), "\n  bob:  ", bob.safety_number())
    wire = sa.seal(b"hello bob")
    print("bob reads:", sb.open(wire), "| bob replies:", sa.open(sb.seal(b"hello alice")))
    try:
        sb.open(wire)
    except ReplayError as e:
        print("replayed message rejected:", e)


if __name__ == "__main__":
    demo()
