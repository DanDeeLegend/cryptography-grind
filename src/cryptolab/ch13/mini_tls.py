"""Assignment 13.5 capstone: a mini TLS-1.3-style handshake and record layer. EDUCATIONAL: not interoperable with TLS.

Flow (see docs/ch13.md for the sequence diagram):
  C -> S  ClientHello      random, ephemeral X25519 public key, server name
  S -> C  ServerHello      random, ephemeral X25519 public key
          Certificate      chain (leaf first)
          CertificateVerify ECDSA signature over the transcript hash so far  (proves the server holds the leaf's key
                            AND is bound to THIS exchange, so a recorded signature can't be replayed)
          Finished         HMAC over the whole transcript with a key from the shared secret
  C -> S  Finished         same, over the transcript including the server's Finished
  both    application records: AES-128-GCM, per-direction keys, nonce = IV xor sequence number, header as AAD

Properties and deliberate omissions are listed in the docs. Notably: no client authentication, no session resumption, no
negotiation (one fixed suite, so no downgrade surface), and no alert protocol beyond close_notify.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptolab.ch13.chain_validate import validate

CLIENT_HELLO, SERVER_HELLO, CERTIFICATE, CERT_VERIFY, FINISHED = 1, 2, 11, 15, 20
REC_APP, REC_CLOSE = 23, 21


class HandshakeError(Exception): ...
class RecordError(Exception): ...


# ---- HKDF (RFC 5869) ----
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out, i = out + t, i + 1
    return out[:length]


def expand_label(secret: bytes, label: str, context: bytes, length: int = 32) -> bytes:
    """Context (a transcript hash) is mixed into every derived key, binding keys to this exact handshake."""
    return hkdf_expand(secret, struct.pack(">H", length) + b"mini-tls " + label.encode() + b"\x00" + context, length)


# ---- message framing: type(1) || length(3) || body ----
def msg(t: int, body: bytes) -> bytes:
    return bytes([t]) + len(body).to_bytes(3, "big") + body


def parse_msgs(data: bytes) -> list[tuple[int, bytes, bytes]]:
    out, i = [], 0
    while i < len(data):
        if i + 4 > len(data):
            raise HandshakeError("truncated handshake message")
        t, n = data[i], int.from_bytes(data[i + 1:i + 4], "big")
        if i + 4 + n > len(data):
            raise HandshakeError("truncated handshake message")
        out.append((t, data[i + 4:i + 4 + n], data[i:i + 4 + n]))
        i += 4 + n
    return out


def _pub(k: x25519.X25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _cv_input(role: str, th: bytes) -> bytes:
    return b" " * 64 + f"mini-tls {role} CertificateVerify".encode() + b"\x00" + th


# ---- record layer ----
class Record:
    """One direction's protection state. The sequence number is implicit (never sent), so replay, reordering and
    deletion all break the nonce and fail authentication."""

    def __init__(self, key: bytes, iv: bytes):
        self.aead, self.iv, self.seq = AESGCM(key), iv, 0

    def _nonce(self) -> bytes:
        return bytes(a ^ b for a, b in zip(self.iv, self.seq.to_bytes(12, "big")))

    def seal(self, rtype: int, data: bytes) -> bytes:
        inner = data + bytes([rtype])  # real type is inside the encryption
        header = bytes([REC_APP]) + struct.pack(">H", len(inner) + 16)
        ct = self.aead.encrypt(self._nonce(), inner, header)
        self.seq += 1
        return header + ct

    def open(self, record: bytes) -> tuple[int, bytes]:
        header, ct = record[:3], record[3:]
        if len(record) < 3 + 17 or header[0] != REC_APP or struct.unpack(">H", header[1:])[0] != len(ct):
            raise RecordError("malformed record")
        try:
            inner = self.aead.decrypt(self._nonce(), ct, header)
        except InvalidTag:
            raise RecordError("record failed authentication") from None
        self.seq += 1
        return inner[-1], inner[:-1]


class Channel:
    def __init__(self, send_keys: Record, recv_keys: Record):
        self._tx, self._rx, self.closed = send_keys, recv_keys, False

    def send(self, data: bytes) -> bytes:
        return self._tx.seal(REC_APP, data)

    def receive(self, record: bytes) -> bytes:
        rtype, data = self._rx.open(record)
        if rtype == REC_CLOSE:
            self.closed = True
            return b""
        return data

    def close(self) -> bytes:
        return self._tx.seal(REC_CLOSE, b"")

    def finish(self) -> None:
        """Call when the transport reports EOF. EOF without close_notify means a truncation attack is possible."""
        if not self.closed:
            raise RecordError("connection ended without close_notify (possible truncation)")


def _channels(hs_secret: bytes, th: bytes, is_client: bool) -> Channel:
    def rec(label):
        s = expand_label(hs_secret, label, th)
        return Record(expand_label(s, "key", b"", 16), expand_label(s, "iv", b"", 12))
    c, s = rec("c ap"), rec("s ap")
    return Channel(c, s) if is_client else Channel(s, c)


@dataclass
class Server:
    chain: list[x509.Certificate]
    key: ec.EllipticCurvePrivateKey

    def __post_init__(self):
        self._eph = x25519.X25519PrivateKey.generate()

    def respond(self, client_hello: bytes) -> bytes:
        (t, body, raw), = parse_msgs(client_hello)
        if t != CLIENT_HELLO or len(body) < 65:
            raise HandshakeError("bad ClientHello")
        shared = self._eph.exchange(x25519.X25519PublicKey.from_public_bytes(body[32:64]))
        sh = msg(SERVER_HELLO, os.urandom(32) + _pub(self._eph))
        certs = b"".join(len(c.public_bytes(serialization.Encoding.DER)).to_bytes(3, "big") + c.public_bytes(serialization.Encoding.DER) for c in self.chain)
        cert = msg(CERTIFICATE, bytes([len(self.chain)]) + certs)
        transcript = raw + sh + cert
        sig = self.key.sign(_cv_input("server", _h(transcript)), ec.ECDSA(hashes.SHA256()))
        cv = msg(CERT_VERIFY, struct.pack(">H", len(sig)) + sig)
        transcript += cv
        self._hs = hkdf_extract(b"", shared)
        fin_key = expand_label(expand_label(self._hs, "s hs", _h(raw + sh)), "finished", b"")
        fin = msg(FINISHED, hmac.new(fin_key, _h(transcript), hashlib.sha256).digest())
        self._transcript = transcript + fin
        self._client_hello_sh = raw + sh
        return sh + cert + cv + fin

    def finish(self, client_finished: bytes) -> Channel:
        (t, body, _), = parse_msgs(client_finished)
        fin_key = expand_label(expand_label(self._hs, "c hs", _h(self._client_hello_sh)), "finished", b"")
        if t != FINISHED or not hmac.compare_digest(body, hmac.new(fin_key, _h(self._transcript), hashlib.sha256).digest()):
            raise HandshakeError("client Finished does not match: handshake was tampered with")
        return _channels(self._hs, _h(self._transcript), is_client=False)


class Client:
    def __init__(self, server_name: str, anchors: list[x509.Certificate]):
        self.name, self.anchors = server_name, anchors
        self._eph = x25519.X25519PrivateKey.generate()

    def hello(self) -> bytes:
        name = self.name.encode()
        self._ch = msg(CLIENT_HELLO, os.urandom(32) + _pub(self._eph) + bytes([len(name)]) + name)
        return self._ch

    def process(self, flight: bytes) -> tuple[bytes, Channel]:
        parts = parse_msgs(flight)
        if [p[0] for p in parts] != [SERVER_HELLO, CERTIFICATE, CERT_VERIFY, FINISHED]:
            raise HandshakeError("unexpected handshake message order")
        (_, sh, sh_raw), (_, cert_body, cert_raw), (_, cv_body, cv_raw), (_, fin_body, fin_raw) = parts
        if len(sh) != 64:
            raise HandshakeError("bad ServerHello")
        # 1. authenticate: certificate chain -> hostname -> signature over this transcript
        n, i, chain = cert_body[0], 1, []
        for _ in range(n):
            ln = int.from_bytes(cert_body[i:i + 3], "big")
            chain.append(x509.load_der_x509_certificate(cert_body[i + 3:i + 3 + ln]))
            i += 3 + ln
        result = validate(chain, self.anchors, self.name)
        if not result.ok:
            raise HandshakeError("certificate rejected: " + "; ".join(result.errors))
        sig = cv_body[2:2 + struct.unpack(">H", cv_body[:2])[0]]
        th = _h(self._ch + sh_raw + cert_raw)
        try:
            chain[0].public_key().verify(sig, _cv_input("server", th), ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise HandshakeError("CertificateVerify failed: server does not hold the certificate's key for this exchange") from None
        # 2. keys and Finished
        shared = self._eph.exchange(x25519.X25519PublicKey.from_public_bytes(sh[32:]))
        hs = hkdf_extract(b"", shared)
        fin_key = expand_label(expand_label(hs, "s hs", _h(self._ch + sh_raw)), "finished", b"")
        if not hmac.compare_digest(fin_body, hmac.new(fin_key, _h(self._ch + sh_raw + cert_raw + cv_raw), hashlib.sha256).digest()):
            raise HandshakeError("server Finished does not match: handshake was tampered with")
        transcript = self._ch + sh_raw + cert_raw + cv_raw + fin_raw
        c_fin_key = expand_label(expand_label(hs, "c hs", _h(self._ch + sh_raw)), "finished", b"")
        client_fin = msg(FINISHED, hmac.new(c_fin_key, _h(transcript), hashlib.sha256).digest())
        return client_fin, _channels(hs, _h(transcript), is_client=True)


def connect(server: Server, name: str, anchors) -> tuple[Channel, Channel]:
    """Run a full handshake in memory; returns (client_channel, server_channel)."""
    c = Client(name, anchors)
    flight = server.respond(c.hello())
    fin, cc = c.process(flight)
    return cc, server.finish(fin)


if __name__ == "__main__":
    from cryptolab.ch13 import pki
    root = pki.make_root()
    inter = pki.make_intermediate(root)
    key, leaf = pki.make_leaf(inter, "chat.example.test")
    cc, sc = connect(Server([leaf, inter.cert], key), "chat.example.test", [root.cert])
    rec = cc.send(b"hello over mini-TLS")
    print("record on the wire:", rec.hex()[:48], "...")
    print("server received:", sc.receive(rec))
