import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from cryptolab.ch13 import mini_tls as tls
from cryptolab.ch13 import pki

HOST = "chat.example.test"


@pytest.fixture()
def world():
    root = pki.make_root()
    inter = pki.make_intermediate(root)
    key, leaf = pki.make_leaf(inter, HOST)
    return root, inter, key, leaf, [leaf, inter.cert]


def run(world, name=HOST, anchors=None, tamper_hello=None, tamper_flight=None):
    root, _, key, _, chain = world
    server, client = tls.Server(chain, key), tls.Client(name, anchors or [root.cert])
    hello = client.hello()
    flight = server.respond(tamper_hello(hello) if tamper_hello else hello)
    fin, cc = client.process(tamper_flight(flight) if tamper_flight else flight)
    return cc, server.finish(fin)


def flip(data: bytes, i: int) -> bytes:
    return data[:i] + bytes([data[i] ^ 1]) + data[i + 1:]


def test_hkdf_rfc5869_case1():
    prk = tls.hkdf_extract(bytes(range(13)), bytes.fromhex("0b" * 22))
    assert prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    assert tls.hkdf_expand(prk, bytes(range(0xF0, 0xFA)), 42).hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")


def test_handshake_and_bidirectional_traffic(world):
    cc, sc = run(world)
    for i in range(3):
        assert sc.receive(cc.send(b"ping %d" % i)) == b"ping %d" % i
        assert cc.receive(sc.send(b"pong %d" % i)) == b"pong %d" % i
    sc.receive(cc.close()); sc.finish()


def test_wire_does_not_contain_plaintext_and_sessions_have_distinct_keys(world):
    cc1, sc1 = run(world)
    cc2, sc2 = run(world)
    rec1, rec2 = cc1.send(b"secret-token-123"), cc2.send(b"secret-token-123")
    assert b"secret-token" not in rec1 and rec1 != rec2
    with pytest.raises(tls.RecordError):
        sc2.receive(rec1)  # another session's key cannot open it


def test_wrong_hostname_and_untrusted_ca_rejected(world):
    with pytest.raises(tls.HandshakeError, match="hostname"):
        run(world, name="other.example.test")
    with pytest.raises(tls.HandshakeError, match="certificate rejected"):
        run(world, anchors=[pki.make_root("Evil Root").cert])


def test_attacker_with_real_chain_but_wrong_private_key_is_caught(world):
    root, _, _, leaf, chain = world
    impostor = tls.Server(chain, ec.generate_private_key(ec.SECP256R1()))  # has the public chain, not the key
    c = tls.Client(HOST, [root.cert])
    with pytest.raises(tls.HandshakeError, match="CertificateVerify"):
        c.process(impostor.respond(c.hello()))


def test_mitm_swapping_ephemeral_keys_is_caught_by_transcript_binding(world):
    mallory = tls.x25519.X25519PrivateKey.generate()
    def swap_client_eph(hello):  # Mallory substitutes her key in ClientHello (bytes 4+32 .. 4+64)
        return hello[:36] + tls._pub(mallory) + hello[68:]
    with pytest.raises(tls.HandshakeError, match="CertificateVerify"):
        run(world, tamper_hello=swap_client_eph)
    def swap_server_eph(flight):  # ... or in ServerHello (bytes 4+32 .. 4+64)
        return flight[:36] + tls._pub(mallory) + flight[68:]
    with pytest.raises(tls.HandshakeError, match="CertificateVerify"):
        run(world, tamper_flight=swap_server_eph)


def test_any_flipped_handshake_byte_is_detected(world):
    root, _, key, _, chain = world
    flight = tls.Server(chain, key).respond(tls.Client(HOST, [root.cert]).hello())  # for length only
    failures = 0
    for i in range(0, len(flight), 37):
        try:
            run(world, tamper_flight=lambda f, i=i: flip(f, i))
        except (tls.HandshakeError, ValueError, IndexError):
            failures += 1
        else:
            pytest.fail(f"flipped byte {i} went unnoticed")
    assert failures > 10


def test_record_tamper_replay_reorder_reflection_truncation(world):
    cc, sc = run(world)
    r1, r2 = cc.send(b"one"), cc.send(b"two")
    with pytest.raises(tls.RecordError):
        sc.receive(flip(r1, 5))                      # tampering
    assert sc.receive(r1) == b"one"                  # a failed open does not advance the counter
    with pytest.raises(tls.RecordError):
        sc.receive(r1)                               # replay
    assert sc.receive(r2) == b"two"
    a, b = cc.send(b"a"), cc.send(b"b")
    with pytest.raises(tls.RecordError):
        sc.receive(b)                                # reordering / deletion of `a`
    with pytest.raises(tls.RecordError):
        cc.receive(cc.send(b"reflect"))              # a client record is not valid as a server record
    with pytest.raises(tls.RecordError):
        sc.finish()                                  # EOF with no close_notify = possible truncation
