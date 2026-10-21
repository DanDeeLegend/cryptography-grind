import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cryptolab import numtheory as nt
from cryptolab.ch08 import ake, bench_dh_groups, dh, dh_mitm, elgamal


# ---------- 8.1 ----------
def test_textbook_dh_values():
    g = dh.TEXTBOOK
    A, B = dh.public_key(g, 6), dh.public_key(g, 15)
    assert (A, B) == (8, 19)
    assert dh.shared_secret(g, 6, B) == dh.shared_secret(g, 15, A) == 2


@pytest.mark.parametrize("group", [dh.FFDHE2048, dh.FFDHE3072, dh.FFDHE4096])
def test_standard_groups_are_safe_primes_and_exchange_works(group):
    assert nt.is_probable_prime(group.p, 8) and nt.is_probable_prime(group.q, 8)
    assert pow(group.g, group.q, group.p) == 1                           # g = 2 lies in the prime-order subgroup
    a, b = dh.private_key(group), dh.private_key(group)
    ka = dh.derive_key(dh.shared_secret(group, a, dh.public_key(group, b)), group)
    kb = dh.derive_key(dh.shared_secret(group, b, dh.public_key(group, a)), group)
    assert ka == kb and len(ka) == 32


def test_public_value_validation_blocks_small_subgroup_tricks():
    g = dh.FFDHE2048
    for bad in (0, 1, g.p - 1, g.p, g.p + 5):
        with pytest.raises(ValueError):
            dh.validate_public(g, bad)
    non_residue = next(a for a in range(2, 100) if pow(a, g.q, g.p) != 1)   # find one instead of assuming
    with pytest.raises(ValueError):
        dh.validate_public(g, non_residue)                                  # outside the prime-order subgroup


def test_small_groups_fall_to_baby_step_giant_step():
    p = nt.gen_safe_prime(32)
    gen = pow(5, 2, p)
    x = 123456
    assert pow(gen, dh.discrete_log(gen, pow(gen, x, p), p, (p - 1) // 2), p) == pow(gen, x, p)


# ---------- 8.2 ----------
def test_unauthenticated_dh_is_silently_hijacked():
    ok = dh_mitm.vulnerable(False)
    assert ok["alice_key"] == ok["bob_key"]
    r = dh_mitm.vulnerable(True)
    assert r["alice_key"] != r["bob_key"]                                  # two different channels...
    assert r["mallory_keys"] == (r["alice_key"], r["bob_key"])             # ...both known to Mallory, nothing raised


def test_signed_dh_detects_the_attack():
    r = dh_mitm.authenticated(False)
    assert r["alice_key"] == r["bob_key"]
    with pytest.raises(dh_mitm.AuthenticationFailure):
        dh_mitm.authenticated(True)


# ---------- 8.3 ----------
def test_elgamal_textbook_and_roundtrip():
    pk, x = elgamal.keygen(2579, 2, 765)
    assert pk.y == 949
    c = elgamal.encrypt(pk, 1299, k=853)
    assert c == (435, 2396) and elgamal.decrypt(pk, x, c) == 1299
    assert all(elgamal.decrypt(pk, x, elgamal.encrypt(pk, m)) == m for m in range(1, 2579, 37))
    assert elgamal.encrypt(pk, 5) != elgamal.encrypt(pk, 5)               # randomised
    with pytest.raises(ValueError):
        elgamal.encrypt(pk, 0)


def test_elgamal_malleability_and_nonce_reuse():
    pk, x = elgamal.keygen(2579, 2, 765)
    c1, c2 = elgamal.encrypt(pk, 100)
    assert elgamal.decrypt(pk, x, (c1, 3 * c2 % pk.p)) == 300
    a, b = elgamal.encrypt(pk, 1000, k=77), elgamal.encrypt(pk, 777, k=77)
    assert b[1] * nt.modinv(a[1], pk.p) * 1000 % pk.p == 777


def test_elgamal_over_a_standard_group():
    g = dh.FFDHE2048
    pk, x = elgamal.keygen(g.p, g.g)
    m = int.from_bytes(b"ElGamal over ffdhe2048", "big")
    assert elgamal.decrypt(pk, x, elgamal.encrypt(pk, m)) == m


# ---------- 8.5 ----------
def test_larger_groups_cost_more_and_ecdh_is_cheapest():
    rows = bench_dh_groups.run(repeats=3)
    assert rows[0]["shared_ms"] < rows[2]["shared_ms"]
    assert rows[-1]["shared_ms"] < rows[0]["shared_ms"] / 10


# ---------- 8.6 ----------
def test_ake_honest_session_both_directions():
    a, b = ake.Identity("alice"), ake.Identity("bob")
    sa, sb = ake.connect(a, b)
    assert sb.open(sa.seal(b"hi bob")) == b"hi bob" and sa.open(sb.seal(b"hi alice")) == b"hi alice"
    assert a.safety_number() != b.safety_number() and len(a.safety_number().split()) == 6


def test_ake_rejects_replay_reorder_and_tampering():
    sa, sb = ake.connect(ake.Identity("alice"), ake.Identity("bob"))
    m1, m2 = sa.seal(b"one"), sa.seal(b"two")
    assert sb.open(m2) == b"two"
    with pytest.raises(ake.ReplayError):
        sb.open(m1)                                                        # older counter after a newer one
    with pytest.raises(ake.ReplayError):
        sb.open(m2)                                                        # replay
    bad = bytearray(sa.seal(b"three")); bad[-1] ^= 1
    with pytest.raises(ake.ReplayError):
        sb.open(bytes(bad))
    assert sb.open(sa.seal(b"four")) == b"four"                            # a rejected message does not wedge the session


def test_ake_mitm_cannot_splice_or_impersonate():
    alice, bob, mallory = ake.Identity("alice"), ake.Identity("bob"), ake.Identity("bob")   # Mallory claims to be "bob"
    store = ake.PeerStore()
    ake.connect(alice, bob, alice_store=store)                             # first contact: trusts bob's real key
    with pytest.raises(ake.IdentityChanged):                               # Mallory presents HER key as bob
        ake.connect(alice, mallory, alice_store=store)

    # Splice: Mallory forwards Bob's real identity but substitutes her own ephemeral key.
    ha, hb = ake.Handshake(alice, ake.PeerStore(), "bob", True), ake.Handshake(bob, ake.PeerStore(), "alice", False)
    evil = ake.Handshake(mallory, ake.PeerStore(), "x", True)
    m1 = ha.msg1()
    m2 = hb.on_msg1({"eph": evil.eph_pub, "id": m1["id"]})                 # Bob answers Mallory's ephemeral
    with pytest.raises(ake.HandshakeError):
        ha.on_msg2(m2)                                                     # transcript differs: signature fails


def test_ake_forward_secrecy_ephemeral_secret_is_discarded():
    alice, bob = ake.Identity("alice"), ake.Identity("bob")
    ha, hb = ake.Handshake(alice, ake.PeerStore(), "bob", True), ake.Handshake(bob, ake.PeerStore(), "alice", False)
    m3 = ha.on_msg2(hb.on_msg1(ha.msg1()))
    sb = hb.on_msg3(m3); ha.initiator_session()
    assert ha._eph is None and hb._eph is None                              # nothing left to steal later
    assert not hasattr(sb, "_eph") and sb._aad                              # session holds only derived symmetric state


def test_ake_changed_identity_can_be_accepted_after_verification():
    store = ake.PeerStore()
    store.check("bob", b"old-key-bytes")
    with pytest.raises(ake.IdentityChanged):
        store.check("bob", b"new-key-bytes")
    store.accept_change("bob", b"new-key-bytes")
    assert store.check("bob", b"new-key-bytes") == "known contact"
