import hashlib
import hmac as std_hmac
import os

import pytest

from cryptolab.ch12 import bench_etm_gcm, compose, hmac_scratch, length_extension, webhook
from cryptolab.ch12.sha256 import sha256


def test_sha256_matches_hashlib_at_every_padding_boundary():
    for n in list(range(0, 200)) + [1000, 4096]:
        b = os.urandom(n)
        assert sha256(b) == hashlib.sha256(b).digest()


@pytest.mark.parametrize("key,msg,want", hmac_scratch.RFC4231)
def test_hmac_rfc4231(key, msg, want):
    assert hmac_scratch.hmac_sha256(key, msg).hex() == want
    assert hmac_scratch.hmac_sha256(key, msg) == std_hmac.new(key, msg, hashlib.sha256).digest()


def test_length_extension_forges_naive_mac_but_not_hmac():
    r = length_extension.demo()
    assert r["accepted"] and r["guessed_secret_len"] == r["true_secret_len"] and r["hmac_resists"]
    assert r["forged_message"].endswith(b"&admin=true") and r["forged_message"].startswith(b"user=guest&amount=100")


def test_extension_state_resume_equals_hashing_whole_message():
    from cryptolab.ch12.sha256 import padding
    secret, msg, suffix = b"k" * 20, b"hello", b"WORLD"
    forged_msg, forged_tag = length_extension.extend(msg, length_extension.naive_mac(secret, msg), len(secret), suffix)
    assert forged_tag == hashlib.sha256(secret + forged_msg).digest()
    assert forged_msg == msg + padding(len(secret) + len(msg)) + suffix


def test_padding_oracle_breaks_mte_and_not_etm():
    r = compose.demo()
    assert r["mte_plaintext_recovered"] and not r["etm_leaks"]
    assert r["queries"] < 16 * 256 * 8  # a few thousand queries for five blocks


def test_compositions_roundtrip_and_etm_rejects_any_modification():
    ke, km = os.urandom(16), os.urandom(32)
    pt = b"attack at dawn" * 5
    iv, ct = compose.mte_encrypt(ke, km, pt)
    assert compose.mte_decrypt(ke, km, iv, ct) == pt
    eiv, ect, tag = compose.etm_encrypt(ke, km, pt)
    assert compose.etm_decrypt(ke, km, eiv, ect, tag) == pt
    for i in (0, len(ect) // 2, len(ect) - 1):
        bad = bytearray(ect); bad[i] ^= 1
        with pytest.raises(compose.Invalid):
            compose.etm_decrypt(ke, km, eiv, bytes(bad), tag)
    with pytest.raises(compose.Invalid):
        compose.etm_decrypt(ke, km, bytes([eiv[0] ^ 1]) + eiv[1:], ect, tag)


class Clock:
    def __init__(self, t=1_000_000.0): self.t = t
    def __call__(self): return self.t


def test_webhook_accepts_valid_and_rejects_tamper_replay_and_staleness():
    clock = Clock()
    v = webhook.Verifier([b"secret"], tolerance=300, clock=clock)
    body = b'{"event":"paid"}'
    h = webhook.sign(b"secret", body, now=clock.t)
    v.verify(h, body)
    with pytest.raises(webhook.WebhookError, match="replayed"):
        v.verify(h, body)
    h2 = webhook.sign(b"secret", body, now=clock.t)
    with pytest.raises(webhook.WebhookError, match="bad signature"):
        v.verify(h2, b'{"event":"refund"}')
    with pytest.raises(webhook.WebhookError, match="bad signature"):
        v.verify(webhook.sign(b"wrong", body, now=clock.t), body)
    with pytest.raises(webhook.WebhookError, match="tolerance"):
        v.verify(webhook.sign(b"secret", body, now=clock.t - 301), body)
    with pytest.raises(webhook.WebhookError, match="malformed"):
        v.verify("garbage", body)


def test_webhook_swapping_id_or_timestamp_breaks_signature_and_failed_auth_does_not_burn_ids():
    clock = Clock()
    v = webhook.Verifier([b"secret"], clock=clock)
    h = webhook.sign(b"secret", b"x", now=clock.t, event_id="abc")
    forged = h.replace("id=abc", "id=zzz")
    with pytest.raises(webhook.WebhookError, match="bad signature"):
        v.verify(forged, b"x")
    v.verify(h, b"x")  # the legitimate id 'abc' was not consumed by an unauthenticated attempt


def test_webhook_key_rotation_and_replay_window_expiry():
    clock = Clock()
    v = webhook.Verifier([b"new", b"old"], tolerance=300, clock=clock)
    v.verify(webhook.sign(b"old", b"b", now=clock.t, event_id="1"), b"b")
    v.verify(webhook.sign(b"new", b"b", now=clock.t, event_id="2"), b"b")
    clock.t += 1000
    v.verify(webhook.sign(b"new", b"b", now=clock.t, event_id="3"), b"b")
    assert "1" not in v._seen  # expired ids are purged so memory is bounded


def test_bench_runs_and_gcm_wins_on_small_messages():
    rows = bench_etm_gcm.run()
    assert rows[1]["gcm_mbps"] > rows[1]["etm_mbps"]
