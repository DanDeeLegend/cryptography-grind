"""Assignment 12.5: signed webhooks with replay protection.

Header:  X-Signature: t=<unix seconds>,id=<unique id>,v1=<hex HMAC-SHA256>
Signed string: f"{t}.{id}.".encode() + raw_body   (timestamp and id are inside the MAC, so they can't be swapped)

Receiver checks, in this order: header well-formed -> timestamp within tolerance -> signature (constant time, any active
secret, which allows key rotation) -> only THEN records the id. Recording ids before authenticating would let anyone
fill the replay cache with junk or burn legitimate ids.
"""
from __future__ import annotations

import hashlib
import hmac
import time
import uuid


class WebhookError(Exception): ...


def sign(secret: bytes, body: bytes, now: float | None = None, event_id: str | None = None) -> str:
    t, i = int(now if now is not None else time.time()), event_id or uuid.uuid4().hex
    mac = hmac.new(secret, f"{t}.{i}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={t},id={i},v1={mac}"


class Verifier:
    def __init__(self, secrets: list[bytes], tolerance: int = 300, clock=time.time):
        self.secrets, self.tolerance, self.clock = secrets, tolerance, clock
        self._seen: dict[str, float] = {}  # id -> expiry. Single process; use Redis SETNX+TTL across instances.

    def verify(self, header: str, body: bytes) -> str:
        try:
            parts = dict(p.split("=", 1) for p in header.split(","))
            t, event_id, sig = int(parts["t"]), parts["id"], parts["v1"]
        except (ValueError, KeyError):
            raise WebhookError("malformed signature header") from None
        now = self.clock()
        if abs(now - t) > self.tolerance:
            raise WebhookError("timestamp outside tolerance")
        msg = f"{t}.{event_id}.".encode() + body
        if not any(hmac.compare_digest(sig, hmac.new(s, msg, hashlib.sha256).hexdigest()) for s in self.secrets):
            raise WebhookError("bad signature")
        self._seen = {k: v for k, v in self._seen.items() if v > now}
        if event_id in self._seen:
            raise WebhookError("replayed event id")
        self._seen[event_id] = t + 2 * self.tolerance  # must outlive the window in which the timestamp would still pass
        return event_id
