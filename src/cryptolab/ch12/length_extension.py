"""Assignment 12.2: length-extension attack on the naive MAC  tag = SHA256(secret || message).

The tag IS the hash's internal state after processing secret||message||padding. An attacker who sees (message, tag)
can load that state, keep hashing, and produce a valid tag for message||padding||suffix WITHOUT knowing the secret --
only its length (which they can guess by trying 1..N). HMAC's outer hash breaks this: its output is a hash of a
fresh, keyed block, so the visible tag is not a resumable state of anything the attacker can extend.
"""
from __future__ import annotations

import hmac as std_hmac
import struct

from cryptolab.ch12.hmac_scratch import hmac_sha256
from cryptolab.ch12.sha256 import padding, sha256


def naive_mac(secret: bytes, msg: bytes) -> bytes:
    return sha256(secret + msg)


def naive_verify(secret: bytes, msg: bytes, tag: bytes) -> bool:
    return std_hmac.compare_digest(naive_mac(secret, msg), tag)


def extend(msg: bytes, tag: bytes, secret_len: int, suffix: bytes) -> tuple[bytes, bytes]:
    """Return (forged_message, forged_tag) given only the message, its tag and a guess of len(secret)."""
    glue = padding(secret_len + len(msg))
    state = struct.unpack(">8I", tag)
    consumed = secret_len + len(msg) + len(glue)  # a multiple of 64
    return msg + glue + suffix, sha256(suffix, state=state, prefix_len=consumed)


def attack(msg: bytes, tag: bytes, suffix: bytes, oracle, max_secret_len: int = 64) -> tuple[bytes, bytes, int] | None:
    """Try every plausible secret length until the verifier accepts. `oracle(msg, tag) -> bool`."""
    for n in range(1, max_secret_len + 1):
        forged_msg, forged_tag = extend(msg, tag, n, suffix)
        if oracle(forged_msg, forged_tag):
            return forged_msg, forged_tag, n
    return None


def hmac_resists(secret: bytes, msg: bytes, suffix: bytes) -> bool:
    """The same procedure against HMAC never produces a valid tag."""
    tag = hmac_sha256(secret, msg)
    for n in range(1, 65):
        fm, ft = extend(msg, tag, n, suffix)
        if std_hmac.compare_digest(hmac_sha256(secret, fm), ft):
            return False
    return True


def demo() -> dict:
    secret = b"s3cr3t-key-unknown-to-attacker"
    msg = b"user=guest&amount=100"
    tag = naive_mac(secret, msg)
    res = attack(msg, tag, b"&admin=true", lambda m, t: naive_verify(secret, m, t))
    fm, ft, n = res
    return {"forged_message": fm, "accepted": naive_verify(secret, fm, ft), "guessed_secret_len": n,
            "true_secret_len": len(secret), "hmac_resists": hmac_resists(secret, msg, b"&admin=true")}


if __name__ == "__main__":
    for k, v in demo().items():
        print(f"{k}: {v}")
