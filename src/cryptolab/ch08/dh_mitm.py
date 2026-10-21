"""Assignment 8.2: MITM on unauthenticated Diffie-Hellman, and the fix with signatures (Station-to-Station style).

Vulnerable: Mallory replaces each public value with her own and ends up with one secret shared with Alice and a
different one shared with Bob. Fixed: each side signs the pair of public values (A, B) with a long-term identity key
the other side already trusts. Mallory cannot forge a signature over her substituted values, so the substitution is
detected and the exchange aborts.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import dh

G = dh.FFDHE2048
L = (G.p.bit_length() + 7) // 8


def _b(x: int) -> bytes:
    return x.to_bytes(L, "big")


class AuthenticationFailure(Exception):
    pass


def vulnerable(mallory: bool) -> dict:
    a, b = dh.private_key(G), dh.private_key(G)
    A, B = dh.public_key(G, a), dh.public_key(G, b)
    if not mallory:
        return {"alice_key": dh.derive_key(dh.shared_secret(G, a, B), G), "bob_key": dh.derive_key(dh.shared_secret(G, b, A), G),
                "mallory_keys": None}
    ma, mb = dh.private_key(G), dh.private_key(G)            # Mallory's two keypairs
    MA, MB = dh.public_key(G, ma), dh.public_key(G, mb)
    alice_key = dh.derive_key(dh.shared_secret(G, a, MB), G)         # Alice was handed MB "from Bob"
    bob_key = dh.derive_key(dh.shared_secret(G, b, MA), G)           # Bob was handed MA "from Alice"
    m_with_alice = dh.derive_key(dh.shared_secret(G, mb, A), G)      # Alice used MB = g^mb, so Mallory uses mb with A
    m_with_bob = dh.derive_key(dh.shared_secret(G, ma, B), G)        # Bob used MA = g^ma, so Mallory uses ma with B
    return {"alice_key": alice_key, "bob_key": bob_key, "mallory_keys": (m_with_alice, m_with_bob)}


def authenticated(mallory: bool) -> dict:
    """Three messages: A ; B, Sig_B(B|A) ; Sig_A(A|B). Identity public keys are known in advance (pinned)."""
    alice_id, bob_id = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    pinned_by_alice = bob_id.public_key()      # Alice already trusts Bob's identity key...
    pinned_by_bob = alice_id.public_key()      # ...and Bob already trusts Alice's
    a, b = dh.private_key(G), dh.private_key(G)
    A, B = dh.public_key(G, a), dh.public_key(G, b)

    A_seen_by_bob = A
    if mallory:
        ma = dh.private_key(G)
        A_seen_by_bob = dh.public_key(G, ma)                 # Mallory swaps Alice's value on its way to Bob
    # Bob answers with his public value and a signature binding it to the A he received.
    sig_bob = bob_id.sign(b"STS|B|" + _b(B) + _b(A_seen_by_bob))
    B_seen_by_alice = B
    if mallory:
        mb = dh.private_key(G)
        B_seen_by_alice = dh.public_key(G, mb)               # ...and swaps Bob's value, hoping to reuse the signature
    try:                                                      # Alice checks the signature against what SHE sent and received
        pinned_by_alice.verify(sig_bob, b"STS|B|" + _b(B_seen_by_alice) + _b(A))
    except InvalidSignature as e:
        raise AuthenticationFailure("Alice: Bob's signature does not match the values I exchanged; aborting") from e
    sig_alice = alice_id.sign(b"STS|A|" + _b(A) + _b(B_seen_by_alice))
    try:
        pinned_by_bob.verify(sig_alice, b"STS|A|" + _b(A_seen_by_bob) + _b(B))
    except InvalidSignature as e:
        raise AuthenticationFailure("Bob: Alice's signature does not match; aborting") from e
    return {"alice_key": dh.derive_key(dh.shared_secret(G, a, B_seen_by_alice), G),
            "bob_key": dh.derive_key(dh.shared_secret(G, b, A_seen_by_bob), G)}


def demo() -> None:
    r = vulnerable(False)
    print("no attacker           : Alice and Bob keys equal:", r["alice_key"] == r["bob_key"])
    r = vulnerable(True)
    ma, mb = r["mallory_keys"]
    print("VULNERABLE + Mallory  : Alice/Bob keys differ:", r["alice_key"] != r["bob_key"],
          "| Mallory shares a key with each side:", ma == r["alice_key"] and mb == r["bob_key"], "| neither side noticed anything")
    r = authenticated(False)
    print("signed, no attacker   : keys equal:", r["alice_key"] == r["bob_key"])
    try:
        authenticated(True)
    except AuthenticationFailure as e:
        print("signed + Mallory      : ABORTED ->", e)


if __name__ == "__main__":
    demo()
