"""Assignment 10.5: forging "textbook" RSA signatures (sign = hash^d with no padding, or even sign = m^d).

Three attacks, none of which needs the private key. Each is then run against the padded scheme from rsa_sign.py,
where it fails.
"""
from __future__ import annotations

import secrets

from cryptolab.numtheory import modinv
from cryptolab.ch10.rsa_sign import verify as verify_padded


def textbook_verify(m: int, s: int, e: int, n: int) -> bool:
    return pow(s, e, n) == m % n


def existential_forgery(e: int, n: int) -> tuple[int, int]:
    """Pick any s, publish m = s^e. (s, m) is a valid pair, but the attacker does not control which m results."""
    s = secrets.randbelow(n - 2) + 2
    return pow(s, e, n), s


def product_forgery(m1: int, s1: int, m2: int, s2: int, n: int) -> tuple[int, int]:
    """Signatures are multiplicative: (m1*m2, s1*s2) is valid. Two signed messages yield a third, chosen product."""
    return (m1 * m2) % n, (s1 * s2) % n


def blinding_attack(target_m: int, sign_oracle, e: int, n: int) -> int:
    """Get a signature on a message the signer would refuse by asking for a signature on a blinded, innocent-looking one."""
    while True:
        r = secrets.randbelow(n - 2) + 2
        try:
            r_inv = modinv(r, n)
        except ValueError:
            continue
        break
    blinded = (target_m * pow(r, e, n)) % n
    return (sign_oracle(blinded) * r_inv) % n


def padded_scheme_rejects(e: int, n: int, message: bytes) -> dict:
    """The same forged integers, offered to the padded verifier, are all rejected."""
    k = (n.bit_length() + 7) // 8
    s = secrets.randbelow(n - 2) + 2
    return {"random_signature_accepted": verify_padded(message, s.to_bytes(k, "big"), e, n)}


def demo() -> dict:
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(65537, 2048)
    nums = key.private_numbers()
    n, e, d = nums.public_numbers.n, nums.public_numbers.e, nums.d
    sign = lambda m: pow(m, d, n)  # textbook signer
    m1, m2 = 12345, 67890
    s1, s2 = sign(m1), sign(m2)
    fm, fs = existential_forgery(e, n)
    pm, ps = product_forgery(m1, s1, m2, s2, n)
    forbidden = int.from_bytes(b"transfer all funds", "big")
    blind_sig = blinding_attack(forbidden, lambda x: sign(x) if x != forbidden else (_ for _ in ()).throw(PermissionError()), e, n)
    return {
        "existential_forgery_valid": textbook_verify(fm, fs, e, n),
        "product_forgery_valid": textbook_verify(pm, ps, e, n) and pm == m1 * m2 % n,
        "blinding_forgery_valid": textbook_verify(forbidden, blind_sig, e, n),
        **padded_scheme_rejects(e, n, b"transfer all funds"),
    }


if __name__ == "__main__":
    for k, v in demo().items():
        print(f"{k}: {v}")
