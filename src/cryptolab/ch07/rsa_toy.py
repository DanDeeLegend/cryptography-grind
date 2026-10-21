"""Assignment 7.1: a textbook-sized RSA key pair, every value shown.

p = 61, q = 53  ->  n = p*q, phi(n) = (p-1)(q-1), pick e coprime to phi, d = e^-1 mod phi.
Encrypt c = m^e mod n; decrypt m = c^d mod n. Correct because e*d = 1 + k*phi(n) and Euler's theorem gives
m^(1 + k*phi) = m (mod n) for the textbook case where gcd(m, n) = 1 (it also holds for all m when n = p*q).
Never use unpadded RSA with tiny numbers for anything real; this is arithmetic practice.
"""
from __future__ import annotations

from dataclasses import dataclass
from math import gcd

from cryptolab.numtheory import modinv


@dataclass
class ToyKey:
    p: int
    q: int
    e: int

    @property
    def n(self) -> int:
        return self.p * self.q

    @property
    def phi(self) -> int:
        return (self.p - 1) * (self.q - 1)

    @property
    def d(self) -> int:
        return modinv(self.e, self.phi)

    def encrypt(self, m: int) -> int:
        return pow(m, self.e, self.n)

    def decrypt(self, c: int) -> int:
        return pow(c, self.d, self.n)


def make_key(p: int = 61, q: int = 53, e: int = 17) -> ToyKey:
    k = ToyKey(p, q, e)
    if gcd(e, k.phi) != 1:
        raise ValueError("e must be coprime to phi(n)")
    return k


def worked_example(m: int = 65) -> str:
    k = make_key()
    c = k.encrypt(m)
    return "\n".join([
        f"p = {k.p}, q = {k.q}",
        f"n = p*q = {k.n}",
        f"phi(n) = (p-1)(q-1) = {k.p - 1}*{k.q - 1} = {k.phi}",
        f"e = {k.e}   (gcd(e, phi) = {gcd(k.e, k.phi)})",
        f"d = e^-1 mod phi = {k.d}   (check: e*d = {k.e * k.d} = 1 + {(k.e * k.d - 1) // k.phi}*phi)",
        f"public key (n, e) = ({k.n}, {k.e});  private key d = {k.d}",
        f"encrypt m = {m}:  c = m^e mod n = {m}^{k.e} mod {k.n} = {c}",
        f"decrypt:        m = c^d mod n = {c}^{k.d} mod {k.n} = {k.decrypt(c)}",
    ])


if __name__ == "__main__":
    print(worked_example())
