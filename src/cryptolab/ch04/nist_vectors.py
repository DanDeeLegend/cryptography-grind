"""Assignment 4.2: AES-128 against official test vectors, using a standard library AND the from-scratch cipher.

Vectors: FIPS-197 Appendix B and C.1, NIST SP 800-38A F.1.1 (ECB-AES128, four blocks), and the all-zero
known-answer test. The library path is PyCryptodome's ECB mode, as the assignment asks.
"""
from __future__ import annotations

from Crypto.Cipher import AES

from . import aes as scratch

# (name, key, plaintext, ciphertext), all hex
VECTORS = [
    ("FIPS-197 App. B", "2b7e151628aed2a6abf7158809cf4f3c", "3243f6a8885a308d313198a2e0370734",
     "3925841d02dc09fbdc118597196a0b32"),
    ("FIPS-197 App. C.1", "000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff",
     "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("SP 800-38A F.1.1 block 1", "2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a",
     "3ad77bb40d7a3660a89ecaf32466ef97"),
    ("SP 800-38A F.1.1 block 2", "2b7e151628aed2a6abf7158809cf4f3c", "ae2d8a571e03ac9c9eb76fac45af8e51",
     "f5d3d58503b9699de785895a96fdbaaf"),
    ("SP 800-38A F.1.1 block 3", "2b7e151628aed2a6abf7158809cf4f3c", "30c81c46a35ce411e5fbc1191a0a52ef",
     "43b1cd7f598ece23881b00e3ed030688"),
    ("SP 800-38A F.1.1 block 4", "2b7e151628aed2a6abf7158809cf4f3c", "f69f2445df4f9b17ad2b417be66c3710",
     "7b0c785e27e8ad3f8223207104725dd4"),
    ("all-zero key and block", "00" * 16, "00" * 16, "66e94bd4ef8a2c3b884cfa59ca342b2e"),
]


def library_encrypt(key: bytes, pt: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(pt)


def scratch_encrypt(key: bytes, pt: bytes) -> bytes:
    """Adapter: the from-scratch cipher takes (block, key); the vector harness passes (key, block)."""
    return scratch.encrypt_block(pt, key)


def check(encrypt=library_encrypt) -> list[tuple[str, bool]]:
    return [(name, encrypt(bytes.fromhex(k), bytes.fromhex(p)) == bytes.fromhex(c)) for name, k, p, c in VECTORS]


def demo() -> None:
    for label, fn in (("PyCryptodome ECB", library_encrypt), ("from-scratch AES-128", scratch_encrypt)):
        results = check(fn)
        print(f"{label}: {sum(ok for _, ok in results)}/{len(results)} vectors pass")
        for name, ok in results:
            print(f"   {'PASS' if ok else 'FAIL'}  {name}")


if __name__ == "__main__":
    demo()
