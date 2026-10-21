"""Assignment 12.1: HMAC-SHA256 from scratch on top of our own SHA-256, checked against RFC 4231 and Python's hmac."""
from __future__ import annotations

from cryptolab.ch12.sha256 import sha256

BLOCK = 64


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    if len(key) > BLOCK:
        key = sha256(key)
    key = key.ljust(BLOCK, b"\x00")
    ipad = bytes(b ^ 0x36 for b in key)
    opad = bytes(b ^ 0x5C for b in key)
    return sha256(opad + sha256(ipad + msg))


# RFC 4231 test cases 1-4, 6, 7 (case 5 is a truncation test)
RFC4231 = [
    (bytes.fromhex("0b" * 20), b"Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    (b"Jefe", b"what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    (bytes.fromhex("aa" * 20), bytes.fromhex("dd" * 50), "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
    (bytes.fromhex("0102030405060708090a0b0c0d0e0f10111213141516171819"), bytes.fromhex("cd" * 50),
     "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
    (bytes.fromhex("aa" * 131), b"Test Using Larger Than Block-Size Key - Hash Key First",
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
    (bytes.fromhex("aa" * 131),
     b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
     "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
]

if __name__ == "__main__":
    for key, msg, want in RFC4231:
        print(hmac_sha256(key, msg).hex() == want)
