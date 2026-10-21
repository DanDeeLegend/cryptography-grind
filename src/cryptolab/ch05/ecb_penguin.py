"""Assignment 5.1: ECB's 'penguin problem'.

ECB encrypts every 16-byte block independently with the same key, so identical plaintext blocks give identical
ciphertext blocks and the picture's shapes survive encryption. CBC chains each block into the next (so equal
blocks differ), and CTR XORs a unique keystream block. The image is generated here (flat colours, like a logo),
which is exactly the kind of data ECB leaks the most about.
"""
from __future__ import annotations

import os

from Crypto.Cipher import AES
from PIL import Image, ImageDraw


def make_logo(n: int = 160) -> Image.Image:
    """A flat-colour penguin-ish mascot. n*n*3 bytes must be a multiple of 16, so n is a multiple of 16."""
    im = Image.new("RGB", (n, n), (40, 90, 200))
    d = ImageDraw.Draw(im)
    f = lambda *v: tuple(int(n * x) for x in v)
    d.ellipse(f(.2, .15, .8, .95), fill=(20, 20, 20))        # body
    d.ellipse(f(.3, .42, .7, .92), fill=(245, 245, 245))     # belly
    d.ellipse(f(.34, .12, .66, .42), fill=(20, 20, 20))      # head
    d.ellipse(f(.40, .22, .48, .30), fill=(255, 255, 255)); d.ellipse(f(.52, .22, .60, .30), fill=(255, 255, 255))
    d.polygon([f(.45, .32)[:2], f(.55, .32)[:2], f(.5, .40)[:2]], fill=(255, 150, 0))   # beak
    d.polygon([f(.22, .85)[:2], f(.40, .95)[:2], f(.22, .97)[:2]], fill=(255, 150, 0))  # feet
    d.polygon([f(.78, .85)[:2], f(.60, .95)[:2], f(.78, .97)[:2]], fill=(255, 150, 0))
    return im


def encrypt_image(img: Image.Image, mode: str, key: bytes | None = None) -> Image.Image:
    key = key or os.urandom(16)
    raw = img.tobytes()
    if mode == "ECB":
        ct = AES.new(key, AES.MODE_ECB).encrypt(raw)
    elif mode == "CBC":
        ct = AES.new(key, AES.MODE_CBC, os.urandom(16)).encrypt(raw)
    elif mode == "CTR":
        ct = AES.new(key, AES.MODE_CTR, nonce=os.urandom(8)).encrypt(raw)
    else:
        raise ValueError(mode)
    return Image.frombytes("RGB", img.size, ct)


def repeated_blocks(data: bytes) -> int:
    """How many 16-byte blocks are copies of an earlier block (a direct measure of the ECB leak)."""
    blocks = [data[i:i + 16] for i in range(0, len(data), 16)]
    return len(blocks) - len(set(blocks))


def side_by_side(path: str, n: int = 160) -> dict[str, int]:
    """Write original | ECB | CBC | CTR to `path` and return the repeated-block count of each."""
    img = make_logo(n)
    panels = [("original", img)] + [(m, encrypt_image(img, m)) for m in ("ECB", "CBC", "CTR")]
    sheet = Image.new("RGB", (4 * n + 5 * 8, n + 32), (255, 255, 255))
    d = ImageDraw.Draw(sheet)
    for i, (label, panel) in enumerate(panels):
        x = 8 + i * (n + 8)
        sheet.paste(panel, (x, 24))
        d.text((x, 6), label, fill=(0, 0, 0))
    sheet.save(path)
    return {label: repeated_blocks(panel.tobytes()) for label, panel in panels}


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(__file__), "..", "..", "..", "docs", "img", "ecb-vs-cbc-ctr.png")
    print("repeated 16-byte blocks:", side_by_side(os.path.normpath(out)))
