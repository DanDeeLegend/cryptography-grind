import json
import zlib

from cryptolab.ch11 import avalanche, birthday, integrity, passwords


def test_good_hashes_avalanche_near_half_and_bytesum_does_not():
    for n in ("SHA-256", "SHA-1", "MD5"):
        assert 0.48 < avalanche.measure(n, trials=500)["mean"] < 0.52
    assert avalanche.measure("byte-sum", trials=500)["mean"] < 0.15


def test_crc32_passes_avalanche_but_is_linear():
    """Avalanche is necessary, not sufficient: CRC32 flips ~half the bits yet is affine, so it is forgeable."""
    assert 0.45 < avalanche.measure("CRC32", trials=500)["mean"] < 0.55
    a, b, c = b"hello world!", b"HELLO world?", b"zzzzzzzzzzzz"
    xor = lambda x, y, z: bytes(i ^ j ^ k for i, j, k in zip(x, y, z))
    assert zlib.crc32(xor(a, b, c)) == zlib.crc32(a) ^ zlib.crc32(b) ^ zlib.crc32(c)


def test_birthday_finds_real_collisions_near_sqrt_bound():
    for fn in (birthday.table_collision, birthday.floyd_collision):
        m1, m2, evals = fn(20, seed=3)
        assert m1 != m2 and birthday.trunc_hash(m1, 20) == birthday.trunc_hash(m2, 20)
        assert evals < 2**20 / 8  # far below 2^k brute force
    counts = [birthday.table_collision(20, s)[2] for s in range(15)]
    assert 0.3 * 1024 < sum(counts) / len(counts) < 3 * 1024


def test_passwords_salted_and_verified():
    a, b = passwords.argon_store("hunter2"), passwords.argon_store("hunter2")
    assert a != b and a.startswith("$argon2id$")
    assert passwords.argon_check("hunter2", a) and not passwords.argon_check("hunter3", a)
    s = passwords.naive_store("hunter2")
    assert passwords.naive_check("hunter2", s) and s == passwords.naive_store("hunter2")  # unsalted: identical hashes leak equality


def test_wordlist_crack_finds_naive_but_cost_gap_is_large():
    words = [f"word{i}" for i in range(1000)] + ["letmein"]
    found, tries = passwords.crack_wordlist(passwords.naive_store("letmein"), words, passwords.naive_check)
    assert found == "letmein" and tries == 1001
    sha = passwords.rate(lambda i: passwords.naive_store(str(i)), 0.2)
    arg = passwords.rate(lambda i: passwords.argon_store(str(i)), 0.5)
    assert sha > 100 * arg


def test_integrity_detects_modify_add_remove_and_forged_manifest(tmp_path):
    root = tmp_path / "data"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("alpha")
    (root / "sub" / "b.txt").write_text("beta")
    key = b"k" * 32
    man = integrity.build(root, key)
    assert integrity.verify(root, man, key)["ok"]
    (root / "a.txt").write_text("ALPHA")
    (root / "sub" / "b.txt").unlink()
    (root / "new.txt").write_text("x")
    r = integrity.verify(root, man, key)
    assert not r["ok"] and r["modified"] == ["a.txt"] and r["missing"] == ["sub/b.txt"] and r["added"] == ["new.txt"]
    # attacker edits a file and regenerates a plain manifest: without a key this is undetectable, with one it is caught
    forged = integrity.build(root)
    assert integrity.verify(root, forged)["ok"]
    assert not integrity.verify(root, forged, key)["ok"]
    tampered = json.loads(json.dumps(man))
    tampered["files"]["a.txt"] = forged["files"]["a.txt"]
    assert integrity.verify(root, tampered, key)["manifest_authentic"] is False
