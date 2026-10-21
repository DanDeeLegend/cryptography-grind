"""Assignment 11.6: file-integrity tool. Build a SHA-256 manifest for a directory and verify it later.

A plain hash manifest detects accidents but not an attacker, who can edit a file AND regenerate the manifest. With
--key the manifest carries an HMAC-SHA256 tag, which an attacker without the key cannot recompute.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path


def file_hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build(root: Path, key: bytes | None = None) -> dict:
    files = {p.relative_to(root).as_posix(): file_hash(p) for p in sorted(root.rglob("*")) if p.is_file()}
    manifest = {"version": 1, "files": files}
    if key:
        manifest["hmac"] = _tag(files, key)
    return manifest


def _tag(files: dict, key: bytes) -> str:
    return hmac.new(key, json.dumps(files, sort_keys=True).encode(), hashlib.sha256).hexdigest()


def verify(root: Path, manifest: dict, key: bytes | None = None) -> dict:
    """Returns {'ok': bool, 'modified': [...], 'missing': [...], 'added': [...], 'manifest_authentic': bool|None}."""
    authentic = None
    if key is not None:
        authentic = "hmac" in manifest and hmac.compare_digest(manifest["hmac"], _tag(manifest["files"], key))
    now = build(root)["files"]
    old = manifest["files"]
    modified = sorted(p for p in old if p in now and not hmac.compare_digest(old[p], now[p]))
    missing = sorted(set(old) - set(now))
    added = sorted(set(now) - set(old))
    ok = not (modified or missing or added) and authentic is not False
    return {"ok": ok, "modified": modified, "missing": missing, "added": added, "manifest_authentic": authentic}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", choices=["build", "verify"])
    ap.add_argument("directory", type=Path)
    ap.add_argument("--manifest", type=Path, default=Path("manifest.json"))
    ap.add_argument("--key-file", type=Path, help="file holding the HMAC key (keep it outside the directory)")
    a = ap.parse_args(argv)
    key = a.key_file.read_bytes().strip() if a.key_file else None
    if a.command == "build":
        a.manifest.write_text(json.dumps(build(a.directory, key), indent=2))
        print(f"wrote {a.manifest}")
        return 0
    result = verify(a.directory, json.loads(a.manifest.read_text()), key)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
