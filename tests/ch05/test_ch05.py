import datetime
import os
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

from cryptolab.ch05 import ecb_penguin, gcm, secure_log, tls_audit


# ---------- 5.1 ----------
def test_ecb_leaks_structure_cbc_and_ctr_do_not(tmp_path):
    counts = ecb_penguin.side_by_side(str(tmp_path / "x.png"))
    assert counts["ECB"] > 1000                 # thousands of repeated ciphertext blocks: the picture survives
    assert counts["CBC"] == 0 and counts["CTR"] == 0
    assert (tmp_path / "x.png").stat().st_size > 0


# ---------- 5.3 ----------
H = bytes.fromhex
GCM_CASES = [  # McGrew & Viega, "The Galois/Counter Mode of Operation", AES-128 test cases 1-3
    ("00" * 16, "00" * 12, "", "", "", "58e2fccefa7e3061367f1d57a4e7455a"),
    ("00" * 16, "00" * 12, "00" * 16, "", "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"),
    ("feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
     "", "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
     "4d5c2af327cd64a62cf35abd2ba6fab4"),
]


@pytest.mark.parametrize("key,iv,pt,aad,ct,tag", GCM_CASES)
def test_gcm_published_test_cases(key, iv, pt, aad, ct, tag):
    c, t = gcm.encrypt(H(key), H(iv), H(pt), H(aad))
    assert c == H(ct) and t == H(tag)
    assert gcm.decrypt(H(key), H(iv), c, t, H(aad)) == H(pt)


def test_gcm_matches_library_on_random_inputs():
    for n in (0, 1, 15, 16, 17, 100, 333):
        key, iv, pt, aad = os.urandom(16), os.urandom(12), os.urandom(n), os.urandom(n % 7)
        c, t = gcm.encrypt(key, iv, pt, aad)
        assert c + t == AESGCM(key).encrypt(iv, pt, aad or None)


def test_gcm_rejects_any_modification():
    key, iv = os.urandom(16), os.urandom(12)
    c, t = gcm.encrypt(key, iv, b"transfer 100 to alice", b"hdr")
    for bad_c, bad_t, bad_aad in ((bytes([c[0] ^ 1]) + c[1:], t, b"hdr"), (c, bytes([t[0] ^ 1]) + t[1:], b"hdr"), (c, t, b"HDR")):
        with pytest.raises(gcm.AuthenticationError):
            gcm.decrypt(key, iv, bad_c, bad_t, bad_aad)


def test_unauthenticated_ctr_is_silently_malleable():
    key, nonce, msg = os.urandom(16), os.urandom(12), b"PAY ALICE $100.00"
    forged = bytearray(gcm.ctr_only(key, nonce, msg)); forged[11] ^= ord("1") ^ ord("9")
    assert gcm.ctr_only(key, nonce, bytes(forged)) == b"PAY ALICE $900.00"


# ---------- 5.6 ----------
MASTER, SEG = os.urandom(32), "seg1"


def _log(tmp_path, n=5):
    p = str(tmp_path / "l.log")
    lg = secure_log.SecureLog(p, MASTER, SEG)
    for i in range(n):
        lg.append(f"event {i}")
    ck = (lg.seq, lg.checkpoint())
    lg.close()
    return p, ck


def _rewrite(p, fn):
    ls = open(p, "rb").read().split(b"\n")[:-1]
    open(p, "wb").write(b"\n".join(fn(ls)) + b"\n")


def test_log_roundtrip_and_reopen_continues_chain(tmp_path):
    p, _ = _log(tmp_path, 3)
    lg = secure_log.SecureLog(p, MASTER, SEG); lg.append("more"); lg.close()
    assert [m.decode() for m in secure_log.read_verified(p, MASTER, SEG)] == ["event 0", "event 1", "event 2", "more"]


@pytest.mark.parametrize("attack", ["flip", "delete", "reorder", "replay"])
def test_log_detects_tampering(tmp_path, attack):
    p, ck = _log(tmp_path)
    if attack == "flip":
        _rewrite(p, lambda ls: ls[:2] + [ls[2][:-3] + (b"AAA" if ls[2][-3:] != b"AAA" else b"BBB")] + ls[3:])
    elif attack == "delete":
        _rewrite(p, lambda ls: ls[:2] + ls[3:])
    elif attack == "reorder":
        _rewrite(p, lambda ls: [ls[0], ls[2], ls[1]] + ls[3:])
    else:
        _rewrite(p, lambda ls: ls + [ls[1]])
    with pytest.raises(secure_log.LogTamperError):
        secure_log.read_verified(p, MASTER, SEG, ck)


def test_tail_truncation_needs_an_external_checkpoint(tmp_path):
    p, ck = _log(tmp_path)
    _rewrite(p, lambda ls: ls[:3])
    assert len(secure_log.read_verified(p, MASTER, SEG)) == 3        # invisible from inside the file: documented limit
    with pytest.raises(secure_log.LogTamperError, match="truncated"):
        secure_log.read_verified(p, MASTER, SEG, ck)


def test_log_wrong_key_wrong_segment_and_single_writer_lock(tmp_path):
    p, _ = _log(tmp_path)
    with pytest.raises(secure_log.LogTamperError):
        secure_log.read_verified(p, os.urandom(32), SEG)
    with pytest.raises(secure_log.LogTamperError):
        secure_log.read_verified(p, MASTER, "other-segment")
    first = secure_log.SecureLog(p, MASTER, SEG)
    with pytest.raises(OSError):                                      # a second writer would risk nonce reuse
        secure_log.SecureLog(p, MASTER, SEG)
    first.close()


# ---------- 5.5 ----------
def test_classify_cipher():
    assert tls_audit.classify_cipher("ECDHE-RSA-AES128-GCM-SHA256") == []
    assert tls_audit.classify_cipher("ECDHE-RSA-CHACHA20-POLY1305") == []
    assert any("3DES" in w for w in tls_audit.classify_cipher("ECDHE-RSA-DES-CBC3-SHA"))
    assert any("forward secrecy" in w for w in tls_audit.classify_cipher("AES128-GCM-SHA256"))
    assert any("RC4" in w for w in tls_audit.classify_cipher("ECDHE-RSA-RC4-SHA"))
    assert any("CBC" in w for w in tls_audit.classify_cipher("ECDHE-RSA-AES128-SHA256") + tls_audit.classify_cipher("ECDHE-RSA-AES256-CBC-SHA"))


@pytest.fixture
def tls12_only_server(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=10))
            .sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(64); srv.settimeout(0.2)
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(1); tls.recv(2048)
                    tls.sendall(b"HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=1\r\n\r\n")
            except (ssl.SSLError, OSError):
                conn.close()
    t = threading.Thread(target=loop, daemon=True); t.start()
    yield srv.getsockname()[1]
    stop.set(); srv.close(); t.join(2)


def test_audit_local_tls12_only_server(tls12_only_server):
    rep = tls_audit.audit("127.0.0.1", tls12_only_server)
    assert rep["protocols"]["TLS 1.2"] == "supported"
    assert rep["protocols"]["TLS 1.3"] != "supported"
    assert rep["tls12_suites_accepted"]                              # at least one suite negotiated
    assert rep["certificate"]["self_signed"] and rep["certificate"]["key"].startswith("EC")
    found = " ".join(f for _, f, _ in tls_audit.findings(rep))
    assert "self-signed" in found and "TLS 1.3 not available" in found
