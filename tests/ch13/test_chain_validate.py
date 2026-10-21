import datetime as dt

from cryptolab.ch13 import pki
from cryptolab.ch13.chain_validate import hostname_matches, revocation_pointers, validate

HOST = "app.example.test"


def hierarchy(**leaf_kw):
    root = pki.make_root()
    inter = pki.make_intermediate(root)
    key, leaf = pki.make_leaf(inter, HOST, **leaf_kw)
    return root, inter, key, leaf


def test_valid_chain():
    root, inter, _, leaf = hierarchy()
    r = validate([leaf, inter.cert], [root.cert], HOST)
    assert r.ok and r.anchor == root.cert.subject.rfc4514_string()


def test_chain_that_includes_the_root_also_validates():
    root, inter, _, leaf = hierarchy()
    assert validate([leaf, inter.cert, root.cert], [root.cert], HOST).ok


def test_wrong_hostname_and_wildcard_rules():
    root, inter, _, leaf = hierarchy()
    assert any("hostname" in e for e in validate([leaf, inter.cert], [root.cert], "evil.example.test").errors)
    _, wild = pki.make_leaf(inter, "*.example.test", san=["*.example.test"])
    assert hostname_matches(wild, "a.example.test")
    assert not hostname_matches(wild, "a.b.example.test") and not hostname_matches(wild, "example.test")


def test_expired_and_not_yet_valid():
    root, inter, _, leaf = hierarchy()
    future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=400)
    assert any("validity" in e for e in validate([leaf, inter.cert], [root.cert], HOST, now=future).errors)
    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=400)
    assert not validate([leaf, inter.cert], [root.cert], HOST, now=past).ok


def test_untrusted_root_and_missing_intermediate():
    root, inter, _, leaf = hierarchy()
    other = pki.make_root("Other Root")
    assert not validate([leaf, inter.cert], [other.cert], HOST).ok
    assert not validate([leaf], [root.cert], HOST).ok  # intermediate not sent and not an anchor


def test_same_name_different_key_root_is_not_trusted():
    """An attacker's root with the same subject name must not match: anchors are matched by key, not just name."""
    root, inter, _, leaf = hierarchy()
    impostor = pki.make_root(root.cert.subject.rfc4514_string().removeprefix("CN="))
    assert not validate([leaf, inter.cert], [impostor.cert], HOST).ok


def test_forged_leaf_signature_is_rejected():
    root, inter, _, leaf = hierarchy()
    rogue = pki.make_intermediate(root, cn=inter.cert.subject.rfc4514_string().removeprefix("CN="))  # same name, other key
    _, forged = pki.make_leaf(rogue, HOST)
    r = validate([forged, inter.cert], [root.cert], HOST)
    assert not r.ok and any("signature does not verify" in e for e in r.errors)


def test_non_ca_intermediate_cannot_sign():
    root = pki.make_root()
    inter = pki.make_intermediate(root)
    # a *leaf* certificate (ca=False) used as an issuer
    ikey, icert = pki.make_leaf(root, "not-a-ca.test")
    fake_ca = pki.Ca(ikey, icert)
    _, leaf = pki.make_leaf(fake_ca, HOST)
    r = validate([leaf, icert], [root.cert], HOST)
    assert not r.ok and any("not allowed to sign" in e for e in r.errors)


def test_path_length_constraint():
    root = pki.make_root(path_length=0)  # root may sign only end-entity certs
    inter = pki.make_intermediate(root)
    _, leaf = pki.make_leaf(inter, HOST)
    r = validate([leaf, inter.cert], [root.cert], HOST)
    assert not r.ok and any("pathLenConstraint" in e for e in r.errors)


def test_revocation_pointers_are_read():
    root = pki.make_root()
    _, leaf = pki.make_leaf(root, HOST, ocsp_url="http://ocsp.example.test")
    assert revocation_pointers(leaf)["ocsp"] == ["http://ocsp.example.test"]
