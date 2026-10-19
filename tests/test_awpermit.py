"""Contract tests: every refusal the format promises, driven through the real code."""

from __future__ import annotations

import json
import os
import sys

import pytest

from awpermit import (
    Cap,
    Denied,
    Issuer,
    MemorySpend,
    PermitError,
    SigningKey,
    Verifier,
    scope_matches,
    valid_scope,
)
from awpermit.cli import main as cli_main
from awpermit.keys import b64, unb64

T0 = 1_800_000_000.0
AUD = "shop.example.com"


@pytest.fixture()
def issuer() -> Issuer:
    return Issuer(SigningKey.generate(), iss="id.example.com")


@pytest.fixture()
def door(issuer: Issuer) -> Verifier:
    return Verifier.from_keysets(audience=AUD, docs=[issuer.keyset()])


def mint(issuer: Issuer, **kw) -> str:
    args = dict(sub="agent:a1", act_for="user:u1", aud=AUD, scope=["browse", "cart:*", "purchase"],
                cap=Cap("USD", per_tx=5000, total=8000), now=T0)
    args.update(kw)
    return issuer.mint(**args)


def resign(issuer: Issuer, token: str, mutate) -> str:
    """Re-sign a mutated payload with the REAL key, so only the rule under test fails."""
    prefix, body, _ = token.split(".")
    payload = json.loads(unb64(body))
    mutate(payload)
    signed = f"{prefix}.{b64(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode())}"
    return f"{signed}.{b64(issuer.key.sign(signed.encode('ascii')))}"


# --- holds ---------------------------------------------------------------------


def test_roundtrip(issuer, door):
    p = door.verify(mint(issuer), now=T0 + 1)
    assert (p.sub, p.act_for, p.aud) == ("agent:a1", "user:u1", AUD)
    assert p.scope == ("browse", "cart:*", "purchase")
    assert p.cap == Cap("USD", per_tx=5000, total=8000)


# --- refused at verify -----------------------------------------------------------


def test_wrong_audience(issuer, door):
    with pytest.raises(PermitError, match="not 'shop.example.com'"):
        door.verify(mint(issuer, aud="forum.example.com"), now=T0)


def test_tampered_payload(issuer, door):
    prefix, body, sig = mint(issuer).split(".")
    payload = json.loads(unb64(body))
    payload["scope"] = ["browse", "cart:*", "purchase", "refund"]
    forged = f"{prefix}.{b64(json.dumps(payload).encode())}.{sig}"
    with pytest.raises(PermitError, match="signature"):
        door.verify(forged, now=T0)


def test_untrusted_issuer(door):
    stranger = Issuer(SigningKey.generate(), iss="evil.example.com")
    with pytest.raises(PermitError, match="not trusted"):
        door.verify(mint(stranger), now=T0)


def test_same_issuer_name_other_key(door):
    impostor = Issuer(SigningKey.generate(), iss="id.example.com")
    with pytest.raises(PermitError, match="no trusted key"):
        door.verify(mint(impostor), now=T0)


def test_kid_swapped_to_trusted_key_still_fails_signature(issuer, door):
    impostor = Issuer(SigningKey.generate(), iss="id.example.com")
    real_kid = issuer.key.public().kid
    forged = resign(impostor, mint(impostor), lambda p: p.update(kid=real_kid))
    with pytest.raises(PermitError, match="signature"):
        door.verify(forged, now=T0)


def test_expired(issuer, door):
    with pytest.raises(PermitError, match="expired"):
        door.verify(mint(issuer, ttl_s=60), now=T0 + 61)


def test_future_issued(issuer, door):
    with pytest.raises(PermitError, match="future"):
        door.verify(mint(issuer, now=T0 + 3600), now=T0)


def test_unknown_field_refused(issuer, door):
    tok = resign(issuer, mint(issuer), lambda p: p.update(region="eu"))
    with pytest.raises(PermitError, match="unknown field"):
        door.verify(tok, now=T0)


def test_missing_field_refused(issuer, door):
    tok = resign(issuer, mint(issuer), lambda p: p.pop("act_for"))
    with pytest.raises(PermitError, match="missing"):
        door.verify(tok, now=T0)


def test_alg_claim_must_match(issuer, door):
    tok = resign(issuer, mint(issuer), lambda p: p.update(alg="hs256"))
    with pytest.raises(PermitError, match="alg"):
        door.verify(tok, now=T0)


def test_signed_bare_star_scope_refused_at_verify(issuer, door):
    tok = resign(issuer, mint(issuer), lambda p: p.update(scope=["*"]))
    with pytest.raises(PermitError, match="scope"):
        door.verify(tok, now=T0)


def test_signed_overlong_lifetime_refused(issuer, door):
    tok = resign(issuer, mint(issuer), lambda p: p.update(exp=p["iat"] + 7 * 24 * 3600))
    with pytest.raises(PermitError, match="lifetime"):
        door.verify(tok, now=T0)


@pytest.mark.parametrize("garbage", ["", "awp1", "awp1.x.y", "awn1.e30.AA", "a.b.c.d"])
def test_garbage_refused(door, garbage):
    with pytest.raises(PermitError):
        door.verify(garbage, now=T0)


# --- refused at mint -------------------------------------------------------------


@pytest.mark.parametrize("kw", [
    {"sub": ""}, {"act_for": ""}, {"aud": ""}, {"aud": "*"}, {"scope": []},
    {"scope": ["*"]}, {"scope": ["Purchase"]}, {"ttl_s": 0}, {"ttl_s": 2 * 24 * 3600},
])
def test_unmintable(issuer, kw):
    with pytest.raises(ValueError):
        mint(issuer, **kw)


@pytest.mark.parametrize("cap", [
    lambda: Cap("usd", per_tx=1), lambda: Cap("USD"), lambda: Cap("USD", per_tx=-1),
    lambda: Cap("USD", total=1.5),
])
def test_bad_cap(cap):
    with pytest.raises(ValueError):
        cap()


# --- scope ---------------------------------------------------------------------


def test_scope_grammar():
    assert valid_scope("purchase") and valid_scope("cart:write") and valid_scope("cart:*")
    for bad in ("*", "", "cart:", ":x", "*:x", "a:*:b", "Cart", "a b"):
        assert not valid_scope(bad), bad
    assert scope_matches("cart:*", "cart:write")
    assert not scope_matches("cart:*", "cart")
    assert not scope_matches("cart:*", "cartography:write")
    assert not scope_matches("purchase", "purchase:refund")


# --- require ---------------------------------------------------------------------


def test_require_scope(issuer, door):
    p = door.verify(mint(issuer), now=T0)
    p.require("browse")
    p.require("cart:add")
    with pytest.raises(Denied, match="does not grant 'refund'"):
        p.require("refund")
    with pytest.raises(Denied, match="concrete"):
        p.require("cart:*")


def test_require_per_tx_and_currency(issuer, door):
    p = door.verify(mint(issuer), now=T0)
    spend = MemorySpend()
    p.require("purchase", amount=5000, currency="USD", spend=spend)
    with pytest.raises(Denied, match="per-transaction"):
        p.require("purchase", amount=5001, currency="USD", spend=spend)
    with pytest.raises(Denied, match="USD"):
        p.require("purchase", amount=1, currency="EUR", spend=spend)
    with pytest.raises(Denied, match="USD"):
        p.require("purchase", amount=1, spend=spend)


def test_require_total_across_calls(issuer, door):
    p = door.verify(mint(issuer), now=T0)
    spend = MemorySpend()
    p.require("purchase", amount=5000, currency="USD", spend=spend)
    p.require("purchase", amount=3000, currency="USD", spend=spend)
    with pytest.raises(Denied, match="total cap"):
        p.require("purchase", amount=1, currency="USD", spend=spend)
    assert spend.spent(p.ledger_key) == 8000  # the refused charge was not recorded


def test_total_cap_without_ledger_refuses(issuer, door):
    p = door.verify(mint(issuer), now=T0)
    with pytest.raises(Denied, match="no spend ledger"):
        p.require("purchase", amount=1, currency="USD")


def test_amount_without_cap_refuses(issuer, door):
    p = door.verify(mint(issuer, cap=None), now=T0)
    p.require("purchase")  # a non-monetary use of the scope is fine
    with pytest.raises(Denied, match="no spending authority"):
        p.require("purchase", amount=1, currency="USD")


def test_ledger_expires_with_permit():
    s = MemorySpend()
    assert s.charge("k", 10, 10, expires_at=100.0, now=50.0)
    assert not s.charge("k", 1, 10, expires_at=100.0, now=60.0)
    assert s.charge("other", 1, 10, expires_at=500.0, now=101.0)
    assert s.spent("k") == 0


# --- keyset ---------------------------------------------------------------------


def test_keyset_kid_mismatch_refused(issuer):
    doc = issuer.keyset()
    doc["keys"][0]["kid"] = "nope"
    with pytest.raises(ValueError, match="kid"):
        Verifier.from_keysets(audience=AUD, docs=[doc])


def test_verifier_with_no_keys_refuses_construction():
    with pytest.raises(ValueError):
        Verifier(audience=AUD, issuers={})


# --- key file + CLI ----------------------------------------------------------------


def test_key_save_load_and_no_overwrite(tmp_path):
    key = SigningKey.generate()
    path = key.save(tmp_path / "issuer.key")
    assert SigningKey.load(path).public().kid == key.public().kid
    with pytest.raises(Exception, match="overwrite"):
        SigningKey.generate().save(path)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_key_file_mode_600(tmp_path):
    path = SigningKey.generate().save(tmp_path / "issuer.key")
    assert (os.stat(path).st_mode & 0o777) == 0o600


def test_cli_end_to_end(tmp_path, capsys):
    key = str(tmp_path / "k")
    assert cli_main(["keygen", "--key", key]) == 0
    assert cli_main(["keyset", "--iss", "id.example.com", "--key", key]) == 0
    out = capsys.readouterr().out
    keyset = tmp_path / "keyset.json"
    keyset.write_text(out[out.index("{"):], encoding="utf-8")
    assert cli_main(["mint", "--iss", "id.example.com", "--key", key, "--sub", "agent:a",
                     "--for", "user:u", "--aud", AUD, "--scope", "purchase",
                     "--per-tx", "500"]) == 0
    token = capsys.readouterr().out.strip()
    base = ["verify", token, "--aud", AUD, "--keyset", str(keyset)]
    assert cli_main(base + ["--action", "purchase", "--amount", "400", "--currency", "USD"]) == 0
    assert cli_main(base + ["--action", "purchase", "--amount", "600", "--currency", "USD"]) == 1
    assert cli_main(["verify", token, "--aud", "other.example.com", "--keyset", str(keyset)]) == 1
    assert cli_main(["verify", token, "--aud", AUD, "--keyset", str(tmp_path / "none")]) == 2
