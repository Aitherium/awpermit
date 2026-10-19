"""awpermit CLI. Exit: 0 holds/allowed, 1 refused/denied, 2 could not judge."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .keys import PermitKeyError, SigningKey
from .permit import Cap, Denied, Issuer, PermitError, Verifier


def _cmd_keygen(a: argparse.Namespace) -> int:
    key = SigningKey.generate()
    path = key.save(Path(a.key) if a.key else None, overwrite=a.force)
    print(f"issuer key written to {path} (mode 600)")
    print(f"kid: {key.public().kid}")
    return 0


def _cmd_keyset(a: argparse.Namespace) -> int:
    issuer = Issuer(SigningKey.load(Path(a.key) if a.key else None), a.iss)
    print(json.dumps(issuer.keyset(), indent=2))
    return 0


def _cmd_mint(a: argparse.Namespace) -> int:
    issuer = Issuer(SigningKey.load(Path(a.key) if a.key else None), a.iss)
    cap = None
    if a.per_tx is not None or a.total is not None:
        cap = Cap(a.currency, per_tx=a.per_tx, total=a.total)
    print(issuer.mint(sub=a.sub, act_for=a.act_for, aud=a.aud, scope=a.scope, cap=cap,
                      ttl_s=a.ttl))
    return 0


def _cmd_verify(a: argparse.Namespace) -> int:
    try:
        docs = [json.loads(Path(p).read_text(encoding="utf-8")) for p in a.keyset]
        door = Verifier.from_keysets(audience=a.aud, docs=docs)
    except (OSError, ValueError) as exc:
        print(f"could not judge: keyset unusable: {exc}", file=sys.stderr)
        return 2
    token = a.token if a.token != "-" else sys.stdin.read().strip()
    try:
        permit = door.verify(token)
    except PermitError as exc:
        print(f"REFUSED: {exc}")
        return 1
    print(f"HOLDS: agent {permit.sub} for {permit.act_for} at {permit.aud}; "
          f"scope {', '.join(permit.scope)}")
    if a.action:
        try:
            # The CLI has no ledger, so a total cap is checked against this one amount.
            reason = permit.check(a.action, amount=a.amount, currency=a.currency)
            if reason:
                raise Denied(reason)
        except Denied as exc:
            print(f"DENIED {a.action}: {exc.reason}")
            return 1
        print(f"ALLOWED {a.action}")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="awpermit", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen", help="create an issuer signing key")
    g.add_argument("--key", help="key file (default ~/.aither/awpermit/issuer.key)")
    g.add_argument("--force", action="store_true", help="overwrite an existing key")
    g.set_defaults(fn=_cmd_keygen)

    k = sub.add_parser("keyset", help="print the public keyset to publish")
    k.add_argument("--iss", required=True)
    k.add_argument("--key")
    k.set_defaults(fn=_cmd_keyset)

    m = sub.add_parser("mint", help="mint a permit")
    m.add_argument("--iss", required=True)
    m.add_argument("--key")
    m.add_argument("--sub", required=True, help="the agent")
    m.add_argument("--for", dest="act_for", required=True, help="the accountable principal")
    m.add_argument("--aud", required=True, help="the one door it opens")
    m.add_argument("--scope", required=True, action="append", help="repeatable")
    m.add_argument("--currency", default="USD")
    m.add_argument("--per-tx", type=int)
    m.add_argument("--total", type=int)
    m.add_argument("--ttl", type=float, default=900.0)
    m.set_defaults(fn=_cmd_mint)

    v = sub.add_parser("verify", help="verify a permit at a door")
    v.add_argument("token", help="the permit, or - for stdin")
    v.add_argument("--aud", required=True)
    v.add_argument("--keyset", required=True, action="append", help="keyset JSON file")
    v.add_argument("--action")
    v.add_argument("--amount", type=int)
    v.add_argument("--currency")
    v.set_defaults(fn=_cmd_verify)

    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except (PermitKeyError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
