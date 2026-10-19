# awpermit

**Let an agent through your door with a scope, a spend cap, and someone accountable.**

```bash
pip install awpermit
```

Platforms block agents for one reason that identity does not fix: once a bot is
in, nothing says what it may do, for whom, or who pays when it is talked into
something. A permit says all three, and a platform checks it offline.

```python
from awpermit import Issuer, Verifier, SigningKey, Cap, MemorySpend

# Issuer: whoever vouches for the person behind the agent.
issuer = Issuer(SigningKey.generate(), iss="id.example.com")
token = issuer.mint(
    sub="agent:shopper-7",            # which agent
    act_for="user:4f2a",              # who is accountable
    aud="shop.example.com",           # the one door it opens
    scope=["browse", "cart:*", "purchase"],
    cap=Cap("USD", per_tx=5000, total=20000),   # cents
)

# Platform: trusts the issuer's published keyset; needs no account for the user.
door = Verifier.from_keysets(audience="shop.example.com", docs=[issuer.keyset()])
permit = door.verify(token)                     # raises PermitError
permit.require("purchase", amount=1999, currency="USD", spend=MemorySpend())  # raises Denied
```

## What it refuses

- a permit for another door, from an untrusted issuer, signed by an unknown key
- an expired one, one issued in the future, one living longer than 24 hours
- any payload field it does not know (an ignored restriction is a grant)
- a bare `*` scope, at mint and at verify
- an amount over the per-transaction cap, in the wrong currency, or with no cap
- an amount against a total cap when no spend ledger was supplied

A hijacked agent holding a permit can do only what the scope names, at the door
it names, up to the cap, until it expires.

## CLI

```bash
awpermit keygen
awpermit keyset --iss id.example.com > keyset.json          # publish this
awpermit mint --iss id.example.com --sub agent:a --for user:u \
  --aud shop.example.com --scope browse --scope purchase --per-tx 5000
awpermit verify <token> --aud shop.example.com --keyset keyset.json \
  --action purchase --amount 1999 --currency USD
```

Exit codes: `0` holds/allowed, `1` refused/denied, `2` could not judge.

Protocol: [docs/SPEC.md](docs/SPEC.md). Licence: Apache-2.0.
