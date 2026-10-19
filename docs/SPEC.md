# awpermit v1 — protocol

A permit is a signed statement that lets one agent do named things at one
platform, on behalf of one accountable principal, within a spend cap, until it
expires. A platform verifies it offline against the issuer's published key.

## Roles

| role | holds | does |
|---|---|---|
| **issuer** | Ed25519 private key | knows the principal (signed in, ideally human-checked), mints permits |
| **agent** | the permit | presents it in the `Agent-Permit` request header |
| **platform** | the issuer's public keyset | verifies, enforces scope and cap, records what happened |

## Token

```
awp1.<base64url(canonical JSON payload)>.<base64url(Ed25519 signature over "awp1.<payload>")>
```

Canonical JSON = sorted keys, `(",", ":")` separators, UTF-8.

### Payload — exactly these fields

| field | type | rule |
|---|---|---|
| `v` | int | `1` |
| `alg` | str | `"ed25519"`. The verifier's key decides; a mismatch refuses. |
| `iss` | str | issuer name; must be trusted by the platform |
| `kid` | str | base64url of the first 12 bytes of SHA-256(public key) |
| `sub` | str | the agent |
| `act_for` | str | the accountable principal, opaque to the platform. Issuers SHOULD make it pairwise per `aud` so platforms cannot join users across sites. |
| `aud` | str | the one platform this permit opens. Never `*`. |
| `scope` | [str] | sorted, non-empty, see grammar |
| `cap` | obj \| null | `{"currency": "USD", "per_tx": int\|null, "total": int\|null}`, integer minor units, at least one limit |
| `iat`, `exp` | number | epoch seconds; `exp - iat ≤ 86400`; default lifetime 900 s |
| `nonce` | str | unique per permit; keys the spend ledger |

A token missing any field **or carrying any other field** is refused. An unknown
field may be a restriction the verifier would ignore, and an ignored restriction
is a grant.

### Scope grammar

`segment(:segment)*`, segment = `[a-z0-9][a-z0-9_.-]{0,63}`. A final `:*` grants a
subtree (`cart:*` covers `cart:add`, not `cart`). A bare `*` is invalid everywhere.
Actions checked against a permit are concrete (no `*`).

Recommended verbs: `browse`, `search`, `cart:*`, `purchase`, `post`, `message`,
`account:read`. Platforms publish which actions they enforce.

## Verification (in order; any failure refuses)

1. prefix `awp1`, three parts, payload decodes to an object
2. exact field set
3. `v == 1`, `alg == "ed25519"`
4. `iss` trusted; `kid` is one of that issuer's keys
5. signature verifies
6. `aud` equals this platform's audience
7. `exp ≥ now`; `iat ≤ now + 60`; lifetime ≤ 86400
8. `sub`, `act_for`, `nonce` non-empty; scope valid; cap valid

## Enforcement

For each action: scope must cover it. With an amount: a cap must exist, the
currency must match, `amount ≤ per_tx`, and — if `total` is set — an atomic
check-and-add on the ledger keyed `iss|nonce` must stay `≤ total`. With a total
cap and no ledger, the platform refuses. A refused charge is never recorded.

## Keyset

Published by the issuer, e.g. at `/.well-known/awpermit.json`:

```json
{"awpermit": 1, "issuer": "id.example.com",
 "keys": [{"kid": "...", "alg": "ed25519", "x": "<base64url raw public key>"}]}
```

Platforms load it at configuration time, not per request. Rotation: publish the
new key alongside the old for at least one maximum lifetime (24 h), then drop
the old one.

## Door document

A platform that accepts permits says so at `/.well-known/agent-permit.json`, so an
agent can learn the door's language without a human reading docs:

```json
{"awpermit": 1, "door": "shop.example.com", "header": "Agent-Permit",
 "actions": {"purchase": {"request": "POST https://shop.example.com/checkout",
                          "spend": "price in minor units, checked against the cap"}},
 "issuers": [{"issuer": "id.example.com",
              "keyset": "https://id.example.com/.well-known/awpermit.json",
              "mint": "POST https://id.example.com/permits",
              "request": "POST https://id.example.com/permits/requests"}]}
```

`door` is the `aud` a permit for this platform must carry; `actions` are exactly
the scopes it enforces; `issuers` are the only issuers it trusts.

## Permit request (an agent with no session)

An agent cannot mint: the permit makes its human accountable, so the human decides.
The issuer named in a door document may offer `request`:

1. `POST <request>` `{"agent_id", "aud", "scope", "per_tx_cents", "total_cents",
   "ttl_seconds"}` -> `{"request_id", "user_code", "approve_url", "poll_url",
   "poll_token", "interval", "expires_in"}`. The issuer validates the grant exactly as
   it would a mint, so a human is never shown something it would refuse.
2. The agent shows its human `approve_url` and `user_code`. The human, signed in to the
   issuer, sees the agent, the door, the actions and the cap, and approves or denies.
3. The agent polls `GET <poll_url>?poll_token=...` every `interval` seconds:
   `pending` · `denied` · `expired` · `approved` (with `permit`, returned ONCE) ·
   `collected` (already returned).

The poll token is the only way to collect the permit; the approve link alone is not.
`awpermit request <door> --agent <id> --scope <action>` runs the whole flow.

## Not in v1

- **Proof of possession.** A permit is a bearer token; theft is bounded by TTL,
  `aud`, scope and cap. v2 binds it to an agent key that signs each request.
- **Revocation.** Short lifetimes stand in for it.
- **Toll / settlement.** Platforms need a signed usage receipt per action to bill
  the principal for agent traffic. Reserved for v2; v1 tokens carry no toll terms.
