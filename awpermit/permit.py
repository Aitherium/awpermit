"""Permits: what an agent may do at your door, for whom, and up to how much.

WHY "AGENT ID" IS NOT THE PRODUCT
=================================
Telling a platform "this caller is a bot" is cheap and changes nothing: the
platform still has to decide what that bot may do, on whose behalf, and who pays
when it goes wrong. A permit answers exactly those three, offline, in one token:

    sub      WHICH agent. The thing acting.
    act_for  FOR WHOM. The accountable principal, as the issuer knows them. The
             platform needs no account for them -- only someone to hold liable.
    aud      AT WHICH DOOR. A permit for one platform opens no other.
    scope    WHAT IT MAY DO there. Named actions; no "everything".
    cap      HOW MUCH it may spend, per transaction and in total.

THE ATTACK THIS FORMAT IS SHAPED BY -- THE HIJACKED AGENT
=========================================================
An agent that reads the open web can be talked into things (prompt injection).
Detection will not save the platform; bounding will. A hijacked agent holding a
permit can do only what the scope names, only at the door it names, only up to
the cap, and only until it expires. Every one of those is checked by the
platform, not trusted to the agent.

FAIL CLOSED
===========
`verify` returns a Permit or raises PermitError. `require` returns None or
raises Denied. There is no "unknown, proceed" anywhere: an unparseable token, an
unknown field, an untrusted issuer and a missing spend ledger all refuse.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional

from .keys import ALG, SigningKey, VerifyKey, b64, unb64
from .spend import Spend

__all__ = [
    "TOKEN_PREFIX", "PERMIT_FIELDS", "MAX_TTL_S", "CLOCK_SKEW_S",
    "PermitError", "Denied", "Cap", "Permit", "Issuer", "Verifier",
    "valid_scope", "scope_matches", "keyset_doc",
]

#: Versioned so a format change is a loud refusal in an old verifier, never a
#: signature error it misreports as tampering.
TOKEN_PREFIX = "awp1"

#: EXACTLY the payload fields. A verifier refuses a token missing any of them AND
#: a token carrying any other: an unknown field may be a restriction this
#: verifier would silently ignore, and an ignored restriction is a grant.
PERMIT_FIELDS = ("v", "alg", "iss", "kid", "sub", "act_for", "aud", "scope", "cap",
                 "iat", "exp", "nonce")

#: A permit is a bearer credential; its lifetime is the damage window if stolen.
MAX_TTL_S = 24 * 3600
DEFAULT_TTL_S = 15 * 60
CLOCK_SKEW_S = 60

_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")


class PermitError(RuntimeError):
    """This permit does not hold. Raised, never returned as a falsy value."""


class Denied(RuntimeError):
    """The permit holds, but not for this action."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# --- scope ---------------------------------------------------------------------


def valid_scope(s: str) -> bool:
    """`verb` or `verb:object[:...]`, lowercase; a trailing `:*` grants a subtree.

    A bare `*` is never valid: a permit that can do anything is the skeleton key
    this whole format exists to avoid.
    """
    if not isinstance(s, str) or not s or s == "*":
        return False
    parts = s.split(":")
    for i, seg in enumerate(parts):
        if seg == "*" and i == len(parts) - 1 and i > 0:
            continue
        if not _SEGMENT.match(seg):
            return False
    return True


def scope_matches(granted: str, action: str) -> bool:
    """Does the granted scope cover this concrete action?"""
    if granted == action:
        return True
    if granted.endswith(":*"):
        return action.startswith(granted[:-1])
    return False


# --- cap -----------------------------------------------------------------------


@dataclass(frozen=True)
class Cap:
    """Spending authority in integer MINOR units (cents), one currency.

    Integers on purpose: a float cap is a rounding argument with a customer.
    """

    currency: str
    per_tx: Optional[int] = None
    total: Optional[int] = None

    def __post_init__(self) -> None:
        if not _CURRENCY.match(self.currency or ""):
            raise ValueError(f"currency must be an ISO 4217 code like 'USD', not {self.currency!r}")
        for name in ("per_tx", "total"):
            val = getattr(self, name)
            if val is not None and (isinstance(val, bool) or not isinstance(val, int) or val < 0):
                raise ValueError(f"cap.{name} must be a non-negative integer of minor units")
        if self.per_tx is None and self.total is None:
            raise ValueError("a cap with no per_tx and no total limits nothing -- omit the cap")

    def to_json(self) -> dict[str, Any]:
        return {"currency": self.currency, "per_tx": self.per_tx, "total": self.total}

    @classmethod
    def from_json(cls, obj: Any) -> "Cap":
        if not isinstance(obj, dict) or set(obj) != {"currency", "per_tx", "total"}:
            raise ValueError("cap must be an object with exactly currency, per_tx, total")
        return cls(currency=obj["currency"], per_tx=obj["per_tx"], total=obj["total"])


# --- the verified permit ---------------------------------------------------------


@dataclass(frozen=True)
class Permit:
    """A verified permit. Only constructed by `Verifier.verify`."""

    iss: str
    kid: str
    sub: str
    act_for: str
    aud: str
    scope: tuple[str, ...]
    cap: Optional[Cap]
    iat: float
    exp: float
    nonce: str

    def check(self, action: str, *, amount: Optional[int] = None,
              currency: Optional[str] = None) -> Optional[str]:
        """The stateless part of `require`: None if allowed, else the reason."""
        if not valid_scope(action) or action.endswith("*"):
            return f"{action!r} is not a concrete action"
        if not any(scope_matches(g, action) for g in self.scope):
            return f"permit does not grant {action!r} (grants: {', '.join(self.scope)})"
        if amount is None:
            return None
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            return "amount must be a non-negative integer of minor units"
        if self.cap is None:
            return "permit carries no spending authority"
        if currency != self.cap.currency:
            return f"permit spends {self.cap.currency}, not {currency!r}"
        if self.cap.per_tx is not None and amount > self.cap.per_tx:
            return f"amount {amount} exceeds the per-transaction cap {self.cap.per_tx}"
        if self.cap.total is not None and amount > self.cap.total:
            return f"amount {amount} exceeds the total cap {self.cap.total}"
        return None

    def require(self, action: str, *, amount: Optional[int] = None,
                currency: Optional[str] = None, spend: Optional[Spend] = None) -> None:
        """Allow this action or raise Denied.

        A total cap is only enforceable with memory of earlier spends, so a
        permit with a total cap REFUSES an amount when no ledger is supplied --
        "we did not count" is not "under the limit".
        """
        reason = self.check(action, amount=amount, currency=currency)
        if reason:
            raise Denied(reason)
        if amount is None or self.cap is None or self.cap.total is None:
            return
        if spend is None:
            raise Denied("permit has a total cap and no spend ledger was supplied")
        if not spend.charge(self.ledger_key, amount, self.cap.total, self.exp):
            raise Denied(f"amount {amount} would exceed the total cap {self.cap.total}")

    @property
    def ledger_key(self) -> str:
        """One permit, one running total. Issuer-scoped so nonces cannot collide."""
        return f"{self.iss}|{self.nonce}"


# --- issuing -------------------------------------------------------------------


def _canon(body: Mapping[str, Any]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def keyset_doc(iss: str, keys: Iterable[VerifyKey]) -> dict[str, Any]:
    """What an issuer publishes (e.g. at /.well-known/awpermit.json)."""
    return {
        "awpermit": 1,
        "issuer": iss,
        "keys": [{"kid": k.kid, "alg": k.alg, "x": k.x} for k in keys],
    }


class Issuer:
    """Mints permits. Holds the private key; lives with whoever vouches for principals."""

    def __init__(self, key: SigningKey, iss: str):
        if not iss:
            raise ValueError("an issuer needs a name the verifier can trust by")
        self.key = key
        self.iss = iss

    def keyset(self) -> dict[str, Any]:
        return keyset_doc(self.iss, [self.key.public()])

    def mint(self, *, sub: str, act_for: str, aud: str, scope: Iterable[str],
             cap: Optional[Cap] = None, ttl_s: float = DEFAULT_TTL_S,
             now: Optional[float] = None, nonce: Optional[str] = None) -> str:
        if not sub:
            raise ValueError("a permit with no agent (sub) is transferable between agents")
        if not act_for:
            raise ValueError("a permit with no principal (act_for) leaves nobody accountable")
        if not aud or aud == "*":
            raise ValueError("name the one door this permit is for (aud)")
        scopes = sorted(set(scope))
        if not scopes:
            raise ValueError("a permit with no scope grants nothing -- do not mint it")
        bad = [s for s in scopes if not valid_scope(s)]
        if bad:
            raise ValueError(f"invalid scope(s) {bad}; a bare '*' is never valid")
        if not 0 < ttl_s <= MAX_TTL_S:
            raise ValueError(f"ttl_s must be in (0, {MAX_TTL_S}]")
        iat = time.time() if now is None else now
        body = {
            "v": 1,
            "alg": ALG,
            "iss": self.iss,
            "kid": self.key.public().kid,
            "sub": sub,
            "act_for": act_for,
            "aud": aud,
            "scope": scopes,
            "cap": cap.to_json() if cap else None,
            "iat": iat,
            "exp": iat + ttl_s,
            "nonce": nonce or secrets.token_urlsafe(16),
        }
        signed = f"{TOKEN_PREFIX}.{b64(_canon(body))}"
        return f"{signed}.{b64(self.key.sign(signed.encode('ascii')))}"


# --- verifying -----------------------------------------------------------------


class Verifier:
    """Checks permits at ONE door, against the issuers that door chose to trust."""

    def __init__(self, *, audience: str, issuers: Mapping[str, Iterable[VerifyKey]]):
        if not audience:
            raise ValueError("a verifier needs the audience of the door it guards")
        self.audience = audience
        self._keys: dict[str, dict[str, VerifyKey]] = {
            iss: {k.kid: k for k in keys} for iss, keys in issuers.items()
        }
        if not any(self._keys.values()):
            raise ValueError("a verifier that trusts no key would refuse everything -- "
                             "configure at least one issuer")

    @classmethod
    def from_keysets(cls, *, audience: str, docs: Iterable[Mapping[str, Any]]) -> "Verifier":
        issuers: dict[str, list[VerifyKey]] = {}
        for doc in docs:
            if doc.get("awpermit") != 1 or not doc.get("issuer"):
                raise ValueError("not an awpermit v1 keyset document")
            for k in doc.get("keys") or []:
                if k.get("alg") != ALG:
                    raise ValueError(f"keyset key alg {k.get('alg')!r} is not {ALG}")
                vk = VerifyKey.from_b64(k["x"])
                if k.get("kid") != vk.kid:
                    raise ValueError("keyset kid does not match its key")
                issuers.setdefault(doc["issuer"], []).append(vk)
        return cls(audience=audience, issuers=issuers)

    def verify(self, token: str, *, now: Optional[float] = None) -> Permit:
        parts = (token or "").split(".")
        if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
            raise PermitError("not an awpermit token (or a different format version)")
        try:
            body = json.loads(unb64(parts[1]))
            sig = unb64(parts[2])
        except Exception as exc:
            raise PermitError(f"permit is not decodable: {exc}") from exc
        if not isinstance(body, dict):
            raise PermitError("permit payload is not an object")
        missing = [f for f in PERMIT_FIELDS if f not in body]
        extra = sorted(set(body) - set(PERMIT_FIELDS))
        if missing:
            raise PermitError(f"permit is missing field(s): {missing}")
        if extra:
            raise PermitError(f"permit carries unknown field(s) {extra}; an ignored "
                              "restriction is a grant, so it is refused")
        if body["v"] != 1:
            raise PermitError(f"permit version {body['v']!r} is not supported")
        # The verifier decides the algorithm; the token only claims one.
        if body["alg"] != ALG:
            raise PermitError(f"permit claims alg={body['alg']!r}; only {ALG} is accepted")
        keys = self._keys.get(body["iss"])
        if not keys:
            raise PermitError(f"issuer {body['iss']!r} is not trusted at this door")
        key = keys.get(body["kid"])
        if key is None:
            raise PermitError(f"issuer {body['iss']!r} has no trusted key {body['kid']!r}")
        if not key.check(f"{parts[0]}.{parts[1]}".encode("ascii"), sig):
            raise PermitError("signature does not verify")

        if body["aud"] != self.audience:
            raise PermitError(f"permit is for {body['aud']!r}, not {self.audience!r}")
        t = time.time() if now is None else now
        try:
            iat, exp = float(body["iat"]), float(body["exp"])
        except (TypeError, ValueError) as exc:
            raise PermitError("permit times are not numbers") from exc
        if exp < t:
            raise PermitError("permit has expired")
        if iat > t + CLOCK_SKEW_S:
            raise PermitError("permit is issued in the future")
        if exp - iat > MAX_TTL_S:
            raise PermitError("permit lifetime exceeds the maximum this format allows")
        for name in ("sub", "act_for", "nonce"):
            if not isinstance(body[name], str) or not body[name]:
                raise PermitError(f"permit field {name!r} is empty")
        scope = body["scope"]
        if (not isinstance(scope, list) or not scope
                or not all(isinstance(s, str) and valid_scope(s) for s in scope)):
            raise PermitError("permit scope is empty or invalid")
        try:
            cap = None if body["cap"] is None else Cap.from_json(body["cap"])
        except (ValueError, TypeError, KeyError) as exc:
            raise PermitError(f"permit cap is invalid: {exc}") from exc

        return Permit(
            iss=body["iss"], kid=body["kid"], sub=body["sub"], act_for=body["act_for"],
            aud=body["aud"], scope=tuple(scope), cap=cap, iat=iat, exp=exp,
            nonce=body["nonce"],
        )
