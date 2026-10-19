"""awpermit -- let an agent through your door with a scope, a cap, and someone accountable.

    from awpermit import Issuer, Verifier, SigningKey, Cap, MemorySpend

    # the issuer (vouches for the human behind the agent)
    issuer = Issuer(SigningKey.generate(), iss="id.example.com")
    token = issuer.mint(sub="agent:shopper-7", act_for="user:4f2a", aud="shop.example.com",
                        scope=["browse", "cart:*", "purchase"],
                        cap=Cap("USD", per_tx=5000, total=20000))

    # the platform (trusts the issuer's published keyset)
    door = Verifier.from_keysets(audience="shop.example.com", docs=[issuer.keyset()])
    permit = door.verify(token)                       # raises PermitError
    permit.require("purchase", amount=1999, currency="USD", spend=MemorySpend())  # raises Denied
"""

from __future__ import annotations

from .keys import DEFAULT_KEY_PATH, PermitKeyError, SigningKey, VerifyKey
from .permit import (
    CLOCK_SKEW_S,
    MAX_TTL_S,
    PERMIT_FIELDS,
    TOKEN_PREFIX,
    Cap,
    Denied,
    Issuer,
    Permit,
    PermitError,
    Verifier,
    keyset_doc,
    scope_matches,
    valid_scope,
)
from .spend import MemorySpend, Spend

__version__ = "0.2.0"

#: The HTTP request header a permit travels in.
HEADER = "Agent-Permit"

__all__ = [
    "HEADER", "TOKEN_PREFIX", "PERMIT_FIELDS", "MAX_TTL_S", "CLOCK_SKEW_S",
    "DEFAULT_KEY_PATH", "SigningKey", "VerifyKey", "PermitKeyError",
    "Cap", "Permit", "Issuer", "Verifier", "PermitError", "Denied",
    "Spend", "MemorySpend", "keyset_doc", "scope_matches", "valid_scope",
]
