"""Ed25519 issuer keys, and the reason a permit is never HMAC.

A permit is checked by a platform that is NOT the issuer -- a shop, a forum, a
marketplace. With a shared secret the platform would hold the key that mints,
so every platform that accepts permits could forge them for every other one.
Ed25519 splits the halves: the issuer signs, anyone holding the public key
verifies, and publishing the public key gives away nothing.

There is no HMAC fallback and no default key. A missing key is an error at the
moment of use.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

#: Where an issuer key lives when not given explicitly. A file, never an env
#: var holding key material: env vars leak into `ps` and child processes.
DEFAULT_KEY_PATH = Path.home() / ".aither" / "awpermit" / "issuer.key"

#: Env var naming an ALTERNATIVE key FILE (a path, never the key itself).
KEY_PATH_ENV = "AWPERMIT_KEY_PATH"

ALG = "ed25519"


class PermitKeyError(RuntimeError):
    """A key could not be loaded, parsed or saved."""


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def unb64(txt: str) -> bytes:
    return base64.urlsafe_b64decode(txt + "=" * (-len(txt) % 4))


class VerifyKey:
    """The public half. Safe to publish; cannot mint."""

    alg = ALG

    def __init__(self, raw: bytes):
        if len(raw) != 32:
            raise PermitKeyError(f"an Ed25519 public key is 32 bytes, got {len(raw)}")
        self._raw = raw
        self._pub = Ed25519PublicKey.from_public_bytes(raw)

    @classmethod
    def from_b64(cls, x: str) -> "VerifyKey":
        try:
            return cls(unb64(x))
        except (ValueError, TypeError) as exc:
            raise PermitKeyError(f"public key is not valid base64url: {exc}") from exc

    @property
    def x(self) -> str:
        return b64(self._raw)

    @property
    def kid(self) -> str:
        """Key id: derived from the key, so it cannot name a different key."""
        return b64(hashlib.sha256(self._raw).digest()[:12])

    def check(self, msg: bytes, sig: bytes) -> bool:
        try:
            self._pub.verify(sig, msg)
            return True
        except InvalidSignature:
            return False


class SigningKey:
    """The private half. Mints permits; never leaves the issuer."""

    alg = ALG

    def __init__(self, priv: Ed25519PrivateKey):
        self._priv = priv

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_bytes(cls, raw: bytes) -> "SigningKey":
        if len(raw) != 32:
            raise PermitKeyError(f"an Ed25519 private key is 32 bytes, got {len(raw)}")
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "SigningKey":
        p = resolve_key_path(path)
        if not p.is_file():
            raise PermitKeyError(f"no issuer key at {p} -- run `awpermit keygen` first")
        try:
            return cls.from_bytes(unb64(p.read_text(encoding="ascii").strip()))
        except (ValueError, UnicodeDecodeError) as exc:
            raise PermitKeyError(f"issuer key at {p} is unreadable: {exc}") from exc

    def save(self, path: Optional[Path] = None, *, overwrite: bool = False) -> Path:
        p = resolve_key_path(path)
        if p.exists() and not overwrite:
            raise PermitKeyError(f"refusing to overwrite the issuer key at {p}")
        p.parent.mkdir(parents=True, exist_ok=True)
        raw = self._priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        # Create with 0600 from the start rather than chmod after: a world-readable
        # window between write and chmod is a window.
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(b64(raw) + "\n")
        return p

    def public(self) -> VerifyKey:
        return VerifyKey(
            self._priv.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )

    def sign(self, msg: bytes) -> bytes:
        return self._priv.sign(msg)


def resolve_key_path(path: Optional[Path] = None) -> Path:
    if path is not None:
        return Path(path)
    env = os.environ.get(KEY_PATH_ENV, "").strip()
    return Path(env) if env else DEFAULT_KEY_PATH
