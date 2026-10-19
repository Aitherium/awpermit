"""Ask a door's issuer for a permit, the way a TV asks to be signed in.

An agent has no session, so it cannot mint. It asks; its human approves on a phone:

    awpermit request shop.example.com --agent shopper-7 --scope purchase --total 2000

1. read https://<door>/.well-known/agent-permit.json -- which issuer, where to ask;
2. POST the request; show the human the short code and the approve link;
3. poll until the human decides; print (or save) the permit.

Stdlib only, so it adds nothing to install. Every network answer is checked: a door
document without an issuer that takes requests, or an answer without the fields this
needs, is "could not judge" (exit 2), never a guess.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Optional

Http = Callable[[str, str, Optional[Dict[str, Any]]], Dict[str, Any]]


class RequestFailed(RuntimeError):
    """Could not get an answer at all (exit 2), as opposed to a human saying no."""


def http_json(method: str, url: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Content-Type": "application/json", "Accept": "application/json",
        "User-Agent": "awpermit/0.1 (+https://github.com/Aitherium/awpermit)"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise RequestFailed(f"{method} {url} -> HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RequestFailed(f"{method} {url} failed: {exc}") from exc


def _strip_verb(value: str) -> str:
    """Door documents write `POST https://...` for humans; keep the URL."""
    parts = (value or "").split()
    return next((p for p in parts if p.startswith("https://")), "")


def door_document(door: str, http: Http = http_json) -> Dict[str, Any]:
    url = door if door.startswith("https://") else f"https://{door}"
    doc = http("GET", url.rstrip("/") + "/.well-known/agent-permit.json", None)
    if doc.get("awpermit") != 1 or not doc.get("door"):
        raise RequestFailed("not an awpermit door document")
    return doc


def request_permit(door: str, *, agent_id: str, scope: list, per_tx: Optional[int] = None,
                   total: Optional[int] = None, ttl: int = 900, http: Http = http_json,
                   show: Callable[[str], None] = print, sleep: Callable[[float], None] = time.sleep,
                   clock: Callable[[], float] = time.time) -> Dict[str, Any]:
    """Run the whole flow. Returns the final poll answer: status approved|denied|expired."""
    doc = door_document(door, http)
    issuer = next((i for i in doc.get("issuers") or [] if _strip_verb(i.get("request", ""))), None)
    if issuer is None:
        raise RequestFailed(f"{doc['door']} names no issuer that takes permit requests")
    unknown = [s for s in scope if s not in (doc.get("actions") or {})]
    if unknown:
        raise RequestFailed(f"{doc['door']} does not enforce {unknown}; "
                            f"it offers {sorted(doc.get('actions') or {})}")
    ask = http("POST", _strip_verb(issuer["request"]), {
        "agent_id": agent_id, "aud": doc["door"], "scope": list(scope),
        "per_tx_cents": per_tx, "total_cents": total, "ttl_seconds": ttl})
    for field in ("request_id", "poll_token", "user_code", "approve_url", "poll_url"):
        if not ask.get(field):
            raise RequestFailed(f"issuer answer is missing {field!r}")
    show(f"Ask your human to open:\n  {ask['approve_url']}\n"
         f"and check the code matches:  {ask['user_code']}")
    deadline = clock() + float(ask.get("expires_in") or 600)
    interval = max(1.0, float(ask.get("interval") or 3))
    poll = f"{ask['poll_url']}?poll_token={urllib.parse.quote(ask['poll_token'])}"
    while clock() < deadline:
        sleep(interval)
        out = http("GET", poll, None)
        if out.get("status") in ("approved", "denied", "expired", "collected"):
            return out
    return {"status": "expired"}


def save_permit(token: str, path: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(token + "\n")
