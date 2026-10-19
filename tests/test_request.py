"""The agent side of a permit request, driven against a fake issuer."""

from __future__ import annotations

import pytest

from awpermit.request import RequestFailed, request_permit

DOOR = {
    "awpermit": 1, "door": "shop.example.com", "header": "Agent-Permit",
    "actions": {"purchase": {}},
    "issuers": [{"issuer": "id.example.com",
                 "keyset": "https://id.example.com/.well-known/awpermit.json",
                 "request": "POST https://id.example.com/permits/requests (no session)"}],
}
ASK = {"request_id": "r1", "poll_token": "pt", "user_code": "ABCD-EFGH",
       "approve_url": "https://id.example.com/approve?r=r1",
       "poll_url": "https://id.example.com/permits/requests/r1", "interval": 1,
       "expires_in": 10}


class FakeIssuer:
    def __init__(self, polls, door=DOOR, ask=ASK):
        self.polls = list(polls)
        self.door, self.ask = door, ask
        self.calls = []

    def __call__(self, method, url, body):
        self.calls.append((method, url, body))
        if url.endswith("/.well-known/agent-permit.json"):
            return self.door
        if method == "POST":
            return self.ask
        return self.polls.pop(0) if self.polls else {"status": "pending"}


def run(http, **kw):
    shown = []
    clock = iter(range(0, 1000))
    out = request_permit("shop.example.com", agent_id="a1", scope=kw.pop("scope", ["purchase"]),
                         total=kw.pop("total", 2000), http=http, show=shown.append,
                         sleep=lambda s: None, clock=lambda: next(clock), **kw)
    return out, shown


def test_approved_after_pending_and_request_body():
    http = FakeIssuer([{"status": "pending"}, {"status": "approved", "permit": "awp1.x.y"}])
    out, shown = run(http)
    assert out == {"status": "approved", "permit": "awp1.x.y"}
    assert "ABCD-EFGH" in shown[0] and "approve?r=r1" in shown[0]
    post = next(c for c in http.calls if c[0] == "POST")
    assert post[1] == "https://id.example.com/permits/requests"  # verb and note stripped
    assert post[2]["aud"] == "shop.example.com" and post[2]["total_cents"] == 2000
    assert http.calls[-1][1].endswith("/permits/requests/r1?poll_token=pt")


def test_denied_is_returned_not_retried():
    out, _ = run(FakeIssuer([{"status": "denied"}]))
    assert out["status"] == "denied"


def test_times_out_as_expired():
    out, _ = run(FakeIssuer([]))  # pending forever; the fake clock runs past expires_in
    assert out["status"] == "expired"


def test_unknown_action_refused_before_asking():
    http = FakeIssuer([])
    with pytest.raises(RequestFailed, match="does not enforce"):
        run(http, scope=["refund"])
    assert not any(c[0] == "POST" for c in http.calls)


def test_door_without_request_issuer_is_could_not_judge():
    door = {**DOOR, "issuers": [{"issuer": "id.example.com", "keyset": "https://x"}]}
    with pytest.raises(RequestFailed, match="no issuer that takes permit requests"):
        run(FakeIssuer([], door=door))


def test_incomplete_issuer_answer_is_could_not_judge():
    with pytest.raises(RequestFailed, match="poll_token"):
        run(FakeIssuer([], ask={k: v for k, v in ASK.items() if k != "poll_token"}))


def test_not_a_door_document():
    with pytest.raises(RequestFailed, match="not an awpermit door"):
        run(FakeIssuer([], door={"hello": 1}))
