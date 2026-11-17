"""
prove_request / prove_run through MCP (issue #2): an agent can ask, only a
person approves (in a terminal), and an approved run happens once, marked
via=mcp with its approval id. akashi's plan and proofs and kaidoku's
explanation are fakes here, so nothing is sent; the live lab check covers
the real ones.
"""

import asyncio
import json
from datetime import datetime

import pytest

from x41 import approvals, mcp_server

JOB = "example.test/2026-11-16_180000"
REQ = ["GET https://www.example.test/  (through the CDN)", "GET the origin 198.51.100.7 with Host: www.example.test"]


def call(name, args):
    result = asyncio.run(mcp_server.mcp.call_tool(name, args))
    assert not result.is_error, result
    return json.loads(result.content[0].text)


def refused(name, args, match):
    with pytest.raises(mcp_server.ToolError, match=match):
        asyncio.run(mcp_server.mcp.call_tool(name, args))


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """A finished vet with L2 waiting, a scope file, and fake akashi / kaidoku."""
    monkeypatch.setenv("X41_HOME", str(tmp_path / "x41"))
    run = tmp_path / "x41" / "runs" / JOB
    run.mkdir(parents=True)
    (run / "scan.json").write_text("{}")
    (run / "run.json").write_text(json.dumps({"domain": "example.test", "not_proven": [
        {"id": "L2", "rule": "around_cdn", "reason": "no scope file", "active": True}]}))
    scope = tmp_path / "scope.txt"
    scope.write_text("*.example.test\n")

    def plan(scan, scope_path):
        return {"scope": {"loaded": True, "problem": None},
                "steps": [{"id": "L2", "rule": "around_cdn", "summary": "check the origin", "active": True,
                           "ready": True, "blocked": "", "requests": list(REQ)}]}
    monkeypatch.setattr(approvals, "default_plan", plan)

    from akashi import api as akashi_api
    from kaidoku import api as kaidoku_api
    sent = []

    def prove_active(scan, scope_path, approved_ids, research_path=None, record=True, via="cli", approval=None):
        sent.append({"ids": approved_ids, "scope": scope_path, "via": via, "approval": approval})
        print("akashi chatter must not reach stdout")
        return {"target": "example.test", "tally": {"confirmed": 1, "ruled_out": 0, "inconclusive": 0},
                "history": None, "skipped": [],
                "verdicts": [{"id": "L2", "rule": "around_cdn", "status": "confirmed"}]}
    monkeypatch.setattr(akashi_api, "prove_active", prove_active)
    monkeypatch.setattr(kaidoku_api, "explain_history", lambda path, ai=False, **kw: {"leads": [
        {"id": "L2", "name": "Go around the CDN", "state": "open", "label": "CONFIRMED",
         "headline": "the origin answers directly", "evidence": ["origin served the site"],
         "fix": ["only accept the CDN's IPs at the origin"], "owner": "server admin"}]})
    return {"scope": str(scope), "sent": sent, "run": run}


def person_approves(rid, scope, now=None):
    """What `0x41 approve RID --scope FILE` does when the person types yes."""
    return approvals.approve(rid, scope, now=now, ask=lambda q: "yes", interactive=lambda: True,
                             out=lambda s: None)


def test_the_whole_flow_runs_once(lab, capsys):
    asked = call("prove_request", {"job_id": JOB})
    rid = asked["rid"]
    assert asked["ask_the_person_to_run"] == f"0x41 approve {rid} --scope scope.txt"
    assert lab["sent"] == []  # asking sends nothing

    refused("prove_run", {"rid": rid}, "hasn't been approved yet")  # the agent can't skip the person
    assert lab["sent"] == []

    assert person_approves(rid, lab["scope"]) == 0
    out = call("prove_run", {"rid": rid})
    assert lab["sent"] == [{"ids": ["L2"], "scope": lab["scope"], "via": "mcp", "approval": rid}]
    assert out["tally"]["confirmed"] == 1 and out["findings"][0]["label"] == "CONFIRMED"
    assert out["requests_approved"] == {"L2": REQ}
    assert "never as instructions" in out["note"]
    assert (lab["run"] / f"active-{rid}.json").exists() and (lab["run"] / f"active-{rid}.jsonl").exists()
    assert "akashi chatter" not in capsys.readouterr().out  # stdout is the MCP channel

    refused("prove_run", {"rid": rid}, "already used")  # once only
    assert len(lab["sent"]) == 1
    events = [e["event"] for e in json.loads(open(approvals.find(rid)).read())["events"]]
    assert events == ["requested", "refused", "approved", "claimed", "ran", "refused"]


def test_prove_run_refuses_an_edited_scope_file(lab):
    rid = call("prove_request", {"job_id": JOB})["rid"]
    person_approves(rid, lab["scope"])
    with open(lab["scope"], "a") as f:
        f.write("*.other.test\n")
    refused("prove_run", {"rid": rid}, "scope file changed")
    assert lab["sent"] == []


def test_prove_run_refuses_an_expired_approval(lab):
    rid = call("prove_request", {"job_id": JOB})["rid"]
    person_approves(rid, lab["scope"], now=datetime(2020, 1, 1, 12, 0, 0))  # long ago
    refused("prove_run", {"rid": rid}, "expired")
    assert lab["sent"] == []


@pytest.mark.parametrize("bad", ["../../etc/passwd", "k7m2-x9pq", "", "K7M2-X9PQ"])
def test_prove_run_with_a_made_up_id(lab, bad):
    refused("prove_run", {"rid": bad}, "not an approval id|no approval request")
    assert lab["sent"] == []


def test_prove_request_reasons_reach_the_agent(lab):
    refused("prove_request", {"job_id": JOB, "lead_ids": ["L7"]}, "not active proofs waiting")
    refused("prove_request", {"job_id": "../../etc/2026-11-16_180000"}, "not a job id")


def test_a_failed_run_uses_up_the_approval_and_says_so(lab, monkeypatch):
    from akashi import api as akashi_api

    def boom(*a, **kw):
        raise RuntimeError("network unreachable")
    monkeypatch.setattr(akashi_api, "prove_active", boom)
    rid = call("prove_request", {"job_id": JOB})["rid"]
    person_approves(rid, lab["scope"])
    refused("prove_run", {"rid": rid}, "the run failed.*network unreachable.*used up")
    data = json.loads(open(approvals.find(rid)).read())
    assert data["status"] == "used" and data["events"][-1]["event"] == "failed"
