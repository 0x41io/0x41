"""
Approvals (x41/approvals.py), issue #2: an active proof runs only after a
person typed yes in a terminal, for exactly what was shown, once, in time,
with the scope file unchanged. A fake akashi plan stands in for the real
one, so the rules are tested directly and nothing is sent anywhere.
"""

import json
import os
import re
from datetime import datetime, timedelta, timezone

import pytest

from monomi import scope as scope_mod

from x41 import approvals, cli, jobs

JOB = "example.test/2026-11-16_180000"
T0 = datetime(2026, 11, 16, 19, 0, 0, tzinfo=timezone.utc)
REQ = ["GET https://www.example.test/  (through the CDN)",
       "GET the origin 198.51.100.7 with Host: www.example.test  (reached via dev.example.test)"]


@pytest.fixture
def lab(tmp_path):
    """A finished vet with one active proof (L2) waiting, and a scope file."""
    run = tmp_path / "runs" / JOB
    run.mkdir(parents=True)
    (run / "scan.json").write_text("{}")
    (run / "run.json").write_text(json.dumps({
        "domain": "example.test",
        "not_proven": [{"id": "L2", "rule": "around_cdn", "reason": "no scope file", "active": True},
                       {"id": "L9", "rule": "around_cdn", "reason": "no scope file", "active": True}]}))
    scope = tmp_path / "scope.txt"
    scope.write_text("example.test\n*.example.test\n")
    return {"root": str(tmp_path / "runs"), "scope": str(scope), "tmp": tmp_path}


def plan_for(requests=REQ, ready=True, problem=None):
    """A stand-in for akashi.api.plan: L2 ready with `requests`, L9 blocked."""
    def plan(scan, scope):
        return {"scope": {"loaded": problem is None, "problem": problem},
                "steps": [{"id": "L2", "rule": "around_cdn", "summary": "check the origin", "active": True,
                           "ready": ready, "blocked": "" if ready else "fronted host out of scope",
                           "requests": list(requests) if ready else []},
                          {"id": "L9", "rule": "around_cdn", "summary": "another origin", "active": True,
                           "ready": False, "blocked": "no in-scope hostname resolves to the origin",
                           "requests": []}]}
    return plan


def approved(lab, answer="yes", now=T0, **kw):
    """request + approve, as the agent and then the person would."""
    rid = approvals.request(JOB, root=lab["root"], now=now)["rid"]
    lines = []
    code = approvals.approve(rid, lab["scope"], root=lab["root"], now=now, plan=kw.get("plan", plan_for()),
                             ask=lambda q: answer, interactive=lambda: True, out=lines.append)
    return rid, code, lines


def saved(lab, rid):
    return json.loads(open(approvals.find(rid, lab["root"])).read())


# --- request (the agent asks) -------------------------------------------------

def test_request_makes_a_pending_approval_and_sends_nothing(lab):
    out = approvals.request(JOB, root=lab["root"], now=T0)
    assert re.fullmatch(r"[a-z2-9]{4}-[a-z2-9]{4}", out["rid"])
    assert out["status"] == "pending" and out["lead_ids"] == ["L2", "L9"]
    assert out["ask_the_person_to_run"] == f"0x41 approve {out['rid']} --scope scope.txt"
    data = saved(lab, out["rid"])
    assert data["state"] == "pending" and data["expires"] == "2026-11-16T20:00:00+00:00"
    assert [e["event"] for e in data["events"]] == ["requested"]


def test_request_for_chosen_leads_only(lab):
    assert approvals.request(JOB, ["L2"], root=lab["root"])["lead_ids"] == ["L2"]
    with pytest.raises(approvals.ApprovalError, match="not active proofs waiting.*L7"):
        approvals.request(JOB, ["L7"], root=lab["root"])


def test_request_needs_a_finished_vet_with_waiting_proofs(lab):
    (lab["tmp"] / "runs" / "other.test" / "2026-11-16_180000").mkdir(parents=True)
    with pytest.raises(approvals.ApprovalError, match="isn't a finished vet"):
        approvals.request("other.test/2026-11-16_180000", root=lab["root"])
    run = lab["tmp"] / "runs" / JOB / "run.json"
    run.write_text(json.dumps({"not_proven": [{"id": "L1", "rule": "x", "reason": "y"}]}))  # none active
    with pytest.raises(approvals.ApprovalError, match="no active proofs waiting"):
        approvals.request(JOB, root=lab["root"])


def test_request_job_ids_cant_reach_outside_runs(lab):
    with pytest.raises(jobs.JobError):
        approvals.request("../../etc/2026-11-16_180000", root=lab["root"])


@pytest.mark.parametrize("bad", ["../x", "k7m2-x9pq/../../a", "K7M2-X9PQ", "k7m2x9pq", "", None, "k7m2-x9p0"])
def test_ids_that_arent_ids_are_refused(lab, bad):
    with pytest.raises(approvals.ApprovalError, match="not an approval id"):
        approvals.find(bad, lab["root"])


# --- approve (the person, in a terminal) ---------------------------------------

def test_approve_shows_every_request_and_locks_them_in(lab):
    rid, code, lines = approved(lab)
    assert code == 0
    shown = "\n".join(lines)
    for r in REQ:
        assert f"would send: {r}" in shown
    assert "L9" in shown and "BLOCKED" in shown  # the blocked one is shown, not approved
    data = saved(lab, rid)
    assert data["state"] == "approved" and data["approved_ids"] == ["L2"]
    assert data["requests"] == {"L2": REQ}
    assert data["scope"]["sha256"] == scope_mod.load(lab["scope"]).sha256
    assert data["expires"] == "2026-11-16T19:15:00+00:00"
    assert data["events"][-1]["event"] == "approved"


def test_anything_but_yes_approves_nothing(lab):
    rid, code, lines = approved(lab, answer="y")
    assert code == 1 and "Nothing will run" in lines[-1]
    assert saved(lab, rid)["state"] == "pending"


def test_approve_needs_a_real_terminal(lab):
    rid = approvals.request(JOB, root=lab["root"], now=T0)["rid"]
    with pytest.raises(approvals.ApprovalError, match="real terminal"):
        approvals.approve(rid, lab["scope"], root=lab["root"], now=T0, plan=plan_for(),
                          ask=lambda q: "yes", interactive=lambda: False, out=lambda s: None)
    data = saved(lab, rid)
    assert data["state"] == "pending" and data["events"][-1]["event"] == "refused"


def test_a_request_nobody_approved_expires(lab):
    rid = approvals.request(JOB, root=lab["root"], now=T0)["rid"]
    with pytest.raises(approvals.ApprovalError, match="expired at 2026-11-16T20:00:00"):
        approvals.approve(rid, lab["scope"], root=lab["root"], now=T0 + timedelta(hours=1, seconds=1),
                          plan=plan_for(), ask=lambda q: "yes", interactive=lambda: True, out=lambda s: None)


def test_a_bad_scope_file_approves_nothing(lab):
    rid = approvals.request(JOB, root=lab["root"], now=T0)["rid"]
    kw = dict(root=lab["root"], now=T0, ask=lambda q: "yes", interactive=lambda: True, out=lambda s: None)
    with pytest.raises(approvals.ApprovalError, match="scope file not found"):
        approvals.approve(rid, str(lab["tmp"] / "nope.txt"), plan=plan_for(), **kw)
    with pytest.raises(approvals.ApprovalError, match="can't be used: no valid rules"):
        approvals.approve(rid, lab["scope"], plan=plan_for(problem="no valid rules"), **kw)
    assert saved(lab, rid)["state"] == "pending"


def test_nothing_ready_means_nothing_to_approve(lab):
    rid, code, lines = approved(lab, plan=plan_for(ready=False))
    assert code == 1 and "nothing to approve" in lines[-1]
    assert saved(lab, rid)["state"] == "pending"


def test_an_unusable_research_file_approves_nothing(lab, monkeypatch):
    monkeypatch.setattr(approvals, "research_problem", lambda p: "no header line")
    rid = approvals.request(JOB, root=lab["root"], now=T0)["rid"]
    research = lab["tmp"] / "research.txt"
    research.write_text("x")
    with pytest.raises(approvals.ApprovalError, match="research header file isn't usable"):
        approvals.approve(rid, lab["scope"], str(research), root=lab["root"], now=T0, plan=plan_for(),
                          ask=lambda q: "yes", interactive=lambda: True, out=lambda s: None)


def test_an_approval_cant_be_approved_twice(lab):
    rid, _, _ = approved(lab)
    with pytest.raises(approvals.ApprovalError, match="is approved, not waiting for a yes"):
        approvals.approve(rid, lab["scope"], root=lab["root"], now=T0, plan=plan_for(),
                          ask=lambda q: "yes", interactive=lambda: True, out=lambda s: None)


# --- claim (the agent runs it) ---------------------------------------------------

def test_claim_runs_once(lab):
    rid, _, _ = approved(lab)
    got = approvals.claim(rid, root=lab["root"], now=T0 + timedelta(minutes=5), plan=plan_for())
    assert got["approved_ids"] == ["L2"] and got["scope"] == os.path.realpath(lab["scope"])
    assert got["scan"].endswith("scan.json") and got["requests"] == {"L2": REQ}
    assert saved(lab, rid)["state"] == "used"  # marked used before anything ran
    with pytest.raises(approvals.ApprovalError, match="already used"):
        approvals.claim(rid, root=lab["root"], now=T0 + timedelta(minutes=6), plan=plan_for())


def test_claim_before_approval_says_how(lab):
    rid = approvals.request(JOB, root=lab["root"], now=T0)["rid"]
    how = f"pending: the person running 0x41 has to approve it first with `0x41 approve {rid} --scope FILE`"
    with pytest.raises(approvals.ApprovalError, match=how):
        approvals.claim(rid, root=lab["root"], now=T0, plan=plan_for())


def test_claim_after_expiry(lab):
    rid, _, _ = approved(lab)
    with pytest.raises(approvals.ApprovalError, match="expired at 2026-11-16T19:15:00"):
        approvals.claim(rid, root=lab["root"], now=T0 + timedelta(minutes=15, seconds=1), plan=plan_for())
    assert saved(lab, rid)["state"] == "approved"  # refused, never run


def test_claim_refuses_if_the_scope_file_changed(lab):
    rid, _, _ = approved(lab)
    with open(lab["scope"], "a") as f:
        f.write("*.other.test\n")  # widened after approval
    with pytest.raises(approvals.ApprovalError, match="scope file changed"):
        approvals.claim(rid, root=lab["root"], now=T0, plan=plan_for())
    assert saved(lab, rid)["state"] == "approved"  # refused, not used up


def test_claim_refuses_if_the_research_file_changed(lab, monkeypatch):
    monkeypatch.setattr(approvals, "research_problem", lambda p: None)
    research = lab["tmp"] / "research.txt"
    research.write_text("X-Research: roi\n")
    rid = approvals.request(JOB, root=lab["root"], now=T0)["rid"]
    approvals.approve(rid, lab["scope"], str(research), root=lab["root"], now=T0, plan=plan_for(),
                      ask=lambda q: "yes", interactive=lambda: True, out=lambda s: None)
    research.write_text("X-Research: someone-else\n")
    with pytest.raises(approvals.ApprovalError, match="research file changed"):
        approvals.claim(rid, root=lab["root"], now=T0, plan=plan_for())


def test_claim_refuses_if_the_plan_no_longer_matches(lab):
    rid, _, _ = approved(lab)
    other = REQ[:1] + ["GET the origin 203.0.113.9 with Host: www.example.test  (reached via dev.example.test)"]
    with pytest.raises(approvals.ApprovalError, match="no longer matches"):
        approvals.claim(rid, root=lab["root"], now=T0, plan=plan_for(requests=other))
    with pytest.raises(approvals.ApprovalError, match="no longer matches"):
        approvals.claim(rid, root=lab["root"], now=T0, plan=plan_for(ready=False))


def test_every_refusal_is_on_record(lab):
    rid, _, _ = approved(lab)
    approvals.claim(rid, root=lab["root"], now=T0, plan=plan_for())
    with pytest.raises(approvals.ApprovalError):
        approvals.claim(rid, root=lab["root"], now=T0, plan=plan_for())
    approvals.record_result(rid, {"tally": {"confirmed": 1}, "skipped": []}, root=lab["root"], now=T0)
    events = [e["event"] for e in saved(lab, rid)["events"]]
    assert events == ["requested", "approved", "used", "refused", "ran"]


# --- the command ------------------------------------------------------------------

def test_cli_approve_reports_a_refusal(lab, capsys, monkeypatch):
    monkeypatch.setenv("X41_HOME", str(lab["tmp"]))
    assert cli.main(["approve", "k7m2-x9pq", "--scope", lab["scope"]]) == 2
    assert "no approval request with id k7m2-x9pq" in capsys.readouterr().err


def test_cli_approve_needs_a_scope_file():
    with pytest.raises(SystemExit):
        cli.main(["approve", "k7m2-x9pq"])


# --- shared core (v0.6.0): what 0x41 gains from mønømi's approvals core -----------

def test_a_second_server_can_not_run_it_too(lab):
    # Another `0x41 mcp` process already claimed it (its .used file exists):
    # this one must refuse, even though its own copy of the record says approved
    rid, _, _ = approved(lab)
    (lab["tmp"] / "runs" / JOB / "approvals" / f"{rid}.used").write_text("")
    with pytest.raises(approvals.ApprovalError, match="already used"):
        approvals.claim(rid, root=lab["root"], now=T0, plan=plan_for())
    assert saved(lab, rid)["state"] == "approved"   # this server never ran it


def test_research_files_are_checked_by_monomis_parser(lab):
    research = lab["tmp"] / "research.txt"
    research.write_text("Host: evil.test\n")   # would change where requests go
    assert "can't be set by a research file" in approvals.research_problem(str(research))
    research.write_text("X-HackerOne-Research: x41ok\n")
    assert approvals.research_problem(str(research)) is None


def test_the_approval_message_shows_local_time(lab):
    rid, code, lines = approved(lab)
    assert code == 0
    local = (T0 + approvals.APPROVAL_TTL).astimezone().strftime("%H:%M")
    assert lines[-1].endswith(f"until {local}.")
