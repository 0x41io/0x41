"""
App checks from Claude (milestone 2): list_cases / app_request / app_run, with
the person's approval in a terminal in between. The real akashi (app_plan,
prove_app) and kaidoku run here; only the network is faked (access._send
answers from a queue), so these tests prove the whole chain, not stand-ins.
"""

import asyncio
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from x41 import app_approvals, cli, mcp_server

RECORD = '{"id": 2, "owner": "bob", "text": "planted"}'
VULNERABLE = [(200, '{"token": "O"}'), (200, RECORD), (401, ""), (200, '{"token": "A"}'), (200, RECORD)]
FIXED = [(200, '{"token": "O"}'), (200, RECORD), (401, ""), (200, '{"token": "A"}'), (404, "")]
CASE = ('type = "access_between_accounts"\nbase = "https://app.41xlab.test"\nresource = "/api/notes/2"\n'
        'owner = "bob"\nactor = "alice"\nlogin = { path = "/api/login" }\n')


def call(name, args):
    result = asyncio.run(mcp_server.mcp.call_tool(name, args))
    assert not result.is_error, result
    return json.loads(result.content[0].text)


def refused(name, args, match):
    with pytest.raises(mcp_server.ToolError, match=match):
        asyncio.run(mcp_server.mcp.call_tool(name, args))


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """A case in cases/, a scope file, a 600 creds file, and a fake network."""
    monkeypatch.setenv("X41_HOME", str(tmp_path / "x41"))
    monkeypatch.setenv("AKASHI_HOME", str(tmp_path / "akashi"))
    cases = tmp_path / "x41" / "cases"
    cases.mkdir(parents=True)
    (cases / "notes-idor.toml").write_text(CASE)
    scope = tmp_path / "scope.txt"
    scope.write_text("app.41xlab.test\n")
    creds = tmp_path / "creds.json"
    creds.write_text(json.dumps({"bob": {"password": "bob-secret-pw"}, "alice": {"password": "alice-secret-pw"}}))
    os.chmod(creds, 0o600)

    from akashi.proofs import access
    net = {"queue": [], "sent": []}

    def send(method, url, headers, body):
        net["sent"].append((method, url))
        status, text = net["queue"].pop(0)
        return access.Fetched(status, text)
    monkeypatch.setattr(access, "_send", send)
    monkeypatch.setattr(access.time, "sleep", lambda s: None)
    return {"scope": str(scope), "creds": str(creds), "cases": cases, "net": net, "tmp": tmp_path}


def person_approves(rid, lab, now=None, creds=None):
    """What `0x41 approve RID --scope FILE --creds FILE` does when the person types yes."""
    return app_approvals.approve(rid, lab["scope"], creds or lab["creds"], now=now, ask=lambda q: "yes",
                                 interactive=lambda: True, out=lambda s: None)


def test_list_cases_shows_names_and_nothing_secret(lab):
    out = call("list_cases", {})
    assert out["cases"] == [{"case": "notes-idor", "type": "access_between_accounts", "host": "app.41xlab.test",
                             "resource": "/api/notes/2", "owner": "bob", "actor": "alice"}]
    assert "secret" not in json.dumps(out)


def test_the_whole_flow_confirms_once_and_never_shows_a_password(lab):
    asked = call("app_request", {"case": "notes-idor"})
    rid = asked["rid"]
    assert asked["status"] == "pending" and f"0x41 approve {rid}" in asked["ask_the_person_to_run"]
    refused("app_run", {"rid": rid}, "approve it first")        # Claude can't skip the person
    assert lab["net"]["sent"] == []

    assert person_approves(rid, lab) == 0
    lab["net"]["queue"] = list(VULNERABLE)
    out = call("app_run", {"rid": rid})
    assert out["tally"]["confirmed"] == 1 and out["kind"] == "verify"
    assert out["findings"][0]["name"] == "Broken access control between accounts"
    assert len(lab["net"]["sent"]) == 5                        # exactly the 5 approved requests
    text = json.dumps(out)
    assert "secret-pw" not in text and "planted" not in text   # no password, no record data

    refused("app_run", {"rid": rid}, "already used")           # single use
    assert len(lab["net"]["sent"]) == 5


def test_recheck_from_claude_reads_confirmed_then_fixed(lab):
    rid = call("app_request", {"case": "notes-idor"})["rid"]
    person_approves(rid, lab)
    lab["net"]["queue"] = list(VULNERABLE)
    call("app_run", {"rid": rid})

    rid2 = call("app_request", {"case": "notes-idor", "kind": "recheck"})["rid"]
    person_approves(rid2, lab)
    lab["net"]["queue"] = list(FIXED)
    out = call("app_run", {"rid": rid2})
    assert out["transition"] == "fixed"
    assert out["findings"][0]["state"] == "fixed"              # kaidoku saw the whole history


@pytest.mark.parametrize("name", ["../notes-idor", "/etc/passwd", "notes-idor.toml", "Notes", "", "a" * 65])
def test_only_bare_case_names_from_the_cases_folder(lab, name):
    refused("app_request", {"case": name}, "not a case name")


def test_an_unknown_case_or_kind_is_refused(lab):
    refused("app_request", {"case": "nope"}, "no case 'nope'")
    refused("app_request", {"case": "notes-idor", "kind": "sweep"}, "verify or recheck")


def test_a_symlink_out_of_the_cases_folder_is_refused(lab):
    outside = lab["tmp"] / "elsewhere.toml"
    outside.write_text(CASE)
    os.symlink(outside, lab["cases"] / "sneaky.toml")
    refused("app_request", {"case": "sneaky"}, "real file inside")


def test_approving_needs_creds_and_a_tight_creds_file(lab):
    rid = call("app_request", {"case": "notes-idor"})["rid"]
    with pytest.raises(app_approvals.ApprovalError, match="needs --creds"):
        app_approvals.approve(rid, lab["scope"], None, interactive=lambda: True, out=lambda s: None)
    os.chmod(lab["creds"], 0o644)
    with pytest.raises(app_approvals.ApprovalError, match="readable by others"):
        person_approves(rid, lab)


def test_a_host_outside_the_scope_file_is_never_approved(lab):
    with open(lab["scope"], "w") as f:
        f.write("other.test\n")
    rid = call("app_request", {"case": "notes-idor"})["rid"]
    with pytest.raises(app_approvals.ApprovalError, match="isn't in the scope file"):
        person_approves(rid, lab)
    refused("app_run", {"rid": rid}, "approve it first")


@pytest.mark.parametrize("which", ["case", "scope", "creds"])
def test_any_pinned_file_changing_after_approval_refuses_and_sends_nothing(lab, which):
    rid = call("app_request", {"case": "notes-idor"})["rid"]
    person_approves(rid, lab)
    target = {"case": lab["cases"] / "notes-idor.toml", "scope": lab["scope"], "creds": lab["creds"]}[which]
    with open(target, "a") as f:
        f.write("\n" if which != "creds" else " ")
    refused("app_run", {"rid": rid}, "changed since it was approved")
    assert lab["net"]["sent"] == []


def test_an_expired_approval_sends_nothing(lab):
    rid = call("app_request", {"case": "notes-idor"})["rid"]
    long_ago = datetime.now(timezone.utc) - timedelta(minutes=30)
    person_approves(rid, lab, now=long_ago)
    refused("app_run", {"rid": rid}, "expired")
    assert lab["net"]["sent"] == []


def test_the_cli_routes_app_ids_and_keeps_creds_off_vet_approvals(lab, capsys, monkeypatch):
    monkeypatch.setattr("x41.cli.check_versions", lambda: True)
    monkeypatch.setattr("sys.stdin", type("Tty", (), {"isatty": lambda self: True})())  # a person is there
    rid = call("app_request", {"case": "notes-idor"})["rid"]
    assert cli.main(["approve", rid, "--scope", lab["scope"]]) == 2           # app id, no --creds
    assert "needs --creds" in capsys.readouterr().err
    assert cli.main(["approve", "k7m2-x9pq", "--scope", lab["scope"], "--creds", lab["creds"]]) == 2
    assert "only for app checks" in capsys.readouterr().err


def test_a_plan_that_changed_after_approval_refuses_and_sends_nothing(lab, monkeypatch):
    # e.g. a newer akashi sending a different request list for the same case:
    # what runs must be exactly what the person was shown
    rid = call("app_request", {"case": "notes-idor"})["rid"]
    person_approves(rid, lab)
    real = app_approvals.default_plan

    def changed(case_file, scope_file):
        p = real(case_file, scope_file)
        p["requests"].append({"method": "GET", "url": "https://app.41xlab.test/api/notes/3", "purpose": "extra"})
        return p
    monkeypatch.setattr(app_approvals, "default_plan", changed)
    refused("app_run", {"rid": rid}, "plan no longer matches")
    assert lab["net"]["sent"] == []


# --- v0.10.1: a privileged_function case (akashi v0.5.0) flows through 0x41 -------

PRIV_CASE = ('type = "privileged_function"\nbase = "https://app.41xlab.test"\n'
             'resource = "/api/admin/users"\nprivileged = "admin"\nactor = "alice"\n'
             'login = { path = "/api/login", session = "cookie" }\n')


def test_list_cases_shows_a_privileged_function_case(lab):
    (lab["cases"] / "admin-authz.toml").write_text(PRIV_CASE)
    out = {c["case"]: c for c in call("list_cases", {})["cases"]}
    assert out["admin-authz"]["type"] == "privileged_function"
    assert out["admin-authz"]["owner"] == "admin" and out["admin-authz"]["actor"] == "alice"
    assert out["admin-authz"]["resource"] == "/api/admin/users"
