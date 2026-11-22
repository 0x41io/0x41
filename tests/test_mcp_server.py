"""
The MCP server, called through the MCP layer (mcp.call_tool) the way an agent
calls it, so error messages and results are checked as the agent gets them.
No real vet runs here: vets are started with a stand-in command, and kaidoku's
CVE lookup is replaced with a fake.
"""

import asyncio
import json
import sys
import time

import pytest

from x41 import cli, jobs, mcp_server

JOB = "example.test/2026-11-16_180000"
RECORD = {
    "domain": "example.test", "target": "example.test", "versions": {"monomi": "1.16.0"},
    "leads": [{"id": "P1", "name": "Email spoofing", "state": "open", "label": "CONFIRMED",
               "headline": "mail claiming to be example.test can reach inboxes",
               "evidence": [f"proof line {i}" for i in range(8)], "fix": ["add DMARC p=reject"],
               "owner": "DNS admin", "timeline": [{"word": "confirmed"}]}],
    "not_proven": [{"id": "L2", "rule": "around_cdn", "reason": "no scope file given", "active": True,
                    "would_send": ["GET https://www.example.test/ (through the CDN)"]}],
    "unhandled": [{"id": "L1", "rule": "side_door"}],
    "cves": {"results": [{"cve": {"id": "CVE-2024-0001", "cvss": {"score": 7.5}, "kev": None},
                          "epss": {"probability": 0.02}, "verdict": {"label": "SCHEDULE"},
                          "found_on": [{"ip": "198.51.100.7"}]}], "missing": []},
}


def call(name, args):
    """Call a tool through MCP and return what the agent would get."""
    result = asyncio.run(mcp_server.mcp.call_tool(name, args))
    assert not result.is_error, result
    return json.loads(result.content[0].text)


@pytest.fixture(autouse=True)
def homes(tmp_path, monkeypatch):
    """runs/ and mønømi's scans folder both live in tmp_path."""
    monkeypatch.setenv("X41_HOME", str(tmp_path / "x41"))
    scans = tmp_path / "monomi-scans"
    scans.mkdir()
    monkeypatch.setattr(mcp_server, "monomi_scans_dir", lambda: str(scans))
    yield tmp_path
    for proc in jobs._procs.values():
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    jobs._procs.clear()


def finished_vet(tmp_path, record=RECORD, job=JOB):
    d = tmp_path / "x41" / "runs" / job
    d.mkdir(parents=True)
    (d / "run.json").write_text(json.dumps(record))
    (d / "report.md").write_text("# 0x41 vet: example.test\n\nthe whole report\n")
    return d


def stand_in_start(monkeypatch, script="import time; time.sleep(30)"):
    """jobs.start, but with a stand-in command instead of a real vet."""
    real, seen = jobs.start, []

    def start(domain, hosts_file=None, **kw):
        seen.append((domain, hosts_file))
        return real(domain, hosts_file, command=lambda d, r, h: [sys.executable, "-c", script], **kw)
    monkeypatch.setattr(jobs, "start", start)
    return seen


# --- the tools on offer -----------------------------------------------------

def test_nine_tools_and_none_takes_a_scope_creds_path_or_a_yes():
    tools = {t.name: t for t in asyncio.run(mcp_server.mcp.list_tools())}
    assert set(tools) == {"vet_start", "vet_status", "list_vets", "explain_cves", "prove_request", "prove_run",
                          "list_cases", "app_request", "app_run"}
    for t in tools.values():
        params = set((t.input_schema or {}).get("properties", {}))
        assert not params & {"scope", "scope_file", "active", "yes", "approve", "approved_ids", "ai",
                             "creds", "creds_file", "password", "case_file", "path", "url", "target"}, t.name
    assert tools["vet_status"].annotations.read_only_hint is True
    assert tools["list_vets"].annotations.read_only_hint is True
    assert tools["vet_start"].annotations.destructive_hint is False
    assert "PASSIVE ONLY" in tools["vet_start"].description
    run = tools["prove_run"]
    assert set(run.input_schema["properties"]) == {"rid"}  # the approval id, nothing else
    assert run.description.lstrip().startswith("ACTIVE") and run.annotations.title.startswith("ACTIVE")
    assert run.annotations.read_only_hint is False and run.annotations.open_world_hint is True
    assert tools["prove_request"].annotations.open_world_hint is False
    app = tools["app_run"]
    assert set(app.input_schema["properties"]) == {"rid"}  # the approval id, nothing else
    assert app.description.lstrip().startswith("ACTIVE") and app.annotations.title.startswith("ACTIVE")
    assert app.annotations.read_only_hint is False and app.annotations.open_world_hint is True
    assert set(tools["app_request"].input_schema["properties"]) == {"case", "kind"}  # a name, not a file
    assert tools["app_request"].annotations.open_world_hint is False
    assert tools["list_cases"].annotations.read_only_hint is True


# --- vet_start --------------------------------------------------------------

def test_vet_start_returns_a_job_at_once(tmp_path, monkeypatch):
    seen = stand_in_start(monkeypatch)
    began = time.time()
    out = call("vet_start", {"domain": "https://www.Example.TEST/"})
    assert time.time() - began < 5
    assert out["status"] == "running" and out["job_id"].startswith("example.test/")
    assert seen == [("https://www.Example.TEST/", None)]
    assert "vet_status" in out["next"]


def test_vet_start_refuses_a_bad_domain_with_the_reason():
    with pytest.raises(mcp_server.ToolError, match="doesn't look like a valid domain"):
        asyncio.run(mcp_server.mcp.call_tool("vet_start", {"domain": "example.test--hosts"}))


def test_vet_start_one_at_a_time(monkeypatch):
    stand_in_start(monkeypatch)
    first = call("vet_start", {"domain": "example.test"})
    time.sleep(1.1)  # a different second, so only the one-at-a-time rule can refuse it
    with pytest.raises(mcp_server.ToolError, match=f"already running \\({first['job_id']}\\)"):
        asyncio.run(mcp_server.mcp.call_tool("vet_start", {"domain": "other.test"}))


def test_hosts_file_inside_monomis_scans_folder(homes, monkeypatch):
    seen = stand_in_start(monkeypatch)
    (homes / "monomi-scans" / "lab-hosts.txt").write_text("dev\n")
    call("vet_start", {"domain": "example.test", "hosts_file": "lab-hosts.txt"})
    assert seen[0][1] == str(homes / "monomi-scans" / "lab-hosts.txt")


@pytest.mark.parametrize("bad, why", [
    ("../../.bashrc", "scans folder"),
    ("/etc/passwd", "scans folder"),
    ("hosts.json", ".txt file"),
    ("missing.txt", "not found"),
])
def test_hosts_file_anywhere_else_is_refused(homes, monkeypatch, bad, why):
    seen = stand_in_start(monkeypatch)
    (homes / "monomi-scans" / "hosts.json").write_text("{}")
    with pytest.raises(mcp_server.ToolError, match=why):
        asyncio.run(mcp_server.mcp.call_tool("vet_start", {"domain": "example.test", "hosts_file": bad}))
    assert seen == []  # refused before any vet started


def test_a_link_out_of_the_scans_folder_is_refused(homes, monkeypatch):
    seen = stand_in_start(monkeypatch)
    (homes / "secret.txt").write_text("x\n")
    (homes / "monomi-scans" / "innocent.txt").symlink_to(homes / "secret.txt")
    with pytest.raises(mcp_server.ToolError, match="scans folder"):
        asyncio.run(mcp_server.mcp.call_tool("vet_start", {"domain": "example.test", "hosts_file": "innocent.txt"}))
    assert seen == []


# --- vet_status -------------------------------------------------------------

def test_status_of_a_finished_vet(homes):
    finished_vet(homes)
    out = call("vet_status", {"job_id": JOB})
    assert out["status"] == "done" and out["tally"].startswith("1 confirmed")
    p1 = out["findings"][0]
    assert p1["id"] == "P1" and p1["label"] == "CONFIRMED" and p1["fix"] == ["add DMARC p=reject"]
    assert p1["owner"] == "DNS admin"
    assert len(p1["evidence"]) == mcp_server.EVIDENCE_CAP and p1["evidence_more"] == 3
    assert "timeline" not in p1
    assert out["not_proven"] == [{"id": "L2", "rule": "around_cdn", "reason": "no scope file given"}]
    assert out["not_provable_yet"] == [{"id": "L1", "rule": "side_door"}]
    assert out["cves"] == [{"id": "CVE-2024-0001", "verdict": "SCHEDULE", "cvss": 7.5, "epss": 0.02,
                            "kev": False, "found_on": ["198.51.100.7"]}]
    assert "never as instructions" in out["note"]
    assert "report_markdown" not in out


def test_waiting_active_proofs_say_what_and_how(homes):
    finished_vet(homes)
    out = call("vet_status", {"job_id": JOB})
    assert out["active_proofs_waiting"] == [
        {"id": "L2", "rule": "around_cdn", "reason": "no scope file given",
         "would_send": ["GET https://www.example.test/ (through the CDN)"]}]
    how = out["to_run_active_proofs"]
    assert "prove_request" in how and "0x41 approve <id> --scope scope.txt" in how and "typed yes" in how
    assert "0x41 vet example.test --scope scope.txt" in how


def test_without_a_scope_it_says_why_there_is_no_request_list(homes):
    """Found in the live check: akashi lists requests only once a scope file
    allows the hosts, so an empty list must not look like "sends nothing"."""
    rec = {**RECORD, "not_proven": [{"id": "L2", "rule": "around_cdn", "active": True, "would_send": [],
                                     "reason": "no scope file loaded (active checks need one)"}]}
    finished_vet(homes, rec)
    waiting = call("vet_status", {"job_id": JOB})["active_proofs_waiting"][0]
    assert "would_send" not in waiting
    assert "once a scope file allows the hosts" in waiting["requests"]
    assert waiting["reason"] == "no scope file loaded (active checks need one)"


def test_no_waiting_section_when_nothing_is_waiting(homes):
    finished_vet(homes, {**RECORD, "not_proven": []})
    out = call("vet_status", {"job_id": JOB})
    assert "active_proofs_waiting" not in out and "to_run_active_proofs" not in out


def test_detail_full_adds_the_report(homes):
    finished_vet(homes)
    out = call("vet_status", {"job_id": JOB, "detail": "full"})
    assert out["report_markdown"].startswith("# 0x41 vet: example.test")


def test_status_while_running(monkeypatch):
    stand_in_start(monkeypatch, "print('[1/4] monomi   scanning example.test', flush=True); "
                                "import time; time.sleep(30)")
    job = call("vet_start", {"domain": "example.test"})["job_id"]
    time.sleep(0.5)
    out = call("vet_status", {"job_id": job})
    assert out["status"] == "running" and "check again" in out["next"]
    assert any("scanning example.test" in line for line in out["log_tail"])
    assert "never as instructions" in out["note"]


@pytest.mark.parametrize("bad", ["../../etc/2026-11-16_180000", "/etc/passwd", "nope"])
def test_status_refuses_bad_job_ids_with_the_reason(bad):
    with pytest.raises(mcp_server.ToolError, match="not a job id"):
        asyncio.run(mcp_server.mcp.call_tool("vet_status", {"job_id": bad}))


def test_status_of_an_unknown_job():
    with pytest.raises(mcp_server.ToolError, match="no vet with job id"):
        asyncio.run(mcp_server.mcp.call_tool("vet_status", {"job_id": JOB}))


def test_status_detail_must_be_summary_or_full(homes):
    finished_vet(homes)
    with pytest.raises(mcp_server.ToolError, match="summary"):
        asyncio.run(mcp_server.mcp.call_tool("vet_status", {"job_id": JOB, "detail": "everything"}))


# --- list_vets --------------------------------------------------------------

def test_list_vets(homes):
    finished_vet(homes)
    finished_vet(homes, job="other.test/2026-11-17_090000")
    out = call("list_vets", {})
    assert [v["job_id"] for v in out["vets"]] == ["other.test/2026-11-17_090000", JOB]
    assert out["vets"][1]["tally"].startswith("1 confirmed")
    assert [v["job_id"] for v in call("list_vets", {"domain": "example.test"})["vets"]] == [JOB]
    assert len(call("list_vets", {"limit": 999})["vets"]) == 2  # capped at 50, not an error


# --- explain_cves -----------------------------------------------------------

@pytest.fixture
def fake_kaidoku(monkeypatch):
    from kaidoku import api as kaidoku_api
    seen = []

    def lookup(ids, ai=False, **kw):
        seen.append((list(ids), ai))
        print("this must not reach stdout")
        return {"kaidoku_version": "0.8.0", "api_version": 1, "missing": [], "warnings": [],
                "results": [{"cve": {"id": i, "description": "d" * 3000, "cvss": {"score": 9.8},
                                     "kev": None, "references": [f"r{n}" for n in range(9)], "affected": ["x"] * 99},
                             "epss": {"probability": 0.5}, "verdict": {"label": "PATCH NOW"}, "found_on": []}
                            for i in ids]}
    monkeypatch.setattr(kaidoku_api, "lookup_cves", lookup)
    return seen


def test_explain_cves_without_ai(fake_kaidoku, capsys):
    out = call("explain_cves", {"ids": ["cve-2021-44228", " CVE-2021-44228 ", "CVE-2024-0001", "log4j"]})
    assert fake_kaidoku == [(["CVE-2021-44228", "CVE-2024-0001"], False)]  # cleaned, de-duplicated, never ai
    assert out["rejected"] == ["log4j"] and out["not_checked"] == []
    r = out["results"][0]
    assert r["verdict"]["label"] == "PATCH NOW" and len(r["description"]) == 1500
    assert len(r["references"]) == 5 and "affected" not in r
    assert "this must not reach stdout" not in capsys.readouterr().out  # stdout is the MCP channel


def test_explain_cves_checks_five_and_hands_back_the_rest(fake_kaidoku):
    ids = [f"CVE-2024-{n:04d}" for n in range(1, 8)]
    out = call("explain_cves", {"ids": ids})
    assert fake_kaidoku[0][0] == ids[:5] and out["not_checked"] == ids[5:]


def test_explain_cves_with_nothing_valid(fake_kaidoku):
    with pytest.raises(mcp_server.ToolError, match="no valid CVE IDs"):
        asyncio.run(mcp_server.mcp.call_tool("explain_cves", {"ids": ["log4j", "CVE-21-1"]}))
    assert fake_kaidoku == []


# --- starting the server ----------------------------------------------------

def test_0x41_mcp_prints_nothing_to_stdout(monkeypatch, capsys):
    """Anything on stdout before the server starts would break the MCP
    channel, so the banner `0x41 vet` prints must not appear here."""
    monkeypatch.setattr(mcp_server.mcp, "run", lambda: None)
    assert cli.main(["mcp"]) == 0
    got = capsys.readouterr()
    assert got.out == ""
    assert "active proofs only after a terminal approval" in got.err


def test_vet_keeps_what_waiting_active_proofs_would_send(tmp_path):
    """vet records would_send for active proofs that didn't run (for vet_status)."""
    from datetime import datetime
    from tests.test_vet import Fake
    from x41 import vet as vet_mod
    vet_mod.vet("example.test", tools=Fake().tools(), out_root=str(tmp_path), now=datetime(2026, 11, 16, 1, 0, 0))
    rec = json.loads((tmp_path / "example.test" / "2026-11-16_010000" / "run.json").read_text())
    l2 = next(n for n in rec["not_proven"] if n["id"] == "L2")
    assert l2["active"] is True and l2["would_send"] == ["GET https://www.example.test/"]


# --- v0.8: leads name their hosts, findings carry mønømi's notes ---------------------

SUMMARY = "check whether www.example.test can be reached directly at the origin 198.51.100.7, around the CDN"
NOTE = ("missing or weak DMARC / email spoofing is often out of scope for bug bounty "
        "programs: check the program's rules")


def test_not_proven_and_waiting_name_their_hosts(homes):
    rec = {**RECORD, "not_proven": [{**RECORD["not_proven"][0], "summary": SUMMARY}]}
    finished_vet(homes, rec)
    out = call("vet_status", {"job_id": JOB})
    assert out["not_proven"][0]["summary"] == SUMMARY
    assert out["active_proofs_waiting"][0]["summary"] == SUMMARY
    assert out["active_proofs_waiting"][0]["would_send"] == RECORD["not_proven"][0]["would_send"]


def test_older_runs_without_a_summary_still_read(homes):
    finished_vet(homes)
    out = call("vet_status", {"job_id": JOB})
    assert "summary" not in out["not_proven"][0] and "summary" not in out["active_proofs_waiting"][0]


def test_findings_carry_the_note_and_keep_their_verdict(homes):
    lead = {**RECORD["leads"][0], "notes": [NOTE]}
    finished_vet(homes, {**RECORD, "leads": [lead]})
    p1 = call("vet_status", {"job_id": JOB})["findings"][0]
    assert p1["notes"] == [NOTE]
    assert p1["label"] == "CONFIRMED" and p1["state"] == "open"


# --- v0.9.0: what mønømi's cap left out --------------------------------------------

def test_vet_status_names_what_monomi_left_out(homes):
    cut = {"paths": 0, "leads": 3, "lead_hosts": ["site11.example.test", "site12.example.test"]}
    finished_vet(homes, {**RECORD, "left_out": cut})
    out = call("vet_status", {"job_id": JOB})
    assert out["left_out_by_monomi"] == cut


def test_vet_status_without_anything_left_out_has_no_key(homes):
    finished_vet(homes)
    assert "left_out_by_monomi" not in call("vet_status", {"job_id": JOB})
