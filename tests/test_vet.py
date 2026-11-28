"""
`0x41 vet` with fake tools: what runs, what never runs, and what the report
says. The safety rules are tested here directly: without a scope file, with
--no-active, without a terminal, or without a typed yes, nothing active runs.
"""

import json
import os
from datetime import datetime

import pytest

from x41 import report, vet as vet_mod

T = "2026-11-16T01:00:00+00:00"


def lead(id_, rule, state, label, **kw):
    base = {"id": id_, "rule": rule, "name": rule.replace("_", " ").capitalize(), "key": id_,
            "state": state, "label": label, "level": "high", "headline": f"{id_} headline",
            "evidence": [f"{id_} proof"], "fix": ["do the fix"], "owner": "DNS admin", "reason": "",
            "checked_at": T, "timeline": [{"word": "confirmed", "checked_at": T}]}
    return {**base, **kw}


class Fake:
    """Records every call; the real tools never run."""

    def __init__(self, *, scope_ok=True, answer="yes", interactive=True, scan_code=0, cve_ids=(),
                 scan_json=None):
        self.calls, self.prompts = [], []
        self.scan_json = scan_json or {}
        self.scope_ok, self.answer, self.is_tty = scope_ok, answer, interactive
        self.scan_code, self.cve_ids = scan_code, list(cve_ids)

    def tools(self):
        return vet_mod.Tools(
            scan=self.scan, plan=self.plan, prove_passive=self.prove_passive,
            prove_active=self.prove_active, explain_history=self.explain_history,
            lookup_cves=self.lookup_cves, cves_in_scan=self.cves_in_scan,
            versions={"monomi": "1.16.0", "akashi": "0.2.1", "kaidoku": "0.8.0"},
            ask=self.ask, interactive=lambda: self.is_tty)

    def scan(self, domain, path, hosts, scope=None, bbot=None):
        self.calls.append(("scan", domain, hosts))
        self.scope_given, self.bbot_given = scope, bbot
        if self.scan_code == 0:
            open(path, "w").write(json.dumps(self.scan_json))
        return self.scan_code

    def plan(self, scan, scope):
        self.calls.append(("plan", scope))
        ready = bool(scope) and self.scope_ok
        return {"target": "example.test", "scope": {"loaded": ready, "problem": None if ready else None},
                "steps": [
                    {"id": "P1", "rule": "email_spoofing", "active": False, "ready": True, "blocked": "",
                     "summary": "re-check email", "requests": []},
                    {"id": "L2", "rule": "around_cdn", "active": True, "ready": ready,
                     "blocked": "" if ready else "no scope file given",
                     "summary": "check whether www.example.test can be reached directly at the origin "
                                "198.51.100.7, around the CDN",
                     "requests": ["GET https://www.example.test/"]}],
                "unhandled": [{"id": "L3", "rule": "side_door", "where": "lead"}]}

    def prove_passive(self, scan):
        self.calls.append(("prove_passive",))
        return {"verdicts": [{"id": "P1", "rule": "email_spoofing", "status": "confirmed"}]}

    def prove_active(self, scan, scope, approved_ids):
        self.calls.append(("prove_active", scope, list(approved_ids)))
        return {"verdicts": [{"id": "L2", "rule": "around_cdn", "status": "confirmed"}], "skipped": []}

    def explain_history(self, path, ai=False):
        rows = [json.loads(line) for line in open(path)]
        self.calls.append(("explain_history", [r["id"] for r in rows], ai))
        return {"leads": [lead(r["id"], r["rule"], "open", "CONFIRMED") for r in rows]}

    def lookup_cves(self, ids, ai=False, found_on=None):
        self.calls.append(("lookup_cves", list(ids), ai, found_on))
        return {"results": [], "missing": [], "warnings": []}

    def cves_in_scan(self, path):
        if not self.cve_ids:
            raise ValueError("no port/CVE data")
        return "example.test", self.cve_ids, {c: [{"ip": "198.51.100.7", "hosts": []}] for c in self.cve_ids}

    def ask(self, prompt):
        self.prompts.append(prompt)
        return self.answer

    def names(self):
        return [c[0] for c in self.calls]


def go(tmp_path, fake, **kw):
    code = vet_mod.vet("example.test", tools=fake.tools(), out_root=str(tmp_path),
                       now=datetime(2026, 11, 16, 1, 0, 0), **kw)
    run_dir = tmp_path / "example.test" / "2026-11-16_010000"
    return code, run_dir


def test_full_vet_with_scope_and_a_yes(tmp_path, capsys):
    fake = Fake()
    code, run_dir = go(tmp_path, fake, scope="scope.txt", ai=True)
    assert code == 0
    assert fake.names() == ["scan", "plan", "prove_passive", "prove_active", "explain_history"]
    assert ("prove_active", "scope.txt", ["L2"]) in fake.calls
    assert ("explain_history", ["P1", "L2"], True) in fake.calls      # both verdicts, AI on
    assert len(fake.prompts) == 1                                     # one yes for the shown plan
    out = capsys.readouterr().out
    assert "would send: GET https://www.example.test/" in out           # every request shown first
    text = (run_dir / "report.md").read_text()
    assert "2 confirmed" in text and "L3" in text and "doesn't prove this kind of lead yet" in text
    saved = json.loads((run_dir / "run.json").read_text())
    assert [v["id"] for v in saved["verdicts"]] == ["P1", "L2"]


def test_without_a_scope_nothing_active_runs_and_it_says_why(tmp_path):
    fake = Fake()
    go(tmp_path, fake)
    assert "prove_active" not in fake.names() and fake.prompts == []
    text = (tmp_path / "example.test" / "2026-11-16_010000" / "report.md").read_text()
    assert "**L2** around_cdn: no scope file given" in text


def test_no_active_flag_never_asks_or_sends(tmp_path):
    fake = Fake()
    go(tmp_path, fake, scope="scope.txt", active=False)
    assert "prove_active" not in fake.names() and fake.prompts == []


def test_without_a_terminal_nothing_active_runs(tmp_path):
    fake = Fake(interactive=False)
    _, run_dir = go(tmp_path, fake, scope="scope.txt")
    assert "prove_active" not in fake.names() and fake.prompts == []
    assert "no terminal to ask for a yes" in (run_dir / "report.md").read_text()


@pytest.mark.parametrize("answer", ["", "no", "y", "yes please", "YES!"])
def test_anything_but_yes_sends_nothing(tmp_path, answer):
    fake = Fake(answer=answer)
    _, run_dir = go(tmp_path, fake, scope="scope.txt")
    assert "prove_active" not in fake.names()
    assert "skipped: not approved" in (run_dir / "report.md").read_text()


def test_yes_is_case_and_space_tolerant(tmp_path):
    fake = Fake(answer="  YES \n")
    go(tmp_path, fake, scope="scope.txt")
    assert "prove_active" in fake.names()


def test_a_failed_scan_stops_everything(tmp_path):
    fake = Fake(scan_code=1)
    code, _ = go(tmp_path, fake, scope="scope.txt")
    assert code == 2 and fake.names() == ["scan"]


def test_cves_monomi_saw_are_looked_up_with_where_they_were(tmp_path):
    fake = Fake(cve_ids=["CVE-2026-0001"])
    go(tmp_path, fake, ai=True)
    call = next(c for c in fake.calls if c[0] == "lookup_cves")
    assert call[1] == ["CVE-2026-0001"] and call[2] is True
    assert call[3]["CVE-2026-0001"][0]["ip"] == "198.51.100.7"


def test_no_cves_flag_skips_the_lookup(tmp_path):
    fake = Fake(cve_ids=["CVE-2026-0001"])
    go(tmp_path, fake, cves=False)
    assert "lookup_cves" not in fake.names()


def test_hosts_file_is_passed_to_monomi(tmp_path):
    fake = Fake()
    go(tmp_path, fake, hosts_file="lab-hosts.txt")
    assert fake.calls[0] == ("scan", "example.test", "lab-hosts.txt")


def test_a_bbot_file_is_passed_to_monomi_and_kept_in_the_record(tmp_path):
    bbot = tmp_path / "output.json"
    bbot.write_text('{"type": "SCAN"}\n')
    fake = Fake()
    go(tmp_path, fake, bbot_file=str(bbot))
    assert fake.bbot_given == str(bbot)
    run = json.loads(next(tmp_path.rglob("run.json")).read_text())
    assert run["bbot"] == str(bbot)


def test_a_missing_bbot_file_stops_before_monomi(tmp_path, capsys):
    fake = Fake()
    code, run_dir = go(tmp_path, fake, bbot_file=str(tmp_path / "nope.json"))
    assert code == 2 and not run_dir.exists()      # refused before any folder was made
    assert not any(c[0] == "scan" for c in fake.calls)
    assert "BBOT file not found" in capsys.readouterr().err


def test_run_monomi_adds_bbot_only_when_given(monkeypatch):
    seen = []

    class Done:
        returncode = 0
    monkeypatch.setattr(vet_mod.subprocess, "run", lambda cmd: seen.append(cmd) or Done())
    vet_mod.run_monomi("example.test", "/tmp/s.json", bbot="/b/output.json")
    vet_mod.run_monomi("example.test", "/tmp/s.json")
    assert seen[0][seen[0].index("--bbot") + 1] == "/b/output.json"
    assert "--bbot" not in seen[1]


@pytest.mark.parametrize("key, says", [("abc", "with your NVD key"), (None, "without a key")])
def test_the_cve_pace_line_says_whether_there_is_an_nvd_key(tmp_path, capsys, monkeypatch, key, says):
    if key:
        monkeypatch.setenv("NVD_API_KEY", key)
    else:
        monkeypatch.delenv("NVD_API_KEY", raising=False)
    go(tmp_path, Fake(cve_ids=["CVE-2024-0001"]))
    out = capsys.readouterr().out
    assert says in out and (key is None or "without a key" not in out)


def test_monomi_runs_with_passive_flags_only(monkeypatch):
    seen = {}

    class Done:
        returncode = 0

    def fake_run(cmd):
        seen["cmd"] = cmd
        return Done()
    monkeypatch.setattr(vet_mod.subprocess, "run", fake_run)
    vet_mod.run_monomi("example.test", "/tmp/s.json", "hosts.txt")
    cmd = seen["cmd"]
    assert cmd[1:4] == ["-m", "monomi", "example.test"]
    assert set(cmd) >= {"--email", "--takeover", "--ports", "--json", "--hosts"}
    assert not {"--fingerprint", "--exposed-files", "--ai"} & set(cmd)   # nothing active, no AI cost


@pytest.mark.parametrize("raw, want", [
    ("Example.TEST", "example.test"), ("https://example.test/path", "example.test"),
    ("../../etc", "domain"), ("..", "domain"), (".hidden.", "hidden"), ("a b;c", "a_b_c"),
    ("", "domain")])
def test_slug_is_a_safe_folder_name(raw, want):
    assert vet_mod.slug(raw) == want
    assert "/" not in vet_mod.slug(raw) and vet_mod.slug(raw) not in (".", "..")


def test_report_neutralizes_text_from_the_target():
    hostile = lead("P1", "email_spoofing", "open", "CONFIRMED",
                   headline="x <script>alert(1)</script> | `rm -rf`",
                   evidence=["evil\x1b[2J `code` | pipe"])
    text = report.markdown({"target": "example.test", "leads": [hostile], "versions": {}})
    assert "<script>" not in text and "\x1b" not in text
    assert "&lt;script>" in text and "\\|" in text and "`rm -rf`" not in text


@pytest.mark.parametrize("bad", ["", "   ", "example.test--hosts", "../../etc", "bad_domain"])
def test_a_bad_domain_is_refused_before_anything_runs(tmp_path, capsys, bad):
    fake = Fake()
    code = vet_mod.vet(bad, tools=fake.tools(), out_root=str(tmp_path))
    assert code == 2
    assert fake.calls == []                 # monomi never started, nothing proven
    assert list(tmp_path.iterdir()) == []   # and no empty run folder was made
    assert "nothing ran" in capsys.readouterr().err


def test_the_domain_is_cleaned_the_way_monomi_cleans_it(tmp_path):
    fake = Fake()
    vet_mod.vet("https://www.Example.TEST/login", tools=fake.tools(), out_root=str(tmp_path),
                now=datetime(2026, 11, 16, 1, 0, 0))
    assert fake.calls[0] == ("scan", "example.test", None)  # monomi gets the clean name
    assert (tmp_path / "example.test" / "2026-11-16_010000" / "report.md").exists()  # folder matches it


# --- v0.8: leads name their hosts, findings carry mønømi's notes ---------------------

EMAIL_NOTE = ("missing or weak DMARC / email spoofing is often out of scope for bug bounty "
              "programs: check the program's rules")
SCAN_WITH_NOTES = {"paths": {
    "paths": [{"id": "P1", "rule": "email_spoofing", "gate": {"result": "finding", "notes": [EMAIL_NOTE]}}],
    "leads": [{"id": "L2", "rule": "around_cdn", "gate": {"result": "lead", "notes": []}}]}}


def test_not_proven_keeps_akashis_summary_naming_the_hosts(tmp_path):
    fake = Fake()
    code, run_dir = go(tmp_path, fake)        # no scope: L2 can't run
    saved = json.loads((run_dir / "run.json").read_text())
    l2 = next(n for n in saved["not_proven"] if n["id"] == "L2")
    assert "www.example.test" in l2["summary"] and "198.51.100.7" in l2["summary"]
    text = (run_dir / "report.md").read_text()
    assert ("**L2** around_cdn: no scope file given. Would check whether www.example.test can be "
            "reached directly at the origin 198.51.100.7, around the CDN") in text


def test_every_way_an_active_proof_is_skipped_keeps_the_summary(tmp_path):
    for kw in ({"answer": "no"}, {"interactive": False}):
        fake = Fake(**kw)
        _, run_dir = go(tmp_path, fake, scope="scope.txt")
        l2 = next(n for n in json.loads((run_dir / "run.json").read_text())["not_proven"] if n["id"] == "L2")
        assert "www.example.test" in l2["summary"]
    _, run_dir = go(tmp_path, Fake(), scope="scope.txt", active=False)
    l2 = next(n for n in json.loads((run_dir / "run.json").read_text())["not_proven"] if n["id"] == "L2")
    assert l2["reason"] == "skipped: --no-active" and "www.example.test" in l2["summary"]


def test_findings_carry_monomis_gate_notes(tmp_path):
    fake = Fake(scan_json=SCAN_WITH_NOTES)
    _, run_dir = go(tmp_path, fake, scope="scope.txt")
    leads = {d["id"]: d for d in json.loads((run_dir / "run.json").read_text())["leads"]}
    assert leads["P1"]["notes"] == [EMAIL_NOTE]
    assert leads["P1"]["state"] == "open"          # labeled, never hidden or changed
    assert "notes" not in leads["L2"]              # no note, no key
    text = (run_dir / "report.md").read_text()
    assert f"**Note (mønømi):** {EMAIL_NOTE}" in text
    assert text.count("**Note (mønømi):**") == 1


def test_gate_notes_reads_paths_and_leads(tmp_path):
    scan = {"paths": {"paths": [{"id": "P1", "gate": {"notes": ["a"]}}],
                      "leads": [{"id": "L4", "gate": {"notes": ["b", "c"]}}, {"id": "L5", "gate": {}}]}}
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(scan))
    assert vet_mod.gate_notes(str(path)) == {"P1": ["a"], "L4": ["b", "c"]}
    path.write_text("{}")
    assert vet_mod.gate_notes(str(path)) == {}


# --- v0.9.0: what mønømi's cap left out is listed, never dropped ----------------------

SCAN_WITH_CUT = {"paths": {"paths": [], "leads": [], "more": 0, "more_leads": 3,
                           "more_leads_hosts": ["site11.example.test", "site12.example.test"]}}


def test_left_out_reads_mønømis_counts_and_hosts(tmp_path):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(SCAN_WITH_CUT))
    assert vet_mod.left_out(str(path)) == {"paths": 0, "leads": 3,
                                           "lead_hosts": ["site11.example.test", "site12.example.test"]}
    # A scan from before mønømi v1.23.0: the count, no hosts
    path.write_text(json.dumps({"paths": {"more": 2, "more_leads": 1}}))
    assert vet_mod.left_out(str(path)) == {"paths": 2, "leads": 1, "lead_hosts": []}
    # Nothing cut, or no attack-path data at all
    path.write_text(json.dumps({"paths": {"more": 0, "more_leads": 0}}))
    assert vet_mod.left_out(str(path)) is None
    path.write_text("{}")
    assert vet_mod.left_out(str(path)) is None


def test_the_report_lists_what_was_left_out_under_not_proven(tmp_path, capsys):
    _, run_dir = go(tmp_path, Fake(scan_json=SCAN_WITH_CUT), scope="scope.txt")
    rec = json.loads((run_dir / "run.json").read_text())
    assert rec["left_out"]["leads"] == 3
    text = (run_dir / "report.md").read_text()
    not_proven = text.split("## Not proven", 1)[1]
    assert ("**Left out by mønømi:** 3 lead(s) past mønømi's top 10, never proven "
            "(leads about site11.example.test, site12.example.test)") in not_proven
    # Counted in the tally, so the summary line doesn't hide them
    assert "4 not proven" in report.tally(rec)   # L3 (akashi can't prove it yet) + the 3 cut
    assert "past mønømi's top 10" in capsys.readouterr().out   # said during the run too


def test_nothing_left_out_adds_nothing(tmp_path):
    _, run_dir = go(tmp_path, Fake(), scope="scope.txt")
    assert json.loads((run_dir / "run.json").read_text())["left_out"] is None
    assert "Left out by mønømi" not in (run_dir / "report.md").read_text()


def test_left_out_line_caps_long_host_lists():
    cut = {"paths": 1, "leads": 12, "lead_hosts": [f"h{n}.example.test" for n in range(12)]}
    line = report.left_out_line(cut)
    assert line.startswith("1 attack path(s) and 12 lead(s) past mønømi's top 10")
    assert "h9.example.test and 2 more" in line and "h10.example.test" not in line


def test_an_inconclusive_verdict_says_why_in_a_few_words(capsys):
    vet_mod.show_verdicts([
        {"id": "L6", "rule": "dangling_ns", "status": "inconclusive", "reason": "pooled_registered"},
        {"id": "L7", "rule": "dangling_ns", "status": "inconclusive", "reason": "registry_unchecked"},
        {"id": "L8", "rule": "dangling_ns", "status": "inconclusive", "reason": "a_code_from_the_future"},
        {"id": "P1", "rule": "email_spoofing", "status": "confirmed", "reason": "pooled_registered"},
        {"id": "L9", "rule": "takeover", "status": "inconclusive"},
    ])
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].endswith("? inconclusive: Route 53, all registered: impractical to take")
    assert lines[1].endswith("? inconclusive: the registry couldn't be checked: run it again later")
    assert lines[2].endswith("? inconclusive")      # an unknown code adds nothing, never a guess
    assert lines[3].endswith("✓ confirmed")         # only an inconclusive verdict gets a reason
    assert lines[4].endswith("? inconclusive")      # no reason at all: as before


def test_every_akashi_dangling_ns_reason_has_words():
    from akashi import verdict
    codes = [getattr(verdict, n) for n in ("PARENT_UNREACHABLE", "DELEGATION_ELSEWHERE", "NS_UNREGISTERED",
                                           "REGISTRY_UNCHECKED", "POOLED_REGISTERED", "NS_REGISTERED",
                                           "ORIGIN_SILENT")]
    assert set(codes) <= set(vet_mod.REASON_WORDS)


# --- v0.12.0 (issue #4): coverage, set-aside items and out-of-scope hosts ----------------

# Like the field runs: crt.sh down (website and database), OTX timed out and
# fell back to a saved copy, Cert Spotter answered; mønømi's gate set one item
# aside and left 147 hosts out of scope
FAILED_SCAN = {
    "errors": {"crt.sh": "HTTP 502", "crt.sh database": "timed out after 60s",
               "AlienVault OTX": "read timed out; using the saved copy from 2026-11-20T10:00:00"},
    "sources": {"certspotter": {"source": "certspotter", "subdomains": []},
                "otx": {"source": "otx", "subdomains": [], "from_saved": True}},
    "paths": {"set_aside": [{"rule": "email_spoofing", "title": "Send email as example.test",
                             "targets": {"hosts": ["example.test"]},
                             "why": "example.test is not in the scope file: no rule matches"}],
              "more_set_aside": 0,
              "out_of_scope_hosts": [f"old{n}.example.test" for n in range(147)]},
}


def scope_file(tmp_path, text):
    path = tmp_path / "scope.txt"
    path.write_text(text)
    return str(path)


def test_a_wildcard_scope_with_failed_sources_is_partial(tmp_path, capsys):
    _, run_dir = go(tmp_path, Fake(scan_json=FAILED_SCAN), scope=scope_file(tmp_path, "*.example.test\n"))
    rec = json.loads((run_dir / "run.json").read_text())
    cov = rec["coverage"]
    assert cov["word"] == "partial" and cov["scope_kind"] == "wildcard"
    assert cov["why"] == "hosts may be missing: crt.sh, crt.sh database, AlienVault OTX didn't answer in full"
    assert cov["sources"]["answered"] == 1 and cov["sources"]["total"] == 4   # Cert Spotter only
    assert {f["source"]: f["why"] for f in cov["sources"]["failed"]}["crt.sh"] == "HTTP 502"
    # The summary line can't say clean
    assert "coverage partial" in report.tally(rec)
    text = (run_dir / "report.md").read_text()
    section = text.split("## Coverage", 1)[1].split("##", 1)[0]
    assert "**partial**: hosts may be missing" in section
    assert "- Sources: 1 of 4 answered (scope: wildcard)" in section
    assert "  - AlienVault OTX failed: read timed out; using the saved copy" in section
    assert "- Out of scope: 147 host(s)" in section and "and 137 more" in section
    assert "coverage partial: hosts may be missing" in capsys.readouterr().out   # said during the run


def test_without_the_coverage_check_a_failed_vet_read_as_clean(tmp_path, monkeypatch):
    # The removal test: the summary line from the field runs, "0 confirmed · 0 unclear"
    monkeypatch.setattr(vet_mod, "coverage", lambda *a, **kw: None)
    _, run_dir = go(tmp_path, Fake(scan_json=FAILED_SCAN), scope=scope_file(tmp_path, "*.example.test\n"))
    rec = json.loads((run_dir / "run.json").read_text())
    assert "coverage" not in report.tally(rec) and "## Coverage" not in (run_dir / "report.md").read_text()


def test_an_exact_host_scope_stays_complete_and_names_the_failures(tmp_path):
    # The scope's hosts are checked directly whatever the sources found
    scope = scope_file(tmp_path, "www.example.test\napi.example.test\n")
    _, run_dir = go(tmp_path, Fake(scan_json=FAILED_SCAN), scope=scope)
    rec = json.loads((run_dir / "run.json").read_text())
    cov = rec["coverage"]
    assert cov["word"] == "complete" and cov["scope_kind"] == "exact hosts"
    assert cov["why"] == "the scope's 2 exact host(s) were checked directly; 3 source(s) didn't answer in full"
    assert "3 source(s) didn't answer in full" in report.tally(rec)
    assert "coverage partial" not in report.tally(rec)


def test_crtsh_down_while_its_database_answered_leaves_no_gap(tmp_path):
    scan = {"errors": {"crt.sh": "HTTP 502"},
            "sources": {"crt.sh database": {"source": "crt.sh database"}, "certspotter": {}, "otx": {}}}
    _, run_dir = go(tmp_path, Fake(scan_json=scan))
    cov = json.loads((run_dir / "run.json").read_text())["coverage"]
    assert cov["word"] == "complete" and cov["scope_kind"] == "whole domain"
    assert cov["why"] == "nothing was lost; 1 source(s) didn't answer in full"
    assert cov["sources"]["failed"] == [{"source": "crt.sh", "why": "HTTP 502"}]


def test_a_source_cut_short_makes_a_whole_domain_scan_partial(tmp_path):
    scan = {"errors": {}, "sources": {"crt.sh": {}, "crt.sh database": {}, "otx": {},
                                      "certspotter": {"partial": "stopped at the 5-page cap"}}}
    _, run_dir = go(tmp_path, Fake(scan_json=scan))
    cov = json.loads((run_dir / "run.json").read_text())["coverage"]
    assert cov["word"] == "partial"
    assert cov["sources"]["cut_short"] == [{"source": "Cert Spotter", "why": "stopped at the 5-page cap"}]
    assert "Cert Spotter was cut short: stopped at the 5-page cap" in (run_dir / "report.md").read_text()


def test_a_full_clean_scan_stays_quiet(tmp_path, capsys):
    scan = {"errors": {}, "sources": {"crt.sh": {}, "crt.sh database": {}, "certspotter": {}, "otx": {}}}
    _, run_dir = go(tmp_path, Fake(scan_json=scan))
    rec = json.loads((run_dir / "run.json").read_text())
    assert rec["coverage"]["word"] == "complete" and rec["coverage"]["why"] is None
    assert report.coverage_lines(rec) == [] and "coverage" not in report.tally(rec)
    assert "**complete**" in (run_dir / "report.md").read_text()


def test_set_aside_items_reach_the_report_with_the_gates_reason(tmp_path):
    _, run_dir = go(tmp_path, Fake(scan_json=FAILED_SCAN), scope=scope_file(tmp_path, "*.example.test\n"))
    rec = json.loads((run_dir / "run.json").read_text())
    assert rec["set_aside"] == [{"rule": "email_spoofing", "title": "Send email as example.test",
                                 "hosts": ["example.test"],
                                 "why": "example.test is not in the scope file: no rule matches"}]
    section = (run_dir / "report.md").read_text().split("## Set aside by mønømi", 1)[1]
    assert ("- **email_spoofing** Send email as example.test (example.test): "
            "example.test is not in the scope file: no rule matches") in section


def test_a_scan_from_before_any_of_this_adds_nothing(tmp_path):
    _, run_dir = go(tmp_path, Fake())   # scan.json is {}: no errors, sources or paths
    rec = json.loads((run_dir / "run.json").read_text())
    assert rec["set_aside"] == [] and rec["out_of_scope"] is None
    assert "## Set aside by mønømi" not in (run_dir / "report.md").read_text()


def test_crtsh_behind_is_said_as_behind_not_failed(tmp_path):
    # The lab: crt.sh answered 0 while Cert Spotter found certificates (mønømi's CRTSH_BEHIND)
    why = "no certificates for this domain yet: the crt.sh database answered with 0 while Cert Spotter found 4"
    scan = {"errors": {"crt.sh": why, "crt.sh database": why},
            "sources": {"certspotter": {}, "otx": {}}}
    _, run_dir = go(tmp_path, Fake(scan_json=scan))
    cov = json.loads((run_dir / "run.json").read_text())["coverage"]
    assert cov["word"] == "partial" and all(f["behind"] for f in cov["sources"]["failed"])
    text = (run_dir / "report.md").read_text()
    assert "  - crt.sh is behind: no certificates" in text and "crt.sh failed" not in text


def test_the_summary_table_comes_before_the_coverage_section(tmp_path):
    _, run_dir = go(tmp_path, Fake(scan_json=FAILED_SCAN), scope=scope_file(tmp_path, "*.example.test\n"))
    text = (run_dir / "report.md").read_text()
    assert text.index("| ID | Finding |") < text.index("## Coverage") < text.index("## Findings")
