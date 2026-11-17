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

    def __init__(self, *, scope_ok=True, answer="yes", interactive=True, scan_code=0, cve_ids=()):
        self.calls, self.prompts = [], []
        self.scope_ok, self.answer, self.is_tty = scope_ok, answer, interactive
        self.scan_code, self.cve_ids = scan_code, list(cve_ids)

    def tools(self):
        return vet_mod.Tools(
            scan=self.scan, plan=self.plan, prove_passive=self.prove_passive,
            prove_active=self.prove_active, explain_history=self.explain_history,
            lookup_cves=self.lookup_cves, cves_in_scan=self.cves_in_scan,
            versions={"monomi": "1.16.0", "akashi": "0.2.1", "kaidoku": "0.8.0"},
            ask=self.ask, interactive=lambda: self.is_tty)

    def scan(self, domain, path, hosts):
        self.calls.append(("scan", domain, hosts))
        if self.scan_code == 0:
            open(path, "w").write("{}")
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
                     "summary": "check the origin", "requests": ["GET https://www.example.test/"]}],
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
