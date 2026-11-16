"""
`0x41 run DOMAIN`: the whole suite in one command.

    [1/4] mønømi   a passive scan (its own command, live output)
    [2/4] akashi   passive proofs: DNS / registry only, run automatically
    [3/4] akashi   active proofs: only inside scope, only after a typed yes
    [4/4] kaidoku  explains every finding (and the CVEs mønømi saw)

then a report in runs/<domain>/<time>/. Nothing is dropped silently: active
proofs that didn't run, and leads akashi can't prove yet, are listed in the
report under "Not proven", with the reason.

The tools are reached through one Tools object, so the tests can stand fakes
in for each of them and nothing real is ever scanned or sent while testing.
"""

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from x41 import home, report

# Monomi's passive checks: certificate logs, DNS, email records, and Shodan's
# existing port/CVE data (--ports; around-the-CDN proofs need it). None of
# these sends anything to the target.
MONOMI_FLAGS = ["--email", "--takeover", "--ports"]


@dataclass
class Tools:
    """Everything a run calls out to. default_tools() wires in the real ones."""
    scan: Callable            # (domain, scan_path, hosts_file) -> exit code
    plan: Callable            # akashi.api.plan
    prove_passive: Callable   # akashi.api.prove_passive
    prove_active: Callable    # akashi.api.prove_active
    explain_history: Callable  # kaidoku.api.explain_history
    lookup_cves: Callable     # kaidoku.api.lookup_cves
    cves_in_scan: Callable    # kaidoku.monomi_import.load
    versions: dict = field(default_factory=dict)
    ask: Callable = input
    interactive: Callable = lambda: sys.stdin.isatty()


def run_monomi(domain: str, scan_path: str, hosts_file: str | None = None) -> int:
    """Monomi's own command, with this same Python, so its live output is the
    progress display. Passive flags only (see MONOMI_FLAGS)."""
    cmd = [sys.executable, "-m", "monomi", domain, *MONOMI_FLAGS, "--json", scan_path]
    if hosts_file:
        cmd += ["--hosts", hosts_file]
    return subprocess.run(cmd).returncode


def default_tools() -> Tools:
    from akashi import __version__ as akashi_version
    from akashi import api as akashi_api
    from kaidoku import api as kaidoku_api
    from kaidoku import monomi_import
    from monomi.common import VERSION as monomi_version
    return Tools(
        scan=run_monomi,
        plan=akashi_api.plan, prove_passive=akashi_api.prove_passive,
        prove_active=akashi_api.prove_active,
        explain_history=kaidoku_api.explain_history, lookup_cves=kaidoku_api.lookup_cves,
        cves_in_scan=monomi_import.load,
        versions={"monomi": monomi_version, "akashi": akashi_version, "kaidoku": kaidoku_api.VERSION},
    )


def slug(domain: str) -> str:
    """A safe folder name for the domain (it comes from the command line).

    Only letters, digits, dots, dashes and underscores, and never "." or "..":
    leading and trailing dots are stripped, so the folder always lands inside
    runs/ (a domain like ../../etc can't choose where files are written)."""
    d = re.sub(r"^[a-z]+://", "", domain.strip().lower()).split("/")[0]
    d = re.sub(r"[^a-z0-9._-]", "_", d).strip(".")
    return d or "domain"


def step(n: int, tool: str, what: str) -> None:
    print(f"\n[{n}/4] {tool.ljust(8)} {what}")


def show_verdicts(verdicts: list) -> None:
    marks = {"confirmed": "✓ confirmed", "ruled_out": "✗ ruled out", "inconclusive": "? inconclusive"}
    for v in verdicts:
        print(f"         {v['id']:<4} {v['rule']:<16} {marks.get(v['status'], v['status'])}")


def write_verdicts(path: str, target: str, verdicts: list) -> None:
    """This run's verdicts, in akashi's own history format, so kaidoku reads
    them exactly like a proof history (one file for this run only)."""
    with open(path, "w", encoding="utf-8") as f:
        for v in verdicts:
            f.write(json.dumps({"target": target, **v}) + "\n")


def run(domain: str, *, scope: str | None = None, ai: bool = False, active: bool = True,
        cves: bool = True, hosts_file: str | None = None, tools: Tools | None = None,
        out_root: str | None = None, now: datetime | None = None) -> int:
    tools = tools or default_tools()
    now = now or datetime.now()
    run_dir = os.path.join(out_root or home.data_dir("runs"), slug(domain), now.strftime("%Y-%m-%d_%H%M%S"))
    os.makedirs(run_dir, exist_ok=True)
    scan_path = os.path.join(run_dir, "scan.json")
    rec = {"domain": domain, "started": now.isoformat(timespec="seconds"), "run_dir": run_dir,
           "versions": tools.versions, "scope": scope, "ai": ai,
           "verdicts": [], "not_proven": [], "unhandled": [], "leads": [], "cves": None}

    # 1. mønømi: a passive scan
    step(1, "mønømi", f"scanning {domain} (passive)")
    code = tools.scan(domain, scan_path, hosts_file)
    if code != 0 or not os.path.exists(scan_path):
        print(f"\n0x41: monomi didn't finish (exit {code}); nothing else ran.", file=sys.stderr)
        return 2

    # 2. akashi: the plan, then every passive proof (never touches the target)
    plan = tools.plan(scan_path, scope)
    target = plan["target"]
    rec["target"], rec["scope_status"] = target, plan["scope"]
    rec["unhandled"] = plan["unhandled"]
    step(2, "akashi", "passive proofs (DNS / registry only, automatic)")
    passive = tools.prove_passive(scan_path)
    rec["verdicts"] += passive["verdicts"]
    show_verdicts(passive["verdicts"]) if passive["verdicts"] else print("         nothing passive to prove")

    # 3. akashi: active proofs, only inside scope and only after a typed yes
    step(3, "akashi", "active proofs (need your yes)")
    act = [s for s in plan["steps"] if s["active"]]
    ready = [s for s in act if s["ready"]]
    for s in act:
        if not s["ready"]:
            rec["not_proven"].append({"id": s["id"], "rule": s["rule"], "reason": s["blocked"] or "blocked"})
    if not act:
        print("         no active proofs needed")
    elif not ready:
        print(f"         {len(act)} blocked: {plan['scope']['problem'] or 'no scope file (--scope)'}")
    elif not active:
        print(f"         {len(ready)} skipped (--no-active)")
        rec["not_proven"] += [{"id": s["id"], "rule": s["rule"], "reason": "skipped: --no-active"} for s in ready]
    elif not tools.interactive():
        print(f"         {len(ready)} skipped: a typed yes needs a person at a terminal")
        rec["not_proven"] += [{"id": s["id"], "rule": s["rule"],
                               "reason": "skipped: no terminal to ask for a yes"} for s in ready]
    else:
        for s in ready:
            print(f"         {s['id']:<4} {s['rule']}: {s['summary']}")
            for r in s["requests"]:
                print(f"              would send: {r}")
        answer = tools.ask(f"         Run these {len(ready)} active proof(s)? "
                           "Type yes to run, anything else to skip: ").strip().lower()
        if answer == "yes":
            out = tools.prove_active(scan_path, scope, approved_ids=[s["id"] for s in ready])
            rec["verdicts"] += out["verdicts"]
            show_verdicts(out["verdicts"])
            rules = {s["id"]: s["rule"] for s in ready}
            rec["not_proven"] += [{"id": k["id"], "rule": rules.get(k["id"], "?"), "reason": k["reason"]}
                                  for k in out["skipped"]]
        else:
            print("         skipped: nothing active was sent")
            rec["not_proven"] += [{"id": s["id"], "rule": s["rule"], "reason": "skipped: not approved"}
                                  for s in ready]

    # 4. kaidoku: explain every finding, and the CVEs mønømi saw
    step(4, "kaidoku", "explaining" + (" (AI briefings)" if ai else ""))
    if rec["verdicts"]:
        verdicts_path = os.path.join(run_dir, "verdicts.jsonl")
        write_verdicts(verdicts_path, target, rec["verdicts"])
        rec["leads"] = tools.explain_history(verdicts_path, ai=ai)["leads"]
        print(f"         {len(rec['leads'])} finding(s) explained")
    else:
        print("         no findings to explain")
    if cves:
        try:
            _, ids, found_on = tools.cves_in_scan(scan_path)
        except ValueError:
            ids, found_on = [], {}
        if ids:
            print(f"         {len(ids)} CVE(s) seen by monomi: looking them up "
                  "(the NVD allows ~5 a minute without a key)")
            rec["cves"] = tools.lookup_cves(ids, ai=ai, found_on=found_on)

    # the report
    with open(os.path.join(run_dir, "run.json"), "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2)
    path = os.path.join(run_dir, "report.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(report.markdown(rec))
    tally = report.tally(rec)
    print(f"\nReport: {path}")
    print(f"        {tally}")
    return 0
