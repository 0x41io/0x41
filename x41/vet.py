"""
`0x41 vet DOMAIN`: the whole suite in one command.

    [1/4] mønømi   a passive scan (its own command, live output)
    [2/4] akashi   passive proofs: DNS / registry (+ one DNS question to a parent zone's nameserver
                   for a broken delegation, akashi v0.7.0), run automatically
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
    """Everything a vet calls out to. default_tools() wires in the real ones."""
    scan: Callable            # (domain, scan_path, hosts_file, scope[, bbot=]) -> exit code
    plan: Callable            # akashi.api.plan
    prove_passive: Callable   # akashi.api.prove_passive
    prove_active: Callable    # akashi.api.prove_active
    explain_history: Callable  # kaidoku.api.explain_history
    lookup_cves: Callable     # kaidoku.api.lookup_cves
    cves_in_scan: Callable    # kaidoku.monomi_import.load
    versions: dict = field(default_factory=dict)
    ask: Callable = input
    interactive: Callable = lambda: sys.stdin.isatty()


def run_monomi(domain: str, scan_path: str, hosts_file: str | None = None, scope: str | None = None,
               bbot: str | None = None) -> int:
    """Monomi's own command, with this same Python, so its live output is the
    progress display. Passive flags only (see MONOMI_FLAGS). With a scope file
    (v0.10.0), mønømi sets aside every host it doesn't allow, with the rule
    named, instead of building leads on them; nothing active runs, since
    MONOMI_FLAGS has no active check."""
    cmd = [sys.executable, "-m", "monomi", domain, *MONOMI_FLAGS, "--json", scan_path]
    if hosts_file:
        cmd += ["--hosts", hosts_file]
    if scope:
        cmd += ["--scope", scope]
    if bbot:  # v0.11.0: a BBOT output.json, one more source of hostnames (mønømi v1.29+)
        cmd += ["--bbot", bbot]
    return subprocess.run(cmd).returncode


def merged_hosts(run_dir: str, hosts_file: str | None, scope_hosts: list) -> str | None:
    """One hosts file for mønømi: the --hosts file's lines plus the scope
    file's exact hosts (v0.10.0), written into the run folder so the run
    keeps what it checked. None when there's nothing to add."""
    if not scope_hosts:
        return hosts_file
    lines = []
    if hosts_file:
        with open(hosts_file, encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    path = os.path.join(run_dir, "hosts.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(dict.fromkeys(lines + scope_hosts)) + "\n")
    return path


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


def clean_target(domain: str) -> str:
    """The domain as mønømi will scan it, using mønømi's own rule
    (monomi.cli.clean_domain): 'https://www.Example.com/x' -> 'example.com'.

    Raises ValueError for anything that isn't a domain (empty, a typo like
    'example.com--hosts', a path), so 0x41 refuses exactly what mønømi would,
    before anything runs. One rule, kept in one place."""
    from monomi.cli import clean_domain
    return clean_domain(domain)


def slug(domain: str) -> str:
    """A safe folder name for the domain (it comes from the command line).

    Only letters, digits, dots, dashes and underscores, and never "." or "..":
    leading and trailing dots are stripped, so the folder always lands inside
    runs/ (a domain like ../../etc can't choose where files are written)."""
    d = re.sub(r"^[a-z]+://", "", domain.strip().lower()).split("/")[0]
    d = re.sub(r"[^a-z0-9._-]", "_", d).strip(".")
    return d or "domain"


def inside(path: str, root: str) -> bool:
    """True if path is a folder strictly inside root, after following links
    and '..' (so 'runs/../../etc' or a link out of runs/ doesn't count)."""
    base = os.path.realpath(root)
    return os.path.realpath(path).startswith(base + os.sep)


def step(n: int, tool: str, what: str) -> None:
    print(f"\n[{n}/4] {tool.ljust(8)} {what}")


# Akashi's reason codes for an inconclusive verdict, in a few words (v0.11.2):
# five broken delegations printed a bare "? inconclusive" each, whether fine
# (Route 53, every domain registered) or not checked at all. A code not listed
# here shows nothing extra; the report has the full headline either way.
REASON_WORDS = {
    "pooled_registered": "Route 53, all registered: impractical to take",
    "ns_registered": "all registered; the DNS service wasn't checked",
    "ns_unregistered": "a nameserver's domain looks unregistered: confirm by hand",
    "registry_unchecked": "the registry couldn't be checked: run it again later",
    "parent_unreachable": "the parent zone couldn't be asked",
    "delegation_elsewhere": "the break may sit elsewhere: check with dig +trace",
    "origin_silent": "the origin didn't answer (dropped, not refused)",
}


def show_verdicts(verdicts: list) -> None:
    marks = {"confirmed": "✓ confirmed", "ruled_out": "✗ ruled out", "inconclusive": "? inconclusive"}
    for v in verdicts:
        line = f"         {v['id']:<4} {v['rule']:<16} {marks.get(v['status'], v['status'])}"
        words = REASON_WORDS.get(v.get("reason") or "") if v["status"] == "inconclusive" else None
        print(f"{line}: {words}" if words else line)


def gate_notes(scan_path: str) -> dict:
    """{id: notes} for every path and lead in mønømi's scan that its gate
    labeled: the program notes (gate.PROGRAM_NOTES, e.g. email spoofing is
    often out of scope) and the scope cautions (beta, staging... hosts).
    A note never changes a verdict; it's carried so the person sees it
    next to the finding. Label, don't hide."""
    with open(scan_path, encoding="utf-8") as f:
        scan = json.load(f)
    built = (scan.get("paths") if isinstance(scan, dict) else None) or {}
    out = {}
    for group in ("paths", "leads"):
        for item in built.get(group) or []:
            notes = (item.get("gate") or {}).get("notes") or []
            if notes and item.get("id"):
                out[item["id"]] = list(notes)
    return out


def left_out(scan_path: str) -> dict | None:
    """What mønømi's cap left out of the scan (it passes on its top 10 attack
    paths and top 10 leads), or None when nothing was: {"paths": n, "leads":
    n, "lead_hosts": [...]}. akashi only plans from what mønømi passes on, so
    these are never proven: the report lists them under "Not proven" so
    nothing is dropped silently. lead_hosts (mønømi v1.23.0) names the hosts
    the cut leads are about; an older scan gives the counts only."""
    with open(scan_path, encoding="utf-8") as f:
        scan = json.load(f)
    built = (scan.get("paths") if isinstance(scan, dict) else None) or {}
    paths, leads = int(built.get("more") or 0), int(built.get("more_leads") or 0)
    if not (paths or leads):
        return None
    return {"paths": paths, "leads": leads,
            "lead_hosts": [str(h) for h in built.get("more_leads_hosts") or []]}


def _scan(scan_path: str) -> dict:
    with open(scan_path, encoding="utf-8") as f:
        scan = json.load(f)
    return scan if isinstance(scan, dict) else {}


def scope_kind(scope: str | None, domain: str) -> str:
    """How the hosts to check were chosen: "whole domain" (no scope file, or one
    that can't be read), "wildcard" (a *. rule covers the domain's subdomains),
    or "exact hosts" (only named hosts, which mønømi checks directly whatever
    its sources found). Read with mønømi's own scope parser."""
    if not scope:
        return "whole domain"
    from monomi import scope as monomi_scope
    s = monomi_scope.load(scope)
    if s.problem():
        return "whole domain"
    domain = domain.lower().rstrip(".")
    if any(r.wildcard and (domain == r.domain or domain.endswith("." + r.domain)) for r in s.inclusions):
        return "wildcard"
    return "exact hosts"


def coverage(scan_path: str, scope: str | None, domain: str, exact_count: int = 0) -> dict:
    """How complete mønømi's scan was, decided by code (issue #4), so a vet
    with no findings can't read as clean when its sources failed:
      partial   the hosts came from discovery (whole domain or a wildcard)
                and a source failed, was behind or was cut short: hosts may be missing
      complete  every source answered in full, or the scope names exact hosts,
                which mønømi checks directly whatever the sources found
    Every failed or cut-short source is listed with mønømi's reason. crt.sh's
    website and database hold the same data: one failing while the other
    worked leaves no gap (mønømi's own baseline_gaps decides)."""
    from monomi.cli import CRTSH_BEHIND, SOURCE_NAMES, baseline_gaps
    scan = _scan(scan_path)
    errors = {str(k): str(v) for k, v in (scan.get("errors") or {}).items()}
    sources = scan.get("sources") or {}
    # "behind": crt.sh answered but hasn't indexed the certificates yet, not broken (mønømi's words)
    failed = [{"source": name, "why": why, **({"behind": True} if why.startswith(CRTSH_BEHIND) else {})}
              for name, why in errors.items()]
    cut_short = [{"source": name, "why": str(sources[key]["partial"])} for name, key in SOURCE_NAMES.items()
                 if (sources.get(key) or {}).get("partial") and not sources[key].get("from_saved")]
    answered = sum(1 for name, key in SOURCE_NAMES.items() if name not in errors and key in sources)
    gaps = baseline_gaps({"errors": errors, "sources": sources}) if errors else []
    kind = scope_kind(scope, domain)
    out = {"word": "complete", "why": None, "scope_kind": kind,
           "sources": {"answered": answered, "total": len(SOURCE_NAMES),
                       "failed": failed, "cut_short": cut_short}}
    missing = gaps + [c["source"] for c in cut_short if c["source"] not in gaps]
    if missing and kind != "exact hosts":
        out["word"] = "partial"
        out["why"] = f"hosts may be missing: {', '.join(missing)} didn't answer in full"
    elif failed or cut_short:
        n = len(failed) + len(cut_short)
        checked = (f"the scope's {exact_count} exact host(s) were checked directly"
                   if kind == "exact hosts" else "nothing was lost")
        out["why"] = f"{checked}; {n} source(s) didn't answer in full"
    return out


def gate_results(scan_path: str) -> tuple[list, int, dict | None]:
    """What mønømi's gate set aside and which hosts were out of scope (issue
    #4), so a vet shows them instead of looking empty: (set aside items,
    how many more past mønømi's cap, {"count", "hosts"} or None)."""
    built = _scan(scan_path).get("paths") or {}
    aside = [{"rule": str(item.get("rule") or "?"), "title": str(item.get("title") or ""),
              "hosts": [str(h) for h in ((item.get("targets") or {}).get("hosts") or [])][:3],
              "why": str(item.get("why") or "")}
             for item in built.get("set_aside") or []]
    oos = [str(h) for h in built.get("out_of_scope_hosts") or []]
    return aside, int(built.get("more_set_aside") or 0), ({"count": len(oos), "hosts": oos} if oos else None)


def write_verdicts(path: str, target: str, verdicts: list) -> None:
    """This vet's verdicts, in akashi's own history format, so kaidoku reads
    them exactly like a proof history (one file for this vet only)."""
    with open(path, "w", encoding="utf-8") as f:
        for v in verdicts:
            f.write(json.dumps({"target": target, **v}) + "\n")


def vet(domain: str, *, scope: str | None = None, ai: bool = False, active: bool = True,
        cves: bool = True, hosts_file: str | None = None, tools: Tools | None = None,
        program: str | None = None, bbot_file: str | None = None,
        out_root: str | None = None, now: datetime | None = None, run_dir: str | None = None) -> int:
    try:
        domain = clean_target(domain)
    except ValueError as e:
        print(f"0x41: {e}; nothing ran.", file=sys.stderr)
        return 2
    if bbot_file and not os.path.isfile(bbot_file):
        print(f"0x41: BBOT file not found: {bbot_file}; nothing ran.", file=sys.stderr)
        return 2
    root = out_root or home.data_dir("runs")
    if run_dir is not None and not inside(run_dir, root):
        print(f"0x41: --run-dir must be a folder inside {root}; nothing ran.", file=sys.stderr)
        return 2
    tools = tools or default_tools()
    now = now or datetime.now()
    run_dir = run_dir or os.path.join(root, slug(domain), now.strftime("%Y-%m-%d_%H%M%S"))
    os.makedirs(run_dir, exist_ok=True)
    scan_path = os.path.join(run_dir, "scan.json")
    rec = {"domain": domain, "started": now.isoformat(timespec="seconds"), "run_dir": run_dir,
           "versions": tools.versions, "scope": scope, "ai": ai,
           "verdicts": [], "not_proven": [], "unhandled": [], "leads": [], "cves": None,
           "left_out": None, "program": program, "scope_hosts": [], "bbot": bbot_file,
           "coverage": None, "set_aside": [], "set_aside_more": 0, "out_of_scope": None}

    # 1. mønømi: a passive scan, scoped when there's a scope file (v0.10.0)
    scoped = f", scoped to {program}" if program else ", scoped" if scope else ""
    with_bbot = ", with BBOT's hostnames" if bbot_file else ""
    step(1, "mønømi", f"scanning {domain} (passive){scoped}{with_bbot}")
    if scope:
        from x41 import programs
        try:
            rec["scope_hosts"] = programs.exact_hosts(scope, domain)
        except OSError as e:
            print(f"0x41: can't read the scope file: {e}; nothing ran.", file=sys.stderr)
            return 2
        if rec["scope_hosts"]:
            print(f"         {len(rec['scope_hosts'])} exact host(s) from the scope added as extra hosts")
    hosts_for_monomi = merged_hosts(run_dir, hosts_file, rec["scope_hosts"])
    code = tools.scan(domain, scan_path, hosts_for_monomi, scope, **({"bbot": bbot_file} if bbot_file else {}))
    if code != 0 or not os.path.exists(scan_path):
        print(f"\n0x41: monomi didn't finish (exit {code}); nothing else ran.", file=sys.stderr)
        return 2
    rec["left_out"] = left_out(scan_path)
    if rec["left_out"]:
        print(f"         {report.left_out_line(rec['left_out'])}")
    # How complete the scan was, and what mønømi set aside (v0.12.0, issue #4)
    rec["coverage"] = coverage(scan_path, scope, domain, len(rec["scope_hosts"]))
    rec["set_aside"], rec["set_aside_more"], rec["out_of_scope"] = gate_results(scan_path)
    for line in report.coverage_lines(rec):
        print(f"         {line}")

    # 2. akashi: the plan, then every passive proof (never touches the target)
    plan = tools.plan(scan_path, scope)
    target = plan["target"]
    rec["target"], rec["scope_status"] = target, plan["scope"]
    rec["unhandled"] = plan["unhandled"]
    step(2, "akashi", "passive proofs (DNS / registry, automatic)")
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

    # Active proofs that didn't run keep what they would have sent, so the
    # MCP server can show it (the report lists them by reason), and akashi's
    # one-line summary, which names the hosts (and origin IP) the lead is about.
    would_send = {s["id"]: s.get("requests") or [] for s in act}
    summaries = {s["id"]: s.get("summary") for s in act}
    for n in rec["not_proven"]:
        if n["id"] in would_send:
            n["active"], n["would_send"] = True, would_send[n["id"]]
        if summaries.get(n["id"]):
            n["summary"] = summaries[n["id"]]

    # 4. kaidoku: explain every finding, and the CVEs mønømi saw
    step(4, "kaidoku", "explaining" + (" (AI briefings)" if ai else ""))
    if rec["verdicts"]:
        verdicts_path = os.path.join(run_dir, "verdicts.jsonl")
        write_verdicts(verdicts_path, target, rec["verdicts"])
        rec["leads"] = tools.explain_history(verdicts_path, ai=ai)["leads"]
        notes = gate_notes(scan_path)
        for lead in rec["leads"]:
            if notes.get(lead.get("id")):
                lead["notes"] = notes[lead["id"]]
        print(f"         {len(rec['leads'])} finding(s) explained")
    else:
        print("         no findings to explain")
    if cves:
        try:
            _, ids, found_on = tools.cves_in_scan(scan_path)
        except ValueError:
            ids, found_on = [], {}
        if ids:
            pace = ("with your NVD key, about 50 every 30 seconds" if os.environ.get("NVD_API_KEY")
                    else "the NVD allows about 5 every 30 seconds without a key; a free key makes it 10x faster")
            print(f"         {len(ids)} CVE(s) seen by monomi: looking them up ({pace})")
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
