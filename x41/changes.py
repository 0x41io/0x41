"""
`0x41 diff`: what changed between two `0x41 vet` runs of the same domain,
and which changes matter.

Read-only: it compares the files two vets saved (scan.json from mønømi,
run.json from 0x41) and contacts nothing.

Three rules keep it honest:

    1. Stable keys, not positions. Leads are matched by akashi's lead_key()
       (rule + targets), hosts by name, ports by IP + port, CVEs by ID, so a
       lead renumbered from P1 to P2 is not a change.
    2. A source that failed or was cut short can't invent a change. A host
       counts as new only if a source that found it now was complete in the
       older run too; otherwise it goes under "couldn't tell".
    3. Only akashi says "fixed". A lead mønømi stops flagging is "no longer
       flagged" (info); a lead akashi confirmed and now rules out is fixed.

Every change is {"level", "kind", "key", "title", "detail"}, with level
"important" or "info".
"""

import json
import os

from akashi.scan import lead_key
from monomi import common
from monomi import scope as scope_mod

from x41 import home, report
from x41.vet import clean_target, slug

IMPORTANT, INFO = "important", "info"
MIN_MONOMI = (1, 15, 0)   # the first scans with rule + targets on every lead

# Weakest to strongest. A missing record is the weakest of all.
DMARC_RANK = {None: 0, "none": 1, "quarantine": 2, "reject": 3}
SPF_RANK = {None: 0, "+all": 0, "all": 0, "?all": 1, "~all": 2, "-all": 3}


class DiffError(Exception):
    """Two runs can't be compared: a file is missing, or they don't match."""


# --- finding and loading runs -------------------------------------------------

def find_runs(domain: str, root: str | None = None) -> tuple[str, str]:
    """The last two finished runs for a domain (older, newer).

    A run counts as finished when it has run.json: vet() writes that last,
    so a run that stopped halfway is skipped. Run folders are named by time
    (2026-11-20_194200), so sorting by name sorts by time."""
    try:
        domain = clean_target(domain)
    except ValueError as e:
        raise DiffError(str(e))
    folder = os.path.join(root or home.data_dir("runs"), slug(domain))
    try:
        names = sorted(os.listdir(folder))
    except FileNotFoundError:
        raise DiffError(f"no runs for {domain} yet (looked in {folder})")
    done = [os.path.join(folder, n) for n in names if os.path.isfile(os.path.join(folder, n, "run.json"))]
    if len(done) < 2:
        raise DiffError(f"{domain} has {len(done)} finished run(s); diff needs two. Run `0x41 vet {domain}`.")
    return done[-2], done[-1]


def _read_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise DiffError(f"missing {path}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise DiffError(f"{path} isn't valid JSON")
    if not isinstance(data, dict):
        raise DiffError(f"{path} isn't a 0x41 run file")
    return data


def load_run(run_dir: str) -> dict:
    """{"dir", "run", "scan"} for one run folder, or a DiffError saying why not."""
    run = _read_json(os.path.join(run_dir, "run.json"))
    scan = _read_json(os.path.join(run_dir, "scan.json"))
    version = common.scan_version(scan)
    if version is None or version < MIN_MONOMI:
        raise DiffError(f"{run_dir}: the scan is from a mønømi older than "
                        f"{'.'.join(map(str, MIN_MONOMI))}, so its leads have no stable keys")
    return {"dir": run_dir, "run": run, "scan": scan}


# --- sources ------------------------------------------------------------------

def source_health(scan: dict) -> dict[str, str]:
    """Each source in a scan: "complete", "incomplete" or "failed".

    incomplete = cut short (mønømi's "partial"), or an old saved copy used
    because the live source failed ("from_saved"). failed = it errored and
    nothing came back."""
    out = {}
    for name, entry in (scan.get("sources") or {}).items():
        out[name] = "incomplete" if entry.get("partial") or entry.get("from_saved") else "complete"
    for name in scan.get("errors") or {}:
        out.setdefault(name, "failed")
    return out


def _found_by(scan: dict) -> dict[str, set]:
    """host -> the sources that listed it in this scan."""
    out = {}
    for name, entry in (scan.get("sources") or {}).items():
        for host in entry.get("subdomains") or []:
            out.setdefault(host, set()).add(name)
    return out


# --- the comparisons ----------------------------------------------------------
# Each takes the older and newer run (from load_run) plus two lists to fill:
# changes and couldnt_tell. Keeping them separate keeps each rule testable.

def _change(level, kind, key, title, detail=""):
    return {"level": level, "kind": kind, "key": key, "title": title, "detail": detail}


def host_changes(old, new, scope, changes, couldnt_tell):
    o, n = old["scan"], new["scan"]
    before = set(o.get("subdomains") or [])
    old_health = source_health(o)
    found_now = _found_by(n)
    unsure = []
    for host in sorted(set(n.get("subdomains") or []) - before):
        sources = found_now.get(host, set())
        # New only if a source that found it now was complete last time too:
        # then the older run would have listed it, had it existed.
        if not any(old_health.get(s) == "complete" for s in sources):
            unsure.append(host)
            continue
        if scope is not None and not scope.match(host).allowed:
            changes.append(_change(INFO, "new_host_out_of_scope", host,
                                   f"new host outside the scope file: {host}", "don't touch it"))
        else:
            changes.append(_change(IMPORTANT, "new_host", host, f"new host: {host}",
                                   "found by " + ", ".join(sorted(sources))))
    if unsure:
        couldnt_tell.append({"what": f"{len(unsure)} host(s) may be new: " + ", ".join(unsure[:10])
                             + (" ..." if len(unsure) > 10 else ""),
                             "why": "the sources that found them weren't complete in the older run"})
    # Gone = live before, and now DNS says the name doesn't exist. Never
    # "missing from a certificate list": CT logs don't drop old entries.
    old_dns = (o.get("enrichment") or {}).get("hosts") or {}
    new_dns = (n.get("enrichment") or {}).get("hosts") or {}
    for host in sorted(old_dns):
        was, now = old_dns[host].get("dns"), (new_dns.get(host) or {}).get("dns")
        if was == "live" and now == "no_such_host":
            changes.append(_change(INFO, "host_gone", host, f"host gone: {host}",
                                   "live in the older run, no DNS record now"))
        # The other way round is how a new subdomain usually shows up: the
        # name was already known (an old certificate, your hosts file) and
        # now it resolves.
        elif was == "no_such_host" and now == "live":
            if scope is not None and not scope.match(host).allowed:
                changes.append(_change(INFO, "host_live_out_of_scope", host,
                                       f"host now live, outside the scope file: {host}", "don't touch it"))
            else:
                changes.append(_change(IMPORTANT, "host_live", host, f"host now live: {host}",
                                       "no DNS record in the older run, resolves now"))


def _own_ips(scan: dict) -> dict[str, dict] | None:
    """The target's own servers (not CDN edge) with what Shodan saw on them,
    or None when the scan has no exposure data to compare."""
    exp = scan.get("exposure")
    if not isinstance(exp, dict) or "ips" not in exp:
        return None
    out = {ip: v for ip, v in exp["ips"].items() if not v.get("shared_edge")}
    for ip, v in (exp.get("nothing_seen") or {}).items():
        if not v.get("shared_edge"):
            out.setdefault(ip, {"ports": [], "vulns": []})
    return out


def exposure_changes(old, new, changes, couldnt_tell):
    before, after = _own_ips(old["scan"]), _own_ips(new["scan"])
    if before is None or after is None:
        couldnt_tell.append({"what": "ports and CVEs", "why": "one of the runs has no port data (--ports)"})
        return
    for ip in sorted(after):
        was = before.get(ip) or {}
        for port in sorted(set(after[ip].get("ports") or []) - set(was.get("ports") or [])):
            changes.append(_change(IMPORTANT, "new_port", f"{ip}:{port}", f"new open port: {ip}:{port}",
                                   "seen in Shodan's data (crawl timing can make ports come and go)"))
        for cve in sorted(set(after[ip].get("vulns") or []) - set(was.get("vulns") or [])):
            changes.append(_change(IMPORTANT, "new_cve", f"{ip}:{cve}", f"new CVE on {ip}: {cve}",
                                   "on the target's own server, from Shodan's banner data"))


def _leads(scan: dict) -> dict[str, dict] | None:
    built = scan.get("paths")
    if not isinstance(built, dict):
        return None
    out = {}
    for group, kind in (("paths", "attack path"), ("leads", "lead")):
        for item in built.get(group) or []:
            out[lead_key(item)] = {**item, "_kind": kind}
    return out


def lead_changes(old, new, changes, couldnt_tell):
    before, after = _leads(old["scan"]), _leads(new["scan"])
    if before is None or after is None:
        couldnt_tell.append({"what": "leads and attack paths", "why": "one of the runs has no attack-path data"})
        return
    for key in sorted(set(after) - set(before)):
        item = after[key]
        changes.append(_change(IMPORTANT, "new_lead", key, f"new {item['_kind']}: {item.get('title') or key}",
                               f"rule {item.get('rule') or '?'}"))
    for key in sorted(set(before) - set(after)):
        item = before[key]
        changes.append(_change(INFO, "lead_not_flagged", key,
                               f"no longer flagged: {item.get('title') or key}",
                               "mønømi stopped flagging it; only akashi can say it's fixed"))


def verdict_changes(old, new, changes, couldnt_tell):
    """Akashi's verdicts, matched by lead key. Its own words decide: a
    confirmed lead it now rules out is fixed; a ruled-out one it now
    confirms is open again."""
    before = {v["key"]: v for v in old["run"].get("verdicts") or [] if v.get("key")}
    for v in new["run"].get("verdicts") or []:
        key, now = v.get("key"), v.get("status")
        if not key:
            continue
        was = (before.get(key) or {}).get("status")
        what = v.get("headline") or key
        if now == "confirmed" and was == "ruled_out":
            changes.append(_change(IMPORTANT, "reopened", key, f"open again: {what}",
                                   "akashi ruled it out before and confirms it now"))
        elif now == "confirmed" and was != "confirmed":
            changes.append(_change(IMPORTANT, "confirmed", key, f"akashi confirms: {what}",
                                   f"was {was or 'not checked'}"))
        elif was == "confirmed" and now == "ruled_out":
            changes.append(_change(IMPORTANT, "fixed", key, f"fixed: {what}",
                                   "akashi confirmed it before and rules it out now"))
        elif was == "confirmed" and now == "inconclusive":
            changes.append(_change(INFO, "unclear", key, f"can't tell any more: {what}",
                                   "akashi confirmed it before; this run was inconclusive"))


def _spf_all(record) -> str | None:
    terms = str(record or "").lower().split()
    rules = [t for t in terms if t in SPF_RANK]
    return rules[-1] if rules else None


def email_changes(old, new, changes, couldnt_tell):
    o, n = old["scan"].get("email"), new["scan"].get("email")
    if not isinstance(o, dict) or not isinstance(n, dict) or "error" in o or "error" in n:
        couldnt_tell.append({"what": "email posture", "why": "the email check didn't run or failed in one of the runs"})
        return
    pairs = (
        ("DMARC policy", DMARC_RANK, (o.get("dmarc") or {}).get("policy"), (n.get("dmarc") or {}).get("policy")),
        ("SPF 'all' rule", SPF_RANK, _spf_all((o.get("spf") or {}).get("record")),
         _spf_all((n.get("spf") or {}).get("record"))),
    )
    for name, rank, was, now in pairs:
        if rank.get(was, 0) == rank.get(now, 0):
            continue
        weaker = rank.get(now, 0) < rank.get(was, 0)
        changes.append(_change(IMPORTANT if weaker else INFO, "email_weaker" if weaker else "email_stronger",
                               name, f"{name} {'weaker' if weaker else 'stronger'}: "
                               f"{was or 'none'} -> {now or 'none'}"))


def wildcard_changes(old, new, changes, couldnt_tell):
    before = (old["scan"].get("enrichment") or {}).get("wildcards") or {}
    after = (new["scan"].get("enrichment") or {}).get("wildcards") or {}
    for zone in sorted(set(before) | set(after)):
        if zone not in before:
            changes.append(_change(INFO, "wildcard_new", zone, f"new wildcard: *.{zone}"))
        elif zone not in after:
            changes.append(_change(INFO, "wildcard_gone", zone, f"wildcard gone: *.{zone}"))
        elif sorted(before[zone].get("ips") or []) != sorted(after[zone].get("ips") or []):
            changes.append(_change(INFO, "wildcard_changed", zone, f"wildcard answers changed: *.{zone}"))


def failed_sources(old, new, couldnt_tell):
    for label, r in (("older", old), ("newer", new)):
        for name, state in sorted(source_health(r["scan"]).items()):
            if state != "complete":
                couldnt_tell.append({"what": f"{name} ({label} run)", "why": state})


# --- putting it together ------------------------------------------------------

def load_scope(path: str | None):
    """(Scope or None, a note or None). A missing or broken scope file isn't
    fatal for a read-only diff: hosts are just compared without it, and the
    note says so."""
    if not path:
        return None, None
    s = scope_mod.load(path)
    problem = s.problem()
    return (None, f"scope not applied: {problem}") if problem else (s, None)


def compare(old: dict, new: dict, scope_path: str | None = None) -> dict:
    """Everything that changed from the older run to the newer one."""
    a, b = old["run"].get("domain"), new["run"].get("domain")
    if a != b:
        raise DiffError(f"these runs are for different domains ({a} and {b})")
    if (old["run"].get("started") or "") > (new["run"].get("started") or ""):
        old, new = new, old   # always older -> newer, whichever order they came in
    scope_path = scope_path or new["run"].get("scope")
    scope, scope_note = load_scope(scope_path)
    changes, couldnt_tell = [], []
    host_changes(old, new, scope, changes, couldnt_tell)
    exposure_changes(old, new, changes, couldnt_tell)
    lead_changes(old, new, changes, couldnt_tell)
    verdict_changes(old, new, changes, couldnt_tell)
    email_changes(old, new, changes, couldnt_tell)
    wildcard_changes(old, new, changes, couldnt_tell)
    failed_sources(old, new, couldnt_tell)
    changes.sort(key=lambda c: (c["level"] != IMPORTANT, c["kind"], c["key"]))
    return {
        "domain": a,
        "older": {"dir": old["dir"], "started": old["run"].get("started")},
        "newer": {"dir": new["dir"], "started": new["run"].get("started")},
        "scope": scope_path if scope else None, "scope_note": scope_note,
        "changes": changes, "couldnt_tell": couldnt_tell,
        "counts": {IMPORTANT: sum(c["level"] == IMPORTANT for c in changes),
                   INFO: sum(c["level"] == INFO for c in changes)},
    }


def markdown(result: dict) -> str:
    """The change report. Hostnames and titles come from the target, so they
    go through report.md() like everything in the vet report."""
    c = result["counts"]
    out = [f"# Changes: {report.md(result['domain'])}", "",
           f"From {result['older']['started']} to {result['newer']['started']}: "
           f"**{c[IMPORTANT]} important**, {c[INFO]} info.", ""]
    if result.get("scope_note"):
        out += [f"_{report.md(result['scope_note'])}_", ""]
    for level, heading in ((IMPORTANT, "Important"), (INFO, "Info")):
        rows = [x for x in result["changes"] if x["level"] == level]
        if rows:
            out += [f"## {heading}", ""]
            out += [f"- {report.md(x['title'])}" + (f": {report.md(x['detail'])}" if x["detail"] else "")
                    for x in rows]
            out.append("")
    if not result["changes"]:
        out += ["No changes.", ""]
    if result["couldnt_tell"]:
        out += ["## Couldn't tell", ""]
        out += [f"- {report.md(x['what'])}: {report.md(x['why'])}" for x in result["couldnt_tell"]]
        out.append("")
    return "\n".join(out)
