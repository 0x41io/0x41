"""
The Markdown report for one `0x41 vet`. Built only from what the tools
returned: akashi decided every verdict, kaidoku explained it; nothing here
judges anything.

Hostnames, headlines and evidence come from the target, so every such string
goes through md() first: control characters are removed and the characters
that could turn data into Markdown or HTML (backticks, pipes, <) are made
harmless.
"""

import re

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
STATE_ORDER = ("open", "unclear", "fixed", "ruled_out")


def md(text) -> str:
    """Target-derived text, made safe to put in Markdown."""
    s = _CONTROL.sub("", str(text if text is not None else ""))
    return s.replace("`", "'").replace("|", "\\|").replace("<", "&lt;")


def _demote(briefing: str) -> str:
    """Kaidoku's briefings use ## headings; inside a finding they sit lower."""
    return re.sub(r"^## ", "#### ", briefing, flags=re.MULTILINE)


def left_out_line(cut: dict, most: int = 10) -> str:
    """One line on what mønømi's cap left out (see vet.left_out)."""
    bits = []
    if cut.get("paths"):
        bits.append(f"{cut['paths']} attack path(s)")
    if cut.get("leads"):
        bits.append(f"{cut['leads']} lead(s)")
    line = f"{' and '.join(bits)} past mønømi's top 10, never proven"
    hosts = cut.get("lead_hosts") or []
    if hosts:
        more = f" and {len(hosts) - most} more" if len(hosts) > most else ""
        line += f" (leads about {', '.join(md(h) for h in hosts[:most])}{more})"
    return line


def _left_out_count(rec: dict) -> int:
    cut = rec.get("left_out") or {}
    return int(cut.get("paths") or 0) + int(cut.get("leads") or 0)


def tally(rec: dict) -> str:
    counts = {s: 0 for s in STATE_ORDER}
    for lead in rec.get("leads") or []:
        counts[lead.get("state", "unclear")] = counts.get(lead.get("state", "unclear"), 0) + 1
    words = {"open": "confirmed", "unclear": "unclear", "fixed": "fixed", "ruled_out": "ruled out"}
    bits = [f"{counts[s]} {words[s]}" for s in STATE_ORDER if counts.get(s) or s in ("open", "unclear")]
    left = len(rec.get("not_proven") or []) + len(rec.get("unhandled") or []) + _left_out_count(rec)
    if left:
        bits.append(f"{left} not proven (see the report)")
    return " · ".join(bits)


def _finding(lead: dict) -> list:
    from kaidoku.akashi_import import next_step, when
    out = [f"### {md(lead['id'])} · {md(lead['name'])}: **{lead['label']}**", "",
           f"> {md(lead['headline'])}", ""]
    for note in lead.get("notes") or []:
        out += [f"**Note (mønømi):** {md(note)}", ""]
    steps = " → ".join(f"{t['word']} ({when(t['checked_at'])})" for t in lead.get("timeline") or [])
    if steps:
        out += [f"**History:** {steps}", ""]
    if lead.get("evidence"):
        out += ["**Proof:**", ""] + [f"- `{md(e)}`" for e in lead["evidence"]] + [""]
    if lead.get("state") == "open" and lead.get("fix"):
        owner = f" ({md(lead['owner'])})" if lead.get("owner") else ""
        out += [f"**Fix{owner}:**", ""] + [f"{n}. {md(s)}" for n, s in enumerate(lead["fix"], 1)] + [""]
    elif lead.get("state") == "fixed":
        out += ["**Fix:** closed: the re-check no longer finds it.", ""]
    nxt = next_step(lead)
    if nxt:
        out += [f"**Next step:** {md(nxt)}", ""]
    if lead.get("briefing"):
        out += ["#### Explained (AI briefing, kaidoku)", "", _demote(lead["briefing"]), ""]
    elif lead.get("briefing_error"):
        out += [f"*AI briefing failed: {md(lead['briefing_error'])}*", ""]
    return out


def _cves(rec: dict) -> list:
    cves = rec.get("cves") or {}
    results = cves.get("results") or []
    if not results and not cves.get("missing"):
        return []
    out = ["## CVEs mønømi saw", "",
           "From Shodan's existing data on the target's own servers (CDN edges left out). "
           "A version banner match, not proof the flaw is reachable.", "",
           "| CVE | Verdict | CVSS | EPSS | CISA KEV | Found on |", "|---|---|---|---|---|---|"]
    for r in results:
        c, e = r["cve"], r.get("epss") or {}
        cvss = c.get("cvss") or {}
        score = f"{cvss['score']} ({cvss.get('version')})" if cvss.get("score") is not None else "-"
        epss = f"{e['probability']:.1%}" if e.get("probability") is not None else "-"
        found = ", ".join(md(loc.get("ip")) for loc in r.get("found_on") or []) or "-"
        out.append(f"| {md(c['id'])} | {md(r['verdict'].get('label'))} | {score} | {epss} | "
                   f"{'**yes**' if c.get('kev') else 'no'} | {found} |")
    if cves.get("missing"):
        out += ["", "Not found in the NVD: " + ", ".join(md(m) for m in cves["missing"])]
    for r in results:
        if r.get("briefing"):
            out += ["", f"### {md(r['cve']['id'])}", "", _demote(r["briefing"])]
    return out + [""]


def markdown(rec: dict) -> str:
    v = rec.get("versions") or {}
    tools = " · ".join(f"{name} {v[name]}" for name in ("monomi", "akashi", "kaidoku") if v.get(name))
    scope = md(rec.get("scope")) if rec.get("scope") else "none (active proofs blocked)"
    leads = sorted(rec.get("leads") or [], key=lambda d: (STATE_ORDER.index(d.get("state", "unclear"))
                                                          if d.get("state") in STATE_ORDER else 9, d["id"]))
    out = [f"# 0x41 vet: {md(rec.get('target') or rec.get('domain'))}", "",
           f"*{md(rec.get('started'))} · {tools} · scope: {scope}*", "",
           "mønømi found it · akashi proved it · kaidoku explained it. Every verdict below was "
           "decided by akashi's code from the evidence shown; the explanations never change one.", "",
           "## Summary", "", f"**{tally(rec)}**", ""]
    if leads:
        out += ["| ID | Finding | State | Fix owner |", "|---|---|---|---|"]
        out += [f"| {md(d['id'])} | {md(d['name'])} | {d['label']} | {md(d.get('owner')) or '-'} |"
                for d in leads]
        out += ["", "## Findings", ""]
        for lead in leads:
            out += _finding(lead)
    else:
        out += ["No findings to prove in this run.", ""]

    not_proven = rec.get("not_proven") or []
    unhandled = rec.get("unhandled") or []
    cut = rec.get("left_out")
    if not_proven or unhandled or cut:
        out += ["## Not proven", "", "Listed so nothing is dropped silently.", ""]
        out += [f"- **{md(n['id'])}** {md(n['rule'])}: {md(n['reason'])}"
                + (f". Would {md(n['summary'])}" if n.get("summary") else "") for n in not_proven]
        out += [f"- **{md(u['id'])}** {md(u['rule'])}: akashi doesn't prove this kind of lead yet"
                for u in unhandled]
        if cut:
            out.append(f"- **Left out by mønømi:** {left_out_line(cut, most=len(cut.get('lead_hosts') or []))}. "
                       "Re-run mønømi on those hosts (`--hosts`) to see them")
        out.append("")

    out += _cves(rec)
    out += ["## Files", "", "- `scan.json`: mønømi's scan",
            "- `verdicts.jsonl`: this run's akashi verdicts (the full proof history stays in akashi)",
            "- `run.json`: everything above, as data", ""]
    return "\n".join(out)
