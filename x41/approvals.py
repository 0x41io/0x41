"""
Approvals: active proofs that start from Claude but run only after a
person's typed yes in a real terminal (issue #2).

    request()  (MCP, prove_request)  a pending approval for a finished vet's
                                      waiting active leads; sends nothing
    approve()  (terminal, `0x41 approve RID --scope FILE`)  shows akashi's
                                      plan with every request, asks for a
                                      typed yes, locks it all in
    claim()    (MCP, prove_run)       every check again, then marks it used
                                      BEFORE anything runs

An approval covers one vet, the leads listed, the exact requests shown and
the scope / research files as they were (sha256). Any difference, an expiry,
a second use or a missing piece means refuse: nothing is sent. No MCP tool
can supply a scope file, a research file or a yes; claim() takes only the
approval id.

Since v0.6.0 the record keeping, the typed yes and the single-use claim are
mønømi's approvals core (monomi.approvalcore), the one every 0x41 approval
gate shares. "Used" is a <rid>.used file only one process can create, so
two `0x41 mcp` servers can never both run the same approval. This module
keeps what is 0x41's own: building a request from a vet's waiting leads,
showing akashi's plan, and checking on claim that the plan still matches.

Each approval is one JSON file, runs/<domain>/<time>/approvals/<rid>.json,
with every event in it (refusals too), so it's its own audit trail. Times
are stored in UTC and shown in your local time.

Honest limit: an agent that has a shell on this machine can fake a terminal.
The gate is against agents with MCP tools only.
"""

import json
import os

from monomi import research as research_mod
from monomi import scope as scope_mod
from monomi.approvalcore import (APPROVAL_TTL, RID, ApprovalError, Store, local_hm,
                                 now_utc, typed_yes)

from x41 import jobs


def _cmd(rid: str) -> str:
    return f"`0x41 approve {rid} --scope FILE`"


def _store(run_dir: str) -> Store:
    return Store(os.path.join(run_dir, "approvals"), "0x41", _cmd)


def find(rid: str, root: str | None = None) -> str:
    """The approval file for an id, or ApprovalError. Only ids shaped like
    'k7m2-x9pq' are looked up, so an id can't name a path."""
    if not isinstance(rid, str) or not RID.fullmatch(rid):
        raise ApprovalError(f"not an approval id: {rid!r} (they look like k7m2-x9pq)")
    for job_id, path in jobs._job_dirs(root):
        candidate = os.path.join(path, "approvals", rid + ".json")
        if os.path.isfile(candidate):
            return candidate
    raise ApprovalError(f"no approval request with id {rid}")


def _locate(rid: str, root: str | None) -> tuple:
    """(run folder, its store) for an approval id."""
    run_dir = os.path.dirname(os.path.dirname(find(rid, root)))
    return run_dir, _store(run_dir)


# --- 1. the request (MCP) -----------------------------------------------------

def request(job_id: str, lead_ids: list | None = None, *, root: str | None = None, now=None) -> dict:
    """A pending approval for a finished vet's waiting active leads. Sends
    nothing and takes no scope: the person gives that when approving."""
    run_dir = jobs.job_dir(job_id, root)
    run_json = os.path.join(run_dir, "run.json")
    if not os.path.isfile(run_json) or not os.path.isfile(os.path.join(run_dir, "scan.json")):
        raise ApprovalError(f"{job_id} isn't a finished vet (check it with vet_status)")
    with open(run_json, encoding="utf-8") as f:
        rec = json.load(f)
    waiting = [n["id"] for n in rec.get("not_proven") or [] if n.get("active")]
    if not waiting:
        raise ApprovalError(f"{job_id} has no active proofs waiting")
    wanted = list(dict.fromkeys(lead_ids or waiting))
    unknown = [i for i in wanted if i not in waiting]
    if unknown:
        raise ApprovalError(f"not active proofs waiting in {job_id}: {unknown} (waiting: {waiting})")

    data = _store(run_dir).create({"job_id": job_id, "domain": rec.get("domain"), "lead_ids": wanted}, now)
    return {"rid": data["rid"], "job_id": job_id, "lead_ids": wanted, "status": "pending",
            "expires": data["expires"],
            "ask_the_person_to_run": f"0x41 approve {data['rid']} --scope scope.txt"}


# --- 2. the approval (terminal) -----------------------------------------------

def default_plan(scan_path: str, scope_path: str) -> dict:
    from akashi import api
    return api.plan(scan_path, scope_path)


def research_problem(path: str) -> str | None:
    """mønømi's check of a research-header file, the one akashi uses too
    (None = usable)."""
    try:
        research_mod.load(path)
    except research_mod.ResearchError as e:
        return str(e)
    return None


def show_plan(steps: list, out) -> None:
    for s in steps:
        out(f"  {s['id']:<4} {s['rule']}: {s['summary']}")
        if s["ready"]:
            for r in s["requests"]:
                out(f"       would send: {r}")
        else:
            out(f"       BLOCKED: {s['blocked'] or 'not ready'} (stays unproven)")


def approve(rid: str, scope_path: str, research_path: str | None = None, *, root: str | None = None,
            now=None, plan=None, ask=input, interactive=None, out=print) -> int:
    """`0x41 approve RID --scope FILE`: show akashi's plan with every request,
    ask for a typed yes, then lock the approval to exactly that."""
    now = now or now_utc()
    run_dir, store = _locate(rid, root)
    data = store.pending(rid, now, interactive)
    if not scope_path or not os.path.isfile(scope_path):
        raise ApprovalError(f"scope file not found: {scope_path}")
    if research_path:
        problem = research_problem(research_path)
        if problem:
            raise ApprovalError(f"the research header file isn't usable: {problem}")

    p = (plan or default_plan)(os.path.join(run_dir, "scan.json"), scope_path)
    if p["scope"].get("problem") or not p["scope"].get("loaded"):
        raise ApprovalError(f"the scope file can't be used: {p['scope'].get('problem') or 'not loaded'}")
    steps = [s for s in p["steps"] if s["id"] in data["lead_ids"] and s["active"]]
    ready = [s for s in steps if s["ready"]]

    out(f"\nApproval {rid}: active proofs for {data['domain']} (vet {data['job_id']})")
    out(f"Scope file: {os.path.realpath(scope_path)}")
    show_plan(steps, out)
    if not ready:
        out("\nNothing is ready to run, so there's nothing to approve.")
        return 1
    out(f"\nThis approval is good for one run of these {len(ready)} proof(s), within "
        f"{int(APPROVAL_TTL.total_seconds() // 60)} minutes, and only while the scope file stays as it is now.")
    if not typed_yes(ask, "Type yes to approve, anything else to cancel: "):
        out("Not approved. Nothing will run.")
        return 1  # stays pending: the person can run approve again within the hour

    scope = scope_mod.load(scope_path)
    data = store.lock_in(data, {
        "approved_ids": [s["id"] for s in ready],
        "requests": {s["id"]: list(s["requests"]) for s in ready},
        "scope": {"path": os.path.realpath(scope_path), "sha256": scope.sha256},
        "research": ({"path": os.path.realpath(research_path),
                      "sha256": research_mod.load(research_path).sha256} if research_path else None),
    }, now, by="terminal")
    out(f"Approved. Claude can now run it once with prove_run (id {rid}), until {local_hm(data['expires'])}.")
    return 0


# --- 3. the claim (MCP) --------------------------------------------------------

def claim(rid: str, *, root: str | None = None, now=None, plan=None) -> dict:
    """Every check again, then mark the approval used BEFORE returning it, so
    it can't run twice even if the run crashes. Returns what to run:
    scan path, scope path, research path, approved ids."""
    run_dir, store = _locate(rid, root)
    scan = os.path.join(run_dir, "scan.json")

    def check(data):
        """0x41's last look: the pinned files, then akashi's plan as it is now."""
        _, problem = scope_mod.check_pinned(data["scope"]["path"], data["scope"]["sha256"], fix=_cmd(rid))
        if problem:
            return f"scope file: {problem}"
        if data.get("research"):
            _, problem = research_mod.check_pinned(data["research"]["path"], data["research"]["sha256"],
                                                   fix=f"`0x41 approve {rid} --scope FILE --research FILE`")
            if problem:
                return f"research file: {problem}"
        p = (plan or default_plan)(scan, data["scope"]["path"])
        now_requests = {s["id"]: list(s["requests"]) for s in p["steps"]
                        if s["id"] in data["approved_ids"] and s["active"] and s["ready"]}
        if now_requests != data["requests"]:
            return "akashi's plan no longer matches what was approved: nothing runs (approve again)"
        return None

    data = store.claim(rid, now, check)
    return {"rid": rid, "job_id": data["job_id"], "run_dir": run_dir, "scan": scan,
            "scope": data["scope"]["path"], "research": (data.get("research") or {}).get("path"),
            "approved_ids": data["approved_ids"], "requests": data["requests"]}


def record_result(rid: str, result: dict, *, root: str | None = None, now=None) -> None:
    """Note the run's outcome in the approval's own history."""
    _, store = _locate(rid, root)
    if result.get("error"):
        store.note(rid, "failed", now, error=result["error"])
    else:
        store.note(rid, "ran", now, tally=result.get("tally"), skipped=result.get("skipped"))
