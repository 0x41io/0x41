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

Each approval is one JSON file, runs/<domain>/<time>/approvals/<rid>.json,
with every event in it (refusals too), so it's its own audit trail.

Honest limit: an agent that has a shell on this machine can fake a terminal,
as with mønømi's --allow-active. The gate is against agents with MCP tools only.
"""

import hashlib
import json
import os
import re
import secrets
import sys
import threading
from datetime import datetime, timedelta

from x41 import jobs

REQUEST_TTL = timedelta(hours=1)       # a pending request nobody approved
APPROVAL_TTL = timedelta(minutes=15)   # an approval nobody used
ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o, 1/l/i: easy to type
RID = re.compile(r"[a-z2-9]{4}-[a-z2-9]{4}")
_lock = threading.Lock()  # claim() is check-then-mark: one at a time


class ApprovalError(ValueError):
    """Refused; the message says why. Nothing was sent."""


def new_rid() -> str:
    pick = "".join(secrets.choice(ALPHABET) for _ in range(8))
    return f"{pick[:4]}-{pick[4:]}"


def sha256_of(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _now(now):
    return now or datetime.now()


def _write(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)  # all at once: never half a file


def _event(data: dict, now, event: str, **extra) -> None:
    data.setdefault("events", []).append({"time": now.isoformat(timespec="seconds"), "event": event, **extra})


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


def _load(rid: str, root: str | None) -> tuple:
    path = find(rid, root)
    with open(path, encoding="utf-8") as f:
        return path, json.load(f)


def _refuse(path: str, data: dict, now, why: str):
    _event(data, now, "refused", reason=why)
    _write(path, data)
    raise ApprovalError(why)


# --- 1. the request (MCP) -----------------------------------------------------

def request(job_id: str, lead_ids: list | None = None, *, root: str | None = None, now=None) -> dict:
    """A pending approval for a finished vet's waiting active leads. Sends
    nothing and takes no scope: the person gives that when approving."""
    now = _now(now)
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

    os.makedirs(os.path.join(run_dir, "approvals"), exist_ok=True)
    rid = new_rid()
    data = {"rid": rid, "job_id": job_id, "domain": rec.get("domain"), "lead_ids": wanted,
            "status": "pending", "created": now.isoformat(timespec="seconds"),
            "request_expires": (now + REQUEST_TTL).isoformat(timespec="seconds")}
    _event(data, now, "requested")
    _write(os.path.join(run_dir, "approvals", rid + ".json"), data)
    return {"rid": rid, "job_id": job_id, "lead_ids": wanted, "status": "pending",
            "expires": data["request_expires"],
            "ask_the_person_to_run": f"0x41 approve {rid} --scope scope.txt"}


# --- 2. the approval (terminal) -----------------------------------------------

def default_plan(scan_path: str, scope_path: str) -> dict:
    from akashi import api
    return api.plan(scan_path, scope_path)


def research_problem(path: str) -> str | None:
    """akashi's own check of a research-header file (None = usable)."""
    from akashi.cli import _load_research
    research, problem = _load_research(path)
    return None if research is not None else (problem or "not usable")


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
    now = _now(now)
    path, data = _load(rid, root)
    if data["status"] != "pending":
        raise ApprovalError(f"{rid} is {data['status']}, not pending")
    if now > datetime.fromisoformat(data["request_expires"]):
        _refuse(path, data, now, f"{rid} expired before it was approved (ask for a new one)")
    if not (interactive or (lambda: sys.stdin.isatty()))():
        _refuse(path, data, now, "approving needs a person at a real terminal (stdin isn't one)")
    if not scope_path or not os.path.isfile(scope_path):
        raise ApprovalError(f"scope file not found: {scope_path}")
    if research_path:
        problem = research_problem(research_path)
        if problem:
            raise ApprovalError(f"the research header file isn't usable: {problem}")

    run_dir = os.path.dirname(os.path.dirname(path))
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
    if ask("Type yes to approve, anything else to cancel: ").strip().lower() != "yes":
        out("Not approved. Nothing will run.")
        return 1

    data.update({
        "status": "approved", "approved_at": now.isoformat(timespec="seconds"),
        "expires": (now + APPROVAL_TTL).isoformat(timespec="seconds"),
        "approved_ids": [s["id"] for s in ready],
        "requests": {s["id"]: list(s["requests"]) for s in ready},
        "scope": {"path": os.path.realpath(scope_path), "sha256": sha256_of(scope_path)},
        "research": ({"path": os.path.realpath(research_path), "sha256": sha256_of(research_path)}
                     if research_path else None),
    })
    _event(data, now, "approved", by="terminal")
    _write(path, data)
    out(f"Approved. Claude can now run it once with prove_run (id {rid}), until {data['expires'][11:16]}.")
    return 0


# --- 3. the claim (MCP) --------------------------------------------------------

def claim(rid: str, *, root: str | None = None, now=None, plan=None) -> dict:
    """Every check again, then mark the approval used BEFORE returning it, so
    it can't run twice even if the run crashes. Returns what to run:
    scan path, scope path, research path, approved ids."""
    now = _now(now)
    with _lock:
        path, data = _load(rid, root)
        status = data["status"]
        if status == "pending":
            _refuse(path, data, now, f"{rid} hasn't been approved yet: the person runs "
                    f"`0x41 approve {rid} --scope FILE` in a terminal first")
        if status != "approved":
            _refuse(path, data, now, f"{rid} was already {status}: an approval runs once (ask for a new one)")
        if now > datetime.fromisoformat(data["expires"]):
            data["status"] = "expired"
            _refuse(path, data, now, f"{rid} expired at {data['expires'][11:16]} (ask for a new one)")
        for name in ("scope", "research"):
            pinned = data.get(name)
            if pinned and (not os.path.isfile(pinned["path"]) or sha256_of(pinned["path"]) != pinned["sha256"]):
                _refuse(path, data, now, f"the {name} file changed or is missing since it was approved: "
                        "nothing runs (approve again)")
        run_dir = os.path.dirname(os.path.dirname(path))
        scan = os.path.join(run_dir, "scan.json")
        p = (plan or default_plan)(scan, data["scope"]["path"])
        now_requests = {s["id"]: list(s["requests"]) for s in p["steps"]
                        if s["id"] in data["approved_ids"] and s["active"] and s["ready"]}
        if now_requests != data["requests"]:
            _refuse(path, data, now, "akashi's plan no longer matches what was approved: nothing runs (approve again)")

        data["status"] = "used"
        data["used_at"] = now.isoformat(timespec="seconds")
        _event(data, now, "claimed")
        _write(path, data)
    return {"rid": rid, "job_id": data["job_id"], "run_dir": run_dir, "scan": scan,
            "scope": data["scope"]["path"], "research": (data.get("research") or {}).get("path"),
            "approved_ids": data["approved_ids"], "requests": data["requests"]}


def record_result(rid: str, result: dict, *, root: str | None = None, now=None) -> None:
    """Note the run's outcome in the approval's own history."""
    now = _now(now)
    with _lock:
        path, data = _load(rid, root)
        if result.get("error"):
            _event(data, now, "failed", error=result["error"])
        else:
            _event(data, now, "ran", tally=result.get("tally"), skipped=result.get("skipped"))
        _write(path, data)
