"""
App-logic checks Claude asks for, approved by a person in a terminal
(milestone 2: akashi v0.3.1's app checks, run through 0x41).

    request()  (MCP, app_request)   a pending approval for one case file, by
                                    name, verify or recheck; sends nothing
    approve()  (terminal, `0x41 approve RID --scope FILE --creds FILE`)
                                    shows akashi's plan (every request),
                                    asks for a typed yes, pins it all
    claim()    (MCP, app_run)       every check again, then marks it used
                                    BEFORE anything is sent

Claude can only NAME a case: case files live in 0x41's cases/ folder, which
the person controls (cases/<name>.toml), so an agent can't point a check at
a new target. Scope, credentials, a research header and the yes come only
from the person, in the terminal. The approval pins the case file, the scope
file and the creds file (sha256) and the exact requests shown; any change
before the run means refuse, and nothing is sent.

Records, the typed yes and the single-use claim are mønømi's approvals core
(monomi.approvalcore), shared by every 0x41 approval gate. Approvals live in
app-approvals/<rid>.json; each run's result in app-runs/<rid>/.
"""

import hashlib
import os
import re

from monomi import research as research_mod
from monomi import scope as scope_mod
from monomi.approvalcore import (APPROVAL_TTL, ApprovalError, Store, local_hm,  # noqa: F401
                                 now_utc, typed_yes)

from x41 import home

KINDS = ("verify", "recheck")
CASE_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")


def cases_dir() -> str:
    return home.data_dir("cases")


def runs_dir(rid: str) -> str:
    return home.data_dir("app-runs", rid)


def _cmd(rid: str) -> str:
    return f"`0x41 approve {rid} --scope FILE --creds FILE`"


def _store() -> Store:
    return Store(home.data_dir("app-approvals"), "0x41", _cmd)


def _sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def case_path(name: str) -> str:
    """cases/<name>.toml for a bare case name, or ApprovalError. Only names,
    never paths: the file must really be inside cases/ (no symlink out)."""
    if not isinstance(name, str) or not CASE_NAME.fullmatch(name):
        raise ApprovalError(f"not a case name: {name!r} (letters, digits, - and _, like notes-idor)")
    folder = os.path.realpath(cases_dir())
    path = os.path.join(folder, name + ".toml")
    if not os.path.isfile(path):
        raise ApprovalError(f"no case {name!r} in {folder} (see list_cases)")
    if os.path.dirname(os.path.realpath(path)) != folder:
        raise ApprovalError(f"case {name!r} must be a real file inside {folder}")
    return path


def list_cases() -> list:
    """Every case in cases/: name, host, resource, owner, actor. Nothing secret
    (creds never live in a case file). A case that won't load says why."""
    from akashi import api as akashi_api
    folder = cases_dir()
    out = []
    for fname in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
        name, ext = os.path.splitext(fname)
        if ext != ".toml" or not CASE_NAME.fullmatch(name):
            continue
        try:
            c = akashi_api.app_plan(os.path.join(folder, fname))["case"]
            out.append({"case": name, "type": c["type"], "host": c["host"], "resource": c["resource"],
                        "owner": c["owner"], "actor": c["actor"]})
        except Exception as e:
            out.append({"case": name, "problem": str(e)})
    return out


def default_plan(case_file: str, scope_file: str | None) -> dict:
    from akashi import api as akashi_api
    return akashi_api.app_plan(case_file, scope_file)


# --- 1. the request (MCP) -------------------------------------------------------

def request(name: str, kind: str = "verify", *, now=None, plan=None) -> dict:
    """A pending approval for one case. Sends nothing; takes no scope or creds."""
    if kind not in KINDS:
        raise ApprovalError(f"kind must be verify or recheck, not {kind!r}")
    path = case_path(name)
    try:
        p = (plan or default_plan)(path, None)
    except Exception as e:
        raise ApprovalError(f"case {name!r} can't be used: {e}")
    rec = _store().create({"case": name, "kind": kind, "target": p["target"]}, now, kind=kind)
    return {"rid": rec["rid"], "case": name, "kind": kind, "target": p["target"], "status": "pending",
            "expires": rec["expires"],
            "ask_the_person_to_run": f"0x41 approve {rec['rid']} --scope scope.txt --creds creds.json"}


# --- 2. the approval (terminal) ---------------------------------------------------

def is_app(rid: str) -> bool:
    """True if this id is an app-check approval (so `0x41 approve` knows which
    kind to show). A malformed id is never one."""
    try:
        return _store().exists(rid)
    except ApprovalError:
        return False


def _check_creds(creds_path: str, case_file: str) -> None:
    """The creds file must be usable for this case's accounts (600, both
    accounts present). Its passwords are read only to check, never shown."""
    from akashi.app import case as case_mod
    from akashi.app import creds as creds_mod
    try:
        creds_mod.load(creds_path, case_mod.load(case_file).accounts)
    except (creds_mod.CredsError, case_mod.CaseError) as e:
        raise ApprovalError(f"the creds file can't be used: {e}")


def approve(rid: str, scope_path: str, creds_path: str | None, research_path: str | None = None, *,
            now=None, plan=None, ask=input, interactive=None, out=print) -> int:
    """`0x41 approve RID --scope FILE --creds FILE` for an app check: show
    akashi's plan with every request, ask for a typed yes, pin it all."""
    now = now or now_utc()
    store = _store()
    data = store.pending(rid, now, interactive)
    if not creds_path:
        raise ApprovalError("an app check needs --creds FILE (your test accounts' logins, chmod 600)")
    if not scope_path or not os.path.isfile(scope_path):
        raise ApprovalError(f"scope file not found: {scope_path}")
    path = case_path(data["case"])
    _check_creds(creds_path, path)
    if research_path:
        try:
            research_mod.load(research_path)
        except research_mod.ResearchError as e:
            raise ApprovalError(f"the research header file isn't usable: {e}")

    p = (plan or default_plan)(path, scope_path)
    if p["scope"].get("problem") or not p["scope"].get("loaded"):
        raise ApprovalError(f"the scope file can't be used: {p['scope'].get('problem') or 'not loaded'}")
    c = p["case"]
    out(f"\nApproval {rid}: app check '{data['case']}' ({data['kind']}) on {c['host']}")
    out(f"  can {c['actor']} read {c['owner']}'s {c['resource']}?  (both your own test accounts)")
    for r in p["requests"]:
        out(f"  would send: {r['method']:<4} {r['url']}   {r['purpose']}")
    out(f"Scope file: {os.path.realpath(scope_path)}")
    out(f"Creds file: {os.path.realpath(creds_path)} (passwords not shown)")
    if not p["scope"]["in_scope"]:
        raise store.refuse(data, f"{c['host']} isn't in the scope file, so there's nothing to approve", now)
    out(f"\nThis approval is good for one run, within {int(APPROVAL_TTL.total_seconds() // 60)} minutes, "
        "and only while the case, scope and creds files stay exactly as they are now.")
    if not typed_yes(ask, "Type yes to approve, anything else to cancel: "):
        out("Not approved. Nothing will run.")
        return 1  # stays pending: the person can approve again within the hour

    data = store.lock_in(data, {
        "requests": [f"{r['method']} {r['url']}" for r in p["requests"]],
        "case_file": {"path": path, "sha256": c["sha256"]},
        "scope": {"path": os.path.realpath(scope_path), "sha256": scope_mod.load(scope_path).sha256},
        "creds": {"path": os.path.realpath(creds_path), "sha256": _sha256(creds_path)},
        "research": ({"path": os.path.realpath(research_path),
                      "sha256": research_mod.load(research_path).sha256} if research_path else None),
    }, now, by="terminal")
    out(f"Approved. Claude can now run it once with app_run (id {rid}), until {local_hm(data['expires'])}.")
    return 0


# --- 3. the claim (MCP) -----------------------------------------------------------

def claim(rid: str, *, now=None, plan=None) -> dict:
    """Every check again, then mark the approval used BEFORE returning it.
    Returns what to run: case, scope, creds, research paths, kind, requests."""
    store = _store()

    def check(data):
        """0x41's last look: every pinned file unchanged, then the plan rebuilt
        from them must be exactly what the person approved, still in scope."""
        case_file = data["case_file"]["path"]
        if not os.path.isfile(case_file) or _sha256(case_file) != data["case_file"]["sha256"]:
            return "the case file changed since it was approved: nothing runs (approve again)"
        _, problem = scope_mod.check_pinned(data["scope"]["path"], data["scope"]["sha256"], fix=_cmd(rid))
        if problem:
            return f"scope file: {problem}"
        creds = data["creds"]["path"]
        if not os.path.isfile(creds) or _sha256(creds) != data["creds"]["sha256"]:
            return "the creds file changed since it was approved: nothing runs (approve again)"
        if data.get("research"):
            fix = f"`0x41 approve {rid} --scope FILE --creds FILE --research FILE`"
            _, problem = research_mod.check_pinned(data["research"]["path"], data["research"]["sha256"], fix=fix)
            if problem:
                return f"research file: {problem}"
        p = (plan or default_plan)(case_file, data["scope"]["path"])
        if not p["scope"].get("in_scope"):
            return "the case's host is no longer in the scope file: nothing runs"
        if [f"{r['method']} {r['url']}" for r in p["requests"]] != data["requests"]:
            return "akashi's plan no longer matches what was approved: nothing runs (approve again)"
        return None

    data = store.claim(rid, now, check)
    return {"rid": rid, "case": data["case"], "kind": data["kind"], "case_file": data["case_file"]["path"],
            "scope": data["scope"]["path"], "creds": data["creds"]["path"],
            "research": (data.get("research") or {}).get("path"), "requests": data["requests"]}


def record_result(rid: str, result: dict, *, now=None) -> None:
    """Note the run's outcome in the approval's own history (no passwords:
    akashi's result never carries them)."""
    store = _store()
    if result.get("error"):
        store.note(rid, "failed", now, error=result["error"])
    else:
        store.note(rid, "ran", now, tally=result.get("tally"), transition=result.get("transition"))
