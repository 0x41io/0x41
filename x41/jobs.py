"""
Background vets, for the MCP server (`0x41 mcp`).

A vet takes minutes, but an MCP tool call has to answer in under ~60 s, and
the MCP server's stdout is its line to the client (a stray print would break
it). So a vet runs as its own process:

    python -m x41 vet DOMAIN --no-active --run-dir runs/<domain>/<time>

with stdin closed (so no question can wait on it) and all its output going to
vet.log in that folder. job.json, written next to it, says which process it
is. The job id is the folder's place under runs/, e.g. "example.com/2026-11-16_180812".

Status is read from the folder, so it still works after the server restarts:

    run.json exists      -> done        (vet writes it as its very last step)
    the process is alive -> running
    no job.json          -> incomplete  (a vet from the terminal: still going, or stopped)
    otherwise            -> failed      (the end of vet.log says why)

Never active: the command always has --no-active and never --scope, and
there is no way to pass either through here (AGENTS.md: active proofs need a
typed yes at a real terminal).
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime

from x41 import home, report
from x41.vet import clean_target, inside, slug

JOB_FILE = "job.json"
LOG_FILE = "vet.log"
TAIL_LINES = 15
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_ART = re.compile(r"[\s░▒▓█]+")  # a line of only block characters: mønømi's banner
_JOB_ID = re.compile(r"[a-z0-9._-]+/\d{4}-\d{2}-\d{2}_\d{6}")

# Processes this server started, by pid. Polling them reaps them when they
# finish (a finished child that's never polled stays a "zombie" and would
# still look alive), and gives the exit code.
_procs: dict = {}


class JobError(ValueError):
    """A job request that can't be done; the message says why."""


def runs_root(root: str | None = None) -> str:
    return os.path.realpath(root or home.data_dir("runs"))


def job_dir(job_id: str, root: str | None = None) -> str:
    """The folder for a job id, or JobError. Only ids shaped like
    'domain/YYYY-MM-DD_HHMMSS' that land inside runs/ are accepted, so a
    job id can't be used to read anywhere else."""
    if not isinstance(job_id, str) or not _JOB_ID.fullmatch(job_id):
        raise JobError(f"not a job id: {job_id!r} (they look like example.com/2026-11-16_180812)")
    base = runs_root(root)
    path = os.path.join(base, job_id)
    if not inside(path, base):
        raise JobError(f"not a job id: {job_id!r}")
    if not os.path.isdir(path):
        raise JobError(f"no vet with job id {job_id}")
    return path


def default_command(domain: str, run_dir: str, hosts_file: str | None, program: str | None = None) -> list:
    """The vet a job runs. Always --no-active: a vet started over MCP never
    sends anything to the target, with or without a program (v0.10.0)."""
    cmd = [sys.executable, "-m", "x41", "vet", domain, "--no-active", "--run-dir", run_dir]
    if hosts_file:
        cmd += ["--hosts", hosts_file]
    if program:
        cmd += ["--program", program]
    return cmd


def _alive(pid) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    proc = _procs.get(pid)
    if proc is not None:
        return proc.poll() is None
    try:  # started by an earlier server: not our child, so no zombie
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _read_json(path: str):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _tail(run_dir: str, lines: int = TAIL_LINES) -> list:
    """The last lines of vet.log, colors removed. The log holds text from the
    target (hostnames and so on): it's data to show, never instructions."""
    try:
        with open(os.path.join(run_dir, LOG_FILE), "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 8192))
            text = f.read().decode("utf-8", "replace")
    except OSError:
        return []
    kept = []
    for ln in text.splitlines():
        ln = _ANSI.sub("", ln).rstrip()
        if ln.strip() and not _ART.fullmatch(ln):  # skip blank lines and banner art
            kept.append(ln)
    return kept[-lines:]


def _job_dirs(root: str | None = None):
    """Every run folder under runs/ (from the MCP server or the terminal)."""
    base = runs_root(root)
    if not os.path.isdir(base):
        return
    for dom in os.listdir(base):
        for stamp in os.listdir(os.path.join(base, dom)) if os.path.isdir(os.path.join(base, dom)) else []:
            job_id = f"{dom}/{stamp}"
            if _JOB_ID.fullmatch(job_id) and os.path.isdir(os.path.join(base, dom, stamp)):
                yield job_id, os.path.join(base, dom, stamp)


def _state(run_dir: str) -> tuple:
    """(state, job.json contents or {}), read from the folder."""
    job = _read_json(os.path.join(run_dir, JOB_FILE)) or {}
    if os.path.exists(os.path.join(run_dir, "run.json")):
        return "done", job
    if not job:
        return "incomplete", job
    if _alive(job.get("pid")):
        return "running", job
    return "failed", job


def running(root: str | None = None) -> str | None:
    """The job id of a vet still running, if any."""
    for job_id, path in _job_dirs(root):
        if _state(path)[0] == "running":
            return job_id
    return None


def start(domain: str, hosts_file: str | None = None, *, root: str | None = None,
          now: datetime | None = None, command=default_command, program: str | None = None) -> dict:
    """Start a vet in the background and return at once.

    One at a time: if a vet is still running, JobError names it. A bad domain
    is refused here, with mønømi's own rule, before any folder is made."""
    try:
        domain = clean_target(domain)
    except ValueError as e:
        raise JobError(str(e)) from None
    busy = running(root)
    if busy:
        raise JobError(f"a vet is already running ({busy}); check it with vet_status, one runs at a time")

    now = now or datetime.now()
    job_id = f"{slug(domain)}/{now.strftime('%Y-%m-%d_%H%M%S')}"
    run_dir = os.path.join(runs_root(root), job_id)
    if os.path.exists(run_dir):
        raise JobError(f"{job_id} already exists; try again in a second")
    os.makedirs(run_dir)

    cmd = command(domain, run_dir, hosts_file, program)
    env = {**os.environ, "PYTHONUNBUFFERED": "1", "NO_COLOR": "1"}
    with open(os.path.join(run_dir, LOG_FILE), "w", encoding="utf-8") as log:
        # start_new_session: the vet keeps going (and writes its report) even
        # if the Claude app closes and takes the server with it.
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                env=env, start_new_session=True)
    _procs[proc.pid] = proc
    job = {"job_id": job_id, "domain": domain, "pid": proc.pid, "hosts_file": hosts_file, "program": program,
           "started": now.isoformat(timespec="seconds"), "command": cmd}
    with open(os.path.join(run_dir, JOB_FILE), "w", encoding="utf-8") as f:
        json.dump(job, f, indent=2)
    return {"job_id": job_id, "domain": domain, "status": "running", "run_dir": run_dir,
            "started": job["started"]}


def status(job_id: str, *, root: str | None = None, now: datetime | None = None) -> dict:
    """Where a vet stands. Done: its full record (run.json) and report path.
    Running: how long so far and the end of the log. Failed: the exit code
    when this server knows it, and the end of the log."""
    run_dir = job_dir(job_id, root)
    state, job = _state(run_dir)
    out = {"job_id": job_id, "domain": job.get("domain") or job_id.split("/")[0], "status": state,
           "run_dir": run_dir, "started": job.get("started")}
    if state == "done":
        out["record"] = _read_json(os.path.join(run_dir, "run.json")) or {}
        out["report"] = os.path.join(run_dir, "report.md")
        return out
    if state == "running" and job.get("started"):
        started = datetime.fromisoformat(job["started"])
        out["seconds"] = int(((now or datetime.now()) - started).total_seconds())
    proc = _procs.get(job.get("pid"))
    if state == "failed" and proc is not None:
        out["exit_code"] = proc.returncode
    out["log_tail"] = _tail(run_dir)
    return out


def list_jobs(domain: str | None = None, *, root: str | None = None, limit: int = 20) -> list:
    """Vets under runs/, newest first: id, state and, when done, the tally.
    Includes vets run from the terminal, not only ones started here."""
    want = slug(domain) if domain else None
    rows = []
    for job_id, path in _job_dirs(root):
        if want and job_id.split("/")[0] != want:
            continue
        state, _ = _state(path)
        row = {"job_id": job_id, "status": state}
        if state == "done":
            rec = _read_json(os.path.join(path, "run.json")) or {}
            row["tally"] = report.tally(rec)
        rows.append(row)
    rows.sort(key=lambda r: r["job_id"].split("/")[1], reverse=True)
    return rows[:limit]
