"""
Background vets (x41/jobs.py), with a stand-in command instead of a real vet,
so nothing is scanned. What's checked: a job runs in its own process and
reports running / done / failed; one runs at a time; job ids can't reach
outside runs/; the real command is never active.
"""

import json
import os
import sys
import time
from datetime import datetime

import pytest

from x41 import jobs, vet as vet_mod

NOW = datetime(2026, 11, 16, 18, 0, 0)
JOB = "example.test/2026-11-16_180000"


def stand_in(script: str):
    """A command that runs `script` (Python) in place of a vet. The script
    gets the run folder as sys.argv[1]."""
    def command(domain, run_dir, hosts_file, program=None):
        return [sys.executable, "-c", script, run_dir]
    return command


FINISHES = stand_in(
    "import json, os, sys\n"
    "print('[1/4] monomi   scanning example.test (passive)')\n"
    "rec = {'domain': 'example.test', 'leads': [{'id': 'P1', 'state': 'open'}], 'not_proven': []}\n"
    "json.dump(rec, open(os.path.join(sys.argv[1], 'run.json'), 'w'))\n")
FAILS = stand_in("import sys; print('0x41: monomi did not finish'); sys.exit(2)")
WAITS = stand_in("import time; time.sleep(30)")


@pytest.fixture(autouse=True)
def clean_procs():
    yield
    for proc in jobs._procs.values():  # never leave a stand-in running
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    jobs._procs.clear()


def wait_for(job_id, root, state, seconds=10):
    end = time.time() + seconds
    while time.time() < end:
        out = jobs.status(job_id, root=root)
        if out["status"] == state:
            return out
        time.sleep(0.05)
    raise AssertionError(f"{job_id} never became {state}: {jobs.status(job_id, root=root)}")


def test_a_job_runs_in_the_background_and_finishes(tmp_path):
    out = jobs.start("example.test", root=str(tmp_path), now=NOW, command=FINISHES)
    assert out["job_id"] == JOB and out["status"] == "running"
    done = wait_for(JOB, str(tmp_path), "done")
    assert done["record"]["leads"][0]["id"] == "P1"
    assert done["report"].endswith("report.md")
    job = json.loads((tmp_path / JOB / "job.json").read_text())
    assert job["domain"] == "example.test" and job["pid"] > 0
    assert "scanning example.test" in (tmp_path / JOB / "vet.log").read_text()  # output went to the log


def test_a_failed_job_says_why(tmp_path):
    jobs.start("example.test", root=str(tmp_path), now=NOW, command=FAILS)
    out = wait_for(JOB, str(tmp_path), "failed")
    assert out["exit_code"] == 2
    assert "monomi did not finish" in out["log_tail"][-1]


def test_the_log_tail_skips_banner_art(tmp_path):
    """Found in the live check: mønømi's banner filled half the tail."""
    d = tmp_path / JOB
    d.mkdir(parents=True)
    (d / "vet.log").write_text("[*] Target: example.test\n▒▓██████▓▒   ▒▓█▓▒\n  ▒▓█▓▒  ▒▓█▓▒  \n"
                               "\x1b[1m[+] done\x1b[0m\n                by Øx41 · v1.16.0\n")
    assert jobs._tail(str(d)) == ["[*] Target: example.test", "[+] done", "                by Øx41 · v1.16.0"]


def test_running_shows_time_and_log(tmp_path):
    jobs.start("example.test", root=str(tmp_path), now=NOW, command=WAITS)
    out = jobs.status(JOB, root=str(tmp_path), now=datetime(2026, 11, 16, 18, 1, 30))
    assert out["status"] == "running" and out["seconds"] == 90


def test_one_vet_at_a_time(tmp_path):
    jobs.start("example.test", root=str(tmp_path), now=NOW, command=WAITS)
    with pytest.raises(jobs.JobError, match="already running.*example.test/2026-11-16_180000"):
        jobs.start("other.test", root=str(tmp_path), now=datetime(2026, 11, 16, 18, 5, 0), command=FINISHES)


def test_a_finished_job_frees_the_slot(tmp_path):
    jobs.start("example.test", root=str(tmp_path), now=NOW, command=FINISHES)
    wait_for(JOB, str(tmp_path), "done")
    out = jobs.start("other.test", root=str(tmp_path), now=datetime(2026, 11, 16, 18, 5, 0), command=FINISHES)
    assert out["job_id"] == "other.test/2026-11-16_180500"


@pytest.mark.parametrize("bad", ["", "example.test--hosts", "../../etc"])
def test_a_bad_domain_is_refused_before_any_folder(tmp_path, bad):
    with pytest.raises(jobs.JobError, match="valid domain"):
        jobs.start(bad, root=str(tmp_path), now=NOW, command=FINISHES)
    assert list(tmp_path.iterdir()) == []


def test_the_domain_is_cleaned_first(tmp_path):
    out = jobs.start("https://www.Example.TEST/x", root=str(tmp_path), now=NOW, command=FINISHES)
    assert out["job_id"] == JOB and out["domain"] == "example.test"


@pytest.mark.parametrize("bad", ["../etc/2026-11-16_180000", "example.test/../../x", "/etc/passwd",
                                 "example.test", "example.test/2026-11-16_180000/../../..", None, 42])
def test_job_ids_cant_reach_outside_runs(tmp_path, bad):
    with pytest.raises(jobs.JobError, match="not a job id"):
        jobs.status(bad, root=str(tmp_path))


def test_a_link_out_of_runs_is_refused(tmp_path):
    outside = tmp_path / "outside" / "2026-11-16_180000"
    outside.mkdir(parents=True)
    root = tmp_path / "runs"
    root.mkdir()
    (root / "evil.test").symlink_to(tmp_path / "outside")
    with pytest.raises(jobs.JobError, match="not a job id"):
        jobs.status("evil.test/2026-11-16_180000", root=str(root))


def test_an_unknown_job_id(tmp_path):
    with pytest.raises(jobs.JobError, match="no vet with job id"):
        jobs.status(JOB, root=str(tmp_path))


def test_status_still_works_after_the_server_restarts(tmp_path):
    jobs.start("example.test", root=str(tmp_path), now=NOW, command=FAILS)
    wait_for(JOB, str(tmp_path), "failed")
    jobs._procs.clear()                      # a new server knows nothing about earlier processes
    out = jobs.status(JOB, root=str(tmp_path))
    assert out["status"] == "failed" and "exit_code" not in out   # read from the folder alone


def test_a_vet_from_the_terminal_shows_up(tmp_path):
    (tmp_path / "example.test" / "2026-11-15_120000").mkdir(parents=True)          # still going, or stopped
    done = tmp_path / "example.test" / "2026-11-14_120000"
    done.mkdir(parents=True)
    (done / "run.json").write_text(json.dumps({"leads": [{"id": "P1", "state": "open"}]}))
    rows = jobs.list_jobs(root=str(tmp_path))
    assert [r["job_id"] for r in rows] == ["example.test/2026-11-15_120000", "example.test/2026-11-14_120000"]
    assert rows[0]["status"] == "incomplete"
    assert rows[1]["status"] == "done" and rows[1]["tally"].startswith("1 confirmed")
    assert jobs.running(str(tmp_path)) is None  # incomplete doesn't block a new vet


def test_list_jobs_newest_first_and_by_domain(tmp_path):
    for name in ("a.test/2026-11-14_120000", "b.test/2026-11-16_120000", "a.test/2026-11-15_120000"):
        (tmp_path / name).mkdir(parents=True)
    assert [r["job_id"] for r in jobs.list_jobs(root=str(tmp_path))] == [
        "b.test/2026-11-16_120000", "a.test/2026-11-15_120000", "a.test/2026-11-14_120000"]
    assert [r["job_id"] for r in jobs.list_jobs("a.test", root=str(tmp_path), limit=1)] == [
        "a.test/2026-11-15_120000"]


def test_the_real_command_is_never_active():
    cmd = jobs.default_command("example.test", "/runs/example.test/x", "hosts.txt")
    assert cmd[:5] == [sys.executable, "-m", "x41", "vet", "example.test"]
    assert "--no-active" in cmd and "--scope" not in cmd
    assert cmd[cmd.index("--run-dir") + 1] == "/runs/example.test/x"
    assert cmd[cmd.index("--hosts") + 1] == "hosts.txt"
    assert "--hosts" not in jobs.default_command("example.test", "/r", None)
    assert "--bbot" not in cmd


def test_a_bbot_file_is_passed_to_the_vet_and_still_never_active():
    cmd = jobs.default_command("example.test", "/r", None, None, bbot="/home/u/.bbot/scans/s/output.json")
    assert cmd[cmd.index("--bbot") + 1] == "/home/u/.bbot/scans/s/output.json"
    assert "--no-active" in cmd


NO_NETWORK_CHILD = (
    "import socket\n"
    "def _blocked(*a, **k):\n"
    "    raise OSError('test child tried to reach the network')\n"
    "socket.socket.connect = socket.socket.connect_ex = _blocked\n"
    "socket.getaddrinfo = _blocked\n")


def test_the_real_command_starts_a_real_vet(tmp_path, monkeypatch):
    """`python -m x41 vet ... --run-dir` really parses; with a run folder
    outside runs/ it refuses before any tool runs (so nothing is scanned).
    The child process gets a sitecustomize.py that blocks the network, so
    even if that refusal ever broke, this test couldn't go online."""
    site = tmp_path / "site"
    site.mkdir()
    (site / "sitecustomize.py").write_text(NO_NETWORK_CHILD)
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(filter(None, [str(site), os.environ.get("PYTHONPATH")])))
    monkeypatch.setenv("X41_HOME", str(tmp_path / "home"))
    out = jobs.start("example.test", root=str(tmp_path / "runs"), now=NOW)  # runs/ != X41_HOME/runs
    done = wait_for(out["job_id"], str(tmp_path / "runs"), "failed", seconds=30)
    assert "--run-dir must be a folder inside" in "\n".join(done["log_tail"])


def test_vet_refuses_a_run_dir_outside_runs(tmp_path, capsys):
    code = vet_mod.vet("example.test", run_dir=str(tmp_path / "elsewhere"), out_root=str(tmp_path / "runs"))
    assert code == 2 and "nothing ran" in capsys.readouterr().err
    assert not (tmp_path / "elsewhere").exists()
    code = vet_mod.vet("example.test", run_dir=str(tmp_path / "runs" / ".." / "x"), out_root=str(tmp_path / "runs"))
    assert code == 2


def test_vet_uses_the_run_dir_it_was_given(tmp_path):
    from tests.test_vet import Fake
    given = tmp_path / "runs" / "example.test" / "2026-11-16_180000"
    code = vet_mod.vet("example.test", tools=Fake().tools(), out_root=str(tmp_path / "runs"), run_dir=str(given))
    assert code == 0 and (given / "report.md").exists()
    assert os.listdir(tmp_path / "runs" / "example.test") == ["2026-11-16_180000"]
