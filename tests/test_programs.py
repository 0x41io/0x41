"""Bug bounty programs (v0.10.0): programs/<name>.txt, named never pathed,
and what a program changes in a vet. No network: mønømi's scan is a stand-in."""

import json
import os
import sys
from datetime import datetime

import pytest

from x41 import cli, jobs, programs, vet as vet_mod
from tests.test_vet import Fake

SCOPE = "shop.test\n*.shop.test\napi-eu.shop.test\napi-us.shop.test\n!old.shop.test\nother.test\n"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("X41_HOME", str(tmp_path / "x41"))
    folder = tmp_path / "x41" / "programs"
    folder.mkdir(parents=True)
    (folder / "shop.txt").write_text(SCOPE)
    return folder


def test_a_program_is_a_name_inside_programs(home):
    assert programs.program_path("shop") == os.path.realpath(home / "shop.txt")
    for bad in ["../shop", "shop.txt", "/etc/passwd", "Shop", "", "a/b"]:
        with pytest.raises(programs.ProgramError, match="not a program name"):
            programs.program_path(bad)
    with pytest.raises(programs.ProgramError, match="no program 'nope'"):
        programs.program_path("nope")


def test_a_link_out_of_programs_is_refused(home, tmp_path):
    outside = tmp_path / "elsewhere.txt"
    outside.write_text(SCOPE)
    (home / "linked.txt").symlink_to(outside)
    with pytest.raises(programs.ProgramError, match="real file inside"):
        programs.program_path("linked")


def test_exact_hosts_are_the_in_scope_names_under_the_domain(home):
    # Not the domain itself, not wildcards, not another domain, not excluded
    assert programs.exact_hosts(str(home / "shop.txt"), "shop.test") == ["api-eu.shop.test", "api-us.shop.test"]
    (home / "x.txt").write_text("*.shop.test\napi.shop.test\n!api.shop.test\n")
    assert programs.exact_hosts(str(home / "x.txt"), "shop.test") == []


def test_list_programs_counts_rules_and_says_what_wont_load(home):
    (home / "empty.txt").write_text("# nothing yet\n")
    (home / "notes.md").write_text("ignored: not a .txt")
    out = {p["program"]: p for p in programs.list_programs()}
    assert set(out) == {"shop", "empty"}
    assert out["shop"]["in_scope_rules"] == 5 and out["shop"]["excluded_rules"] == 1
    assert out["shop"]["wildcards"] == ["*.shop.test"] and out["shop"]["exact_hosts"] == 4
    assert "no valid rules" in out["empty"]["problem"]


def go(tmp_path, fake, **kw):
    vet_mod.vet("shop.test", tools=fake.tools(), out_root=str(tmp_path / "runs"),
                now=datetime(2026, 11, 22, 10, 0, 0), **kw)
    return tmp_path / "runs" / "shop.test" / "2026-11-22_100000"


def test_a_scoped_vet_gives_mønømi_the_scope_and_the_exact_hosts(home, tmp_path):
    fake = Fake()
    run_dir = go(tmp_path, fake, scope=str(home / "shop.txt"), program="shop", active=False)
    assert fake.scope_given == str(home / "shop.txt")
    hosts = [c for c in fake.calls if c[0] == "scan"][0][2]
    assert hosts == str(run_dir / "hosts.txt")
    assert (run_dir / "hosts.txt").read_text().split() == ["api-eu.shop.test", "api-us.shop.test"]
    rec = json.loads((run_dir / "run.json").read_text())
    assert rec["program"] == "shop" and rec["scope_hosts"] == ["api-eu.shop.test", "api-us.shop.test"]


def test_the_hosts_file_and_the_scope_hosts_are_merged(home, tmp_path):
    mine = tmp_path / "mine.txt"
    mine.write_text("dev.shop.test\napi-eu.shop.test\n")
    fake = Fake()
    run_dir = go(tmp_path, fake, scope=str(home / "shop.txt"), hosts_file=str(mine), active=False)
    assert (run_dir / "hosts.txt").read_text().split() == ["dev.shop.test", "api-eu.shop.test", "api-us.shop.test"]


def test_an_unscoped_vet_passes_no_scope_and_no_new_hosts_file(tmp_path):
    fake = Fake()
    run_dir = go(tmp_path, fake)
    assert fake.scope_given is None and [c for c in fake.calls if c[0] == "scan"][0][2] is None
    assert not (run_dir / "hosts.txt").exists()


def test_run_monomi_passes_the_scope_and_nothing_active(monkeypatch):
    seen = []

    class Done:
        returncode = 0

    def fake_run(cmd):
        seen.append(cmd)
        return Done()
    monkeypatch.setattr(vet_mod.subprocess, "run", fake_run)
    assert vet_mod.run_monomi("shop.test", "scan.json", "hosts.txt", "scope.txt") == 0
    [cmd] = seen
    assert cmd[cmd.index("--scope") + 1] == "scope.txt" and cmd[cmd.index("--hosts") + 1] == "hosts.txt"
    assert not {"--fingerprint", "--exposed-files"} & set(cmd)   # a scope file never turns on an active check


def test_cli_program_resolves_by_name_and_refuses_an_unknown_one(home, monkeypatch, capsys):
    seen = {}
    monkeypatch.setattr(vet_mod, "vet", lambda domain, **kw: seen.update(kw) or 0)
    assert cli.main(["vet", "shop.test", "--program", "shop"]) == 0
    assert seen["scope"] == os.path.realpath(home / "shop.txt") and seen["program"] == "shop"
    assert cli.main(["vet", "shop.test", "--program", "nope"]) == 2
    assert "no program 'nope'" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli.main(["vet", "shop.test", "--program", "shop", "--scope", "x.txt"])   # one or the other


def test_a_background_vet_is_never_active_with_or_without_a_program():
    cmd = jobs.default_command("shop.test", "/runs/x", None, "shop")
    assert cmd[:4] == [sys.executable, "-m", "x41", "vet"] and "--no-active" in cmd
    assert cmd[cmd.index("--program") + 1] == "shop"
    assert "--program" not in jobs.default_command("shop.test", "/runs/x", None)
