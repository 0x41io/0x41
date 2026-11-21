"""
The startup version check (x41/versions.py): an installed tool older than
0x41's pin stops 0x41 with the exact fix, before anything else can crash.
No network: pins and installed versions are faked, except the test that the
pins really come from pyproject.toml.
"""

import os
import tomllib

import pytest

from x41 import cli, versions

URL = "git+https://github.com/0x41io/monomi"
PINS = {"monomi": ("1.21.0", URL), "akashi": ("0.2.8", "git+https://github.com/0x41io/akashi"),
        "kaidoku": ("0.10.0", "git+https://github.com/0x41io/kaidoku")}


@pytest.fixture
def suite(monkeypatch):
    """Pins as 0x41 v0.6.x has them; installed versions set per test."""
    have = {"monomi": "1.21.0", "akashi": "0.2.8", "kaidoku": "0.10.0"}
    monkeypatch.setattr(versions, "pins", lambda: dict(PINS))
    monkeypatch.setattr(versions, "installed", lambda name: have[name])
    return have


def test_matching_versions_start(suite):
    assert versions.check("0.6.1") == ([], [])


def test_todays_failure_an_old_monomi_refuses_with_the_fix(suite):
    suite["monomi"] = "1.19.0"   # what the venv really had on 2026-11-21
    problems, _ = versions.check("0.6.1")
    assert len(problems) == 1
    assert "monomi 1.19.0 is installed, but 0x41 0.6.1 needs 1.21.0" in problems[0]
    assert f'pip install --force-reinstall --no-deps "monomi @ {URL}@v1.21.0"' in problems[0]


def test_a_newer_version_only_warns(suite):
    suite["akashi"] = "0.3.0"
    problems, warnings = versions.check("0.6.1")
    assert problems == [] and "akashi 0.3.0 is newer than the 0.2.8" in warnings[0]


def test_a_missing_tool_refuses(suite):
    suite["kaidoku"] = None
    problems, _ = versions.check("0.6.1")
    assert "kaidoku isn't installed" in problems[0] and "kaidoku@v0.10.0" in problems[0]


@pytest.mark.parametrize("have, want, older", [
    ("1.9.0", "1.10.0", True), ("1.10.0", "1.9.0", False), ("0.10.0", "0.9.1", False), ("1.21", "1.21.0", True),
])
def test_versions_compare_as_numbers_not_text(have, want, older):
    # "1.9.0" < "1.10.0" as numbers; as text it would sort the other way
    assert (versions._parse(have) < versions._parse(want)) is older


def test_the_pins_are_read_from_pyproject_not_copied():
    pins = versions.pins()
    if not pins:
        pytest.skip("0x41 isn't installed in this environment")
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "pyproject.toml"), "rb") as f:
        deps = tomllib.load(f)["project"]["dependencies"]
    for name, (version, url) in pins.items():
        assert f"{name} @ {url}@v{version}" in deps


# --- the CLI: which commands are checked, and how it tells you ---------------------

def old_monomi(monkeypatch):
    monkeypatch.setattr(versions, "pins", lambda: dict(PINS))
    monkeypatch.setattr(versions, "installed", lambda name: "1.19.0" if name == "monomi" else PINS[name][0])


@pytest.mark.parametrize("argv", [["vet", "lab.test"], ["approve", "k7m2-x9pq", "--scope", "s.txt"], ["mcp"]])
def test_commands_that_use_the_tools_refuse_on_stderr(monkeypatch, capsys, argv):
    old_monomi(monkeypatch)
    assert cli.main(argv) == 2
    out, err = capsys.readouterr()
    assert out == ""   # stdout stays clean: for `0x41 mcp` it's the MCP channel
    assert "0x41 can't start" in err and "monomi 1.19.0" in err


def test_mcp_setup_is_not_blocked(monkeypatch):
    # setup only edits the Claude app's config: it must work even when the
    # suite is out of date, or you couldn't fix things from the terminal
    old_monomi(monkeypatch)
    ran = {}
    from x41 import mcp_setup
    monkeypatch.setattr(mcp_setup, "main", lambda **kw: ran.setdefault("setup", 0))
    assert cli.main(["mcp", "setup"]) == 0 and "setup" in ran
