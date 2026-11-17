"""
0x41 mcp setup, against config files in a temp folder: the entry it builds
(WSL and not), that only the "0x41" entry changes, that a broken config is
never overwritten, and that data folders go in but API keys never do.
"""

import json
import sys

import pytest

from x41 import cli, mcp_setup


@pytest.fixture
def config(tmp_path, monkeypatch):
    """One Claude config with another server already in it."""
    path = tmp_path / "claude_desktop_config.json"
    path.write_text(json.dumps({"mcpServers": {"monomi": {"command": "wsl.exe", "args": ["x"]}},
                                "theme": "dark"}))
    monkeypatch.setattr(mcp_setup, "config_paths", lambda: ([str(path)], str(path)))
    for var in mcp_setup.HOME_VARS + ("OTX_API_KEY", "ANTHROPIC_API_KEY", "NVD_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    return path


@pytest.fixture
def wsl(monkeypatch):
    monkeypatch.setattr(mcp_setup, "in_wsl", lambda: True)
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu")


def test_wsl_entry_starts_0x41_mcp_through_wsl(config, wsl):
    entry = mcp_setup.server_entry()
    assert entry == {"command": "wsl.exe", "args": ["-d", "Ubuntu", "-e", sys.executable, "-m", "x41", "mcp"]}


def test_wsl_entry_carries_the_data_folders_but_never_keys(config, wsl, monkeypatch, tmp_path):
    monkeypatch.setenv("MONOMI_HOME", str(tmp_path / "0x41-recon"))
    monkeypatch.setenv("AKASHI_HOME", str(tmp_path / "akashi"))
    monkeypatch.setenv("OTX_API_KEY", "secret-otx")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
    args = mcp_setup.server_entry()["args"]
    assert args[:4] == ["-d", "Ubuntu", "-e", "env"]
    assert f"MONOMI_HOME={tmp_path / '0x41-recon'}" in args and f"AKASHI_HOME={tmp_path / 'akashi'}" in args
    assert args[-4:] == [sys.executable, "-m", "x41", "mcp"]
    assert "secret" not in json.dumps(args)


def test_outside_wsl_the_folders_go_in_the_env_key(config, monkeypatch, tmp_path):
    monkeypatch.setattr(mcp_setup, "in_wsl", lambda: False)
    monkeypatch.setenv("KAIDOKU_HOME", str(tmp_path / "kaidoku"))
    monkeypatch.setenv("NVD_API_KEY", "secret-nvd")
    entry = mcp_setup.server_entry()
    assert entry == {"command": sys.executable, "args": ["-m", "x41", "mcp"],
                     "env": {"KAIDOKU_HOME": str(tmp_path / "kaidoku")}}


def test_setup_adds_0x41_and_keeps_everything_else(config, wsl, capsys):
    assert mcp_setup.setup(yes=True) == 0
    saved = json.loads(config.read_text())
    assert saved["mcpServers"]["0x41"]["command"] == "wsl.exe"
    assert saved["mcpServers"]["monomi"] == {"command": "wsl.exe", "args": ["x"]}  # untouched
    assert saved["theme"] == "dark"
    out = capsys.readouterr().out
    assert "0x41: new" in out and "backup of the old file" in out and "quit the Claude app" in out
    backups = list(config.parent.glob("claude_desktop_config.json.bak-*"))
    assert len(backups) == 1 and "0x41" not in json.loads(backups[0].read_text())["mcpServers"]


def test_setup_twice_changes_nothing(config, wsl, capsys):
    mcp_setup.setup(yes=True)
    capsys.readouterr()
    assert mcp_setup.setup(yes=True) == 0
    assert "already set up" in capsys.readouterr().out


def test_setup_asks_first_and_no_means_no(config, wsl, monkeypatch):
    before = config.read_text()
    monkeypatch.setattr(mcp_setup, "ask", lambda q: False)
    assert mcp_setup.setup() == 0
    assert config.read_text() == before


def test_a_broken_config_is_never_overwritten(tmp_path, monkeypatch, capsys):
    good, bad = tmp_path / "a.json", tmp_path / "b.json"
    good.write_text('{"mcpServers": {}}')
    bad.write_text('{"mcpServers": {')  # broken JSON
    monkeypatch.setattr(mcp_setup, "config_paths", lambda: ([str(good), str(bad)], str(good)))
    assert mcp_setup.main(yes=True) == 1
    assert good.read_text() == '{"mcpServers": {}}'  # not even the good one: all are read first
    assert bad.read_text() == '{"mcpServers": {'
    assert "isn't valid JSON" in capsys.readouterr().err


def test_print_only_writes_nothing(config, wsl, capsys):
    before = config.read_text()
    assert cli.main(["mcp", "setup", "--print"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["mcpServers"]["0x41"]["command"] == "wsl.exe"
    assert config.read_text() == before


def test_cli_mcp_setup_yes(config, wsl):
    assert cli.main(["mcp", "setup", "--yes"]) == 0
    assert "0x41" in json.loads(config.read_text())["mcpServers"]
