"""
The key file (x41/keys.py): only OTX / NVD keys load, only from a file
nobody else can read, never printed; `0x41 mcp keys` writes it from the
terminal's keys without showing them. Every test uses a temp file and a
stand-in environment (a dict), so no real key or env var is touched.
"""

import os
import stat

import pytest

from x41 import cli, keys, mcp_server

OTX, NVD = "otx-secret-1234", "nvd-secret-5678"


@pytest.fixture
def keyfile(tmp_path):
    def make(text, mode=0o600):
        path = tmp_path / "keys.env"
        path.write_text(text)
        os.chmod(path, mode)
        return str(path)
    return make


def test_load_puts_the_allowed_keys_in_the_environment(keyfile):
    env = {}
    notes = keys.load(keyfile(f"# mine\nOTX_API_KEY={OTX}\nexport NVD_API_KEY=\"{NVD}\"\n"), env)
    assert env == {"OTX_API_KEY": OTX, "NVD_API_KEY": NVD}
    assert "OTX_API_KEY, NVD_API_KEY" in notes[0]
    assert OTX not in "".join(notes) and NVD not in "".join(notes)  # names only, never values


def test_only_otx_and_nvd_load(keyfile):
    env = {}
    notes = keys.load(keyfile(f"ANTHROPIC_API_KEY=sk-ant-secret\nOTX_API_KEY={OTX}\n"), env)
    assert env == {"OTX_API_KEY": OTX}
    assert any("ANTHROPIC_API_KEY ignored" in n for n in notes)
    assert "sk-ant-secret" not in "".join(notes)


@pytest.mark.skipif(os.name != "posix", reason="Unix permissions")
@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660])
def test_a_file_others_can_read_is_refused(keyfile, mode):
    env = {}
    path = keyfile(f"OTX_API_KEY={OTX}\n", mode)
    notes = keys.load(path, env)
    assert env == {}
    assert "refused" in notes[0] and f"chmod 600 {path}" in notes[0]


def test_a_link_is_refused(tmp_path, keyfile):
    real = keyfile(f"OTX_API_KEY={OTX}\n")
    link = tmp_path / "link.env"
    link.symlink_to(real)
    env = {}
    assert "is a link" in keys.load(str(link), env)[0] and env == {}


def test_a_key_already_set_wins(keyfile):
    env = {"OTX_API_KEY": "from-the-shell"}
    notes = keys.load(keyfile(f"OTX_API_KEY={OTX}\nNVD_API_KEY={NVD}\n"), env)
    assert env == {"OTX_API_KEY": "from-the-shell", "NVD_API_KEY": NVD}
    assert any("kept: OTX_API_KEY" in n for n in notes)


def test_no_file_is_fine_and_says_so(tmp_path):
    env = {}
    notes = keys.load(str(tmp_path / "missing.env"), env)
    assert env == {} and "no key file" in notes[0] and "0x41 mcp keys" in notes[0]


def test_bad_lines_are_noted_by_line_number_not_content(keyfile):
    env = {}
    notes = keys.load(keyfile("just-a-secret-string\nOTX_API_KEY=\n"), env)
    assert env == {}
    assert "line 1 isn't NAME=value" in notes[1] and "OTX_API_KEY is empty" in notes[2]
    assert "just-a-secret-string" not in "".join(notes)


# --- 0x41 mcp keys ------------------------------------------------------------

def test_write_from_env_writes_a_private_file_without_showing_values(tmp_path):
    path = tmp_path / "cfg" / "0x41" / "keys.env"
    shown = []
    code = keys.write_from_env(str(path), {"OTX_API_KEY": OTX, "NVD_API_KEY": NVD, "ANTHROPIC_API_KEY": "sk"},
                               ask=lambda q: "y", out=shown.append)
    assert code == 0
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(path.parent).st_mode) == 0o700
    text = path.read_text()
    assert f"OTX_API_KEY={OTX}" in text and f"NVD_API_KEY={NVD}" in text and "ANTHROPIC" not in text
    assert OTX not in "".join(shown) and NVD not in "".join(shown)
    env = {}
    keys.load(str(path), env)  # and the server can read what it wrote
    assert env == {"OTX_API_KEY": OTX, "NVD_API_KEY": NVD}


def test_write_from_env_asks_first(tmp_path):
    path = tmp_path / "keys.env"
    assert keys.write_from_env(str(path), {"OTX_API_KEY": OTX}, ask=lambda q: "n", out=lambda s: None) == 0
    assert not path.exists()


def test_write_from_env_with_nothing_set(tmp_path):
    shown = []
    assert keys.write_from_env(str(tmp_path / "k.env"), {}, ask=lambda q: "y", out=shown.append) == 1
    assert "nothing to write" in shown[0]


def test_write_from_env_keeps_the_other_key_and_fixes_permissions(keyfile):
    path = keyfile(f"NVD_API_KEY={NVD}\n", 0o644)
    keys.write_from_env(path, {"OTX_API_KEY": OTX}, ask=lambda q: "y", out=lambda s: None)
    env = {}
    keys.load(path, env)
    assert env == {"OTX_API_KEY": OTX, "NVD_API_KEY": NVD}
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


# --- the server ------------------------------------------------------------------

def test_the_server_loads_keys_at_start_and_prints_only_names(keyfile, monkeypatch, capsys):
    path = keyfile(f"OTX_API_KEY={OTX}\n")
    monkeypatch.setattr(keys, "keys_path", lambda: path)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    monkeypatch.setattr(mcp_server.mcp, "run", lambda: None)
    try:
        assert cli.main(["mcp"]) == 0
        assert os.environ.get("OTX_API_KEY") == OTX  # vets started from here inherit it
    finally:
        os.environ.pop("OTX_API_KEY", None)
    got = capsys.readouterr()
    assert got.out == ""  # stdout is the MCP channel
    assert "keys loaded" in got.err and "OTX_API_KEY" in got.err and OTX not in got.err


def test_cli_mcp_keys_runs_the_writer(monkeypatch):
    monkeypatch.setattr(keys, "write_from_env", lambda: 7)
    assert cli.main(["mcp", "keys"]) == 7
