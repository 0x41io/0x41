"""
The command line: `0x41 vet` is the command, and the old `run` name is gone
(a clean rename, so nobody ends up with two names for one thing).
"""

import pytest

from x41 import cli


def test_vet_is_the_command():
    args = cli.build_parser().parse_args(["vet", "example.test", "--scope", "scope.txt", "--no-active"])
    assert args.command == "vet"
    assert args.domain == "example.test"
    assert args.scope == "scope.txt" and args.no_active is True


def test_the_old_run_name_is_refused(capsys):
    with pytest.raises(SystemExit) as e:
        cli.build_parser().parse_args(["run", "example.test"])
    assert e.value.code == 2
    assert "vet" in capsys.readouterr().err  # argparse names the real choice


def test_main_hands_vet_to_the_vet_module(monkeypatch):
    seen = {}

    def fake_vet(domain, **kw):
        seen["domain"], seen["kw"] = domain, kw
        return 0

    monkeypatch.setattr(cli.vet_mod, "vet", fake_vet)
    assert cli.main(["vet", "example.test", "--no-cves"]) == 0
    assert seen["domain"] == "example.test"
    assert seen["kw"]["cves"] is False and seen["kw"]["active"] is True
