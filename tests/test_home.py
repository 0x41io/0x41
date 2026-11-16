import os

from x41 import home


def test_x41_home_wins(monkeypatch, tmp_path):
    monkeypatch.setenv("X41_HOME", str(tmp_path))
    assert home.data_dir("runs") == os.path.join(str(tmp_path), "runs")


def test_running_from_the_repo_uses_it(monkeypatch):
    monkeypatch.delenv("X41_HOME", raising=False)
    assert home.data_home() == home.REPO_DIR


def test_installed_uses_dot_0x41(monkeypatch):
    monkeypatch.delenv("X41_HOME", raising=False)
    monkeypatch.setattr(home, "running_from_repo", lambda folder=None: False)
    assert home.data_home() == os.path.join(os.path.expanduser("~"), ".0x41")
