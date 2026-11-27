"""Shared test setup: no test may reach the network.

0x41 drives monomi, akashi and kaidoku. Tests must stub their network calls. A
blocked call raises inside the code (which may catch it and carry on), so the
attempt is also recorded and the test fails at the end, naming where it tried
to go."""

import socket

import pytest


@pytest.fixture(autouse=True)
def no_real_key_file(tmp_path, monkeypatch):
    """No test reads the real ~/.config/0x41/keys.env (v0.11.1: `0x41 vet`
    loads it): tests that want one make their own."""
    from x41 import keys
    monkeypatch.setattr(keys, "keys_path", lambda: str(tmp_path / "no-keys.env"))


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    tried = []

    def blocked(self, address, *rest):
        tried.append(str(address))
        raise OSError(f"test tried to reach the network: {address}")

    def blocked_sendto(self, data, *rest):
        return blocked(self, rest[-1] if rest else "?")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket.socket, "sendto", blocked_sendto)
    yield
    assert not tried, f"test tried to reach the network: {sorted(set(tried))}"
