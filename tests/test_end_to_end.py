"""
The whole chain with the REAL akashi.api, kaidoku.api and report: a scan
built by monomi's own code, the passive email proof, the active
around-the-CDN proof after a typed yes, and kaidoku's explanation, ending in
the report. Only monomi's scan step, DNS and HTTP are stubbed.
"""

from datetime import datetime

import pytest
from monomi import cli as monomi_cli
from monomi import emailauth, evidence
from monomi.paths import build_paths

from x41 import vet as vet_mod

T = "2026-11-08T12:00:00+00:00"
PAGE = "<title>Origins test site</title>hello"


def _host(ip, provider):
    return {"ips": [ip], "dns": "live", "private_ips": [], "provider": provider}


def _ip(hosts, provider, edge):
    return {"ports": [80, 443], "vulns": [], "tags": [], "cpes": [], "hosts": hosts,
            "provider": provider, "shared_edge": edge, "risky": []}


def write_scan(path):
    """www behind Cloudflare, the apex on its own origin, no DMARC (from akashi's tests)."""
    names = ["origins.test", "www.origins.test"]
    results = {
        "target": "origins.test",
        "sources": {"certspotter": {"source": "certspotter", "subdomains": names, "collected_at": T}},
        "errors": {}, "subdomains": sorted(names),
        "enrichment": {"hosts": {"www.origins.test": _host("198.51.100.40", "Cloudflare"),
                                 "origins.test": _host("203.0.113.10", "DigitalOcean")},
                       "private_ip_hosts": [], "collected_at": T},
        "exposure": {"ips": {"198.51.100.40": _ip(["www.origins.test"], "Cloudflare", True),
                             "203.0.113.10": _ip(["origins.test"], "DigitalOcean", False)},
                     "nothing_seen": {}, "collected_at": T},
        "email": {
            "spf": {"record": None, "issues": [{"problem": "missing", "detail": "no SPF"}]},
            "dmarc": {"record": None, "policy": None, "issues": [{"problem": "missing", "detail": "no DMARC"}]},
            "dkim": {"record": None, "selectors": [], "issues": [{"problem": "not-confirmed", "detail": "none"}]},
            "verdict": {"verdict": "spoofable", "summary": "no DMARC enforcement", "notes": []},
            "collected_at": T},
    }
    results["evidence"] = evidence.build_evidence(results)
    results["paths"] = build_paths(results, results["evidence"])
    monomi_cli.save_json(results, path)


@pytest.fixture
def stubbed_network(monkeypatch, tmp_path):
    from akashi.proofs import around_cdn
    monkeypatch.setenv("AKASHI_HOME", str(tmp_path / "akashi-home"))
    monkeypatch.setattr(emailauth, "check_email", lambda domain: {
        "spf": emailauth.check_spf([]), "dmarc": emailauth.check_dmarc([]),
        "dkim": {"record": None, "selectors": [], "issues": []},
        "verdict": {"verdict": "spoofable", "summary": "", "notes": []}})
    sent = []

    def send(url, headers, verify):
        sent.append(url)
        return around_cdn.Fetched(url, 200, {}, PAGE)
    monkeypatch.setattr(around_cdn, "_send", send)
    return sent


def real_tools(answer):
    tools = vet_mod.default_tools()
    tools.scan = lambda domain, path, hosts: (write_scan(path), 0)[1]
    tools.ask = lambda prompt: answer
    tools.interactive = lambda: True
    return tools


def test_the_whole_chain(tmp_path, stubbed_network):
    scope = tmp_path / "scope.txt"
    scope.write_text("origins.test\n*.origins.test\n", encoding="utf-8")
    code = vet_mod.vet("origins.test", scope=str(scope), tools=real_tools("yes"),
                       out_root=str(tmp_path / "runs"), now=datetime(2026, 11, 16, 2, 0, 0))
    assert code == 0 and len(stubbed_network) == 2              # the two around-the-CDN requests
    text = (tmp_path / "runs" / "origins.test" / "2026-11-16_020000" / "report.md").read_text()
    assert "# 0x41 vet: origins.test" in text
    assert "Email spoofing: **CONFIRMED**" in text
    assert "Origin reachable around the CDN: **CONFIRMED**" in text
    assert "no SPF and no DKIM" in text                          # akashi v0.1.3's tailored fix
    assert "**2 confirmed" in text


def test_the_whole_chain_without_a_yes_sends_nothing(tmp_path, stubbed_network):
    scope = tmp_path / "scope.txt"
    scope.write_text("origins.test\n*.origins.test\n", encoding="utf-8")
    vet_mod.vet("origins.test", scope=str(scope), tools=real_tools("no"),
                out_root=str(tmp_path / "runs"), now=datetime(2026, 11, 16, 2, 0, 0))
    assert stubbed_network == []                                 # nothing sent to the origin
    text = (tmp_path / "runs" / "origins.test" / "2026-11-16_020000" / "report.md").read_text()
    assert "Email spoofing: **CONFIRMED**" in text and "skipped: not approved" in text
