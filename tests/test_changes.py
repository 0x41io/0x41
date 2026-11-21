"""0x41 diff: one test per row of the levels table (issue #3), plus the
honesty rules. Every run here is planted: .test domains, documentation IPs
(203.0.113.x, 198.51.100.x), nothing real, nothing sent."""

import copy
import json
import os

import pytest

from x41 import changes, cli

D = "diff.test"


def scan(**over):
    """A small, complete mønømi scan; tests change only what they're about."""
    s = {
        "monomi_version": "1.19.0", "target": D,
        "sources": {"certspotter": {"source": "certspotter", "subdomains": [D, f"www.{D}"]}},
        "errors": {},
        "subdomains": [D, f"www.{D}"],
        "enrichment": {"hosts": {D: {"dns": "live"}, f"www.{D}": {"dns": "live"}}, "wildcards": {}},
        "exposure": {"ips": {"203.0.113.10": {"ports": [443], "vulns": [], "shared_edge": False},
                             "198.51.100.40": {"ports": [80, 443], "vulns": [], "shared_edge": True}},
                     "nothing_seen": {}},
        "email": {"spf": {"record": "v=spf1 include:mail.test -all"},
                  "dmarc": {"record": "v=DMARC1; p=reject", "policy": "reject"}},
        "paths": {"paths": [], "leads": []},
    }
    s.update(over)
    return s


def run(**over):
    r = {"domain": D, "started": "2026-11-20T10:00:00", "scope": None, "verdicts": []}
    r.update(over)
    return r


def save(root, name, s, r):
    d = os.path.join(root, name)
    os.makedirs(d)
    for fname, data in (("scan.json", s), ("run.json", r)):
        with open(os.path.join(d, fname), "w") as f:
            json.dump(data, f)
    return d


def diff(tmp_path, old_scan, new_scan, old_run=None, new_run=None, scope=None):
    a = save(tmp_path, "a", old_scan, old_run or run())
    b = save(tmp_path, "b", new_scan, new_run or run(started="2026-11-21T10:00:00"))
    return changes.compare(changes.load_run(a), changes.load_run(b), scope)


def kinds(result, level=None):
    return [c["kind"] for c in result["changes"] if level is None or c["level"] == level]


def with_host(s, host, source="certspotter", dns="live"):
    s = copy.deepcopy(s)
    s["sources"][source]["subdomains"].append(host)
    s["subdomains"].append(host)
    s["enrichment"]["hosts"][host] = {"dns": dns}
    return s


# --- no change ------------------------------------------------------------------

def test_same_scan_twice_is_no_change(tmp_path):
    r = diff(tmp_path, scan(), scan())
    assert r["changes"] == [] and r["couldnt_tell"] == []
    assert "No changes." in changes.markdown(r)


# --- hosts ----------------------------------------------------------------------

def test_new_host_is_important(tmp_path):
    r = diff(tmp_path, scan(), with_host(scan(), f"api.{D}"))
    assert kinds(r, "important") == ["new_host"]


def test_new_host_outside_scope_is_info(tmp_path):
    sc = tmp_path / "scope.txt"
    sc.write_text(f"www.{D}\n{D}\n")
    r = diff(tmp_path, scan(), with_host(scan(), f"api.{D}"), scope=str(sc))
    assert kinds(r) == ["new_host_out_of_scope"]
    assert r["changes"][0]["level"] == "info"


def test_scope_defaults_to_the_newer_runs_scope(tmp_path):
    sc = tmp_path / "scope.txt"
    sc.write_text(f"www.{D}\n")
    r = diff(tmp_path, scan(), with_host(scan(), f"api.{D}"),
             new_run=run(started="2026-11-21T10:00:00", scope=str(sc)))
    assert kinds(r) == ["new_host_out_of_scope"]


def test_missing_scope_file_says_so_and_compares_anyway(tmp_path):
    r = diff(tmp_path, scan(), with_host(scan(), f"api.{D}"), scope=str(tmp_path / "nope.txt"))
    assert kinds(r) == ["new_host"]
    assert "scope not applied" in r["scope_note"]


def test_host_from_a_source_that_failed_last_time_is_couldnt_tell(tmp_path):
    old = scan()
    old["sources"]["otx"] = {"source": "otx", "subdomains": []}
    old["sources"]["otx"]["partial"] = "stopped early"
    new = scan()
    new["sources"]["otx"] = {"source": "otx", "subdomains": []}
    new = with_host(new, f"api.{D}", source="otx")
    r = diff(tmp_path, old, new)
    assert "new_host" not in kinds(r)
    assert any("may be new" in c["what"] for c in r["couldnt_tell"])


def test_host_from_a_source_missing_last_time_is_couldnt_tell(tmp_path):
    new = scan()
    new["sources"]["hosts file"] = {"source": "hosts file", "subdomains": []}
    new = with_host(new, f"api.{D}", source="hosts file")
    r = diff(tmp_path, scan(), new)
    assert "new_host" not in kinds(r)


def test_host_gone_needs_no_such_host(tmp_path):
    new = scan()
    new["enrichment"]["hosts"][f"www.{D}"] = {"dns": "no_such_host"}
    r = diff(tmp_path, scan(), new)
    assert kinds(r, "info") == ["host_gone"]


def test_host_that_starts_resolving_is_important(tmp_path):
    old = with_host(scan(), f"api.{D}", dns="no_such_host")
    new = with_host(scan(), f"api.{D}", dns="live")
    assert kinds(diff(tmp_path, old, new), "important") == ["host_live"]


def test_host_that_starts_resolving_outside_scope_is_info(tmp_path):
    sc = tmp_path / "scope.txt"
    sc.write_text(f"www.{D}\n")
    old = with_host(scan(), f"api.{D}", dns="no_such_host")
    new = with_host(scan(), f"api.{D}", dns="live")
    assert kinds(diff(tmp_path, old, new, scope=str(sc)), "info") == ["host_live_out_of_scope"]


def test_host_missing_from_lists_is_not_gone(tmp_path):
    new = scan(subdomains=[D])
    new["enrichment"]["hosts"].pop(f"www.{D}")
    new["sources"]["certspotter"]["subdomains"] = [D]
    assert "host_gone" not in kinds(diff(tmp_path, scan(), new))


def test_failed_source_is_couldnt_tell_never_a_change(tmp_path):
    new = scan(errors={"crt.sh": "HTTP 502"})
    r = diff(tmp_path, scan(), new)
    assert r["changes"] == []
    assert {"what": "crt.sh", "why": "HTTP 502 (newer run)"} in r["couldnt_tell"]


BEHIND = "no certificates for this domain yet: the crt.sh database answered with 0 while Cert Spotter found 3"


def test_same_failure_in_both_runs_is_one_line_with_monomis_reason(tmp_path):
    r = diff(tmp_path, scan(errors={"crt.sh": BEHIND}), scan(errors={"crt.sh": BEHIND}))
    assert r["couldnt_tell"] == [{"what": "crt.sh", "why": "behind on the CT logs (both runs)"}]


def test_different_failures_say_which_run(tmp_path):
    r = diff(tmp_path, scan(errors={"crt.sh": BEHIND}), scan(errors={"crt.sh": "HTTP 502"}))
    assert r["couldnt_tell"] == [{"what": "crt.sh",
                                  "why": "older run: behind on the CT logs; newer run: HTTP 502"}]


def test_saved_copy_is_one_entry_not_two(tmp_path):
    # From the 41xlab lab run: OTX timed out, mønømi used its saved copy, and
    # filed the error as "AlienVault OTX" but the copy as "otx".
    new = scan(errors={"AlienVault OTX": "read timed out; using the saved copy from 2026-11-21T03:05:41+00:00"})
    new["sources"]["otx"] = {"source": "otx", "subdomains": [], "from_saved": True,
                             "collected_at": "2026-11-21T03:05:41+00:00"}
    r = diff(tmp_path, scan(), new)
    assert r["couldnt_tell"] == [{"what": "AlienVault OTX",
                                  "why": "used a saved copy from 2026-11-21T03:05:41+00:00 (newer run)"}]


def test_saved_copy_counts_as_incomplete(tmp_path):
    new = scan()
    new["sources"]["certspotter"]["from_saved"] = True
    assert changes.source_health(new)["certspotter"] == "incomplete"


# --- ports and CVEs ---------------------------------------------------------------

def test_new_port_on_own_server_is_important(tmp_path):
    new = scan()
    new["exposure"]["ips"]["203.0.113.10"]["ports"] = [443, 8080]
    r = diff(tmp_path, scan(), new)
    assert kinds(r, "important") == ["new_port"]
    assert r["changes"][0]["key"] == "203.0.113.10:8080"


def test_new_port_on_cdn_edge_is_ignored(tmp_path):
    new = scan()
    new["exposure"]["ips"]["198.51.100.40"]["ports"] = [80, 443, 8443]
    assert diff(tmp_path, scan(), new)["changes"] == []


def test_new_cve_on_own_server_is_important(tmp_path):
    new = scan()
    new["exposure"]["ips"]["203.0.113.10"]["vulns"] = ["CVE-2099-0001"]
    assert kinds(diff(tmp_path, scan(), new), "important") == ["new_cve"]


def test_ip_moving_from_nothing_seen_to_open_port(tmp_path):
    old = scan()
    old["exposure"]["nothing_seen"] = {"203.0.113.20": {"shared_edge": False}}
    new = scan()
    new["exposure"]["ips"]["203.0.113.20"] = {"ports": [22], "vulns": [], "shared_edge": False}
    assert kinds(diff(tmp_path, old, new)) == ["new_port"]


def test_no_port_data_is_couldnt_tell(tmp_path):
    old = scan()
    del old["exposure"]
    r = diff(tmp_path, old, scan())
    assert r["changes"] == []
    assert any(c["what"] == "ports and CVEs" for c in r["couldnt_tell"])


# --- leads and akashi verdicts ----------------------------------------------------

TAKEOVER = {"id": "P1", "rule": "takeover", "title": f"takeover: old.{D}",
            "targets": {"hosts": [f"old.{D}"], "cname": "old-zz9.azurewebsites.net"}}


def test_new_lead_is_important(tmp_path):
    new = scan(paths={"paths": [TAKEOVER], "leads": []})
    assert kinds(diff(tmp_path, scan(), new), "important") == ["new_lead"]


def test_renumbered_lead_is_not_a_change(tmp_path):
    old = scan(paths={"paths": [TAKEOVER], "leads": []})
    new = scan(paths={"paths": [{**TAKEOVER, "id": "P2"}], "leads": []})
    assert diff(tmp_path, old, new)["changes"] == []


def test_lead_that_disappears_is_not_called_fixed(tmp_path):
    old = scan(paths={"paths": [TAKEOVER], "leads": []})
    r = diff(tmp_path, old, scan())
    assert kinds(r) == ["lead_not_flagged"]
    assert r["changes"][0]["level"] == "info"
    assert "fixed" not in r["changes"][0]["title"]


KEY = "takeover:old.diff.test>old-zz9.azurewebsites.net"


def test_disappeared_lead_akashi_confirmed_points_at_recheck(tmp_path):
    # The lab case: akashi confirmed email spoofing, then DMARC went to
    # reject, mønømi stopped flagging it and akashi had nothing to prove.
    old = scan(paths={"paths": [TAKEOVER], "leads": []})
    r = diff(tmp_path, old, scan(), run(verdicts=[verdict("confirmed")]))
    assert kinds(r) == ["lead_not_flagged"]
    assert "akashi recheck" in r["changes"][0]["detail"]
    assert "fixed" not in r["changes"][0]["title"]


def test_disappeared_lead_never_confirmed_has_no_recheck_pointer(tmp_path):
    old = scan(paths={"paths": [TAKEOVER], "leads": []})
    r = diff(tmp_path, old, scan(), run(verdicts=[verdict("inconclusive")]))
    assert "akashi recheck" not in r["changes"][0]["detail"]


def verdict(status):
    return {"id": "P1", "rule": "takeover", "status": status, "key": KEY, "headline": f"takeover: old.{D}"}


@pytest.mark.parametrize("was, now, kind, level", [
    (None, "confirmed", "confirmed", "important"),
    ("inconclusive", "confirmed", "confirmed", "important"),
    ("confirmed", "ruled_out", "fixed", "important"),
    ("ruled_out", "confirmed", "reopened", "important"),
    ("confirmed", "inconclusive", "unclear", "info"),
])
def test_verdict_transitions(tmp_path, was, now, kind, level):
    old_run = run(verdicts=[verdict(was)] if was else [])
    new_run = run(started="2026-11-21T10:00:00", verdicts=[verdict(now)])
    r = diff(tmp_path, scan(), scan(), old_run, new_run)
    assert [(c["kind"], c["level"]) for c in r["changes"]] == [(kind, level)]


@pytest.mark.parametrize("was", [None, "inconclusive", "ruled_out"])
def test_ruled_out_is_only_fixed_after_confirmed(tmp_path, was):
    old_run = run(verdicts=[verdict(was)] if was else [])
    new_run = run(started="2026-11-21T10:00:00", verdicts=[verdict("ruled_out")])
    assert diff(tmp_path, scan(), scan(), old_run, new_run)["changes"] == []


def test_same_verdict_twice_is_no_change(tmp_path):
    r = diff(tmp_path, scan(), scan(), run(verdicts=[verdict("confirmed")]),
             run(started="2026-11-21T10:00:00", verdicts=[verdict("confirmed")]))
    assert r["changes"] == []


# --- email and wildcards --------------------------------------------------------

def test_weaker_dmarc_is_important(tmp_path):
    new = scan()
    new["email"]["dmarc"] = {"record": "v=DMARC1; p=none", "policy": "none"}
    r = diff(tmp_path, scan(), new)
    assert kinds(r, "important") == ["email_weaker"]
    assert "reject -> none" in r["changes"][0]["title"]


def test_stronger_dmarc_is_info(tmp_path):
    old = scan()
    old["email"]["dmarc"] = {"record": None, "policy": None}
    assert kinds(diff(tmp_path, old, scan()), "info") == ["email_stronger"]


def test_weaker_spf_is_important(tmp_path):
    new = scan()
    new["email"]["spf"] = {"record": "v=spf1 include:mail.test ~all"}
    assert kinds(diff(tmp_path, scan(), new), "important") == ["email_weaker"]


def test_email_error_is_couldnt_tell(tmp_path):
    r = diff(tmp_path, scan(), scan(email={"error": "timeout"}))
    assert r["changes"] == []
    assert any(c["what"] == "email posture" for c in r["couldnt_tell"])


def test_new_wildcard_is_info(tmp_path):
    new = scan()
    new["enrichment"]["wildcards"] = {f"dev.{D}": {"ips": ["203.0.113.30"]}}
    assert kinds(diff(tmp_path, scan(), new), "info") == ["wildcard_new"]


def test_changed_wildcard_is_info(tmp_path):
    old = scan()
    old["enrichment"]["wildcards"] = {f"dev.{D}": {"ips": ["203.0.113.30"]}}
    new = scan()
    new["enrichment"]["wildcards"] = {f"dev.{D}": {"ips": ["203.0.113.31"]}}
    assert kinds(diff(tmp_path, old, new)) == ["wildcard_changed"]


# --- refusals, ordering, finding runs -------------------------------------------

def test_different_domains_refused(tmp_path):
    with pytest.raises(changes.DiffError, match="different domains"):
        diff(tmp_path, scan(), scan(), new_run=run(domain="other.test", started="2026-11-21T10:00:00"))


def test_old_monomi_scan_refused(tmp_path):
    with pytest.raises(changes.DiffError, match="older than"):
        diff(tmp_path, scan(monomi_version="1.14.0"), scan())


def test_runs_given_backwards_are_put_in_order(tmp_path):
    a = save(tmp_path, "a", scan(), run(started="2026-11-21T10:00:00"))
    b = save(tmp_path, "b", with_host(scan(), f"api.{D}"), run(started="2026-11-20T10:00:00"))
    r = changes.compare(changes.load_run(a), changes.load_run(b))
    # b is older, so going b -> a, api disappears from lists (never "gone") and nothing is new
    assert r["older"]["dir"] == b and "new_host" not in kinds(r)


def test_find_runs_skips_unfinished_and_takes_the_last_two(tmp_path):
    folder = tmp_path / D
    for name, finished in (("2026-11-18_100000", True), ("2026-11-19_100000", True),
                           ("2026-11-20_100000", True), ("2026-11-21_100000", False)):
        (folder / name).mkdir(parents=True)
        if finished:
            (folder / name / "run.json").write_text("{}")
    older, newer = changes.find_runs(D, root=str(tmp_path))
    assert older.endswith("2026-11-19_100000") and newer.endswith("2026-11-20_100000")


def test_find_runs_needs_two(tmp_path):
    (tmp_path / D / "2026-11-20_100000").mkdir(parents=True)
    (tmp_path / D / "2026-11-20_100000" / "run.json").write_text("{}")
    with pytest.raises(changes.DiffError, match="needs two"):
        changes.find_runs(D, root=str(tmp_path))


# --- the report and the command ---------------------------------------------------

def test_markdown_makes_target_text_safe(tmp_path):
    host = f"x`y|z<a.{D}"
    r = diff(tmp_path, scan(), with_host(scan(), host))
    text = changes.markdown(r)
    assert "`" not in text.split("\n", 3)[-1] and "<a" not in text


def test_cli_json_is_pure_json_and_exit_code(tmp_path, capsys):
    a = save(tmp_path, "a", scan(), run())
    b = save(tmp_path, "b", with_host(scan(), f"api.{D}"), run(started="2026-11-21T10:00:00"))
    assert cli.main(["diff", a, b, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["counts"]["important"] == 1
    assert cli.main(["diff", a, b, "--exit-code"]) == 1
    assert cli.main(["diff", a, a, "--exit-code"]) == 0


def test_cli_cant_compare_exits_2(tmp_path, capsys):
    assert cli.main(["diff", str(tmp_path / "nope"), str(tmp_path / "nope2")]) == 2
    assert "missing" in capsys.readouterr().err
