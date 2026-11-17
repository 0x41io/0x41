# [0x41]

**One command for the 0x41 suite: [mønømi](https://github.com/0x41io/monomi) finds · [akashi](https://github.com/0x41io/akashi) proves · [kaidoku](https://github.com/0x41io/kaidoku) explains.**

```bash
0x41 vet example.com --scope scope.txt
```

```
[1/4] mønømi   scanning example.com (passive)
               … monomi's own live output …
[2/4] akashi   passive proofs (DNS / registry only, automatic)
               P1   email_spoofing   ✓ confirmed
[3/4] akashi   active proofs (need your yes)
               L2   around_cdn: check whether www.example.com can be reached directly at the origin …
                    would send: GET https://www.example.com/  (through the CDN)
                    would send: GET the origin 203.0.113.10 with Host: www.example.com
               Run these 1 active proof(s)? Type yes to run, anything else to skip: yes
               L2   around_cdn       ✓ confirmed
[4/4] kaidoku  explaining
               2 finding(s) explained

Report: runs/example.com/2026-11-16_183000/report.md
        2 confirmed · 0 unclear
```

## What `0x41 vet` does

1. **mønømi scans** the domain with its passive checks only: certificate logs, DNS, email records, and Shodan's existing port/CVE data. Nothing is sent to the target.
2. **akashi proves the passive leads** (takeovers, email spoofing) with fresh DNS and registry lookups. These run automatically: they never contact the target.
3. **akashi proves the active leads** (going around the CDN) only if you gave a scope file, only for hosts it allows, and only after it has shown every request it would send and you type `yes`. No terminal, no `yes`, or `--no-active`: nothing active is sent.
4. **kaidoku explains** every finding (with `--ai`, an AI briefing that cites the proof and never changes a verdict), and the CVEs mønømi saw on the target's own servers.

The report (`report.md`) has a summary table, each finding with its proof, fix and owner, the CVEs, and a **Not proven** list: active proofs that didn't run and leads akashi doesn't prove yet, each with the reason. Nothing is dropped silently.

## Install

Requires Python 3.14 (mønømi needs it).

```bash
git clone https://github.com/0x41io/0x41.git
cd 0x41
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

`pip install -e .` installs the `0x41` command and the three tools at release tags that are tested together (see `pyproject.toml`). Exact tags, not loose version ranges: the tools aren't on PyPI, and a bare package name could pull a stranger's package.

## Use

```bash
0x41 vet example.com                          # scan, passive proofs, explain
0x41 vet example.com --scope scope.txt        # plus active proofs, after your yes
0x41 vet example.com --scope scope.txt --ai   # plus AI briefings (needs ANTHROPIC_API_KEY)
0x41 vet example.com --no-active              # never run active proofs
0x41 vet example.com --no-cves                # skip the CVE lookups
0x41 vet example.com --hosts lab-hosts.txt    # also check hostnames you already know
```

The scope file uses mønømi's format (in/out lines, as on a bug bounty program's page). Without the NVD API key, CVE lookups are spaced out (~5 a minute); `NVD_API_KEY` makes them faster.

**Where runs go:** `runs/<domain>/<time>/` in the clone (`scan.json`, `verdicts.jsonl`, `run.json`, `report.md`). A plain install uses `~/.0x41`; `X41_HOME` overrides both. Every verdict also goes into akashi's proof history, so `akashi recheck` works after you fix something.

## Guardrails

- Passive by default: mønømi's passive checks and akashi's DNS/registry proofs.
- Active proofs are fail-closed: no scope file, no active proof. In scope only.
- Every active request is shown before it's sent, and nothing active runs without a typed `yes` at a real terminal. There is no flag that skips the question.
- Text from the target (hostnames, headlines, evidence) is made harmless before it goes into the report.
- The run folder name comes from the domain with only safe characters, so a domain can't choose where files are written.

## Development

```bash
pip install -e . pytest
python -m pytest -q
```

The tests stand fakes in for the tools (so the safety rules are tested directly) and run the real akashi and kaidoku once end to end. No test can reach the network.

## License

MIT
