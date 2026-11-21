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

## What changed? `0x41 diff`

```bash
0x41 diff example.com                          # its last two finished runs
0x41 diff runs/example.com/A runs/example.com/B  # two runs you pick
0x41 diff example.com --json                   # as data
0x41 diff example.com --exit-code              # exit 1 if anything important changed
```

Read-only: it compares two saved vets and contacts nothing. **Important:** new hosts (or known names that start resolving), new open ports or CVEs on the target's own servers (not CDN edge), new leads and attack paths, a lead akashi now confirms, a confirmed lead now fixed (or open again), weaker email posture. **Info:** new hosts outside the scope file (don't touch), hosts that stopped existing in DNS, stronger email posture, wildcard changes, leads mønømi stopped flagging.

It stays honest: leads are matched by what they're about, never their P1/L2 number; a host only counts as new if a source that found it was complete in the older run too; a source that failed is listed under "Couldn't tell", never as a change; and only akashi can call something fixed.

0x41 is open source. A hosted, paid continuous-monitoring service will reuse this same change engine; that service isn't part of this repo.

## Use it from Claude (MCP)

`0x41 mcp` is an MCP server, so an AI agent like Claude can run the whole chain: mønømi finds, akashi proves, kaidoku explains. (mønømi's own MCP server stays the place for its separate checks.)

```bash
0x41 mcp setup        # adds "0x41" to the Claude desktop app's config (shows the change, asks first)
```

Then fully quit and reopen the Claude app. The tools:

| Tool | What it does |
|---|---|
| `vet_start(domain, hosts_file?)` | starts a passive vet in the background and returns a job id at once (a vet takes 1-3 minutes) |
| `vet_status(job_id, detail?)` | running, failed (with the end of its log), or done: the tally, each finding with akashi's verdict, proof, fix and owner, what wasn't proven and why, active proofs waiting, the CVEs mønømi saw. `detail="full"` adds the whole report |
| `list_vets(domain?)` | earlier vets, newest first, including ones run from the terminal |
| `explain_cves(ids)` | kaidoku's CVE lookup: NVD, EPSS, CISA KEV and a verdict, up to 5 per call |
| `prove_request(job_id, lead_ids?)` | asks you to approve a vet's waiting active proofs; sends nothing, returns an approval id |
| `prove_run(rid)` | **ACTIVE**: runs what you approved, once |

### Active proofs from Claude: you approve them in your terminal

Active proofs (they send requests to the target's own servers) never run on Claude's say-so. The flow:

1. Claude calls `prove_request` and gives you an approval id. Nothing is sent.
2. **You** run, in your own terminal:
   ```bash
   0x41 approve k7m2-x9pq --scope scope.txt
   ```
   It shows every lead and every exact request it would send (and anything blocked or out of scope), then waits for you to type `yes`. It refuses if stdin isn't a real terminal.
3. Claude calls `prove_run` with the id. It runs only what you were shown.

An approval covers one vet, the leads listed, the exact requests shown, and the scope file (and research header file) **as they were when you approved** (sha256). It's good for **one run, within 15 minutes**, even with more than one `0x41 mcp` server running (the first to claim it wins, the rest refuse); an unanswered request expires after an hour. If anything differs (the scope file was edited, akashi's plan changed, it was already used, it expired), `prove_run` refuses and nothing is sent. Every event, refusals included, is kept in `runs/<domain>/<time>/approvals/<id>.json` (times in UTC), and every request akashi sends is in its `scans/active.log` with `"via": "mcp"` and the approval id.

**The limit:** this stops an agent that only has MCP tools. An agent that can also run shell commands on your machine could fake a terminal, the same limit as mønømi's own approvals: anything that can run commands as you can approve as you. Don't leave an agent with both unattended.

The approvals use mønømi's approvals core (`monomi.approvalcore`), the same code that gates mønømi's own active checks, so every 0x41 approval gate shares one tested copy.

Why not a confirmation popup in the Claude app (MCP "elicitation")? It was tested on 2026-11-16 and the app doesn't support it (it answers `Method not found`), and other clients have been reported to accept such prompts without showing them. A terminal yes can't be faked by the model.

What it never does:

- **Active proofs without you.** No tool takes a scope file, a research file or a yes, and every vet runs with `--no-active`. Active proofs run only through `prove_run`, after your typed `yes` in a terminal.
- **AI briefings.** In a chat, Claude is already the explainer, so kaidoku runs without them here (nothing is billed to your Anthropic API key).
- **Read other files.** Job ids only reach folders inside `runs/`, and `hosts_file` must be a `.txt` inside mønømi's scans folder.

One vet runs at a time. A vet keeps going if the Claude app closes, and `vet_status` picks it up later. Setup copies `X41_HOME`, `MONOMI_HOME`, `AKASHI_HOME` and `KAIDOKU_HOME` (if set) into the entry, because the Claude app doesn't read your shell's startup files; API keys are never written there.

**API keys for vets started from Claude.** For the same reason, keys in your `~/.bashrc` don't reach them (mønømi's OTX source then falls back to its saved copy). Save them once:

```bash
0x41 mcp keys        # copies OTX_API_KEY / NVD_API_KEY from this terminal (shows names, never values; asks first)
```

That writes `~/.config/0x41/keys.env`, readable only by you (permissions 600). The server loads it at startup and every vet it starts inherits the keys. Only `OTX_API_KEY` and `NVD_API_KEY` are loaded (nothing over MCP uses AI briefings, so `ANTHROPIC_API_KEY` stays out); a file others can read, or a link, is refused; values are never printed or logged; a key already set in the environment wins. Restart the Claude app after changing it.

## Guardrails

- Passive by default: mønømi's passive checks and akashi's DNS/registry proofs.
- Active proofs are fail-closed: no scope file, no active proof. In scope only.
- Every active request is shown before it's sent, and nothing active runs without a typed `yes` at a real terminal. There is no flag that skips the question.
- Text from the target (hostnames, headlines, evidence) is made harmless before it goes into the report.
- The run folder name comes from the domain with only safe characters, so a domain can't choose where files are written.
- Over MCP: active proofs only after your typed `yes` in a terminal (`0x41 approve`), once, for exactly what you were shown; no tool can take a scope file; text from the target is marked as data, never instructions.

## Development

```bash
pip install -e . pytest
python -m pytest -q
```

The tests stand fakes in for the tools (so the safety rules are tested directly) and run the real akashi and kaidoku once end to end. No test can reach the network.

## License

MIT
