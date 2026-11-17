# Rules for AI agents working on 0x41

- Work on a branch whose name differs from any tag (e.g. `v0.1.1-fix`, never `v0.1.1`).
- Nothing is merged or tagged until Claude has reviewed it.
- Never add a way to run active proofs without a scope file and a typed `yes` at a real terminal. No `--yes` flag.
  Over MCP that yes is `0x41 approve` (x41/approvals.py, issue #2): no MCP tool may take a scope file, a research
  file, a yes or an approval, and `prove_run` takes only the approval id. Approvals are single use, short-lived,
  and bound to the exact requests and file hashes shown.
- Tool versions are pinned to exact tags in `pyproject.toml`. Bump them together, and only to tags whose tests pass together.
- Release checklist: VERSION (`x41/__init__.py`), README, behavior tests, `pycodestyle --max-line-length=120`, `git diff --check`, one lab run on 41xlab.
