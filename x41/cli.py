"""
The 0x41 command line.

    0x41 vet example.com                        scan, prove (passive), explain
    0x41 vet example.com --scope scope.txt      ...and active proofs, after a typed yes
    0x41 vet example.com --ai                   ...with AI briefings (kaidoku)
    0x41 mcp                                    the MCP server, for AI agents
    0x41 mcp setup                              add it to the Claude desktop app's config
    0x41 mcp keys                               save this terminal's OTX / NVD keys for it (600 file)
    0x41 approve RID --scope scope.txt          approve active proofs Claude asked for (typed yes)
    0x41 approve RID --scope FILE --creds FILE  ...or an app check Claude asked for (app_request)
    0x41 diff example.com                       what changed between its last two runs (read-only)
    0x41 diff RUN_DIR RUN_DIR                   ...or between two run folders you pick
"""

import argparse
import sys

from x41 import __version__, vet as vet_mod


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="0x41", description="0x41: mønømi finds · akashi proves · kaidoku explains")
    p.add_argument("--version", action="version", version=f"0x41 {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("vet", help="scan a domain, prove its leads, explain every finding")
    r.add_argument("domain", help="target domain, e.g. example.com")
    scope = r.add_mutually_exclusive_group()
    scope.add_argument("--scope", metavar="FILE",
                       help="scope file (Monomi's format): out-of-scope hosts are set aside, its exact hosts "
                            "are checked too, and active proofs need it (they still ask first)")
    scope.add_argument("--program", metavar="NAME",
                       help="a program's scope file by name: programs/NAME.txt in 0x41's data folder")
    r.add_argument("--ai", action="store_true", help="AI briefings for each finding and CVE (kaidoku)")
    r.add_argument("--no-active", action="store_true", help="never run active proofs, even with --scope")
    r.add_argument("--no-cves", action="store_true", help="skip explaining the CVEs monomi saw")
    r.add_argument("--hosts", metavar="FILE", help="also check hostnames you already know (passed to monomi)")
    # Hidden: the MCP server picks the run folder up front so it can follow the job.
    # vet() still refuses any folder outside runs/.
    r.add_argument("--run-dir", help=argparse.SUPPRESS)
    a = sub.add_parser("approve", help="approve active proofs an agent asked for (shows every request, typed yes)")
    a.add_argument("rid", help="the approval id the agent gave you, e.g. k7m2-x9pq")
    a.add_argument("--scope", metavar="FILE", required=True,
                   help="scope file (mønømi's format): only hosts it allows are touched")
    a.add_argument("--research", metavar="FILE", help="research header file (sent on active requests)")
    a.add_argument("--creds", metavar="FILE",
                   help="app checks only: your test accounts' logins (JSON, chmod 600); never shown")
    d = sub.add_parser("diff", help="what changed between two vet runs, and which changes matter (read-only)")
    d.add_argument("runs", nargs="+", metavar="DOMAIN_OR_RUN",
                   help="a domain (its last two runs), or two run folders")
    d.add_argument("--scope", metavar="FILE",
                   help="scope file for new hosts (default: the one the newer vet used)")
    d.add_argument("--json", action="store_true", help="print the result as JSON")
    d.add_argument("--exit-code", action="store_true",
                   help="exit 1 when there are important changes (for scripts), like git diff")
    m = sub.add_parser("mcp", help="run the MCP server for AI agents (talks over stdin/stdout)")
    m.add_argument("action", nargs="?", choices=["setup", "keys"],
                   help="setup: add the server to the Claude desktop app's config; "
                        "keys: save this terminal's OTX / NVD keys for it")
    m.add_argument("--yes", action="store_true", help="setup: write without asking")
    m.add_argument("--print", dest="print_only", action="store_true",
                   help="setup: only print the config entry")
    return p


def check_versions() -> bool:
    """False (after saying why on stderr) if an installed tool is older than
    0x41 pins. stderr, never stdout: for `0x41 mcp` stdout is the MCP channel,
    and the Claude app shows stderr in its log for the server."""
    from x41 import versions
    problems, warnings = versions.check(__version__)
    for w in warnings:
        print(f"0x41: note: {w}", file=sys.stderr)
    if problems:
        print("0x41 can't start:", file=sys.stderr)
        for p in problems:
            print(f"- {p}", file=sys.stderr)
        return False
    return True


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    needs_tools = args.command in ("vet", "approve") or (args.command == "mcp" and args.action is None)
    if needs_tools and not check_versions():
        return 2
    if args.command == "mcp":
        if args.action == "setup":
            from x41 import mcp_setup
            return mcp_setup.main(yes=args.yes, print_only=args.print_only)
        if args.action == "keys":
            from x41 import keys
            return keys.main()
        # nothing may reach stdout before the server starts: it's the MCP channel
        from x41 import mcp_server
        mcp_server.main([])
        return 0
    if args.command == "diff":
        return run_diff(args)   # before the banner, so --json output is pure JSON
    print(f"[0x41] {__version__} · mønømi finds · akashi proves · kaidoku explains")
    if args.command == "approve":
        from x41 import app_approvals, approvals
        try:
            if app_approvals.is_app(args.rid):
                return app_approvals.approve(args.rid, args.scope, args.creds, args.research)
            if args.creds:
                raise approvals.ApprovalError("--creds is only for app checks; this id is a vet's active proofs")
            return approvals.approve(args.rid, args.scope, args.research)
        except approvals.ApprovalError as e:
            print(f"0x41: {e}", file=sys.stderr)
            return 2
        except (KeyboardInterrupt, EOFError):
            print("\n0x41: not approved. Nothing will run.", file=sys.stderr)
            return 130
    if args.command == "vet":
        try:
            scope_file = args.scope
            if args.program:
                from x41 import programs
                try:
                    scope_file = programs.program_path(args.program)
                except programs.ProgramError as e:
                    print(f"0x41: {e}; nothing ran.", file=sys.stderr)
                    return 2
            return vet_mod.vet(args.domain, scope=scope_file, ai=args.ai, active=not args.no_active,
                               cves=not args.no_cves, hosts_file=args.hosts, run_dir=args.run_dir,
                               program=args.program)
        except KeyboardInterrupt:
            print("\n0x41: stopped. Anything already proven is in akashi's proof history.", file=sys.stderr)
            return 130
    return 1


def run_diff(args) -> int:
    """0x41 diff: exit 0 (or 1 with --exit-code and important changes), 2 if it can't compare."""
    import json
    from x41 import changes
    try:
        if len(args.runs) == 1:
            older, newer = changes.find_runs(args.runs[0])
        elif len(args.runs) == 2:
            older, newer = args.runs
        else:
            raise changes.DiffError("give a domain, or exactly two run folders")
        result = changes.compare(changes.load_run(older), changes.load_run(newer), args.scope)
    except changes.DiffError as e:
        print(f"0x41 diff: {e}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2) if args.json else changes.markdown(result))
    return 1 if args.exit_code and result["counts"]["important"] else 0
