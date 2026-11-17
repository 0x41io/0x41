"""
The 0x41 command line.

    0x41 vet example.com                        scan, prove (passive), explain
    0x41 vet example.com --scope scope.txt      ...and active proofs, after a typed yes
    0x41 vet example.com --ai                   ...with AI briefings (kaidoku)
    0x41 mcp                                    the MCP server, for AI agents
    0x41 mcp setup                              add it to the Claude desktop app's config
    0x41 mcp keys                               save this terminal's OTX / NVD keys for it (600 file)
    0x41 approve RID --scope scope.txt          approve active proofs Claude asked for (typed yes)
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
    r.add_argument("--scope", metavar="FILE",
                   help="scope file (Monomi's format): needed for active proofs, which still ask first")
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
    m = sub.add_parser("mcp", help="run the MCP server for AI agents (talks over stdin/stdout)")
    m.add_argument("action", nargs="?", choices=["setup", "keys"],
                   help="setup: add the server to the Claude desktop app's config; "
                        "keys: save this terminal's OTX / NVD keys for it")
    m.add_argument("--yes", action="store_true", help="setup: write without asking")
    m.add_argument("--print", dest="print_only", action="store_true",
                   help="setup: only print the config entry")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
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
    print(f"[0x41] {__version__} · mønømi finds · akashi proves · kaidoku explains")
    if args.command == "approve":
        from x41 import approvals
        try:
            return approvals.approve(args.rid, args.scope, args.research)
        except approvals.ApprovalError as e:
            print(f"0x41: {e}", file=sys.stderr)
            return 2
        except (KeyboardInterrupt, EOFError):
            print("\n0x41: not approved. Nothing will run.", file=sys.stderr)
            return 130
    if args.command == "vet":
        try:
            return vet_mod.vet(args.domain, scope=args.scope, ai=args.ai, active=not args.no_active,
                               cves=not args.no_cves, hosts_file=args.hosts, run_dir=args.run_dir)
        except KeyboardInterrupt:
            print("\n0x41: stopped. Anything already proven is in akashi's proof history.", file=sys.stderr)
            return 130
    return 1
