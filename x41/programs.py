"""
Bug bounty programs: a scope file per program, named, so a vet can be scoped
from the terminal (`0x41 vet DOMAIN --program NAME`) or by an agent over MCP
(`vet_start(domain, program=NAME)`) without anyone handing it a path.

A program is programs/<name>.txt in 0x41's data folder, in mønømi's scope
format (one rule per line: `example.com`, `*.example.com`, `!excluded.example.com`),
so a program's scope list can be pasted in. The person writes these files;
an agent can only name one, the same rule as app-check cases (cases/<name>.toml):
no MCP tool takes a scope file, a path or a target list.

What a program does in a vet (v0.10.0), all passive:
  - mønømi gets it as --scope: hosts it doesn't allow are set aside, with the
    rule named, instead of becoming leads (gate check 1);
  - its exact in-scope hosts under the vetted domain go to mønømi as extra
    hosts, so hosts certificate logs never show (behind a wildcard
    certificate) are still checked.
Active proofs still need a person: `0x41 approve` at a terminal, or `0x41 vet
--scope` in one. A vet started over MCP never runs them.
"""

import os
import re

from x41 import home

# Same shape as an app-check case name: letters, digits, - and _
PROGRAM_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")


class ProgramError(ValueError):
    pass


def programs_dir() -> str:
    return home.data_dir("programs")


def program_path(name: str) -> str:
    """programs/<name>.txt for a bare program name, or ProgramError. Only
    names, never paths: the file must really be inside programs/ (no symlink out)."""
    if not isinstance(name, str) or not PROGRAM_NAME.fullmatch(name):
        raise ProgramError(f"not a program name: {name!r} (lowercase letters, digits, - and _, "
                           "like superdrug)")
    folder = os.path.realpath(programs_dir())
    path = os.path.join(folder, name + ".txt")
    if not os.path.isfile(path):
        raise ProgramError(f"no program {name!r} in {folder} (see list_programs)")
    if os.path.dirname(os.path.realpath(path)) != folder:
        raise ProgramError(f"program {name!r} must be a real file inside {folder}")
    return path


def exact_hosts(scope_path: str, domain: str) -> list[str]:
    """The scope file's exact in-scope hosts under this domain (not the domain
    itself, not wildcards, not excluded), for mønømi to check as extra hosts.
    Read with mønømi's own scope parser, so 0x41 reads the file the same way."""
    from monomi import scope as monomi_scope
    s = monomi_scope.load(scope_path)
    domain = domain.lower().rstrip(".")
    return sorted({r.domain for r in s.inclusions
                   if not r.wildcard and r.domain.endswith("." + domain) and s.match(r.domain).allowed})


def list_programs() -> list:
    """Every program in programs/: its name and what its scope holds (counts
    and a few domains), or why it won't load. The file's lines are the
    person's own; still, they're data, never instructions."""
    from monomi import scope as monomi_scope
    folder = programs_dir()
    out = []
    for fname in sorted(os.listdir(folder)) if os.path.isdir(folder) else []:
        name, ext = os.path.splitext(fname)
        if ext != ".txt" or not PROGRAM_NAME.fullmatch(name):
            continue
        s = monomi_scope.load(os.path.join(folder, fname))
        problem = s.problem()
        if problem:
            out.append({"program": name, "problem": problem})
            continue
        out.append({"program": name,
                    "in_scope_rules": len(s.inclusions), "excluded_rules": len(s.exclusions),
                    "wildcards": sorted(r.text for r in s.inclusions if r.wildcard)[:10],
                    "exact_hosts": sum(1 for r in s.inclusions if not r.wildcard),
                    "rejected_lines": len(s.rejected)})
    return out
