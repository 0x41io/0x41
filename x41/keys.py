"""
API keys for vets, started from Claude or from a terminal.

The Claude app starts `0x41 mcp` without reading ~/.bashrc, so keys set
there never reach the vets it starts, and mønømi's OTX source falls back to
its saved copy. The tools already read their keys from the environment, and
every vet inherits the server's, so the server loads them from one file at
startup:

    ~/.config/0x41/keys.env        OTX_API_KEY=...   (one per line, # comments ok)

Rules:
- Only OTX_API_KEY and NVD_API_KEY load. Anything else is ignored with a
  note (ANTHROPIC_API_KEY on purpose: nothing over MCP uses AI briefings).
- The file is refused unless only you can read it (permissions 600, owned by
  you, not a link), the same rule ssh uses for private keys.
- Values are never printed, logged or returned: only names.
- A key already set in the environment wins.

`0x41 mcp keys` writes the file from the keys set in your terminal, so you
never type them: it shows the names (not the values) and asks first.

Since v0.11.1 `0x41 vet` in a terminal loads the same file too (load_for_vet),
so a key saved once works everywhere; a key set in the terminal still wins.
"""

import os
import stat
import sys

ALLOWED = ("OTX_API_KEY", "NVD_API_KEY")


def keys_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".config", "0x41", "keys.env")


def private_problem(path: str) -> str | None:
    """Why the file can't be trusted with keys, or None."""
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        return f"{path} is a link; use a real file"
    if os.name != "posix":
        return None  # native Windows: no Unix permissions to check
    if st.st_uid != os.getuid():
        return f"{path} isn't owned by you"
    if st.st_mode & 0o077:
        return f"{path} can be read by others (permissions {stat.S_IMODE(st.st_mode):o}); run: chmod 600 {path}"
    return None


def read(path: str) -> tuple[dict, list]:
    """(allowed keys found, notes). Notes name lines, never values."""
    keys, notes = {}, []
    with open(path, encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):].strip()
            name, eq, value = line.partition("=")
            name, value = name.strip(), value.strip().strip("'\"")
            if not eq or not name:
                notes.append(f"line {n} isn't NAME=value, skipped")
            elif name not in ALLOWED:
                notes.append(f"{name} ignored (only {', '.join(ALLOWED)} are loaded)")
            elif not value:
                notes.append(f"{name} is empty, skipped")
            else:
                keys[name] = value
    return keys, notes


def load(path: str | None = None, environ=None) -> list:
    """Put the file's keys into the environment (so every vet inherits them).
    Returns lines for the server's startup notes: names only."""
    path = path or keys_path()
    environ = os.environ if environ is None else environ
    if not os.path.lexists(path):
        return [f"no key file ({path}): vets started here run without OTX / NVD keys "
                "(`0x41 mcp keys` writes one)"]
    problem = private_problem(path)
    if problem:
        return [f"key file refused, running without it: {problem}"]
    keys, notes = read(path)
    loaded, kept = [], []
    for name, value in keys.items():
        if environ.get(name):
            kept.append(name)
        else:
            environ[name] = value
            loaded.append(name)
    out = [f"keys loaded from {path}: {', '.join(loaded) or 'none'}"]
    if kept:
        out.append(f"already set in the environment, kept: {', '.join(kept)}")
    return out + notes


def load_for_vet(path: str | None = None, environ=None) -> list:
    """`0x41 vet` (v0.11.1): the same file and rules as load(), but only says
    something when it matters: which keys it loaded, or why the file was
    refused. Quiet when there's no file or every key was already set (a vet
    started over MCP already has the server's keys). Names only."""
    path = path or keys_path()
    environ = os.environ if environ is None else environ
    if not os.path.lexists(path):
        return []
    problem = private_problem(path)
    if problem:
        return [f"key file refused, running without it: {problem}"]
    keys, _ = read(path)
    loaded = [n for n, v in keys.items() if not environ.get(n)]
    for name in loaded:
        environ[name] = keys[name]
    return [f"keys from {path}: {', '.join(loaded)}"] if loaded else []


def write_from_env(path: str | None = None, environ=None, ask=input, out=print) -> int:
    """`0x41 mcp keys`: write the allowed keys set in this terminal to the
    key file, readable only by you. Shows names, never values; asks first."""
    path = path or keys_path()
    environ = os.environ if environ is None else environ
    names = [n for n in ALLOWED if environ.get(n)]
    if not names:
        out(f"None of {', '.join(ALLOWED)} is set in this terminal, so there's nothing to write.")
        return 1
    existing = {}
    if os.path.lexists(path):
        problem = private_problem(path)
        if problem and "permissions" not in problem:  # a loose mode gets fixed by the rewrite below
            out(f"Not touching it: {problem}")
            return 1
        existing, _ = read(path)
    keys = {**existing, **{n: environ[n] for n in names}}
    out(f"Will write {', '.join(names)} (from this terminal; values not shown) to {path}")
    if existing:
        out(f"  keeping from the file: {', '.join(k for k in existing if k not in names) or 'nothing else'}")
    out("  readable only by you (permissions 600)")
    try:
        if ask("Write it? [y/N] ").strip().lower() not in ("y", "yes"):
            out("Nothing was written.")
            return 0
    except EOFError:
        out("Nothing was written.")
        return 0
    folder = os.path.dirname(path)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # 600 from the first byte
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("# API keys for vets started from Claude (0x41 mcp). Only you can read this file.\n")
        for name, value in keys.items():
            f.write(f"{name}={value}\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    out(f"Wrote {path}. Fully quit and reopen the Claude app so the server loads it.")
    return 0


def main(argv=None) -> int:
    return write_from_env()


if __name__ == "__main__":
    sys.exit(main())
