"""
0x41 mcp setup: add the 0x41 MCP server to the Claude desktop app's config.

    0x41 mcp setup          # show the change, ask, then write it
    0x41 mcp setup --yes    # write without asking
    0x41 mcp setup --print  # only print the entry (to add it by hand)

The careful parts come from mønømi's own setup (monomi.mcp_setup), so both
tools find the same config files and follow the same safety rules: every
copy of the config is found (Windows can have several, and the app reads
only one), all are read before any is written (a broken file stops
everything), only the "0x41" entry changes, the old file is backed up, and
the new one is swapped in whole.

Nothing here can turn anything active on: the server has no active tools.

The data folders. The Claude app starts a WSL server with `wsl.exe -e`,
which doesn't read ~/.bashrc, so X41_HOME / MONOMI_HOME / AKASHI_HOME /
KAIDOKU_HOME from there would be missing and the vets would quietly use
other folders than your terminal does. So setup copies the ones set right
now into the entry. Folder paths only: API keys are never written into the
config (a plaintext secret in an agent's config is exactly what not to do).
"""

import json
import os
import sys

from monomi.mcp_setup import SetupError, ask, config_paths, in_wsl, load_config, write_text

NAME = "0x41"  # the server's name in the config
HOME_VARS = ("X41_HOME", "MONOMI_HOME", "AKASHI_HOME", "KAIDOKU_HOME")
RESTART = ("fully quit the Claude app, not just its window (Windows: right-click its tray "
           "icon > Quit), open it again, and ask Claude to list the 0x41 vets")


def homes() -> dict:
    """The data-folder variables set right now, as full paths."""
    return {v: os.path.abspath(os.path.expanduser(os.environ[v]))
            for v in HOME_VARS if os.environ.get(v, "").strip()}


def server_entry() -> dict:
    """How the Claude app should start `0x41 mcp`.

    In WSL the app runs on Windows, so it starts Linux through wsl.exe (-d
    picks this Linux, -e runs a program directly, no shell); the data
    folders go in through the `env` program, since Windows-side settings
    don't reach Linux. Elsewhere the config's own "env" key carries them."""
    run = [sys.executable, "-m", "x41", "mcp"]
    folders = homes()
    if in_wsl():
        if folders:
            run = ["env", *[f"{k}={v}" for k, v in folders.items()], *run]
        distro = os.environ.get("WSL_DISTRO_NAME")
        return {"command": "wsl.exe", "args": (["-d", distro] if distro else []) + ["-e", *run]}
    entry = {"command": run[0], "args": run[1:]}
    if folders:
        entry["env"] = folders
    return entry


def setup(yes: bool = False) -> int:
    found, standard = config_paths()
    targets = found or [standard]
    configs = {path: load_config(path) for path in targets}  # all read first: a broken one stops everything
    entry = server_entry()

    plans = {}
    for path, cfg in configs.items():
        old = cfg.get("mcpServers", {}).get(NAME)
        plans[path] = "new" if old is None else "unchanged" if old == entry else "changing"
        print(f"\n{path}")
        if not os.path.exists(path):
            print("  no config yet: it will be created")
        print(f"  0x41: {plans[path]}")
        if plans[path] == "changing":
            print("  now:\n" + "\n".join("    " + ln for ln in json.dumps(old, indent=2).splitlines()))
        if plans[path] != "unchanged":
            print("  will be:\n" + "\n".join("    " + ln for ln in json.dumps(entry, indent=2).splitlines()))

    to_write = [p for p, status in plans.items() if status != "unchanged"]
    if not to_write:
        print("\n0x41 is already set up in the Claude app. Nothing to change.")
        return 0
    if not yes and not ask("\nWrite this? [y/N] "):
        print("Nothing was changed.")
        return 0
    for path in to_write:
        cfg = configs[path]
        new = {**cfg, "mcpServers": {**cfg.get("mcpServers", {}), NAME: entry}}
        backup = write_text(path, json.dumps(new, indent=2) + "\n")
        print(f"Updated {path}" + (f"\n  backup of the old file: {backup}" if backup else ""))
    missing = [v for v in HOME_VARS if v not in homes()]
    if missing:
        print(f"Not set right now, so not in the entry: {', '.join(missing)} "
              "(each tool then uses its default folder).")
    print(f"\nNext: {RESTART}.")
    return 0


def main(yes: bool = False, print_only: bool = False) -> int:
    try:
        if print_only:
            print(json.dumps({"mcpServers": {NAME: server_entry()}}, indent=2))
            return 0
        return setup(yes=yes)
    except SetupError as e:
        print(f"0x41 mcp setup: {e}", file=sys.stderr)
        return 1
