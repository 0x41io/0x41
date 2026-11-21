"""
Check that the installed mønømi, akashi and kaidoku match what this 0x41 pins.

0x41 pins each tool to an exact git tag in pyproject.toml. `pip install -e .`
doesn't always upgrade a git package that's already installed, so after a pin
bump the venv can quietly keep an old version. Then 0x41 crashes on its first
import of something new, and the Claude app only shows "couldn't start". This
check runs first and says what's wrong and the one command that fixes it.

    older than the pin  -> refuse to start (new code needs what the old version lacks)
    newer than the pin  -> start, with a one-line warning (newer releases keep the
                           contracts 0x41 relies on, so they shouldn't block you)
    not installed       -> refuse to start

The pins come from 0x41's own installed metadata (the dependency lines in
pyproject.toml, as pip recorded them), so a pin bump updates this check by
itself. The installed versions come from each tool's own code, not from pip's
records, which can be stale for editable installs.
"""

import importlib
import importlib.metadata
import re

# Where each tool keeps its version in its own code.
VERSION_ATTRS = {
    "monomi": ("monomi.common", "VERSION"),
    "akashi": ("akashi", "__version__"),
    "kaidoku": ("kaidoku.sources", "VERSION"),
}
_PIN = re.compile(r"^(?P<name>[a-z0-9_-]+)\s*@\s*(?P<url>git\+\S+?)@v(?P<version>\d+(?:\.\d+)*)$")


def _parse(version: str) -> tuple:
    return tuple(int(p) for p in version.split("."))


def pins() -> dict:
    """{name: (version, git url)} for every tool 0x41 pins. Empty when 0x41
    isn't installed (running from a plain source folder): nothing to check."""
    try:
        reqs = importlib.metadata.requires("0x41") or []
    except importlib.metadata.PackageNotFoundError:
        return {}
    out = {}
    for req in reqs:
        m = _PIN.match(req.strip())
        if m and m["name"] in VERSION_ATTRS:
            out[m["name"]] = (m["version"], m["url"])
    return out


def installed(name: str) -> str | None:
    """The version the tool's own code reports, or None if it won't import."""
    module, attr = VERSION_ATTRS[name]
    try:
        return str(getattr(importlib.import_module(module), attr))
    except Exception:
        return None


def fix_command(name: str, version: str, url: str) -> str:
    return f'pip install --force-reinstall --no-deps "{name} @ {url}@v{version}"'


def check(x41_version: str) -> tuple[list, list]:
    """(problems, warnings): each a list of messages. Problems mean 0x41
    shouldn't start; warnings are worth one line."""
    problems, warnings = [], []
    for name, (want, url) in sorted(pins().items()):
        have = installed(name)
        if have is None:
            problems.append(f"{name} isn't installed (or won't load), but 0x41 {x41_version} needs {want}.\n"
                            f"  Fix: {fix_command(name, want, url)}")
        elif _parse(have) < _parse(want):
            problems.append(f"{name} {have} is installed, but 0x41 {x41_version} needs {want}.\n"
                            f"  Fix: {fix_command(name, want, url)}")
        elif _parse(have) > _parse(want):
            warnings.append(f"{name} {have} is newer than the {want} 0x41 {x41_version} was tested with")
    return problems, warnings
