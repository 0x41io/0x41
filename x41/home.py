"""
Where 0x41 keeps its runs (runs/<domain>/<time>/). The same rule as the
other 0x41 tools:

    1. the X41_HOME environment variable, if it's set
    2. else the repo folder, when 0x41 runs from a copy of the repo
    3. else ~/.0x41 (a plain install)
"""

import os
import re

PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.dirname(PACKAGE_DIR)
ENV_VAR = "X41_HOME"
_NAME_LINE = re.compile(r'^\s*name\s*=\s*"0x41"\s*$', re.MULTILINE)


def running_from_repo(folder: str = REPO_DIR) -> bool:
    try:
        with open(os.path.join(folder, "pyproject.toml"), encoding="utf-8") as f:
            return bool(_NAME_LINE.search(f.read()))
    except OSError:
        return False


def data_home() -> str:
    chosen = os.environ.get(ENV_VAR, "").strip()
    if chosen:
        return os.path.abspath(os.path.expanduser(chosen))
    if running_from_repo():
        return REPO_DIR
    return os.path.join(os.path.expanduser("~"), ".0x41")


def data_dir(*parts: str) -> str:
    return os.path.join(data_home(), *parts)
