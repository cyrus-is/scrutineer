"""Forward the old `scrutineer` command to vld8, with a notice on stderr.

The notice goes to stderr because installed skills read some commands' stdout
(`scrutineer servicemap schema` prints a path they open).
"""

from __future__ import annotations

import sys

# Worded for every way scrutineer could have been installed. Under pipx or
# `uv tool`, the vld8 that came in as a dependency has no `vld8` on PATH, so the
# user has to install vld8 itself, the same way they installed scrutineer.
NOTICE = (
    "scrutineer has been renamed vld8 and is no longer maintained under this name.\n"
    "This command forwards to vld8 for now. To switch:\n"
    "  1. Install vld8 the way you installed scrutineer: pip install vld8,\n"
    "     pipx install vld8, or uv tool install vld8.\n"
    "  2. Run `vld8 install` in each repo to replace the /scrutineer-* skills with /vld8-*.\n"
    "  3. Uninstall scrutineer the same way you installed it.\n"
    "Details: https://pypi.org/project/scrutineer/"
)

# Subcommands whose name changed in the rename; everything else kept its name.
RENAMED = {"servicemap": "map"}


def translate(argv: list[str]) -> list[str]:
    """Map scrutineer's arguments onto vld8's."""
    if argv and argv[0] in RENAMED:
        return [RENAMED[argv[0]], *argv[1:]]
    return list(argv)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    print(NOTICE, file=sys.stderr, flush=True)
    from vld8.cli import main as vld8_main

    return vld8_main(translate(argv))
