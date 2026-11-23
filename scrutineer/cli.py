"""Command-line front door.

``scrutineer install [target]`` installs the skill set. ``scrutineer mcp …`` and
``scrutineer servicemap …`` run the toolkit's bundled scripts, which is how the
installed skills reach them from any repo.

Reachable two ways, both running the same shared core:
    python -m scrutineer install /path/to/repo        # from a clone
    pip install scrutineer && scrutineer install .    # from PyPI
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from . import __version__, installer, paths


def _run_script(script: Path, args: list[str]) -> int:
    """Run a bundled script with this interpreter, passing its arguments through."""
    if not script.exists():
        print(f"ERROR: bundled script is missing: {script}", file=sys.stderr)
        return 1
    return subprocess.run([sys.executable, str(script), *args]).returncode


def _add_mcp_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "mcp",
        help="Run an MCP-review script (used by /scrutineer-mcp).",
        description=(
            "Run one of the bundled MCP-review scripts. Everything after the script name "
            "is passed to it unchanged; `scrutineer mcp analyze --help` shows its options."
        ),
    )
    p.add_argument("script", choices=sorted(paths.MCP_SCRIPTS), help="Which script to run.")
    p.add_argument("args", nargs=argparse.REMAINDER, help="Arguments for the script.")
    p.set_defaults(func=lambda a: _run_script(paths.MCP_SCRIPTS[a.script], a.args))


def _add_servicemap_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "servicemap",
        help="Service-map helpers (used by /scrutineer-servicemap).",
        description="`validate PATH` checks a service map; `schema` prints the schema's path.",
    )
    actions = p.add_subparsers(dest="action", required=True)
    v = actions.add_parser("validate", help="Validate a servicemap.json.")
    v.add_argument("args", nargs=argparse.REMAINDER, help="Arguments for the validator.")
    v.set_defaults(func=lambda a: _run_script(paths.SERVICEMAP_VALIDATOR, a.args))
    s = actions.add_parser("schema", help="Print the path of the service-map schema.")
    s.set_defaults(func=_cmd_schema)


def _cmd_schema(args: argparse.Namespace) -> int:
    if not paths.SERVICEMAP_SCHEMA.exists():
        print(f"ERROR: schema is missing: {paths.SERVICEMAP_SCHEMA}", file=sys.stderr)
        return 1
    print(paths.SERVICEMAP_SCHEMA)
    return 0


def _add_install_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "install",
        help="Install the full Scrutineer skill set into a repo.",
        description=(
            "Copy the servicemap, mcp and setup skills and generate the peer-review and "
            "security-review skills into TARGET/.claude/commands/, all named scrutineer-*."
        ),
    )
    p.add_argument(
        "target", nargs="?", default=".",
        help="Repo to install into (default: current directory).",
    )
    sm = p.add_mutually_exclusive_group()
    sm.add_argument(
        "--crawl", action="store_true",
        help="If no servicemap.json exists, run a headless `claude -p` crawl to create one.",
    )
    sm.add_argument(
        "--service-map", "-s", metavar="PATH", default=None,
        help="Use an existing service map at PATH instead of discovering/crawling.",
    )
    p.add_argument(
        "--force", "-f", action="store_true",
        help="Overwrite existing command files.",
    )
    p.set_defaults(func=_cmd_install)


def _cmd_install(args: argparse.Namespace) -> int:
    try:
        result = installer.install(
            args.target,
            crawl=args.crawl,
            service_map=args.service_map,
            force=args.force,
        )
    except (FileNotFoundError, NotADirectoryError, RuntimeError) as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 1

    print("\n" + "─" * 60)
    if result.installed:
        print(f"✓ Installed into {result.target}/.claude/commands/:")
        for name in result.installed:
            print(f"    /{name[:-3]}")  # strip .md → slash command name
    else:
        print("Nothing was written (all targets existed; re-run with --force).")
    if result.skipped_crawl:
        print(
            "\nNote: skills were generated without a service map. For cross-service\n"
            "      awareness, run /scrutineer-servicemap in Claude Code, then re-run\n"
            "      `scrutineer install --force` (or pass --crawl)."
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scrutineer",
        description="Agentic code review toolkit.",
    )
    parser.add_argument("--version", action="version", version=f"scrutineer {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    _add_install_parser(sub)
    _add_mcp_parser(sub)
    _add_servicemap_parser(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
