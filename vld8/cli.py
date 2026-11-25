"""Command-line front door.

``vld8 install [target]`` installs the skill set. ``vld8 mcp …`` and
``vld8 map …`` run the toolkit's bundled scripts, which is how the
installed skills reach them from any repo.

Reachable two ways, both running the same shared core:
    python -m vld8 install /path/to/repo        # from a clone
    pip install vld8 && vld8 install .    # from PyPI
"""

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
        help="Run an MCP-review script (used by /vld8-mcp).",
        description=(
            "Run one of the bundled MCP-review scripts. Everything after the script "
            "name is passed to it unchanged; `vld8 mcp analyze --help` shows its "
            "options."
        ),
    )
    p.add_argument(
        "script", choices=sorted(paths.MCP_SCRIPTS), help="Which script to run."
    )
    p.add_argument("args", nargs=argparse.REMAINDER, help="Arguments for the script.")
    p.set_defaults(func=lambda a: _run_script(paths.MCP_SCRIPTS[a.script], a.args))


def _add_map_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "map",
        help="Service-map helpers (used by /vld8-map).",
        description=(
            "`validate PATH` checks a service map; `schema` prints the schema's path."
        ),
    )
    actions = p.add_subparsers(dest="action", required=True)
    v = actions.add_parser("validate", help="Validate a servicemap.json.")
    v.add_argument(
        "args", nargs=argparse.REMAINDER, help="Arguments for the validator."
    )
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
        help="Install the full vld8 skill set into a repo.",
        description=(
            "Copy the map, mcp and setup skills and generate the peer-review and "
            "security-review skills into TARGET/.claude/commands/, all named vld8-*."
        ),
    )
    p.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Repo to install into (default: current directory).",
    )
    sm = p.add_mutually_exclusive_group()
    sm.add_argument(
        "--crawl",
        action="store_true",
        help=(
            "If no servicemap.json exists, run a headless `claude -p` crawl to "
            "create one."
        ),
    )
    sm.add_argument(
        "--service-map",
        "-s",
        metavar="PATH",
        default=None,
        help="Use an existing service map at PATH instead of discovering/crawling.",
    )
    p.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Overwrite existing command files.",
    )
    p.add_argument(
        "--preview",
        action="append",
        default=[],
        metavar="MILESTONE",
        choices=sorted(paths.PREVIEW_MILESTONES),
        help=(
            "Include review output that is still behind a milestone's preview flag "
            "(available: "
            + ", ".join(
                f"{m}, {desc}" for m, desc in sorted(paths.PREVIEW_MILESTONES.items())
            )
            + "). Repeatable. Add --force if the review skills already exist. "
            "Reinstalling with --force and without --preview goes back to the "
            "default output."
        ),
    )
    p.set_defaults(func=_cmd_install)


def _cmd_install(args: argparse.Namespace) -> int:
    try:
        result = installer.install(
            args.target,
            crawl=args.crawl,
            service_map=args.service_map,
            force=args.force,
            previews=args.preview,
        )
    except (FileNotFoundError, NotADirectoryError, RuntimeError, ValueError) as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 1

    print("\n" + "─" * 60)
    if result.installed:
        print(f"✓ Installed into {result.target}/.claude/commands/:")
        for name in result.installed:
            print(f"    /{name[:-3]}")  # strip .md → slash command name
    else:
        print("Nothing was written (all targets existed; re-run with --force).")
    status = 0
    if result.previews:
        listed = ", ".join(
            f"{m} ({paths.PREVIEW_MILESTONES[m]})" for m in result.previews
        )
        if not result.preview_missing:
            print(f"✓ Review skills include preview output: {listed}")
            print(
                "  Reinstall with --force and without --preview to go back to "
                "the default."
            )
        else:
            why = (
                "generation failed (see above)"
                if args.force
                else "not regenerated (re-run with --force)"
            )
            print(
                f"✗ Preview {listed} NOT applied to "
                f"{_commands(result.preview_missing)}: {why}.",
                file=sys.stderr,
            )
            status = 1
    if result.preview_kept:
        undo = (
            "Regeneration failed (see above)."
            if args.force
            else "Re-run with --force to go back to the default."
        )
        print(
            f"Note: {_commands(result.preview_kept)} still hold preview output "
            f"from an earlier install. {undo}"
        )
    if result.preview_dropped:
        print(
            f"Note: {_commands(result.preview_dropped)} held preview output and "
            "are now back to the default. Pass --preview again to keep it."
        )
    if result.moved_suppressions:
        print(f"✓ Moved the MCP suppressions file to {paths.SUPPRESSIONS_FILE}")
    if result.retired:
        print(
            "✓ Moved the scrutineer-era commands they replace to "
            f"{paths.LEGACY_BACKUP_DIR}/:"
        )
        for name in result.retired:
            print(f"    /{name[:-3]}")
        print(
            "  Delete that folder once you've copied over any edits you made to them."
        )
    if result.skipped_crawl:
        print(
            "\nNote: skills were generated without a service map. For cross-service\n"
            "      awareness, run /vld8-map in Claude Code, then re-run\n"
            "      `vld8 install --force` (or pass --crawl)."
        )
    return status


def _commands(files: list[str]) -> str:
    return ", ".join(f"/{name[:-3]}" for name in files)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vld8",
        description=(
            "Dev tooling for Claude Code: service map, code and security review, "
            "MCP review."
        ),
    )
    parser.add_argument("--version", action="version", version=f"vld8 {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    _add_install_parser(sub)
    _add_mcp_parser(sub)
    _add_map_parser(sub)
    return parser


def _passthrough(argv: list[str]) -> int | None:
    """Run a bundled script directly when argv names one; None otherwise.

    argparse can't hand a script its own options: with a REMAINDER positional,
    a leading `-x` is parsed as an option of the wrapper, so
    `vld8 map validate --help` printed the wrapper's help. The
    parsers above still exist for `vld8 --help` and for bad script names.
    """
    if len(argv) >= 2 and argv[0] == "mcp" and argv[1] in paths.MCP_SCRIPTS:
        return _run_script(paths.MCP_SCRIPTS[argv[1]], argv[2:])
    if len(argv) >= 2 and argv[:2] == ["map", "validate"]:
        return _run_script(paths.SERVICEMAP_VALIDATOR, argv[2:])
    return None


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    code = _passthrough(argv)
    if code is not None:
        return code
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
