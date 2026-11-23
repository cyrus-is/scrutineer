#!/usr/bin/env python3
"""Regression suite for the CLI and installer.

Dependency-free (no pytest): run from the repo root with

    python tests/test_cli.py

Exits non-zero if any check fails. The defect this guards against: the installer
copied skills into a target repo that told Claude to run scripts by repo-relative
paths (``mcp-review/.venv/bin/python mcp-review/analyze_mcp.py``) that only exist in
a clone of this repo, so from a pip install they could never run. The checks install
into a throwaway repo and assert that every command an installed skill names is one
the CLI actually accepts.
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scrutineer import cli, installer, paths  # noqa: E402

_results: list[tuple[str, bool]] = []


def check(name: str, cond) -> None:
    _results.append((name, bool(cond)))


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "scrutineer", *args],
        cwd=ROOT, capture_output=True, text=True,
    )


def main() -> int:
    check("no required asset is missing", paths.missing_assets() == [])

    # The bundled-script subcommands reach their scripts.
    for name in sorted(paths.MCP_SCRIPTS):
        proc = run_cli("mcp", name, "--help")
        check(f"`scrutineer mcp {name} --help` exits 0", proc.returncode == 0)
    proc = run_cli("servicemap", "schema")
    check("`scrutineer servicemap schema` prints an existing path",
          proc.returncode == 0 and Path(proc.stdout.strip()).is_file())
    proc = run_cli("servicemap", "validate", "--help")
    check("`scrutineer servicemap validate --help` reaches the validator, not the wrapper",
          proc.returncode == 0 and "path-to-servicemap.json" in proc.stdout)
    with tempfile.TemporaryDirectory() as tmp:
        bad = Path(tmp) / "bad.json"
        bad.write_text("{}")
        proc = run_cli("servicemap", "validate", str(bad))
        check("`scrutineer servicemap validate` fails an invalid map", proc.returncode != 0)
    check("unknown mcp script is rejected", run_cli("mcp", "bogus").returncode != 0)

    # Install into a throwaway repo, then check what the installed skills ask for.
    with tempfile.TemporaryDirectory(prefix="scrutineer-cli-test-") as tmp:
        target = Path(tmp) / "repo"
        target.mkdir()
        (target / "index.ts").write_text("export const x = 1;\n")
        subprocess.run(["git", "init", "-q"], cwd=target, check=True)
        result = installer.install(target, log=lambda *_: None)
        cmd_dir = target / ".claude" / "commands"
        expected = {
            paths.SERVICEMAP_COMMAND, paths.MCP_COMMAND, paths.SETUP_COMMAND,
            paths.PEER_COMMAND, paths.SECURITY_COMMAND,
        }
        check("installer writes all five command files",
              expected == set(result.installed) and all((cmd_dir / f).is_file() for f in expected))

        mcp_actions = set(paths.MCP_SCRIPTS)
        servicemap_actions = {"validate", "schema"}
        for f in sorted(expected):
            text = (cmd_dir / f).read_text()
            check(f"{f}: no clone-only venv path", ".venv/bin/python" not in text)
            used_mcp = set(re.findall(r"scrutineer mcp (\w+)", text))
            check(f"{f}: every `scrutineer mcp X` is a real subcommand {sorted(used_mcp - mcp_actions)}",
                  used_mcp <= mcp_actions)
            used_sm = set(re.findall(r"scrutineer servicemap (\w+)", text))
            check(f"{f}: every `scrutineer servicemap X` is a real subcommand {sorted(used_sm - servicemap_actions)}",
                  used_sm <= servicemap_actions)
        mcp_text = (cmd_dir / paths.MCP_COMMAND).read_text()
        check("mcp skill runs the analyzer through the CLI", "scrutineer mcp analyze" in mcp_text)

    # The parser accepts what the skills use, so the regex above checks real choices.
    parser = cli.build_parser()
    ns = parser.parse_args(["mcp", "analyze", "--config", "x.json"])
    check("mcp parser accepts script options", ns.args == ["--config", "x.json"])

    for n, ok in _results:
        print(("PASS " if ok else "FAIL ") + n)
    fails = [n for n, ok in _results if not ok]
    if fails:
        print(f"\nFAILURES: {len(fails)}")
        return 1
    print(f"\nAll {len(_results)} checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
