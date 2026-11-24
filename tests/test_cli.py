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

from vld8 import cli, installer, paths  # noqa: E402

_results: list[tuple[str, bool]] = []


def check(name: str, cond) -> None:
    _results.append((name, bool(cond)))


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "vld8", *args],
        cwd=ROOT, capture_output=True, text=True,
    )


def main() -> int:
    check("no required asset is missing", paths.missing_assets() == [])

    # The bundled-script subcommands reach their scripts.
    for name in sorted(paths.MCP_SCRIPTS):
        proc = run_cli("mcp", name, "--help")
        check(f"`vld8 mcp {name} --help` exits 0", proc.returncode == 0)
    proc = run_cli("map", "schema")
    check("`vld8 map schema` prints an existing path",
          proc.returncode == 0 and Path(proc.stdout.strip()).is_file())
    proc = run_cli("map", "validate", "--help")
    check("`vld8 map validate --help` reaches the validator, not the wrapper",
          proc.returncode == 0 and "path-to-servicemap.json" in proc.stdout)
    with tempfile.TemporaryDirectory() as tmp:
        bad = Path(tmp) / "bad.json"
        bad.write_text("{}")
        proc = run_cli("map", "validate", str(bad))
        check("`vld8 map validate` fails an invalid map", proc.returncode != 0)
    check("unknown mcp script is rejected", run_cli("mcp", "bogus").returncode != 0)

    # Install into a throwaway repo, then check what the installed skills ask for.
    with tempfile.TemporaryDirectory(prefix="vld8-cli-test-") as tmp:
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
            used_mcp = set(re.findall(r"vld8 mcp (\w+)", text))
            check(f"{f}: every `vld8 mcp X` is a real subcommand {sorted(used_mcp - mcp_actions)}",
                  used_mcp <= mcp_actions)
            used_sm = set(re.findall(r"vld8 map (\w+)", text))
            check(f"{f}: every `vld8 map X` is a real subcommand {sorted(used_sm - servicemap_actions)}",
                  used_sm <= servicemap_actions)
        mcp_text = (cmd_dir / paths.MCP_COMMAND).read_text()
        check("a default install has no preview marker",
              all("vld8 preview output" not in (cmd_dir / f).read_text()
                  for f in (paths.PEER_COMMAND, paths.SECURITY_COMMAND)))

        # #81: --preview reaches both generators, and a plain reinstall undoes it.
        result = installer.install(target, force=True, previews=["2.1"], log=lambda *_: None)
        review = [paths.PEER_COMMAND, paths.SECURITY_COMMAND]
        check("install --preview 2.1 marks both review skills",
              result.previews == ["2.1"] and result.preview_missing == []
              and all(paths.PREVIEW_MARKER in (cmd_dir / f).read_text() for f in review))
        result = installer.install(target, log=lambda *_: None)
        check("a reinstall without --force reports the skills still hold the preview",
              result.preview_kept == review and result.preview_dropped == [])
        result = installer.install(target, force=True, log=lambda *_: None)
        check("reinstalling with --force and without --preview goes back to the default, and says so",
              result.preview_dropped == review
              and all(paths.PREVIEW_MARKER not in (cmd_dir / f).read_text() for f in review))
        # Existing skills and no --force: the preview can't apply, and the CLI must not claim it did.
        result = installer.install(target, previews=["2.1"], log=lambda *_: None)
        check("install --preview without --force over existing skills reports them as missing it",
              result.preview_missing == review
              and all(paths.PREVIEW_MARKER not in (cmd_dir / f).read_text() for f in review))
        proc = run_cli("install", str(target), "--preview", "2.1")
        check("vld8 install --preview without --force over existing skills fails and says why",
              proc.returncode != 0 and "NOT applied" in proc.stderr
              and "include preview output" not in proc.stdout)
        (cmd_dir / paths.SECURITY_COMMAND).unlink()
        proc = run_cli("install", str(target), "--preview", "2.1")
        check("a preview applied to only one review skill is reported as not applied to the other",
              proc.returncode != 0 and "/vld8-review" in proc.stderr
              and "/vld8-security" not in proc.stderr)
        proc = run_cli("install", str(target), "--force", "--preview", "2.1")
        check("vld8 install --force --preview 2.1 succeeds and says so",
              proc.returncode == 0 and "include preview output: 2.1" in proc.stdout)
        try:
            installer.install(target, force=True, previews=["9.9"], log=lambda *_: None)
            rejected = False
        except ValueError:
            rejected = True
        check("the installer rejects a milestone with no preview", rejected)
        proc = run_cli("install", str(target), "--preview", "9.9")
        check("vld8 install --preview 9.9 fails with the available milestones",
              proc.returncode != 0 and "2.1" in proc.stderr)
        check("mcp skill runs the analyzer through the CLI", "vld8 mcp analyze" in mcp_text)
        for f in sorted(expected):
            check(f"{f}: no leftover scrutineer name", "scrutineer" not in (cmd_dir / f).read_text().lower())

    # Upgrading a repo that scrutineer set up: its own files go, anything else stays.
    with tempfile.TemporaryDirectory(prefix="vld8-cli-test-") as tmp:
        target = Path(tmp) / "repo"
        cmd_dir = target / ".claude" / "commands"
        cmd_dir.mkdir(parents=True)
        (target / "index.ts").write_text("export const x = 1;\n")
        subprocess.run(["git", "init", "-q"], cwd=target, check=True)
        (cmd_dir / "scrutineer-mcp.md").write_text("---\nname: scrutineer-mcp\n---\nold\n")
        (cmd_dir / "scrutineer-code.md").write_text(
            "You are a TL/Principal SDE performing a peer code review. Old.\n")
        (cmd_dir / "scrutineer-security.md").write_text("A hand-written command that shares the name.\n")
        (cmd_dir / "scrutineer-notes.md").write_text("Not one of ours.\n")
        (target / ".claude" / "scrutineer-mcp-suppressions.json").write_text('{"suppressions": []}\n')
        result = installer.install(target, log=lambda *_: None)
        backup = target / paths.LEGACY_BACKUP_DIR
        check("upgrade moves the scrutineer files it replaced out of .claude/commands",
              sorted(result.retired) == ["scrutineer-code.md", "scrutineer-mcp.md"]
              and not (cmd_dir / "scrutineer-mcp.md").exists()
              and not (cmd_dir / "scrutineer-code.md").exists())
        check("upgrade keeps the retired files, edits included, in the backup folder",
              "Old." in (backup / "scrutineer-code.md").read_text()
              and (backup / "scrutineer-mcp.md").is_file()
              and not backup.is_relative_to(cmd_dir))
        # A second upgrade (say the user restored an old file) must not clobber the first backup.
        (cmd_dir / "scrutineer-code.md").write_text(
            "You are a TL/Principal SDE performing a peer code review. Second.\n")
        installer.install(target, log=lambda *_: None)
        check("a later upgrade doesn't overwrite an earlier backup",
              "Old." in (backup / "scrutineer-code.md").read_text()
              and "Second." in (backup / "scrutineer-code.1.md").read_text())
        check("upgrade keeps a same-named file scrutineer did not write",
              (cmd_dir / "scrutineer-security.md").exists())
        check("upgrade leaves unrelated command files alone", (cmd_dir / "scrutineer-notes.md").exists())
        check("upgrade moves the MCP suppressions file to its vld8 name",
              result.moved_suppressions and (target / paths.SUPPRESSIONS_FILE).is_file()
              and not (target / paths.LEGACY_SUPPRESSIONS_FILE).exists())
        check("the mcp skill names the suppressions file the installer moves to",
              paths.SUPPRESSIONS_FILE in (cmd_dir / paths.MCP_COMMAND).read_text())

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
