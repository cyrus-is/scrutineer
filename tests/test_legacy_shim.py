"""Tests for the final `scrutineer` release in legacy/scrutineer/.

It must forward every old command to vld8, keep stdout clean (skills read it),
and require a vld8 version this repo actually builds. Dependency-free.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEGACY = ROOT / "legacy" / "scrutineer"
sys.path[:0] = [str(LEGACY), str(ROOT)]

from scrutineer import cli as shim  # noqa: E402

_results: list[tuple[str, bool]] = []


def check(name: str, ok: bool) -> None:
    _results.append((name, bool(ok)))


def run_shim(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(LEGACY), str(ROOT)]))
    return subprocess.run([sys.executable, "-m", "scrutineer", *args],
                          capture_output=True, text=True, env=env, cwd=ROOT)


def version_of(pyproject: Path) -> str:
    return re.search(r'^version = "([^"]+)"', pyproject.read_text(), re.M).group(1)


def main() -> int:
    check("servicemap becomes map", shim.translate(["servicemap", "validate", "x"]) == ["map", "validate", "x"])
    check("other subcommands pass through", shim.translate(["mcp", "analyze", "--help"]) == ["mcp", "analyze", "--help"])
    check("no arguments pass through", shim.translate([]) == [])

    proc = run_shim("servicemap", "schema")
    out = proc.stdout.strip()
    check("`scrutineer servicemap schema` prints only the schema path on stdout",
          proc.returncode == 0 and Path(out).is_file() and "\n" not in out)
    check("the notice goes to stderr", "renamed vld8" in proc.stderr)
    check("the notice covers tool installs, where vld8 isn't on PATH",
          "pipx install vld8" in proc.stderr and "uv tool install vld8" in proc.stderr
          and "already installed" not in proc.stderr)

    proc = run_shim("mcp", "analyze", "--help")
    check("`scrutineer mcp analyze --help` reaches the analyzer", proc.returncode == 0 and "--config" in proc.stdout)

    proc = run_shim("--version")
    check("`scrutineer --version` reports vld8", proc.returncode == 0 and "vld8" in proc.stdout)

    vld8_version = version_of(ROOT / "pyproject.toml")
    legacy_py = (LEGACY / "pyproject.toml").read_text()
    major = int(vld8_version.split(".")[0])
    check(f"shim requires the vld8 major this repo builds ({vld8_version})",
          f'"vld8>={major}.0.0,<{major + 1}"' in legacy_py)
    check("shim version is above every pre-rename scrutineer release",
          int(version_of(LEGACY / "pyproject.toml").split(".")[0]) >= 2)

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
