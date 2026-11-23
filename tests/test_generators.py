#!/usr/bin/env python3
"""Regression suite for the peer-review and security-review generators.

Dependency-free (no pytest), same shape as mcp-review/tests: run from the repo root with

    python tests/test_generators.py

It needs PyYAML, as the generators do. Exits non-zero if any check fails.

The generators had no tests, and their worst defects were invisible from inside one
run: a section rendered as a code block only when a repo had two or more platforms, or
a memory-safe language; a TypeScript service got no checklist because no platform
claimed ``*.ts``. So these checks run each generator across a small matrix of throwaway
repos, built to trigger those conditions, and assert properties of the output that
must hold for every repo.
"""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GENERATORS = {
    "peer": ROOT / "generate-peer-review" / "generate.py",
    "security": ROOT / "generate-security-review" / "generate.py",
}

_results: list[tuple[str, bool]] = []


def check(name: str, cond) -> None:
    _results.append((name, bool(cond)))


def make_repo(base: Path, name: str, files: dict[str, str]) -> Path:
    repo = base / name
    for rel, text in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t",
         "commit", "-qm", "fixture"],
        cwd=repo, check=True,
    )
    return repo


SERVICE_MAP = {
    "components": [
        {"id": "api", "name": "api", "type": "service", "path": "packages/api", "language": "typescript"},
        {"id": "worker", "name": "worker", "type": "service", "path": "cmd/worker", "language": "go"},
    ],
    "connections": [
        {"source": "api", "target": "worker", "type": "queue"},
        {"source": "worker", "target": "api", "type": "http"},
    ],
}


def fixtures(base: Path) -> dict[str, tuple[Path, Path | None]]:
    """name → (repo, service map or None). Each targets a condition that once broke output."""
    ts_only = make_repo(base, "ts-only", {
        "packages/api/package.json": "{}\n",
        "packages/api/src/index.ts": "export const f = (x: number): number => x;\n",
        "packages/api/src/types.mts": "export type T = 1;\n",
    })
    go_only = make_repo(base, "go-only", {  # a memory-safe language: the FP-section note
        "go.mod": "module example\n\ngo 1.22\n",
        "main.go": "package main\n\nfunc main() {}\n",
    })
    polyglot = make_repo(base, "polyglot", {  # 2+ platforms, and a map with connections
        "packages/api/package.json": "{}\n",
        "packages/api/src/index.ts": "export const x = 1;\n",
        "cmd/worker/main.go": "package main\n\nfunc main() {}\n",
        "go.mod": "module example\n\ngo 1.22\n",
        "Dockerfile": "FROM scratch\n",
        "servicemap.json": json.dumps(SERVICE_MAP),
    })
    empty = make_repo(base, "empty", {"README.md": "nothing to detect\n"})
    return {
        "ts-only": (ts_only, None),
        "go-only": (go_only, None),
        "polyglot": (polyglot, polyglot / "servicemap.json"),
        "empty": (empty, None),
    }


def generate(generator: Path, repo: Path, service_map: Path | None) -> str:
    cmd = [sys.executable, str(generator), str(repo), "--output", "out.md", "--force"]
    cmd += ["--service-map", str(service_map)] if service_map else ["--no-service-map"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"{generator.parent.name} failed on {repo.name}:\n{proc.stderr}")
    return (repo / "out.md").read_text()


def lines_outside_fences(text: str):
    fenced = False
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if not fenced:
            yield n, line


def check_rendering(label: str, text: str) -> None:
    """Markdown structure that must hold for any repo.

    A heading that is indented, or a run of lines indented 5+ spaces outside a fence,
    is a section Markdown will show as a code block. List continuations legitimately
    reach 4 spaces, so anything deeper means a template's dedent went wrong.
    """
    bad_headings = [n for n, l in lines_outside_fences(text) if re.match(r"^ +#{1,6} ", l)]
    check(f"{label}: every heading starts at column 0 {bad_headings[:3]}", not bad_headings)
    deep = [n for n, l in lines_outside_fences(text) if l.strip() and len(l) - len(l.lstrip(" ")) > 4]
    check(f"{label}: nothing outside a fence is indented more than 4 spaces {deep[:3]}", not deep)
    check(f"{label}: code fences are balanced", text.count("```") % 2 == 0)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="scrutineer-gen-test-") as tmp:
        repos = fixtures(Path(tmp))
        outputs = {
            (g, name): generate(path, repo, sm)
            for g, path in GENERATORS.items()
            for name, (repo, sm) in repos.items()
        }

    for (g, name), text in outputs.items():
        check_rendering(f"{g}/{name}", text)

    # TypeScript is detected, and mapped to where the TypeScript is.
    for g in GENERATORS:
        text = outputs[(g, "ts-only")]
        check(f"{g}/ts-only: TypeScript detected as Node/TS platform",
              "`packages/api` → **Node.js / JavaScript / TypeScript**" in text)

    # Mode 2 fetches the PR description.
    for g in GENERATORS:
        text = outputs[(g, "empty")]
        check(f"{g}: Mode 2 fetches the PR body",
              re.search(r"gh pr view 123 --json [a-zA-Z,]*\bbody\b", text))
        check(f"{g}: mode count matches the four modes listed",
              "supports four modes" in text and "### Mode 4" in text)

    # The clean-review template no longer contradicts "always include Check Performance".
    peer = outputs[("peer", "empty")]
    check("peer: clean template points at Check Performance",
          "Follow it with the Check Performance section" in peer and "That's it." not in peer)

    # The security exclusion list no longer discards prompt injection that reaches tools or data.
    sec = outputs[("security", "go-only")]
    check("security: prompt-injection exclusion is narrowed",
          "Prompt injection that reaches nothing" in sec
          and "is not a vulnerability in this context" not in sec)

    # The polyglot repo exercises the multi-line interpolations (detection block, flow hints).
    poly = outputs[("peer", "polyglot")]
    check("peer/polyglot: most-connected components rendered",
          "**Most-connected components (start here):**" in poly)

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
