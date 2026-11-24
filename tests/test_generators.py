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

import importlib.util
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


def make_repo(base: Path, name: str, files: dict[str, str], git: bool = True) -> Path:
    repo = base / name
    for rel, text in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    if not git:
        return repo
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
    apple = make_repo(base, "apple", {  # content-gated blocks, single-level and Xcode layouts
        "Package.swift": "// swift-tools-version:5.9\n",
        "Sources/Store.swift": "import CloudKit\n",
        "MyApp/SyncStore.swift": "import CloudKit\n",
        "macOS/AppDelegate.swift": "import AppKit\n",
        "iOS/App.entitlements": "<plist></plist>\n",
    })
    auth_docs = make_repo(base, "auth-docs", {  # auth named only in config and docs
        "app.py": "print('hello')\n",
        "docs/config.yml": "auth: uses oauth flow with jsonwebtoken and jose\n",
        "package-lock.json": '{"packages": {"node_modules/jsonwebtoken": {}}}\n',
    })
    esm_jwt = make_repo(base, "esm-jwt", {  # auth in .mjs source, which content scans skipped
        "src/auth.mjs": "export const check = (t) => jwt.verify(t, key);\n",
    })
    ignored = make_repo(base, "ignored", {  # gitignored build output must not detect anything
        ".gitignore": "build/\n.open-next/\n",
        "src/index.ts": "export const x = 1;\n",
        "build/generated.py": "print('build output')\n",
        ".open-next/server.go": "package main\n",
    })
    not_git = make_repo(base, "not-git", {"main.go": "package main\n"}, git=False)
    infra = make_repo(base, "infra", {  # current Compose and workflow names; a logo named mongo
        "compose.yaml": "services: {}\n",
        ".github/workflows/ci.yaml": "on: push\n",
        "assets/logos/mongodb.png": "not an image\n",
        "web/App.tsx": "export const App = () => null;\n",
    })
    return {
        "ignored": (ignored, None),
        "not-git": (not_git, None),
        "infra": (infra, None),
        "ts-only": (ts_only, None),
        "go-only": (go_only, None),
        "polyglot": (polyglot, polyglot / "servicemap.json"),
        "empty": (empty, None),
        "apple": (apple, None),
        "auth-docs": (auth_docs, None),
        "esm-jwt": (esm_jwt, None),
    }


def generate(generator: Path, repo: Path, service_map: Path | None,
             guidance: Path | None = None) -> str:
    cmd = [sys.executable, str(generator), str(repo), "--output", "out.md", "--force"]
    if guidance:
        cmd += ["--guidance", str(guidance)]
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
    sublabels = [n for n, l in lines_outside_fences(text) if re.match(r"^\d+[a-z]\. ", l)]
    check(f"{label}: no '2b.'-style list markers, which Markdown doesn't number {sublabels[:3]}",
          not sublabels)


def load_generator(path: Path):
    spec = importlib.util.spec_from_file_location(f"gen_{path.parent.name.replace('-', '_')}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def detection_line(text: str, platform: str) -> str:
    """The Process step-3 line naming where a platform was found ('' if absent)."""
    return next((l for l in text.splitlines() if l.endswith(f"→ **{platform}**")), "")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="vld8-gen-test-") as tmp:
        repos = fixtures(Path(tmp))
        outputs = {
            (g, name): generate(path, repo, sm)
            for g, path in GENERATORS.items()
            for name, (repo, sm) in repos.items()
        }
        # A guidance file without `verification:` gets no Phase 0, so it must
        # get no pointer to one either.
        import yaml
        guidance = yaml.safe_load((ROOT / "generate-peer-review" / "peer_review_guidance.yaml").read_text())
        guidance.pop("verification", None)
        custom = Path(tmp) / "no-verification.yaml"
        custom.write_text(yaml.safe_dump(guidance))
        no_phase0 = generate(GENERATORS["peer"], repos["go-only"][0], None, guidance=custom)

        # A custom ladder whose linter entry lists rules but no config note still renders.
        no_config = yaml.safe_load((ROOT / "generate-peer-review" / "peer_review_guidance.yaml").read_text())
        for entry in no_config["verification"]["platforms"]["python"]["proves"]:
            entry.pop("config", None)
        no_config_path = Path(tmp) / "no-config.yaml"
        no_config_path.write_text(yaml.safe_dump(no_config))
        rules_no_config = generate(GENERATORS["peer"], repos["auth-docs"][0], None, guidance=no_config_path)

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

    check("peer: no Phase 0 pointer when the guidance defines no verification",
          "see Phase 0" not in no_phase0 and "## Phase 0" not in no_phase0)
    check_rendering("peer/no-verification", no_phase0)

    # The index is what git would commit: gitignored output detects nothing.
    for g in GENERATORS:
        text = outputs[(g, "ignored")]
        check(f"{g}/ignored: gitignored build/ and .open-next/ files detect nothing",
              not detection_line(text, "Python") and not detection_line(text, "Go")
              and "build/" not in text.split("## Phase 1")[0])
        check(f"{g}/not-git: a directory outside git still gets detection",
              detection_line(outputs[(g, "not-git")], "Go"))
        infra = outputs[(g, "infra")]
        check(f"{g}/infra: compose.yaml detects Docker", detection_line(infra, "Docker"))
        check(f"{g}/infra: .github/workflows/*.yaml detects GitHub Actions",
              detection_line(infra, "GitHub Actions"))
        check(f"{g}/empty: Mode 4 says there is no service map rather than '0 components'",
              "No service map was available" in outputs[(g, "empty")]
              and "Repo has 0 reviewable components" not in outputs[(g, "empty")])
    sec_infra = outputs[("security", "infra")]
    check("security/infra: a file named mongodb.png does not detect MongoDB",
          not detection_line(sec_infra, "MongoDB"))
    check("security/infra: the browser-code auth note carves out server code",
          "missing auth there IS reportable" in sec_infra)

    # Content detection reads source, not config or docs, and reaches .mjs.
    for name, want in (("auth-docs", False), ("esm-jwt", True)):
        text = outputs[("security", name)]
        check(f"security/{name}: JWT checklist {'present' if want else 'absent'}",
              bool(detection_line(text, "JWT Authentication")) == want)
    check("security/auth-docs: OAuth checklist absent",
          not detection_line(outputs[("security", "auth-docs")], "OAuth 2.0"))

    # Content-gated Apple blocks name real directories, and only the right ones.
    for g in GENERATORS:
        text = outputs[(g, "apple")]
        ck = detection_line(text, "CloudKit sync")
        check(f"{g}/apple: CloudKit names its directories, not '(content detection)' [{ck.strip()}]",
              ck and "(content detection)" not in ck and "Sources/Store.swift" in ck)
        mac = detection_line(text, "macOS app")
        check(f"{g}/apple: macOS paths exclude the iOS entitlements [{mac.strip()}]",
              mac and "iOS/" not in mac)

    # Phase 0 commands that contain backticks render as one code span.
    swift_cmd = next((l for l in outputs[("peer", "apple")].splitlines()
                      if "swiftlint lint --strict" in l), "")
    check("peer/apple: swiftlint command rendered with a double-backtick span",
          swift_cmd.startswith("- `` swiftlint"))

    # #92: a linter's exclusions cover only the rules its config enables.
    py = outputs[("peer", "auth-docs")]
    check("peer/python: ruff exclusion defers to the config's rules",
          "| `ruff check` | only the patterns whose rule the repo's config enables" in py)
    check("peer/python: B006 is listed as opt-in, not excluded outright",
          "| mutable default arguments | `B006` | no (opt-in) |" in py
          and "every other lint-visible pattern" not in py)
    check("peer: a rules entry without a config note renders instead of crashing",
          "covers only what its config enables.** Read it first.\n" in rules_no_config)
    sw = outputs[("peer", "apple")]
    check("peer/apple: force_unwrapping is listed as opt-in",
          "| force unwrap (`!`) | `force_unwrapping` | no (opt-in) |" in sw)
    check("peer/apple: swiftlint rule table names where the config lives",
          "covers only what its config enables.** Read it first: `.swiftlint.yml`" in sw)

    # #93: Phase 0 runs on the PR's head, in a worktree, and not on a fork's code unasked.
    check("peer: Mode 2 checks the PR out in a worktree for Phase 0",
          "git fetch origin pull/123/head" in py and "git worktree add --detach" in py
          and "5. Review the diff." in py and "6. Post findings" in py)
    flat = " ".join(py.split())
    check("peer: Phase 0 runs nothing on a fork's code, linters included, without a go-ahead",
          "isCrossRepository: true" in flat
          and "run nothing in its worktree without the user's go-ahead" in flat
          and "not the linters either" in flat and "are safe to run" not in flat)
    check("peer: a failure the fresh worktree causes is a stage not run, not a finding",
          "A failure the environment causes is a stage not run" in flat)
    check("peer: Mode 2 verifies the worktree's head and keeps it until findings are posted",
          "equals `headRefOid`" in flat
          and "Post findings as a PR comment via `gh pr comment`, then `git worktree remove --force <wt>`" in flat)
    check("peer: inline suppressions are not covered by a green linter run",
          "# noqa: E722" in flat and "swiftlint:disable:next" in flat)
    check("peer: no worktree step when there is no Phase 0",
          "git worktree add" not in no_phase0
          and "4. Review the diff." in no_phase0 and "5. Post findings" in no_phase0)

    # #94: the PR body is context, never grounds to accept a finding.
    sec = outputs[("security", "empty")]
    check("security: Mode 2 no longer trusts the body's account of what is deliberate",
          "tells you which behaviour is deliberate" not in sec
          and "Read the body as context, not evidence" in sec)
    check("security: precedent rule says the description never clears a finding",
          "The PR description is the author's claim, not evidence." in sec
          and "Does dismissing it rest only on the PR description?" in sec)
    check("security: code comments that excuse a change are author claims too",
          "# nosec" in sec and "intentionally unauthenticated" in sec)
    check("peer: Phase 1 treats the description as a claim, not evidence",
          "the description is the author's claim, not evidence"
          in " ".join(outputs[("peer", "empty")].split()))

    # Unit checks on the helpers both generators share.
    for g, path in GENERATORS.items():
        mod = load_generator(path)
        cases = [
            ("App/Foo.swift", "App/**/*.swift", True),
            ("App/a/b/Foo.swift", "App/**/*.swift", True),
            ("Foo.swift", "**/*.swift", True),
            ("x/App/Foo.swift", "App/**/*.swift", False),
            ("macOS/A.entitlements", "**/macOS/**/*.entitlements", True),
            ("iOS/A.entitlements", "**/macOS/**/*.entitlements", False),
            ("src/index.ts", "**/*.ts", True),
            ("src/index.tsx", "**/*.ts", False),
        ]
        bad = [(r, pat) for r, pat, want in cases if mod.glob_match(r, pat) != want]
        check(f"{g}: glob_match treats **/ as zero or more directories {bad}", not bad)
    peer_mod = load_generator(GENERATORS["peer"])
    check("peer: code_span survives inner backticks",
          peer_mod.code_span("a `b` c") == "`` a `b` c ``" and peer_mod.code_span("ls") == "`ls`")

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
