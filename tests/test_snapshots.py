#!/usr/bin/env python3
"""Golden-output snapshot harness for the generated review skills.

Dependency-free (stdlib + PyYAML, matching the generators; no network and no
sleeps). Run from the repository root:

    python tests/test_snapshots.py           # compare outputs to golden files
    python tests/test_snapshots.py --update  # regenerate checked-in golden files

Each synthetic fixture repo under ``tests/snapshots/fixtures/`` is copied into
an isolated temporary git repository and run through both
``generate-peer-review/generate.py`` and ``generate-security-review/generate.py``
in both default mode and ``--preview 2.1`` mode. Any temporary working, repo, or
toolkit paths in generated output are normalized before comparing or writing
golden files under ``tests/snapshots/golden/``.

Exits zero when all snapshots and harness checks pass, and non-zero with a
unified diff on any mismatch or missing golden file.
"""

from __future__ import annotations

import argparse
import difflib
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vld8 import paths  # noqa: E402

SNAPSHOTS_DIR = Path(__file__).resolve().parent / "snapshots"
FIXTURES_DIR = SNAPSHOTS_DIR / "fixtures"
GOLDEN_DIR = SNAPSHOTS_DIR / "golden"

FIXTURE_NAMES: tuple[str, ...] = ("python-ts", "swift-apple", "servicemap-app")
MODES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("default", ()),
    ("preview-2.1", ("2.1",)),
)
GENERATORS: tuple[tuple[str, Path, str], ...] = (
    ("peer", paths.PEER_GENERATOR, paths.PEER_COMMAND),
    ("security", paths.SECURITY_GENERATOR, paths.SECURITY_COMMAND),
)

HOST_PATH_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("macOS user path", re.compile(r"/Users/[^\s`'\")>]+")),
    ("Linux user path", re.compile(r"/home/[^\s`'\")>]+")),
    ("macOS var/folders path", re.compile(r"/var/folders/[^\s`'\")>]+")),
    ("macOS private temp path", re.compile(r"/private/(?:var|tmp)/[^\s`'\")>]+")),
    ("snapshot tempdir path", re.compile(r"/tmp/vld8-snap-[^\s`'\")>]+")),
    ("Windows drive path", re.compile(r"[A-Za-z]:\\[^\s`'\")>]+")),
)


@dataclass(frozen=True)
class SnapshotSpec:
    fixture: str
    mode: str
    previews: tuple[str, ...]
    generator_key: str
    generator_path: Path
    skill_filename: str

    @property
    def golden_rel(self) -> Path:
        return Path(self.fixture) / self.mode / self.skill_filename

    @property
    def golden_path(self) -> Path:
        return GOLDEN_DIR / self.golden_rel

    @property
    def label(self) -> str:
        return f"{self.fixture}/{self.mode}/{self.skill_filename}"


def all_specs() -> list[SnapshotSpec]:
    return [
        SnapshotSpec(
            fixture=fixture,
            mode=mode,
            previews=previews,
            generator_key=gen_key,
            generator_path=gen_path,
            skill_filename=skill_filename,
        )
        for fixture in FIXTURE_NAMES
        for mode, previews in MODES
        for gen_key, gen_path, skill_filename in GENERATORS
    ]


def _path_variants(path: Path) -> list[str]:
    variants: list[str] = []
    for candidate in (path, path.resolve()):
        for text in (str(candidate), candidate.as_posix()):
            if text and text not in ("/", "\\") and text not in variants:
                variants.append(text)
    return variants


def normalize_output(
    text: str,
    *,
    repo_dir: Path,
    work_dir: Path,
    toolkit_root: Path,
) -> str:
    """Normalize temporary, repo, and toolkit paths and line endings."""
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    replacements: list[tuple[str, str]] = []
    for path, token in (
        (repo_dir, "<REPO_ROOT>"),
        (work_dir, "<WORK_ROOT>"),
        (toolkit_root, "<TOOLKIT_ROOT>"),
    ):
        for variant in _path_variants(path):
            replacements.append((variant, token))

    seen: set[str] = set()
    for prefix, token in sorted(
        replacements, key=lambda item: len(item[0]), reverse=True
    ):
        if prefix in seen:
            continue
        seen.add(prefix)
        normalized = normalized.replace(prefix, token)
    return normalized


def find_leaked_paths(
    text: str, *, forbidden_roots: tuple[Path, ...] = ()
) -> list[str]:
    """Return descriptions of any local or temporary paths found in text."""
    leaks: list[str] = []
    for root in forbidden_roots:
        for variant in _path_variants(root):
            if variant in text:
                leaks.append(f"forbidden path {variant!r}")
    for label, pattern in HOST_PATH_PATTERNS:
        match = pattern.search(text)
        if match:
            leaks.append(f"{label} {match.group(0)!r}")
    return leaks


def format_unified_diff(
    expected: str,
    actual: str,
    *,
    expected_label: str,
    actual_label: str,
) -> str:
    """Return a unified diff string, or empty string when contents match."""
    lines = list(
        difflib.unified_diff(
            expected.splitlines(keepends=True),
            actual.splitlines(keepends=True),
            fromfile=expected_label,
            tofile=actual_label,
        )
    )
    if not lines:
        return ""
    diff = "".join(lines)
    if not diff.endswith("\n"):
        diff += "\n"
    return diff


def compare_snapshot(
    expected: str | None,
    actual: str,
    *,
    golden_rel: Path,
) -> tuple[bool, str]:
    """Compare actual text against expected golden text; return (ok, detail)."""
    rel_posix = f"tests/snapshots/golden/{golden_rel.as_posix()}"
    if expected is None:
        return False, f"Missing golden snapshot: {rel_posix}"
    if expected == actual:
        return True, ""
    diff = format_unified_diff(
        expected,
        actual,
        expected_label=f"a/{rel_posix}",
        actual_label=f"b/{rel_posix} (generated)",
    )
    return False, diff


def _run_git(repo_dir: Path, *args: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.autocrlf=false",
            *args,
        ],
        cwd=repo_dir,
        check=True,
        capture_output=True,
        text=True,
    )


def stage_fixture_repo(src_dir: Path, dest_dir: Path) -> Path:
    """Copy a synthetic fixture repo into dest_dir with an isolated git repo."""
    shutil.copytree(
        src_dir,
        dest_dir,
        symlinks=False,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store", ".git"),
    )
    _run_git(dest_dir, "init", "-q", "-b", "main")
    _run_git(dest_dir, "config", "user.email", "fixture@example.invalid")
    _run_git(dest_dir, "config", "user.name", "Fixture")
    _run_git(dest_dir, "add", "-A")
    _run_git(dest_dir, "commit", "-qm", "fixture")
    return dest_dir


def run_generator(
    generator: Path,
    repo_dir: Path,
    *,
    previews: tuple[str, ...],
    use_service_map: bool,
) -> str:
    """Run one generator against repo_dir and return the generated skill text."""
    out_rel = ".vld8-snapshot-out.md"
    out_path = repo_dir / out_rel
    if out_path.exists():
        out_path.unlink()
    cmd = [
        sys.executable,
        str(generator),
        str(repo_dir),
        "--output",
        out_rel,
        "--force",
    ]
    for milestone in previews:
        cmd += ["--preview", milestone]
    if not use_service_map:
        cmd.append("--no-service-map")

    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"{generator.parent.name} failed on {repo_dir.name} "
            f"(previews={previews}):\n{proc.stderr}"
        )
    try:
        return out_path.read_text(encoding="utf-8")
    finally:
        if out_path.exists():
            out_path.unlink()


def _load_servicemap_validator():
    spec = importlib.util.spec_from_file_location(
        "validate_servicemap",
        paths.SERVICEMAP_VALIDATOR,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"Could not load service map validator from {paths.SERVICEMAP_VALIDATOR}"
        )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_golden(path: Path, content: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = path.read_text(encoding="utf-8")
        if existing == content:
            return "unchanged"
        status = "updated"
    else:
        status = "created"
    with path.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    return status


def _prune_stale_golden(expected_paths: set[Path]) -> list[Path]:
    removed: list[Path] = []
    if not GOLDEN_DIR.exists():
        return removed
    for path in sorted(GOLDEN_DIR.rglob("*")):
        if path.is_file() and path not in expected_paths:
            path.unlink()
            removed.append(path)
    for directory in sorted(GOLDEN_DIR.rglob("*"), reverse=True):
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()
    return removed


def _run_self_checks(check) -> None:
    sample_work = Path("/tmp/vld8-snap-selfcheck")
    sample_repo = sample_work / "demo-repo"
    sample_raw = (
        f"Repo: {sample_repo}\r\n"
        f"Work: {sample_work}\r\n"
        f"Tool: {ROOT}\r\n"
        "Worktree: ${TMPDIR:-/tmp}/vld8-<repo>-pr-123\r\n"
    )
    normalized = normalize_output(
        sample_raw,
        repo_dir=sample_repo,
        work_dir=sample_work,
        toolkit_root=ROOT,
    )
    check(
        "harness: normalize_output replaces repo/work/toolkit paths and CRLF",
        normalized
        == (
            "Repo: <REPO_ROOT>\n"
            "Work: <WORK_ROOT>\n"
            "Tool: <TOOLKIT_ROOT>\n"
            "Worktree: ${TMPDIR:-/tmp}/vld8-<repo>-pr-123\n"
        ),
    )
    check(
        "harness: find_leaked_paths detects local paths and ignores template paths",
        bool(find_leaked_paths("bad /Users/alice/work"))
        and bool(find_leaked_paths("bad /private/var/folders/xx/file"))
        and not find_leaked_paths("Worktree: ${TMPDIR:-/tmp}/vld8-<repo>-pr-123"),
    )
    ok_match, diff_match = compare_snapshot(
        "line1\n", "line1\n", golden_rel=Path("demo/default/vld8-review.md")
    )
    ok_diff, diff_text = compare_snapshot(
        "line1\nold\n", "line1\nnew\n", golden_rel=Path("demo/default/vld8-review.md")
    )
    check(
        "harness: compare_snapshot produces unified diff only on mismatch",
        ok_match
        and diff_match == ""
        and not ok_diff
        and "--- a/tests/snapshots/golden/demo/default/vld8-review.md" in diff_text
        and "+++ b/tests/snapshots/golden/demo/default/vld8-review.md (generated)"
        in diff_text
        and "-old\n+new\n" in diff_text,
    )


def _check_fixtures(check) -> None:
    actual_fixtures = (
        sorted(p.name for p in FIXTURES_DIR.iterdir() if p.is_dir())
        if FIXTURES_DIR.is_dir()
        else []
    )
    check(
        "fixtures: directory list matches expected matrix",
        actual_fixtures == sorted(FIXTURE_NAMES),
        f"Expected fixtures {sorted(FIXTURE_NAMES)}, found {actual_fixtures}",
    )

    sm_validator = _load_servicemap_validator()
    sm_fixture = FIXTURES_DIR / "servicemap-app"
    sm_file = sm_fixture / "servicemap.json"
    sm_data = json.loads(sm_file.read_text(encoding="utf-8"))
    sm_res = sm_validator.validate_map(
        sm_data,
        check_evidence=True,
        repo_path=sm_fixture,
        strict=True,
    )
    check(
        "fixtures: servicemap-app/servicemap.json passes schema 1.2 + strict evidence",
        not sm_res.errors
        and not sm_res.warnings
        and sm_res.evidence_counts.get("verified", 0) == 2,
        "\n".join(sm_res.errors + sm_res.warnings),
    )


def _generate_outputs(
    specs: list[SnapshotSpec], check
) -> dict[tuple[str, str, str], str]:
    outputs: dict[tuple[str, str, str], str] = {}
    with tempfile.TemporaryDirectory(prefix="vld8-snap-") as tmp:
        work_dir = Path(tmp)
        staged_repos = {
            fixture: stage_fixture_repo(FIXTURES_DIR / fixture, work_dir / fixture)
            for fixture in FIXTURE_NAMES
        }
        forbidden_roots = (work_dir, ROOT, Path.home())
        for spec in specs:
            repo_dir = staged_repos[spec.fixture]
            raw = run_generator(
                spec.generator_path,
                repo_dir,
                previews=spec.previews,
                use_service_map=(repo_dir / "servicemap.json").is_file(),
            )
            normalized = normalize_output(
                raw,
                repo_dir=repo_dir,
                work_dir=work_dir,
                toolkit_root=ROOT,
            )
            outputs[(spec.fixture, spec.mode, spec.generator_key)] = normalized
            leaks = find_leaked_paths(normalized, forbidden_roots=forbidden_roots)
            check(
                f"{spec.label}: zero leaked host or temporary paths",
                not leaks,
                f"Leaked paths in {spec.label}: {', '.join(leaks)}",
            )
    return outputs


def _check_content_invariants(outputs: dict[tuple[str, str, str], str], check) -> None:
    for fixture in FIXTURE_NAMES:
        for gen_key, _gen_path, skill_filename in GENERATORS:
            default_out = outputs[(fixture, "default", gen_key)]
            preview_out = outputs[(fixture, "preview-2.1", gen_key)]
            check(
                f"{fixture}/{skill_filename}: default omits preview marker and "
                "preview-2.1 includes it",
                paths.PREVIEW_MARKER not in default_out
                and paths.PREVIEW_MARKER in preview_out
                and "--preview 2.1" in preview_out
                and default_out != preview_out,
            )

    py_peer = outputs[("python-ts", "default", "peer")]
    py_sec = outputs[("python-ts", "default", "security")]
    check(
        "python-ts: both generators detect Python and Node/TS",
        "**Python**" in py_peer
        and "**Node.js / JavaScript / TypeScript**" in py_peer
        and "**Python**" in py_sec
        and "**Node.js / JavaScript / TypeScript**" in py_sec,
    )

    sw_peer = outputs[("swift-apple", "default", "peer")]
    sw_sec = outputs[("swift-apple", "default", "security")]
    check(
        "swift-apple: peer detects Swift, SwiftUI, CloudKit, macOS, and Swift Testing",
        "**Swift (language & concurrency)**" in sw_peer
        and "**SwiftUI**" in sw_peer
        and "**CloudKit sync**" in sw_peer
        and "**macOS app**" in sw_peer
        and "**Swift Testing**" in sw_peer,
    )
    check(
        "swift-apple: security detects Swift, SwiftUI, CloudKit, and macOS",
        "**Swift (language & concurrency)**" in sw_sec
        and "**SwiftUI**" in sw_sec
        and "**CloudKit sync**" in sw_sec
        and "**macOS app**" in sw_sec,
    )

    sm_peer = outputs[("servicemap-app", "default", "peer")]
    sm_sec = outputs[("servicemap-app", "default", "security")]
    check(
        "servicemap-app: peer renders service map component table and flow hints",
        "**Available components for full review:**" in sm_peer
        and "| `gateway` | service | `services/gateway` | go |" in sm_peer
        and "| `portal` | app | `apps/portal` | typescript |" in sm_peer
        and "**Most-connected components (start here):**" in sm_peer,
    )
    check(
        "servicemap-app: security renders service map endpoints and shared datastores",
        "**Available components for full security audit:**" in sm_sec
        and "### Known Unauthenticated Endpoints (from service map)" in sm_sec
        and "### Shared Datastores (from service map)" in sm_sec
        and "`datastore-users-db`" in sm_sec,
    )


def _apply_update(
    specs: list[SnapshotSpec],
    outputs: dict[tuple[str, str, str], str],
    results: list[tuple[str, bool]],
    details: list[str],
) -> int:
    if any(not ok for _name, ok in results):
        for name, ok in results:
            print(("PASS " if ok else "FAIL ") + name)
        for detail in details:
            print(detail)
        print("\nRefusing to update golden files while pre-checks fail.")
        return 1

    expected_golden = {spec.golden_path for spec in specs}
    removed = _prune_stale_golden(expected_golden)
    counts = {"created": 0, "updated": 0, "unchanged": 0}
    for spec in specs:
        content = outputs[(spec.fixture, spec.mode, spec.generator_key)]
        status = _write_golden(spec.golden_path, content)
        counts[status] += 1
        print(f"{status.upper():9s} tests/snapshots/golden/{spec.golden_rel}")
    for stale in removed:
        print(f"REMOVED   {stale.relative_to(ROOT)}")
    for name, ok in results:
        print(("PASS " if ok else "FAIL ") + name)
    print(
        f"\nGolden update complete ({counts['created']} created, "
        f"{counts['updated']} updated, {counts['unchanged']} unchanged, "
        f"{len(removed)} removed); {len(results)} invariant checks passed."
    )
    return 0


def _compare_golden(
    specs: list[SnapshotSpec],
    outputs: dict[tuple[str, str, str], str],
    check,
) -> None:
    for spec in specs:
        actual = outputs[(spec.fixture, spec.mode, spec.generator_key)]
        expected = (
            spec.golden_path.read_text(encoding="utf-8")
            if spec.golden_path.exists()
            else None
        )
        ok, diff_or_msg = compare_snapshot(expected, actual, golden_rel=spec.golden_rel)
        check(f"snapshot matches: {spec.label}", ok, diff_or_msg)
        if expected is not None:
            golden_leaks = find_leaked_paths(
                expected, forbidden_roots=(ROOT, Path.home())
            )
            check(
                f"golden file clean: {spec.label}",
                not golden_leaks,
                f"Leaked paths in checked-in golden {spec.label}: "
                f"{', '.join(golden_leaks)}",
            )

    expected_golden = {spec.golden_path for spec in specs}
    actual_golden = (
        {p for p in GOLDEN_DIR.rglob("*") if p.is_file()}
        if GOLDEN_DIR.exists()
        else set()
    )
    unexpected = sorted(
        p.relative_to(ROOT).as_posix() for p in actual_golden - expected_golden
    )
    check(
        "golden: no unexpected files under tests/snapshots/golden/",
        not unexpected,
        f"Unexpected golden files: {', '.join(unexpected)}",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify or update golden snapshots for generated review skills.",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Regenerate checked-in golden files under tests/snapshots/golden/.",
    )
    args = parser.parse_args(argv)

    results: list[tuple[str, bool]] = []
    details: list[str] = []

    def check(name: str, cond: object, detail: str = "") -> None:
        ok = bool(cond)
        results.append((name, ok))
        if not ok and detail:
            details.append(detail)

    _run_self_checks(check)
    _check_fixtures(check)
    specs = all_specs()
    outputs = _generate_outputs(specs, check)
    _check_content_invariants(outputs, check)

    if args.update:
        return _apply_update(specs, outputs, results, details)

    _compare_golden(specs, outputs, check)
    for name, ok in results:
        print(("PASS " if ok else "FAIL ") + name)
    for detail in details:
        print("\n" + detail.rstrip())

    fails = [name for name, ok in results if not ok]
    if fails:
        print(
            f"\nFAILURES: {len(fails)}\n"
            "Run 'python tests/test_snapshots.py --update' to regenerate golden "
            "files if the output change is intentional."
        )
        return 1
    print(f"\nAll {len(results)} checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
