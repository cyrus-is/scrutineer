#!/usr/bin/env python3
"""Golden-output snapshot harness for the generated review skills.

Dependency-free (stdlib + PyYAML, matching the generators; no network and no
sleeps). Run from the repository root:

    python tests/test_snapshots.py           # compare outputs to golden files
    python tests/test_snapshots.py --update  # regenerate checked-in golden files

Each synthetic fixture repo under ``tests/snapshots/fixtures/`` is copied into
an isolated temporary git repository and run through both
``generate-peer-review/generate.py`` and ``generate-security-review/generate.py``
across default mode and every preview milestone in ``vld8.paths.PREVIEW_MILESTONES``.
Raw outputs are checked for zero leaked repo, temp, toolkit, host, or
placeholder paths, normalized for line endings, and compared against golden files
under ``tests/snapshots/golden/``.

Exits zero when all snapshots and harness checks pass, and non-zero with a
unified diff on any mismatch or missing golden file.
"""

from __future__ import annotations

import argparse
import contextlib
import difflib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vld8 import paths  # noqa: E402

SNAPSHOTS_DIR = Path(__file__).resolve().parent / "snapshots"
FIXTURES_DIR = SNAPSHOTS_DIR / "fixtures"
GOLDEN_DIR = SNAPSHOTS_DIR / "golden"

FIXTURE_NAMES: tuple[str, ...] = ("python-ts", "swift-apple", "servicemap-app")


def build_modes(
    milestones: Iterable[str] | None = None,
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Build default and per-milestone snapshot modes from PREVIEW_MILESTONES."""
    source = paths.PREVIEW_MILESTONES.keys() if milestones is None else milestones
    ordered = tuple(sorted(set(source)))
    return (
        ("default", ()),
        *((f"preview-{milestone}", (milestone,)) for milestone in ordered),
    )


MODES: tuple[tuple[str, tuple[str, ...]], ...] = build_modes()
GENERATORS: tuple[tuple[str, Path, str], ...] = (
    ("peer", paths.PEER_GENERATOR, paths.PEER_COMMAND),
    ("security", paths.SECURITY_GENERATOR, paths.SECURITY_COMMAND),
)

_FORBIDDEN_PLACEHOLDERS: tuple[str, ...] = (
    "<REPO_ROOT>",
    "<WORK_ROOT>",
    "<TOOLKIT_ROOT>",
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

    def golden_path_for(self, golden_dir: Path = GOLDEN_DIR) -> Path:
        return golden_dir / self.golden_rel

    @property
    def golden_path(self) -> Path:
        return self.golden_path_for(GOLDEN_DIR)

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


def normalize_output(text: str) -> str:
    """Normalize line endings to LF without masking leaked paths."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def find_leaked_paths(
    text: str, *, forbidden_roots: tuple[Path, ...] = ()
) -> list[str]:
    """Return descriptions of any local, temporary, or placeholder paths in text."""
    leaks: list[str] = []
    for placeholder in _FORBIDDEN_PLACEHOLDERS:
        if placeholder in text:
            leaks.append(f"placeholder {placeholder!r}")
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


def _isolated_git_env(work_dir: Path | None = None) -> dict[str, str]:
    """Build a subprocess env isolated from host git config, hooks, and overrides."""
    env = dict(os.environ)
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
    ):
        env.pop(key, None)
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_ATTR_NOSYSTEM"] = "1"
    if work_dir is not None:
        xdg_dir = work_dir / ".xdg-config"
        xdg_dir.mkdir(parents=True, exist_ok=True)
        env["XDG_CONFIG_HOME"] = str(xdg_dir)
    else:
        env["XDG_CONFIG_HOME"] = os.devnull
    return env


def _run_git(repo_dir: Path, *args: str, env: dict[str, str] | None = None) -> None:
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
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )


def stage_fixture_repo(
    src_dir: Path, dest_dir: Path, *, env: dict[str, str] | None = None
) -> Path:
    """Copy a synthetic fixture repo into dest_dir with an isolated git repo."""
    git_env = _isolated_git_env() if env is None else env
    shutil.copytree(
        src_dir,
        dest_dir,
        symlinks=False,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store", ".git"),
    )
    _run_git(dest_dir, "init", "-q", "-b", "main", env=git_env)
    _run_git(dest_dir, "config", "user.email", "fixture@example.invalid", env=git_env)
    _run_git(dest_dir, "config", "user.name", "Fixture", env=git_env)
    _run_git(dest_dir, "add", "-A", env=git_env)
    _run_git(dest_dir, "commit", "--no-verify", "-qm", "fixture", env=git_env)
    return dest_dir


def run_generator(
    generator: Path,
    repo_dir: Path,
    *,
    previews: tuple[str, ...],
    use_service_map: bool,
    env: dict[str, str] | None = None,
) -> str:
    """Run one generator against repo_dir and return the generated skill text."""
    git_env = _isolated_git_env() if env is None else env
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

    proc = subprocess.run(cmd, cwd=ROOT, env=git_env, capture_output=True, text=True)
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


def _prune_stale_golden(
    expected_paths: set[Path], golden_dir: Path = GOLDEN_DIR
) -> list[Path]:
    removed: list[Path] = []
    if not golden_dir.exists():
        return removed
    for path in sorted(golden_dir.rglob("*")):
        if path.is_file() and path not in expected_paths:
            path.unlink()
            removed.append(path)
    for directory in sorted(golden_dir.rglob("*"), reverse=True):
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()
    return removed


def _run_self_checks(check) -> None:
    sample_work = Path("/tmp/vld8-snap-selfcheck")
    sample_repo = sample_work / "demo-repo"
    sample_raw = (
        f"Repo: {sample_repo}\r\n"
        f"Work: {sample_work}\r\n"
        "Worktree: ${TMPDIR:-/tmp}/vld8-<repo>-pr-123\r\n"
    )
    normalized = normalize_output(sample_raw)
    check(
        "harness: normalize_output normalizes CRLF without hiding paths",
        normalized == sample_raw.replace("\r\n", "\n"),
    )
    raw_leaks = find_leaked_paths(
        normalized, forbidden_roots=(sample_repo, sample_work, ROOT)
    )
    check(
        "harness: find_leaked_paths catches raw repo/work/toolkit/placeholder paths",
        any(str(sample_repo) in item for item in raw_leaks)
        and bool(find_leaked_paths(f"bad {ROOT}"))
        and bool(find_leaked_paths("bad <REPO_ROOT>/x"))
        and bool(find_leaked_paths("bad /Users/alice/work"))
        and bool(find_leaked_paths("bad /private/var/folders/xx/file"))
        and not find_leaked_paths("Worktree: ${TMPDIR:-/tmp}/vld8-<repo>-pr-123"),
    )
    check(
        "harness: build_modes derives modes dynamically from milestone list",
        build_modes(["2.2", "2.1", "2.1"])
        == (("default", ()), ("preview-2.1", ("2.1",)), ("preview-2.2", ("2.2",)))
        and build_modes([]) == (("default", ()),),
    )

    ok_match, diff_match = compare_snapshot(
        "line1\n", "line1\n", golden_rel=Path("demo/default/vld8-review.md")
    )
    ok_missing, missing_msg = compare_snapshot(
        None, "line1\n", golden_rel=Path("demo/default/vld8-review.md")
    )
    ok_diff, diff_text = compare_snapshot(
        "line1\nold\n", "line1\nnew\n", golden_rel=Path("demo/default/vld8-review.md")
    )
    check(
        "harness: compare_snapshot handles match, missing, and mismatch diffs",
        ok_match
        and diff_match == ""
        and not ok_missing
        and (
            "Missing golden snapshot: "
            "tests/snapshots/golden/demo/default/vld8-review.md"
        )
        in missing_msg
        and not ok_diff
        and "--- a/tests/snapshots/golden/demo/default/vld8-review.md" in diff_text
        and "+++ b/tests/snapshots/golden/demo/default/vld8-review.md (generated)"
        in diff_text
        and "-old\n+new\n" in diff_text,
    )

    with tempfile.TemporaryDirectory(prefix="vld8-snap-self-") as tmp:
        tmp_golden = Path(tmp) / "golden"
        demo_spec = SnapshotSpec(
            fixture="demo",
            mode="default",
            previews=(),
            generator_key="peer",
            generator_path=paths.PEER_GENERATOR,
            skill_filename=paths.PEER_COMMAND,
        )
        demo_out = {
            (demo_spec.fixture, demo_spec.mode, demo_spec.generator_key): "ok\n"
        }
        stale_file = tmp_golden / "old" / "default" / "stale.md"
        stale_file.parent.mkdir(parents=True, exist_ok=True)
        stale_file.write_text("stale\n", encoding="utf-8")

        with contextlib.redirect_stdout(io.StringIO()):
            rc_refuse = _apply_update(
                [demo_spec],
                demo_out,
                [("precheck", False)],
                ["failed"],
                golden_dir=tmp_golden,
            )
        target_golden = demo_spec.golden_path_for(tmp_golden)
        check(
            "harness: _apply_update refuses write and prune on failing pre-checks",
            rc_refuse == 1 and not target_golden.exists() and stale_file.exists(),
        )

        with contextlib.redirect_stdout(io.StringIO()):
            rc_ok = _apply_update(
                [demo_spec],
                demo_out,
                [("precheck", True)],
                [],
                golden_dir=tmp_golden,
            )
        st_unchanged = _write_golden(target_golden, "ok\n")
        st_updated = _write_golden(target_golden, "ok2\n")
        extra_file = tmp_golden / "unexpected.md"
        extra_file.write_text("extra\n", encoding="utf-8")
        unexpected_results: list[tuple[str, bool]] = []
        unexpected_details: list[str] = []

        def _rec(name: str, cond: object, detail: str = "") -> None:
            unexpected_results.append((name, bool(cond)))
            if not cond and detail:
                unexpected_details.append(detail)

        _write_golden(target_golden, "ok\n")
        _compare_golden([demo_spec], demo_out, _rec, golden_dir=tmp_golden)
        unexpected_map = dict(unexpected_results)
        unexpected_key = "golden: no unexpected files under tests/snapshots/golden/"
        check(
            "harness: _apply_update, _prune_stale_golden, and _compare_golden work",
            rc_ok == 0
            and target_golden.read_text(encoding="utf-8") == "ok\n"
            and not stale_file.exists()
            and not (tmp_golden / "old").exists()
            and st_unchanged == "unchanged"
            and st_updated == "updated"
            and not unexpected_map[unexpected_key]
            and "unexpected.md" in "\n".join(unexpected_details),
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
        git_env = _isolated_git_env(work_dir)
        staged_repos = {
            fixture: stage_fixture_repo(
                FIXTURES_DIR / fixture, work_dir / fixture, env=git_env
            )
            for fixture in FIXTURE_NAMES
        }
        for spec in specs:
            repo_dir = staged_repos[spec.fixture]
            raw = run_generator(
                spec.generator_path,
                repo_dir,
                previews=spec.previews,
                use_service_map=(repo_dir / "servicemap.json").is_file(),
                env=git_env,
            )
            forbidden_roots = (repo_dir, work_dir, ROOT, Path.home())
            leaks = find_leaked_paths(raw, forbidden_roots=forbidden_roots)
            check(
                f"{spec.label}: zero leaked host or temporary paths",
                not leaks,
                f"Leaked paths in {spec.label}: {', '.join(leaks)}",
            )
            outputs[(spec.fixture, spec.mode, spec.generator_key)] = normalize_output(
                raw
            )
    return outputs


def _check_content_invariants(outputs: dict[tuple[str, str, str], str], check) -> None:
    preview_modes = [(mode, previews) for mode, previews in MODES if previews]
    for fixture in FIXTURE_NAMES:
        for gen_key, _gen_path, skill_filename in GENERATORS:
            default_out = outputs[(fixture, "default", gen_key)]
            check(
                f"{fixture}/{skill_filename}: default omits preview marker",
                paths.PREVIEW_MARKER not in default_out,
            )
            for mode, previews in preview_modes:
                preview_out = outputs[(fixture, mode, gen_key)]
                check(
                    f"{fixture}/{skill_filename}: {mode} includes preview marker",
                    paths.PREVIEW_MARKER in preview_out
                    and all(f"--preview {m}" in preview_out for m in previews)
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
    golden_dir: Path = GOLDEN_DIR,
) -> int:
    if any(not ok for _name, ok in results):
        for name, ok in results:
            print(("PASS " if ok else "FAIL ") + name)
        for detail in details:
            print(detail)
        print("\nRefusing to update golden files while pre-checks fail.")
        return 1

    expected_golden = {spec.golden_path_for(golden_dir) for spec in specs}
    removed = _prune_stale_golden(expected_golden, golden_dir=golden_dir)
    counts = {"created": 0, "updated": 0, "unchanged": 0}
    for spec in specs:
        content = outputs[(spec.fixture, spec.mode, spec.generator_key)]
        status = _write_golden(spec.golden_path_for(golden_dir), content)
        counts[status] += 1
        print(f"{status.upper():9s} tests/snapshots/golden/{spec.golden_rel}")
    for stale in removed:
        label = (
            stale.relative_to(ROOT)
            if stale.is_relative_to(ROOT)
            else stale.relative_to(golden_dir)
        )
        print(f"REMOVED   {label}")
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
    golden_dir: Path = GOLDEN_DIR,
) -> None:
    for spec in specs:
        golden_path = spec.golden_path_for(golden_dir)
        actual = outputs[(spec.fixture, spec.mode, spec.generator_key)]
        expected = (
            golden_path.read_text(encoding="utf-8") if golden_path.exists() else None
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

    expected_golden = {spec.golden_path_for(golden_dir) for spec in specs}
    actual_golden = (
        {p for p in golden_dir.rglob("*") if p.is_file()}
        if golden_dir.exists()
        else set()
    )
    unexpected = sorted(
        p.relative_to(golden_dir).as_posix() for p in actual_golden - expected_golden
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
