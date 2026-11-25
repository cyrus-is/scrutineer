#!/usr/bin/env python3
"""Tests for vld8 check routing and diff sizing (vld8/checks.py).

Dependency-free (no pytest): run from the repo root with

    python tests/test_checks.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vld8 import checks, findings, paths  # noqa: E402

_results: list[tuple[str, bool]] = []


def check(name: str, cond: object) -> None:
    _results.append((name, bool(cond)))


def _expect_error(name: str, fn, *args, needle: str = "", **kwargs) -> None:
    try:
        fn(*args, **kwargs)
        check(name, False)
    except checks.ChecksError as exc:
        msg = str(exc)
        check(name, not needle or needle in msg)


def _run_cli(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "vld8", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def _init_git_repo(repo: Path, branch: str = "main") -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q", "-b", branch)
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")


def _commit_files(repo: Path, files: dict[str, str | bytes], msg: str) -> None:
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", msg)


def test_assets_and_validation() -> None:
    check("PEER_GUIDANCE path exists", paths.PEER_GUIDANCE.is_file())
    check("SECURITY_GUIDANCE path exists", paths.SECURITY_GUIDANCE.is_file())
    check("no missing toolkit assets", paths.missing_assets() == [])

    for valid_path in ("a.py", "src/api/routes.ts", "dir with spaces/file.go"):
        check(
            f"accept valid rel path {valid_path!r}",
            checks.validate_repo_relative_path(valid_path) == valid_path,
        )

    for bad_path in (
        "",
        "/abs/path.py",
        "dir/",
        "../escape.py",
        "a/../b.py",
        "./a.py",
        "a/./b.py",
        "a//b.py",
        "a\\b.py",
        "C:foo.py",
        "a\x00b.py",
        "a\nb.py",
        "\x1b[31ma.py",
        "bad\ud800.py",
        "x" * 1025,
        123,
    ):
        _expect_error(
            f"reject unsafe rel path {checks.safe_error_text(bad_path)}",
            checks.validate_repo_relative_path,
            bad_path,
        )

    for valid_ref in ("main...HEAD", "HEAD~1..HEAD", "v1.0.0", "feat/x"):
        check(
            f"accept valid ref {valid_ref!r}",
            checks.validate_git_ref_or_range(valid_ref) == valid_ref,
        )

    for bad_ref in (
        "",
        "-n",
        "--upload-pack=evil",
        "-",
        "main HEAD",
        "main\nHEAD",
        "main\x00HEAD",
        "main\ud800",
        "x" * 1025,
        99,
    ):
        _expect_error(
            f"reject unsafe ref {checks.safe_error_text(bad_ref)}",
            checks.validate_git_ref_or_range,
            bad_ref,
        )

    check("validate_pr_number accepts 1", checks.validate_pr_number(1) == 1)
    for bad_pr in (0, -5, True, False, "1", None):
        _expect_error(
            f"reject invalid PR {bad_pr!r}",
            checks.validate_pr_number,
            bad_pr,
        )

    with tempfile.TemporaryDirectory(prefix="vld8-checks-repo-") as tmp:
        root = Path(tmp)
        sub = root / "my-repo"
        sub.mkdir()
        resolved, label = checks.resolve_repo_root(sub)
        check("resolve_repo_root returns resolved path", resolved == sub.resolve())
        check(
            "resolve_repo_root label omits host path",
            label == "my-repo" and "/" not in label,
        )
        _, dot_label = checks.resolve_repo_root(".")
        check("resolve_repo_root '.' preserves '.' label", dot_label == ".")

        f = root / "plain.txt"
        f.write_text("hi")
        _expect_error(
            "resolve_repo_root rejects missing dir",
            checks.resolve_repo_root,
            root / "missing",
        )
        _expect_error(
            "resolve_repo_root rejects file path",
            checks.resolve_repo_root,
            f,
        )
        _expect_error(
            "resolve_repo_root rejects control chars",
            checks.resolve_repo_root,
            "repo\x00name",
        )
        _expect_error(
            "resolve_repo_root rejects non-path type",
            checks.resolve_repo_root,
            123,  # type: ignore[arg-type]
        )

    sanitized = checks.safe_error_text("\x1b[31mboom\x1b[0m\nnext")
    check(
        "safe_error_text strips ANSI and escapes control chars",
        "\x1b" not in sanitized and "\\x0a" in sanitized and "boom" in sanitized,
    )


def test_globs_and_previews() -> None:
    cases = [
        ("App/Foo.swift", "App/**/*.swift", True),
        ("App/a/b/Foo.swift", "App/**/*.swift", True),
        ("Foo.swift", "**/*.swift", True),
        ("x/App/Foo.swift", "App/**/*.swift", False),
        ("macOS/A.entitlements", "**/macOS/**/*.entitlements", True),
        ("iOS/A.entitlements", "**/macOS/**/*.entitlements", False),
        ("src/index.ts", "**/*.ts", True),
        ("src/index.tsx", "**/*.ts", False),
        ("Dockerfile", "**/Dockerfile", True),
        ("services/api/Dockerfile.prod", "**/Dockerfile.*", True),
        ("dockerfile", "**/Dockerfile", True),
    ]
    bad = [(p, g) for p, g, want in cases if checks.glob_match(p, g) != want]
    check(f"glob_match handles recursive & case-insensitive globs {bad}", not bad)

    _expect_error(
        "glob_match rejects excessive '**/' expansion",
        checks.glob_match,
        "a/b",
        "**/".join(["x"] * 10),
    )

    sample = {
        "items": [
            {"id": "keep"},
            {"id": "p21", "preview": "2.1"},
            {"id": "old", "replaced_in": "2.1"},
        ]
    }
    check(
        "_apply_previews default keeps replaced_in and drops preview",
        checks._apply_previews(sample, frozenset())
        == {"items": [{"id": "keep"}, {"id": "old"}]},
    )
    check(
        "_apply_previews with milestone swaps entries",
        checks._apply_previews(sample, frozenset({"2.1"}))
        == {"items": [{"id": "keep"}, {"id": "p21"}]},
    )
    _expect_error(
        "_apply_previews rejects bad gate value",
        checks._apply_previews,
        {"items": [{"preview": 2.1}]},
    )
    _expect_error(
        "_apply_previews rejects conflicting gates",
        checks._apply_previews,
        {"items": [{"preview": "2.1", "replaced_in": "2.1"}]},
    )

    norm_code = checks._normalize_code_checks(
        [{"id": "c1", "title": "t", "kind": "hybrid", "tier": "fast"}]
    )
    norm_fa = checks._normalize_focus_areas(
        [{"area": "a", "description": "d", "lens": "correctness", "why": "because"}]
    )
    norm_sec = checks._normalize_security_checks(
        [{"id": "s1", "title": "t", "kind": "code", "tier": "fast"}]
    )
    check(
        "normalizers preserve optional kind, tier, and why fields",
        norm_code[0].get("kind") == "hybrid"
        and norm_code[0].get("tier") == "fast"
        and norm_fa[0].get("why") == "because"
        and norm_sec[0].get("kind") == "code"
        and norm_sec[0].get("tier") == "fast",
    )


def test_checks_changed() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-changed-") as tmp:
        repo = Path(tmp) / "sample-repo"
        repo.mkdir()
        outside = Path(tmp) / "outside_secret.py"
        outside.write_text("jwt.verify(token, secret)\n", encoding="utf-8")

        # Synthetic non-existent paths + unmatched README.md + duplicates.
        res_both = checks.select_checks(
            changed=[
                "src/app.py",
                "src/app.py",
                "services/api/Dockerfile.prod",
                "web/index.ts",
                "README.md",
            ],
            repo=repo,
        )
        check(
            "select_checks schemaVersion and metadata",
            res_both["schemaVersion"] == "1.0"
            and res_both["mode"] == "changed"
            and res_both["lens"] == "both"
            and res_both["repo"] == "sample-repo",
        )
        check(
            "changedPaths sorted and deduplicated",
            res_both["changedPaths"]
            == [
                "README.md",
                "services/api/Dockerfile.prod",
                "src/app.py",
                "web/index.ts",
            ],
        )
        check(
            "unmatchedPaths contains README.md only",
            res_both["unmatchedPaths"] == ["README.md"],
        )

        block_ids = [(b["lens"], b["category"], b["key"]) for b in res_both["blocks"]]
        check(
            "blocks deterministically ordered by (lens, category, key)",
            block_ids == sorted(block_ids)
            and ("code", "backend", "python") in block_ids
            and ("code", "backend", "node") in block_ids
            and ("code", "infrastructure", "docker") in block_ids
            and ("security", "backend", "python") in block_ids
            and ("security", "backend", "node") in block_ids
            and ("security", "infrastructure", "docker") in block_ids,
        )

        py_code = next(
            b
            for b in res_both["blocks"]
            if b["lens"] == "code" and b["key"] == "python"
        )
        check(
            "code block normalizes checks, focusAreas, changeTypeSignals",
            bool(py_code["checks"])
            and "failureMode" in py_code["checks"][0]
            and bool(py_code["focusAreas"])
            and bool(py_code["changeTypeSignals"])
            and py_code["matchedPaths"] == ["src/app.py"]
            and py_code["matchedContent"] == [],
        )
        py_sec = next(
            b
            for b in res_both["blocks"]
            if b["lens"] == "security" and b["key"] == "python"
        )
        check(
            "security block normalizes checklist keys",
            bool(py_sec["checks"])
            and "secureAlternative" in py_sec["checks"][0]
            and "severityIfFound" in py_sec["checks"][0]
            and "owasp" in py_sec["checks"][0],
        )

        # Lens filter: code only vs security only.
        res_code = checks.select_checks(changed=["src/app.py"], lens="code", repo=repo)
        check(
            "lens=code returns only code blocks",
            res_code["blocks"] and all(b["lens"] == "code" for b in res_code["blocks"]),
        )
        res_sec = checks.select_checks(
            changed=["src/app.py"], lens="security", repo=repo
        )
        check(
            "lens=security returns only security blocks",
            res_sec["blocks"]
            and all(b["lens"] == "security" for b in res_sec["blocks"]),
        )

        # Content-confirmed matching on disk + symlink rejection.
        (repo / "Sources").mkdir()
        (repo / "Sources" / "Store.swift").write_text(
            "import CloudKit\n", encoding="utf-8"
        )
        (repo / "Sources" / "Plain.swift").write_text(
            "package func helper() {}\nmodule Foo {}\n", encoding="utf-8"
        )
        (repo / "Sources" / "Mac.swift").write_text("import AppKit\n", encoding="utf-8")
        (repo / "auth.py").write_text(
            "def verify(t, k):\n    return jwt.verify(t, k)\n", encoding="utf-8"
        )
        (repo / "big.py").write_bytes(b"# " + b"a" * (1024 * 1024 + 16))
        (repo / "link.py").symlink_to(outside)
        outside_dir = Path(tmp) / "outside_dir"
        outside_dir.mkdir()
        (outside_dir / "nested.py").write_text("jwt.verify(a, b)\n", encoding="utf-8")
        (repo / "sublink").symlink_to(outside_dir)

        res_content = checks.select_checks(
            changed=[
                "Sources/Store.swift",
                "Sources/Plain.swift",
                "Sources/Mac.swift",
                "auth.py",
                "big.py",
                "link.py",
                "sublink/nested.py",
            ],
            repo=repo,
        )
        keys_code = {b["key"] for b in res_content["blocks"] if b["lens"] == "code"}
        keys_sec = {b["key"] for b in res_content["blocks"] if b["lens"] == "security"}

        check(
            "content-gated blocks match when confirmed and stay off otherwise",
            "swift" in keys_code
            and "cloudkit" in keys_code
            and "macos_app" in keys_code
            and "swiftui" not in keys_code
            and "apple_on_device_ai" not in keys_code
            and "swift_testing" not in keys_code
            and "go" not in keys_code
            and "java" not in keys_code,
        )
        ck_block = next(
            b
            for b in res_content["blocks"]
            if b["lens"] == "code" and b["key"] == "cloudkit"
        )
        check(
            "cloudkit scopes matchedPaths and records matchedContent",
            ck_block["matchedPaths"] == ["Sources/Store.swift"]
            and ck_block["matchedContent"]
            == [{"path": "Sources/Store.swift", "pattern": "^import CloudKit"}],
        )

        check("security matches auth.jwt on real auth.py", "jwt" in keys_sec)
        jwt_block = next(
            b
            for b in res_content["blocks"]
            if b["lens"] == "security" and b["key"] == "jwt"
        )
        check(
            "symlinks and oversized files never match detect_content",
            jwt_block["matchedPaths"] == ["auth.py"]
            and all(m["path"] == "auth.py" for m in jwt_block["matchedContent"]),
        )

        # Validation errors.
        _expect_error(
            "reject both changed and diff_range",
            checks.select_checks,
            changed=["a.py"],
            diff_range="main..HEAD",
            repo=repo,
        )
        _expect_error(
            "reject neither changed nor diff_range",
            checks.select_checks,
            repo=repo,
        )
        _expect_error(
            "reject empty changed list",
            checks.select_checks,
            changed=[],
            repo=repo,
        )
        _expect_error(
            "reject invalid lens",
            checks.select_checks,
            changed=["a.py"],
            lens="bogus",
            repo=repo,
        )
        _expect_error(
            "reject unsafe changed path",
            checks.select_checks,
            changed=["../escape.py"],
            repo=repo,
        )


def test_checks_diff_and_subproc_errors() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-diff-checks-") as tmp:
        repo = Path(tmp) / "git-repo"
        _init_git_repo(repo)
        _commit_files(
            repo,
            {
                "db/migrations/001.sql": "CREATE TABLE users (id INT);\n",
                "app.py": "print(1)\n",
                "README.md": "hello\n",
            },
            "initial",
        )
        # Empty diff against HEAD..HEAD.
        empty_res = checks.select_checks(diff_range="HEAD..HEAD", repo=repo)
        check(
            "empty diff yields empty changedPaths and blocks",
            empty_res["mode"] == "diff"
            and empty_res["changedPaths"] == []
            and empty_res["unmatchedPaths"] == []
            and empty_res["blocks"] == [],
        )

        # Delete sql file + modify python + add doc file.
        (repo / "db" / "migrations" / "001.sql").unlink()
        _commit_files(
            repo,
            {
                "app.py": "print(2)\n",
                "docs/notes.txt": "note\n",
            },
            "delete sql and edit py",
        )
        diff_res = checks.select_checks(diff_range="HEAD~1..HEAD", repo=repo)
        check(
            "diff mode includes deleted files without failing on disk read",
            diff_res["changedPaths"]
            == ["app.py", "db/migrations/001.sql", "docs/notes.txt"]
            and diff_res["unmatchedPaths"] == ["docs/notes.txt"],
        )
        keys = {(b["lens"], b["key"]) for b in diff_res["blocks"]}
        check(
            "diff mode selects sql_general for deleted sql and python for py",
            ("code", "sql_general") in keys and ("code", "python") in keys,
        )

        # Bad git range and injection attempts.
        _expect_error(
            "diff mode rejects leading dash range",
            checks.select_checks,
            diff_range="--output=/tmp/x",
            repo=repo,
        )
        _expect_error(
            "diff mode handles failing git command cleanly",
            checks.select_checks,
            diff_range="nonexistent..HEAD",
            repo=repo,
        )

        # Subprocess error cases via mock.
        with mock.patch(
            "subprocess.run",
            side_effect=FileNotFoundError("no git"),
        ):
            _expect_error(
                "missing binary raises ChecksError",
                checks.select_checks,
                diff_range="HEAD~1..HEAD",
                repo=repo,
                needle="required command not found",
            )
        with mock.patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(["git"], 60),
        ):
            _expect_error(
                "timed out subprocess raises ChecksError",
                checks.select_checks,
                diff_range="HEAD~1..HEAD",
                repo=repo,
                needle="timed out",
            )
        with mock.patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess(
                ["git"], 128, b"", b"\x1b[31mfatal error\x1b[0m\n"
            ),
        ):
            try:
                checks.select_checks(diff_range="HEAD~1..HEAD", repo=repo)
                check("sanitized subprocess stderr error", False)
            except checks.ChecksError as exc:
                msg = str(exc)
                check(
                    "sanitized subprocess stderr error",
                    "\x1b" not in msg and "fatal error" in msg,
                )

        with mock.patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess(["git"], 0, "a.py\x00", None),
        ):
            str_res = checks.select_checks(diff_range="HEAD~1..HEAD", repo=repo)
            check(
                "subprocess str stdout handled cleanly",
                str_res["changedPaths"] == ["a.py"],
            )

        with mock.patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess(
                ["git"], 0, b"x" * (checks.MAX_COMMAND_STDOUT_BYTES + 1), b""
            ),
        ):
            _expect_error(
                "oversized subprocess stdout raises ChecksError",
                checks.select_checks,
                diff_range="HEAD~1..HEAD",
                repo=repo,
                needle="exceeds max",
            )


def test_size_diff_tiers_renames_binary_and_servicemap() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-size-diff-") as tmp:
        repo = Path(tmp) / "sized-repo"
        _init_git_repo(repo)
        _commit_files(
            repo,
            {
                "services/api/old.py": "\n".join(f"line_{i} = {i}" for i in range(20))
                + "\n",
                "services/api-v2/keep.py": "v = 1\n",
                "apps/worker/job.py": "j = 1\n",
                "bin/data.bin": b"\x00\x01\x02\x03",
                "README.md": "root\n",
            },
            "base",
        )

        # Small diff with rename + binary + prefix boundary check.
        _git(repo, "checkout", "-qb", "feat")
        (repo / "services/api/old.py").rename(repo / "services/api/renamed.py")
        _commit_files(
            repo,
            {
                "services/api-v2/keep.py": "v = 1\nv2 = 2\nv3 = 3\n",
                "apps/worker/job.py": "j = 1\nj2 = 2\n",
                "bin/data.bin": b"\x00\x01\x02\x04\xff",
                "README.md": "root\nmore\n",
            },
            "feat commit",
        )

        # Move main ahead by 25 commits: main...feat counts only feat's 1 commit.
        _git(repo, "checkout", "-q", "main")
        for idx in range(25):
            _commit_files(repo, {"main_only.txt": f"{idx}\n"}, f"main {idx}")
        _git(repo, "checkout", "-q", "feat")

        small_res = checks.size_review(diff_range="main...feat", repo=repo)
        check(
            "small diff counts files, binary, lines, and right-only commits",
            small_res["schemaVersion"] == "1.0"
            and small_res["mode"] == "diff"
            and small_res["target"] == "main...feat"
            and small_res["files"] == 5
            and small_res["listedFiles"] == 5
            and small_res["filesTruncated"] is False
            and small_res["binaryFiles"] == 1
            and small_res["additions"] == 4
            and small_res["deletions"] == 0
            and small_res["commits"] == 1
            and small_res["tier"] == "small"
            and small_res["strategy"] == "single-unit"
            and small_res["partitionRecommended"] is False
            and small_res["reasons"] == [],
        )
        part_names = [p["name"] for p in small_res["partitions"]]
        check(
            "default 2-segment partitions include rename dest & root file",
            "services/api" in part_names
            and "services/api-v2" in part_names
            and "apps/worker" in part_names
            and "bin/data.bin" in part_names
            and "README.md" in part_names,
        )
        check(
            "partitions sorted by (-additions, -files, name)",
            small_res["partitions"][0]["name"] == "services/api-v2"
            and small_res["partitions"][0]["additions"] == 2,
        )

        # Auto-discovered servicemap.json (plus prefix boundary & stub skip).
        sm_payload = {
            "schema_version": "1.2.0",
            "components": [
                {
                    "id": "svc-api",
                    "name": "api",
                    "type": "service",
                    "path": "services/api",
                },
                {
                    "id": "svc-api-sub",
                    "name": "api-sub",
                    "type": "service",
                    "path": "services/api/sub",
                },
                {
                    "id": "app-worker",
                    "name": "worker",
                    "type": "app",
                    "path": "apps/worker",
                },
                {
                    "id": "ext-skip",
                    "name": "ext",
                    "type": "external",
                    "path": "README.md",
                },
                {
                    "id": "stub-skip",
                    "name": "stub",
                    "type": "service",
                    "path": "services/api-v2",
                    "stub": True,
                },
            ],
        }
        sm_file = repo / "servicemap.json"
        sm_file.write_text(json.dumps(sm_payload), encoding="utf-8")
        sm_res = checks.size_review(diff_range="main...feat", repo=repo)
        sm_parts = {p["name"]: p for p in sm_res["partitions"]}
        check(
            "servicemap assigns longest prefix without 'api-v2' bleed",
            set(sm_parts) == {"api", "worker", "other"}
            and sm_parts["api"]["files"] == 1
            and sm_parts["worker"]["files"] == 1
            and sm_parts["other"]["files"] == 3,
        )

        # Auto-discovered symlinked servicemap.json is ignored safely.
        outside_sm = Path(tmp) / "outside_sm.json"
        outside_sm.write_text(
            json.dumps(
                {
                    "components": [
                        {
                            "id": "svc-leak",
                            "name": "leaked-svc",
                            "path": "services/api-v2",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        sm_file.unlink()
        sm_file.symlink_to(outside_sm)
        sym_res = checks.size_review(diff_range="main...feat", repo=repo)
        check(
            "auto-discovered symlinked servicemap.json is not followed",
            all(p["name"] != "leaked-svc" for p in sym_res["partitions"]),
        )
        sm_file.unlink()

        # Explicit --service-map with root_path/paths + error cases.
        explicit_sm = Path(tmp) / "explicit.json"
        explicit_sm.write_text(
            json.dumps(
                {
                    "components": [
                        {
                            "id": "svc-api",
                            "name": "api-explicit",
                            "paths": ["services/api"],
                        },
                        {
                            "id": "app-w",
                            "name": "worker-explicit",
                            "root_path": "apps/worker",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        exp_res = checks.size_review(
            diff_range="main...feat", repo=repo, service_map=explicit_sm
        )
        check(
            "explicit --service-map supports paths and root_path",
            {"api-explicit", "worker-explicit", "other"}
            == {p["name"] for p in exp_res["partitions"]},
        )

        _expect_error(
            "missing explicit --service-map fails",
            checks.size_review,
            diff_range="main...feat",
            repo=repo,
            service_map=Path(tmp) / "missing.json",
        )
        sym_explicit = Path(tmp) / "sym_explicit.json"
        sym_explicit.symlink_to(explicit_sm)
        _expect_error(
            "symlink explicit --service-map rejected",
            checks.size_review,
            diff_range="main...feat",
            repo=repo,
            service_map=sym_explicit,
        )
        bad_json_sm = Path(tmp) / "bad.json"
        bad_json_sm.write_text("{not json", encoding="utf-8")
        _expect_error(
            "invalid JSON service map fails",
            checks.size_review,
            diff_range="main...feat",
            repo=repo,
            service_map=bad_json_sm,
        )
        bad_prefix_sm = Path(tmp) / "bad_prefix.json"
        bad_prefix_sm.write_text(
            json.dumps({"components": [{"id": "x", "name": "x", "path": "../escape"}]}),
            encoding="utf-8",
        )
        _expect_error(
            "service map with '../' component path fails",
            checks.size_review,
            diff_range="main...feat",
            repo=repo,
            service_map=bad_prefix_sm,
        )
        dir_sm = Path(tmp) / "dir_sm"
        dir_sm.mkdir()
        _expect_error(
            "directory passed as --service-map rejected",
            checks.size_review,
            diff_range="main...feat",
            repo=repo,
            service_map=dir_sm,
        )
        big_sm = Path(tmp) / "big_sm.json"
        big_sm.write_bytes(b" " * (checks.MAX_SERVICEMAP_BYTES + 1))
        _expect_error(
            "oversized --service-map rejected",
            checks.size_review,
            diff_range="main...feat",
            repo=repo,
            service_map=big_sm,
        )
        list_sm = Path(tmp) / "list_sm.json"
        list_sm.write_text("[]", encoding="utf-8")
        _expect_error(
            "non-object service map JSON rejected",
            checks.size_review,
            diff_range="main...feat",
            repo=repo,
            service_map=list_sm,
        )
        bad_comps_sm = Path(tmp) / "bad_comps.json"
        bad_comps_sm.write_text('{"components": "nope"}', encoding="utf-8")
        _expect_error(
            "non-array components in service map rejected",
            checks.size_review,
            diff_range="main...feat",
            repo=repo,
            service_map=bad_comps_sm,
        )
        id_only_sm = Path(tmp) / "id_only_sm.json"
        id_only_sm.write_text(
            json.dumps(
                {
                    "components": [
                        {"id": "svc-only-id", "path": "apps/worker"},
                        {"id": "dot-root", "name": "root", "path": "."},
                    ]
                }
            ),
            encoding="utf-8",
        )
        id_only_res = checks.size_review(
            diff_range="main...feat", repo=repo, service_map=id_only_sm
        )
        check(
            "component without name falls back to id and '.' prefix is skipped",
            {"svc-only-id", "other"} == {p["name"] for p in id_only_res["partitions"]},
        )
        single_ref_res = checks.size_review(diff_range="HEAD~1", repo=repo)
        check(
            "single-ref diff counts commits from ref..HEAD",
            single_ref_res["commits"] == 1,
        )
        _expect_error(
            "size_review rejects missing mode",
            checks.size_review,
            repo=repo,
        )
        _expect_error(
            "size_review rejects both diff and pr",
            checks.size_review,
            diff_range="HEAD~1..HEAD",
            pr_number=1,
            repo=repo,
        )

        # Medium (50 files) & Large (>150 files) + Commit threshold (>20 commits).
        _git(repo, "checkout", "-qb", "sizing-tests")
        _commit_files(
            repo,
            {f"pkg/mod_{i:03d}.py": f"x = {i}\n" for i in range(50)},
            "50 files",
        )
        med_res = checks.size_review(diff_range="HEAD~1..HEAD", repo=repo)
        check(
            "50 files classifies as medium single-unit-sorted",
            med_res["files"] == 50
            and med_res["tier"] == "medium"
            and med_res["strategy"] == "single-unit-sorted"
            and med_res["partitionRecommended"] is False
            and med_res["reasons"] == ["files >= 50"],
        )

        _commit_files(
            repo,
            {f"bulk/f_{i:03d}.py": f"y = {i}\n" for i in range(151)},
            "151 files",
        )
        large_files_res = checks.size_review(diff_range="HEAD~1..HEAD", repo=repo)
        check(
            "151 files classifies as large partition",
            large_files_res["files"] == 151
            and large_files_res["tier"] == "large"
            and large_files_res["strategy"] == "partition"
            and large_files_res["partitionRecommended"] is True
            and large_files_res["reasons"] == ["files > 150"],
        )

        # 21 commits -> large even with 1 file.
        _git(repo, "checkout", "-qb", "many-commits")
        for c in range(21):
            _commit_files(repo, {"counter.txt": f"{c}\n"}, f"c{c}")
        large_commits_res = checks.size_review(diff_range="HEAD~21..HEAD", repo=repo)
        check(
            "21 commits classifies as large with commits > 20 reason",
            large_commits_res["commits"] == 21
            and large_commits_res["files"] == 1
            and large_commits_res["tier"] == "large"
            and large_commits_res["partitionRecommended"] is True
            and large_commits_res["reasons"] == ["commits > 20"],
        )

        # Direct parser checks for git numstat -z edge cases.
        _expect_error(
            "numstat rejects malformed record",
            checks._parse_git_numstat_z,
            b"badrecord\x00",
        )
        _expect_error(
            "numstat rejects truncated rename record",
            checks._parse_git_numstat_z,
            b"1\t0\t\x00only_old\x00",
        )
        _expect_error(
            "numstat rejects negative count",
            checks._parse_git_numstat_z,
            b"-1\t0\ta.py\x00",
        )
        _expect_error(
            "numstat rejects non-integer count",
            checks._parse_git_numstat_z,
            b"abc\t0\ta.py\x00",
        )


def test_size_pr_mocked_gh() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-size-pr-") as tmp:
        repo = Path(tmp) / "pr-repo"
        repo.mkdir()

        def make_gh_mock(
            view_obj: object,
            files_bytes: bytes,
            rc_view: int = 0,
            rc_files: int = 0,
        ):
            def fake_run(argv, **kwargs):
                if argv[:3] == ["gh", "pr", "view"]:
                    return subprocess.CompletedProcess(
                        argv,
                        rc_view,
                        json.dumps(view_obj).encode("utf-8"),
                        b"pr view err\n" if rc_view else b"",
                    )
                if argv[:3] == ["gh", "api", "--paginate"]:
                    return subprocess.CompletedProcess(
                        argv,
                        rc_files,
                        files_bytes,
                        b"api err\n" if rc_files else b"",
                    )
                raise AssertionError(f"unexpected command: {argv}")

            return fake_run

        # Multi-page arrays + filesTruncated when changedFiles > listedFiles.
        page1 = json.dumps(
            [
                {"filename": "services/api/a.py", "additions": 40, "deletions": 5},
                {"filename": "services/api/b.py", "additions": 10, "deletions": 2},
            ]
        ).encode("utf-8")
        page2 = json.dumps(
            [{"filename": "apps/web/index.ts", "additions": 120, "deletions": 0}]
        ).encode("utf-8")

        with mock.patch(
            "subprocess.run",
            side_effect=make_gh_mock(
                {
                    "changedFiles": 3200,
                    "additions": 5000,
                    "deletions": 400,
                    "commits": [{"oid": "1"}, {"oid": "2"}],
                },
                page1 + page2,
            ),
        ):
            res = checks.size_review(pr_number=123, repo=repo)

        check(
            "PR mode handles concatenated paginated arrays and filesTruncated",
            res["mode"] == "pr"
            and res["target"] == "123"
            and res["files"] == 3200
            and res["listedFiles"] == 3
            and res["filesTruncated"] is True
            and res["additions"] == 5000
            and res["deletions"] == 400
            and res["commits"] == 2
            and res["tier"] == "large"
            and res["partitionRecommended"] is True
            and res["reasons"] == ["files > 150"]
            and res["partitions"][0]
            == {
                "name": "apps/web",
                "files": 1,
                "additions": 120,
                "deletions": 0,
            }
            and res["partitions"][1]
            == {
                "name": "services/api",
                "files": 2,
                "additions": 50,
                "deletions": 7,
            },
        )

        # Medium PR with integer commits.
        with mock.patch(
            "subprocess.run",
            side_effect=make_gh_mock(
                {"changedFiles": 75, "additions": 300, "deletions": 50, "commits": 21},
                b"[]\n",
            ),
        ):
            med_commit_res = checks.size_review(pr_number=5, repo=repo)
        check(
            "PR mode supports integer commits and >20 commits -> large",
            med_commit_res["commits"] == 21
            and med_commit_res["tier"] == "large"
            and med_commit_res["reasons"] == ["commits > 20"],
        )

        # Empty PR.
        with mock.patch(
            "subprocess.run",
            side_effect=make_gh_mock(
                {"changedFiles": 0, "additions": 0, "deletions": 0, "commits": []},
                b"[]",
            ),
        ):
            empty_pr = checks.size_review(pr_number=1, repo=repo)
        check(
            "empty PR returns small tier and empty partitions",
            empty_pr["files"] == 0
            and empty_pr["filesTruncated"] is False
            and empty_pr["tier"] == "small"
            and empty_pr["partitions"] == [],
        )

        # Failing gh / bad JSON / unsafe path from API / item limit.
        with mock.patch(
            "subprocess.run",
            side_effect=make_gh_mock({}, b"[]", rc_view=1),
        ):
            _expect_error(
                "failing gh pr view raises ChecksError",
                checks.size_review,
                pr_number=9,
                repo=repo,
            )
        with mock.patch(
            "subprocess.run",
            side_effect=make_gh_mock(
                {"changedFiles": 1, "additions": 1, "deletions": 0, "commits": []},
                b"{not an array}",
            ),
        ):
            _expect_error(
                "non-array gh api response raises ChecksError",
                checks.size_review,
                pr_number=9,
                repo=repo,
            )
        for bad_view, label in [
            ([], "non-object view"),
            ({"changedFiles": 1}, "missing view keys"),
            (
                {
                    "changedFiles": -1,
                    "additions": 0,
                    "deletions": 0,
                    "commits": [],
                },
                "negative changedFiles",
            ),
            (
                {
                    "changedFiles": 1,
                    "additions": 0,
                    "deletions": 0,
                    "commits": "bad",
                },
                "invalid commits type",
            ),
        ]:
            with mock.patch(
                "subprocess.run",
                side_effect=make_gh_mock(bad_view, b"[]"),
            ):
                _expect_error(
                    f"gh pr view rejects {label}",
                    checks.size_review,
                    pr_number=9,
                    repo=repo,
                )
        for bad_api, label in [
            (b'[{"filename": "a.py", "additions": -1, "deletions": 0}]', "neg add"),
            (b'[{"filename": "a.py", "additions": 0, "deletions": "x"}]', "bad del"),
            (b'["not_an_object"]', "non-object entry"),
            (b"not json", "invalid api json"),
        ]:
            with mock.patch(
                "subprocess.run",
                side_effect=make_gh_mock(
                    {"changedFiles": 1, "additions": 1, "deletions": 0, "commits": []},
                    bad_api,
                ),
            ):
                _expect_error(
                    f"gh api rejects {label}",
                    checks.size_review,
                    pr_number=9,
                    repo=repo,
                )
        bad_pr_files = json.dumps(
            [{"filename": "../escape.py", "additions": 1, "deletions": 0}]
        ).encode()
        with mock.patch(
            "subprocess.run",
            side_effect=make_gh_mock(
                {"changedFiles": 1, "additions": 1, "deletions": 0, "commits": []},
                bad_pr_files,
            ),
        ):
            _expect_error(
                "gh api unsafe filename rejected",
                checks.size_review,
                pr_number=9,
                repo=repo,
            )
        too_many = json.dumps(
            [{"filename": "a.py", "additions": 0, "deletions": 0}] * 3501
        ).encode("utf-8")
        with mock.patch(
            "subprocess.run",
            side_effect=make_gh_mock(
                {"changedFiles": 3501, "additions": 0, "deletions": 0, "commits": []},
                too_many,
            ),
        ):
            _expect_error(
                "gh api item cap enforced",
                checks.size_review,
                pr_number=9,
                repo=repo,
            )


def test_cli_integration() -> None:
    proc = _run_cli("checks", "--help")
    check(
        "`vld8 checks --help` exits 0",
        proc.returncode == 0 and "--changed" in proc.stdout,
    )

    proc = _run_cli("review", "size", "--help")
    check(
        "`vld8 review size --help` exits 0",
        proc.returncode == 0 and "--service-map" in proc.stdout,
    )

    with tempfile.TemporaryDirectory(prefix="vld8-cli-checks-") as tmp:
        repo = Path(tmp) / "cli-repo"
        _init_git_repo(repo)
        _commit_files(repo, {"a.py": "x = 1\n"}, "c1")
        _commit_files(repo, {"a.py": "x = 2\n", "b.ts": "export const y = 1;\n"}, "c2")

        p_changed = _run_cli(
            "checks",
            "--changed",
            "a.py",
            "docs/readme.txt",
            "--lens",
            "code",
            "--repo",
            str(repo),
        )
        data_changed = json.loads(p_changed.stdout) if p_changed.returncode == 0 else {}
        check(
            "`vld8 checks --changed` outputs valid deterministic JSON",
            p_changed.returncode == 0
            and data_changed.get("schemaVersion") == "1.0"
            and data_changed.get("unmatchedPaths") == ["docs/readme.txt"]
            and any(b["key"] == "python" for b in data_changed.get("blocks", [])),
        )

        p_bad_path = _run_cli("checks", "--changed", "../bad.py", "--repo", str(repo))
        check(
            "`vld8 checks --changed ../bad.py` exits 1 with ERROR on stderr",
            p_bad_path.returncode == 1 and "ERROR:" in p_bad_path.stderr,
        )

        p_bad_range = _run_cli(
            "checks", "--diff=--upload-pack=evil", "--repo", str(repo)
        )
        check(
            "`vld8 checks --diff=--upload-pack=evil` exits 1",
            p_bad_range.returncode == 1 and "ERROR:" in p_bad_range.stderr,
        )

        p_size = _run_cli(
            "review", "size", "--diff", "HEAD~1..HEAD", "--repo", str(repo)
        )
        data_size = json.loads(p_size.stdout) if p_size.returncode == 0 else {}
        check(
            "`vld8 review size --diff` outputs valid JSON",
            p_size.returncode == 0
            and data_size.get("schemaVersion") == "1.0"
            and data_size.get("files") == 2
            and data_size.get("tier") == "small",
        )

        p_diff_ok = _run_cli(
            "checks",
            "--diff",
            "HEAD~1..HEAD",
            "--repo",
            str(repo),
        )
        data_diff = json.loads(p_diff_ok.stdout) if p_diff_ok.returncode == 0 else {}
        check(
            "`vld8 checks --diff HEAD~1..HEAD` exits 0 with diff mode JSON",
            p_diff_ok.returncode == 0
            and data_diff.get("mode") == "diff"
            and data_diff.get("changedPaths") == ["a.py", "b.ts"]
            and any(b["key"] == "python" for b in data_diff.get("blocks", [])),
        )

        p_bad_pr = _run_cli("review", "size", "--pr", "0", "--repo", str(repo))
        p_alpha_pr = _run_cli("review", "size", "--pr", "abc", "--repo", str(repo))
        check(
            "`vld8 review size --pr 0` and `--pr abc` exit non-zero",
            p_bad_pr.returncode != 0 and p_alpha_pr.returncode != 0,
        )

        p_bad_sm = _run_cli(
            "review",
            "size",
            "--diff",
            "HEAD~1..HEAD",
            "--repo",
            str(repo),
            "--service-map",
            str(repo / "missing.json"),
        )
        check(
            "`vld8 review size` with missing --service-map exits 1 with ERROR",
            p_bad_sm.returncode == 1 and "ERROR:" in p_bad_sm.stderr,
        )


def test_round1_review_regressions() -> None:
    # Finding 5: bounded _glob_regex LRU cache
    check(
        "_glob_regex uses bounded lru_cache(maxsize=1024)",
        checks._glob_regex.cache_info().maxsize == 1024,
    )

    with tempfile.TemporaryDirectory(prefix="vld8-r1-regress-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        _init_git_repo(repo)
        _commit_files(repo, {"auth.py": "x = 1\n", "README.md": "hi\n"}, "base")

        # Finding 2: range diffs read right-hand git tree, not working tree on disk.
        _git(repo, "checkout", "-qb", "feat")
        _commit_files(
            repo,
            {
                "auth.py": "def verify(t, k):\n    return jwt.verify(t, k)\n",
                "big.py": (b"# " + b"a" * (checks.MAX_CONTENT_FILE_BYTES + 32))
                + b"\njwt.verify(a, b)\n",
            },
            "feat adds jwt and huge blob",
        )
        # Also commit a git symlink pointing to auth.py (mode 120000).
        (repo / "link_auth.py").symlink_to("auth.py")
        _git(repo, "add", "link_auth.py")
        _git(repo, "commit", "-qm", "add symlink")

        # Checkout main where auth.py has NO jwt, so working tree disagrees with feat.
        _git(repo, "checkout", "-q", "main")
        range_res = checks.select_checks(diff_range="main...feat", repo=repo)
        jwt_blocks = [
            b
            for b in range_res["blocks"]
            if b["lens"] == "security" and b["key"] == "jwt"
        ]
        check(
            "main...feat inspects target tree (not disk) and skips symlinks/oversized",
            len(jwt_blocks) == 1 and jwt_blocks[0]["matchedPaths"] == ["auth.py"],
        )

        # Single-ref diff_range compares against working tree on disk.
        (repo / "auth.py").write_text(
            "def verify(t, k):\n    return jwt.verify(t, k)\n", encoding="utf-8"
        )
        single_res = checks.select_checks(diff_range="main", repo=repo)
        check(
            "single-ref diff_range reads uncommitted working tree changes",
            any(
                b["lens"] == "security" and b["key"] == "jwt"
                for b in single_res["blocks"]
            ),
        )
        (repo / "auth.py").write_text("x = 1\n", encoding="utf-8")

        # Empty right-hand range defaults to HEAD; leading-dash rhs rejected.
        _git(repo, "checkout", "-q", "feat")
        rhs_empty = checks.select_checks(diff_range="main...", repo=repo)
        check(
            "empty right-hand range main... resolves target HEAD tree",
            any(
                b["lens"] == "security" and b["key"] == "jwt"
                for b in rhs_empty["blocks"]
            ),
        )
        _expect_error(
            "range with leading-dash right-hand ref is rejected",
            checks.select_checks,
            diff_range="main..-n",
            repo=repo,
        )

        # Finding 3: _BoundedTextCache bounds bytes and zero-byte miss entries.
        orig_bytes = checks.MAX_TEXT_CACHE_BYTES
        orig_entries = checks.MAX_TEXT_CACHE_ENTRIES
        try:
            checks.MAX_TEXT_CACHE_BYTES = 12
            checks.MAX_TEXT_CACHE_ENTRIES = 2
            tcache = checks._BoundedTextCache(repo)
            _commit_files(repo, {"c1.py": "12345678\n", "c2.py": "abcdefgh\n"}, "c")
            t1 = tcache.get_text("c1.py")
            t2 = tcache.get_text("c2.py")
            check(
                "_BoundedTextCache evicts under byte cap",
                t1 == "12345678\n"
                and t2 == "abcdefgh\n"
                and len(tcache._cache) == 1
                and "c2.py" in tcache._cache,
            )
            tcache.get_text("missing1.py")
            tcache.get_text("missing2.py")
            tcache.get_text("missing3.py")
            check(
                "_BoundedTextCache evicts zero-byte miss entries under entry cap",
                len(tcache._cache) == 2 and "c2.py" not in tcache._cache,
            )
        finally:
            checks.MAX_TEXT_CACHE_BYTES = orig_bytes
            checks.MAX_TEXT_CACHE_ENTRIES = orig_entries

        # Finding 4: symlinked --repo target basename with C1 controls is escaped.
        ctrl_target = root / "evil\x9b31m"
        ctrl_target.mkdir()
        ctrl_link = root / "safe-link"
        ctrl_link.symlink_to(ctrl_target)
        _, ctrl_label = checks.resolve_repo_root(ctrl_link)
        ctrl_checks = checks.select_checks(changed=["README.md"], repo=ctrl_link)
        check(
            "resolve_repo_root sanitizes resolved symlink target basename",
            "\x9b" not in ctrl_label
            and "\x9b" not in ctrl_checks["repo"]
            and "\\x9b" in ctrl_checks["repo"],
        )

        # Finding 1: servicemap labels reject controls, surrogates, and length.
        bad_labels = [
            ("\ud800evil", "surrogate name"),
            ("evil\u009b31m\u007f\u2028", "C1/DEL/U+2028 name"),
            ("\x1b[31m", "ANSI name"),
            ("a" * (findings.MAX_IDENTIFIER_LENGTH + 1), "oversized name"),
        ]
        for idx, (bad_name, desc) in enumerate(bad_labels):
            bad_sm = root / f"bad_label_{idx}.json"
            bad_sm.write_text(
                json.dumps(
                    {
                        "components": [
                            {"id": "svc-1", "name": bad_name, "path": "auth.py"}
                        ]
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
                errors="surrogatepass",
            )
            try:
                checks.size_review(
                    diff_range="main...feat", repo=repo, service_map=bad_sm
                )
                check(f"reject unsafe component label ({desc})", False)
            except checks.ChecksError:
                check(f"reject unsafe component label ({desc})", True)

        id_bad_sm = root / "bad_id_only.json"
        id_bad_sm.write_text(
            json.dumps({"components": [{"id": "evil\x9b31m", "path": "auth.py"}]}),
            encoding="utf-8",
        )
        _expect_error(
            "reject unsafe component id when name is omitted",
            checks.size_review,
            diff_range="main...feat",
            repo=repo,
            service_map=id_bad_sm,
        )

        # Also test auto-discovered servicemap with C1 CSI fails CLI cleanly (exit 1).
        (repo / "servicemap.json").write_text(
            json.dumps(
                {
                    "components": [
                        {"id": "svc-bad", "name": "evil\x9b31m", "path": "auth.py"}
                    ]
                }
            ),
            encoding="utf-8",
        )
        p_bad_label = _run_cli(
            "review", "size", "--diff", "main...feat", "--repo", str(repo)
        )
        check(
            "CLI size exits 1 with clean error on unsafe servicemap label",
            p_bad_label.returncode == 1
            and "ERROR:" in p_bad_label.stderr
            and "\x9b" not in p_bad_label.stdout
            and "\x9b" not in p_bad_label.stderr,
        )
        (repo / "servicemap.json").unlink()

        # Finding 6: fallback bucket disambiguates component named 'other'.
        other_sm = root / "other_sm.json"
        other_sm.write_text(
            json.dumps(
                {
                    "components": [
                        {"id": "c-other", "name": "other", "path": "auth.py"},
                        {"id": "c-unmap", "name": "unmapped", "path": "c1.py"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        other_res = checks.size_review(
            diff_range="main...feat", repo=repo, service_map=other_sm
        )
        other_names = {p["name"] for p in other_res["partitions"]}
        check(
            "fallback bucket avoids merging into component named 'other' or 'unmapped'",
            {"other", "unmapped", "unmapped-2"} <= other_names,
        )


def main() -> int:
    # Ensure no leftover environment overrides break deterministic cwd checks.
    os.environ.pop("GIT_DIR", None)
    test_assets_and_validation()
    test_globs_and_previews()
    test_checks_changed()
    test_checks_diff_and_subproc_errors()
    test_size_diff_tiers_renames_binary_and_servicemap()
    test_size_pr_mocked_gh()
    test_cli_integration()
    test_round1_review_regressions()

    passed = sum(1 for _, ok in _results if ok)
    total = len(_results)
    for name, ok in _results:
        print(("PASS " if ok else "FAIL ") + name)
    print(f"\ntest_checks: {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
