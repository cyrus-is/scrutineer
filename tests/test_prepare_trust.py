#!/usr/bin/env python3
"""Tests for trust boundaries, external state, PR worktrees, and evidence (#128).

Dependency-free (no pytest): run from the repo root with

    python tests/test_prepare_trust.py
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vld8 import checks, findings, trust  # noqa: E402

_results: list[tuple[str, bool]] = []


def check(name: str, cond: object) -> None:
    _results.append((name, bool(cond)))


def _expect_error(
    name: str, fn: Any, *args: Any, needle: str = "", **kwargs: Any
) -> None:
    try:
        fn(*args, **kwargs)
        check(name, False)
    except trust.TrustError as exc:
        msg = str(exc)
        check(name, not needle or needle in msg)


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    )
    return proc.stdout.strip()


def _init_git_repo(repo: Path, branch: str = "main") -> None:
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q", "-b", branch)
    _git(repo, "config", "user.email", "test@example.invalid")
    _git(repo, "config", "user.name", "Test")


def _commit_files(repo: Path, files: dict[str, str], msg: str) -> str:
    for rel, content in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", msg)
    return _git(repo, "rev-parse", "HEAD")


def _make_code_finding(
    file: str = "app.py",
    line_start: int = 1,
    line_end: int = 1,
    quote: str = "x = 1",
    check_id: str = "ruff-s101",
    source: str = "code",
) -> dict[str, Any]:
    return {
        "file": file,
        "lineStart": line_start,
        "lineEnd": line_end,
        "quote": quote,
        "lens": "code",
        "checkId": check_id,
        "claim": "Deterministic check matched.",
        "evidence": "Rule matched.",
        "severity": "ISSUE",
        "basis": "written rule",
        "blocking": True,
        "source": source,
        "fingerprint": findings.compute_fingerprint(check_id, quote),
    }


def test_state_dir_run_dir_and_atomic_writes() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-trust-state-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        _init_git_repo(repo)
        head_oid = _commit_files(repo, {"a.py": "x = 1\n"}, "init")
        tree_id = trust.compute_tree_id(repo, head_oid)
        check(
            "compute_tree_id returns 40/64 hex tree OID",
            len(tree_id) in (40, 64)
            and findings._TREE_ID_RE.match(tree_id) is not None,
        )
        _expect_error(
            "compute_tree_id rejects git range '..'",
            trust.compute_tree_id,
            repo,
            "HEAD~1..HEAD",
        )
        _expect_error(
            "compute_tree_id rejects leading-dash ref",
            trust.compute_tree_id,
            repo,
            "--all",
        )

        # Default state_dir uses <git-common-dir>/vld8, shared across linked worktrees.
        default_state = trust.resolve_state_dir(repo)
        wt_path = root / "linked-wt"
        _git(repo, "worktree", "add", "--detach", str(wt_path), "HEAD")
        try:
            wt_state = trust.resolve_state_dir(wt_path)
            check(
                "linked worktree shares <git-common-dir>/vld8 state dir",
                default_state == wt_state and default_state.name == "vld8",
            )
        finally:
            _git(repo, "worktree", "remove", "--force", str(wt_path))

        # Explicit --state-dir outside repo works; inside repo or symlink rejected.
        ext_state = root / "ext-state"
        resolved_ext = trust.resolve_state_dir(repo, ext_state)
        check(
            "explicit external state-dir resolves cleanly",
            resolved_ext == ext_state.resolve(),
        )

        _expect_error(
            "--state-dir inside reviewed worktree rejected",
            trust.resolve_state_dir,
            repo,
            repo / ".vld8-inside",
            needle="outside",
        )
        link_inside = root / "state-link"
        link_inside.symlink_to(repo / "sub")
        _expect_error(
            "symlinked --state-dir rejected",
            trust.resolve_state_dir,
            repo,
            link_inside,
            needle="symlink",
        )
        _expect_error(
            "control chars in --state-dir rejected",
            trust.resolve_state_dir,
            repo,
            "bad\x1bdir",
        )

        # prepare_run_dir creates <state>/runs/<treeId>/<runId>/ safely.
        run_dir = trust.prepare_run_dir(resolved_ext, tree_id, run_id="run-01")
        check(
            "prepare_run_dir creates runs/<treeId>/<runId> outside worktree",
            run_dir.is_dir()
            and run_dir.parent.name == tree_id
            and run_dir.name == "run-01"
            and not run_dir.is_relative_to(repo.resolve()),
        )
        rand_dir = trust.prepare_run_dir(resolved_ext, tree_id)
        check("prepare_run_dir generates safe default runId", rand_dir.is_dir())

        _expect_error(
            "prepare_run_dir rejects traversal runId",
            trust.prepare_run_dir,
            resolved_ext,
            tree_id,
            run_id="../escape",
        )
        _expect_error(
            "prepare_run_dir rejects traversal treeId",
            trust.prepare_run_dir,
            resolved_ext,
            "../bad",
            run_id="ok",
        )

        # Symlink component inside runs dir is rejected.
        sym_run = resolved_ext / "runs" / tree_id / "sym-run"
        sym_run.symlink_to(root)
        _expect_error(
            "prepare_run_dir rejects symlinked run directory",
            trust.prepare_run_dir,
            resolved_ext,
            tree_id,
            run_id="sym-run",
            needle="symlink",
        )

        # Atomic JSON/text writes leave no temp files on success or failure.
        out_json = run_dir / "prepare.json"
        trust.atomic_write_json(out_json, {"b": 2, "a": 1})
        written = json.loads(out_json.read_text(encoding="utf-8"))
        leftover_tmps = list(run_dir.glob(".vld8-tmp-*"))
        check(
            "atomic_write_json writes sorted UTF-8 JSON with no leftover tempfiles",
            written == {"a": 1, "b": 2} and not leftover_tmps,
        )
        _expect_error(
            "atomic_write_text rejects surrogates cleanly",
            trust.atomic_write_text,
            run_dir / "bad.txt",
            "bad\ud800text",
        )
        check(
            "failed atomic write leaves no leftover tempfiles",
            not list(run_dir.glob(".vld8-tmp-*")),
        )


def test_pr_metadata_fork_bot_and_worktree() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-trust-pr-") as tmp:
        root = Path(tmp)
        upstream_bare = root / "upstream.git"
        origin_bare = root / "origin.git"
        work_repo = root / "dev"
        clone_repo = root / "clone"

        _git(root, "init", "-q", "--bare", str(upstream_bare))
        _git(root, "init", "-q", "--bare", str(origin_bare))
        _init_git_repo(work_repo)
        base_oid = _commit_files(
            work_repo,
            {"app.py": "x = 1\n", ".vld8.toml": "[review]\nmax = 10\n"},
            "base",
        )
        _git(work_repo, "branch", "-M", "main")
        _git(work_repo, "remote", "add", "origin", str(origin_bare))
        _git(work_repo, "remote", "add", "upstream", str(upstream_bare))
        _git(work_repo, "push", "-q", "upstream", "main")

        # Create PR commit on feat and expose as refs/pull/7/head on upstream ONLY
        # (so origin fetch fails and fallback to upstream remote succeeds).
        _git(work_repo, "checkout", "-qb", "feat")
        pr_oid = _commit_files(
            work_repo,
            {"app.py": "x = 2\n", ".vld8.toml": "[review]\nmax = 999\n"},
            "pr change",
        )
        _git(work_repo, "push", "-q", "upstream", f"{pr_oid}:refs/pull/7/head")

        # Push different commit to origin pull/7/head to verify OID mismatch falls back.
        _git(work_repo, "checkout", "-q", "main")
        wrong_oid = _commit_files(work_repo, {"evil.py": "bad\n"}, "wrong")
        _git(work_repo, "push", "-q", "origin", f"{wrong_oid}:refs/pull/7/head")
        _git(work_repo, "push", "-q", "origin", "main")

        _git(root, "clone", "-q", str(origin_bare), str(clone_repo))
        _git(clone_repo, "remote", "add", "upstream", str(upstream_bare))

        def _fake_gh_same(argv: list[str], **_kwargs: Any) -> bytes:
            return json.dumps(
                {
                    "number": 7,
                    "title": "Trusted same-repo PR",
                    "body": "Fix something",
                    "url": "https://github.com/org/repo/pull/7",
                    "author": {"login": "alice", "is_bot": False},
                    "headRefName": "feat",
                    "headRefOid": pr_oid,
                    "baseRefName": "main",
                    "isCrossRepository": False,
                }
            ).encode("utf-8")

        with mock.patch("vld8.checks._run_command", side_effect=_fake_gh_same):
            meta_same = trust.fetch_pr_metadata(clone_repo, 7)
        check(
            "trusted same-repo PR marked trusted=True",
            meta_same.trusted is True
            and meta_same.untrusted_reasons == ()
            and meta_same.head_ref_oid == pr_oid,
        )

        # Fork, bot variants, and force_untrusted all produce trusted=False.
        for label, author_obj, cross, forced, expected_reasons in [
            ("fork", {"login": "bob", "is_bot": False}, True, False, ("fork",)),
            ("is_bot", {"login": "dep", "is_bot": True}, False, False, ("bot",)),
            ("type Bot", {"login": "dep", "type": "Bot"}, False, False, ("bot",)),
            ("suffix [bot]", {"login": "dependabot[bot]"}, False, False, ("bot",)),
            ("prefix app/", {"login": "app/renovate"}, False, False, ("bot",)),
            (
                "fork+bot+forced",
                {"login": "app/bot", "is_bot": True},
                True,
                True,
                ("fork", "bot", "forced-untrusted"),
            ),
        ]:
            payload = {
                "number": 8,
                "title": "PR",
                "body": "",
                "url": "https://github.com/org/repo/pull/8",
                "author": author_obj,
                "headRefName": "feat",
                "headRefOid": pr_oid,
                "baseRefName": "main",
                "isCrossRepository": cross,
            }
            with mock.patch(
                "vld8.checks._run_command",
                return_value=json.dumps(payload).encode("utf-8"),
            ):
                m = trust.fetch_pr_metadata(clone_repo, 8, force_untrusted=forced)
                check(
                    f"untrusted PR detection ({label})",
                    m.trusted is False and m.untrusted_reasons == expected_reasons,
                )

        # Reject invalid metadata fields safely.
        bad_payloads: list[tuple[str, dict[str, Any]]] = [
            ("http url rejected", {"url": "http://github.com/org/repo/pull/8"}),
            ("bad oid rejected", {"headRefOid": "not-hex"}),
            ("dash ref rejected", {"baseRefName": "-bad"}),
            ("non-bool cross", {"isCrossRepository": "false"}),
            ("mismatched num", {"number": 99}),
        ]
        for label, overrides in bad_payloads:
            bad = {
                "number": 8,
                "title": "T",
                "body": "",
                "url": "https://github.com/org/repo/pull/8",
                "author": {"login": "alice", "is_bot": False},
                "headRefName": "feat",
                "headRefOid": pr_oid,
                "baseRefName": "main",
                "isCrossRepository": False,
            }
            bad.update(overrides)
            with mock.patch(
                "vld8.checks._run_command",
                return_value=json.dumps(bad).encode("utf-8"),
            ):
                _expect_error(
                    f"fetch_pr_metadata rejects {label}",
                    trust.fetch_pr_metadata,
                    clone_repo,
                    8,
                )

        # checkout_pr_worktree validates wrong origin OID -> falls back to upstream
        # -> checks out external detached worktree at pr_oid -> cleans up on error.
        wt_seen: Path | None = None
        try:
            with trust.checkout_pr_worktree(clone_repo, meta_same) as wt:
                wt_seen = wt.path
                check(
                    "worktree checks out exact headRefOid outside clone via upstream",
                    wt.available is True
                    and wt.fetch_source == "upstream"
                    and wt.path is not None
                    and wt.path.is_dir()
                    and not wt.path.is_relative_to(clone_repo.resolve())
                    and _git(wt.path, "rev-parse", "HEAD") == pr_oid,
                )
                raise RuntimeError("boom during review")
        except RuntimeError:
            pass
        check(
            "worktree and tempdir removed cleanly after exception",
            wt_seen is not None
            and not wt_seen.exists()
            and not wt_seen.parent.exists()
            and str(wt_seen) not in _git(clone_repo, "worktree", "list"),
        )

        # Untrusted fork and same-repo bot PRs with .gitmodules skip submodules.
        _git(work_repo, "checkout", "-q", "feat")
        sub_gm_oid = _commit_files(
            work_repo,
            {
                ".gitmodules": (
                    '[submodule "ext"]\n'
                    "\tpath = ext\n"
                    "\turl = https://example.invalid/sub.git\n"
                )
            },
            "pr with gitmodules",
        )
        _git(work_repo, "push", "-q", "origin", f"{sub_gm_oid}:refs/pull/77/head")
        orig_run = checks._run_command
        for kind, is_cross, is_bot, reasons in [
            ("fork", True, False, ("fork",)),
            ("same-repo bot", False, True, ("bot",)),
        ]:
            untrusted_meta = trust.PRMetadata(
                number=77,
                title=f"{kind} PR",
                body="",
                url="https://github.com/org/repo/pull/77",
                author_login="dependabot[bot]" if is_bot else "bob",
                author_is_bot=is_bot,
                head_ref_name="feat",
                head_ref_oid=sub_gm_oid,
                base_ref_name="main",
                is_cross_repository=is_cross,
                trusted=False,
                untrusted_reasons=reasons,
            )
            seen_cmds: list[list[str]] = []

            def _make_spy(cmd_log: list[list[str]]) -> Any:
                def _spy(argv: list[str], **kwargs: Any) -> bytes:
                    cmd_log.append(list(argv))
                    return orig_run(argv, **kwargs)

                return _spy

            with mock.patch(
                "vld8.checks._run_command", side_effect=_make_spy(seen_cmds)
            ):
                with trust.checkout_pr_worktree(clone_repo, untrusted_meta) as wt_u:
                    check(
                        f"{kind} PR worktree checks out without submodules",
                        wt_u.available is True
                        and wt_u.path is not None
                        and (wt_u.path / ".gitmodules").is_file()
                        and wt_u.submodules_initialized is False,
                    )
            check(
                f"{kind} PR never executes git submodule command",
                not any("submodule" in cmd for cmd in seen_cmds),
            )

        # Unfetchable headRefOid fails gracefully with available=False (never fallback).
        missing_meta = trust.PRMetadata(
            number=999,
            title="Missing",
            body="",
            url="https://github.com/org/repo/pull/999",
            author_login="alice",
            author_is_bot=False,
            head_ref_name="feat",
            head_ref_oid="deadbeef" * 5,
            base_ref_name="main",
            is_cross_repository=False,
            trusted=True,
            untrusted_reasons=(),
        )
        with mock.patch(
            "vld8.trust._resolve_gh_repo_url",
            return_value=None,
        ):
            with trust.checkout_pr_worktree(clone_repo, missing_meta) as wt_missing:
                check(
                    "unfetchable PR yields available=False instead of user checkout",
                    wt_missing.available is False
                    and wt_missing.path is None
                    and wt_missing.reason is not None,
                )

        # Trusted base-ref config ignores PR branch's modified .vld8.toml (`max = 999`).
        _git(work_repo, "push", "-q", "upstream", "main")
        _git(clone_repo, "fetch", "-q", "origin", "main")
        cfg, prov = trust.load_trusted_config(
            work_repo, base_ref=base_oid, config_rel_path=".vld8.toml"
        )
        check(
            "load_trusted_config reads TOML from base_ref, ignoring PR working tree",
            cfg == {"review": {"max": 10}}
            and prov["source"] == "base-ref"
            and prov["ref"] == base_oid,
        )

        # Missing config on ref returns default empty dict cleanly.
        empty_cfg, empty_prov = trust.load_trusted_config(
            work_repo, base_ref=base_oid, config_rel_path="no_such.toml"
        )
        check(
            "missing base-ref config falls back to empty defaults",
            empty_cfg == {} and empty_prov["source"] == "default",
        )


def test_config_evidence_and_trusted_execution() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-trust-ev-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        _init_git_repo(repo)
        base_oid = _commit_files(
            repo,
            {"pyproject.toml": "[tool.ruff]\nline-length = 88\n"},
            "base config",
        )
        # Symlinked config in git tree must be ignored by extract_base_tool_config.
        (repo / "link.toml").symlink_to("pyproject.toml")
        _git(repo, "add", "link.toml")
        _git(repo, "commit", "-qm", "add symlink config")
        _git(repo, "checkout", "-qb", "pr-branch")
        _commit_files(
            repo,
            {"pyproject.toml": "[tool.ruff]\nline-length = 999\n"},
            "pr alters config",
        )

        # External TOML config outside repo works; inside repo or symlink rejected.
        ext_cfg_path = root / "external.toml"
        ext_cfg_path.write_text("[rules]\nenabled = true\n", encoding="utf-8")
        ext_cfg, ext_prov = trust.load_trusted_config(
            repo, external_config=ext_cfg_path
        )
        check(
            "load_trusted_config loads external TOML outside repo",
            ext_cfg == {"rules": {"enabled": True}}
            and ext_prov["source"] == "external",
        )
        _expect_error(
            "load_trusted_config rejects external config inside repo",
            trust.load_trusted_config,
            repo,
            external_config=repo / "pyproject.toml",
            needle="outside",
        )
        sym_ext = root / "sym_ext.toml"
        sym_ext.symlink_to(ext_cfg_path)
        _expect_error(
            "load_trusted_config rejects symlinked external config",
            trust.load_trusted_config,
            repo,
            external_config=sym_ext,
        )

        # extract_base_tool_config extracts base_ref config into external dest only.
        out_cfg_dir = root / "extracted"
        extracted = trust.extract_base_tool_config(
            repo, base_oid, "pyproject.toml", out_cfg_dir
        )
        check(
            "extract_base_tool_config extracts base-ref file without PR changes",
            extracted is not None
            and extracted.read_text(encoding="utf-8")
            == "[tool.ruff]\nline-length = 88\n"
            and not extracted.is_relative_to(repo.resolve()),
        )
        check(
            "extract_base_tool_config ignores symlinked config in git tree",
            trust.extract_base_tool_config(repo, "HEAD", "link.toml", out_cfg_dir)
            is None,
        )
        _expect_error(
            "extract_base_tool_config rejects dest inside repo",
            trust.extract_base_tool_config,
            repo,
            base_oid,
            "pyproject.toml",
            repo / "out",
        )

        # --evidence validation (vld8 format + SARIF 2.1.0 + treeId matching).
        tree_id = trust.compute_tree_id(repo, "HEAD")
        other_tree_id = trust.compute_tree_id(repo, base_oid)

        ev_ok_path = root / "ev_ok.json"
        ev_ok_path.write_text(
            json.dumps(
                {
                    "schemaVersion": "1.0",
                    "treeId": tree_id,
                    "tools": ["ruff"],
                    "exclusions": ["ruff:E501"],
                    "findings": [_make_code_finding()],
                }
            ),
            encoding="utf-8",
        )
        ev_ok = trust.load_evidence(ev_ok_path, expected_tree_id=tree_id)
        check(
            "load_evidence accepts matching treeId with exclusions and findings",
            ev_ok["accepted"] is True
            and ev_ok["format"] == "vld8"
            and ev_ok["exclusions"] == ["ruff:E501"]
            and len(ev_ok["findings"]) == 1,
        )

        # Mismatched treeId NEVER grants exclusions or findings.
        ev_stale = trust.load_evidence(ev_ok_path, expected_tree_id=other_tree_id)
        check(
            "load_evidence refuses exclusions when treeId mismatches",
            ev_stale["accepted"] is False
            and ev_stale["exclusions"] == []
            and ev_stale["findings"] == []
            and "does not match" in (ev_stale["reason"] or ""),
        )

        # SARIF 2.1.0 evidence (matching + mismatching + conflicting multi-run).
        sarif_path = root / "ev_sarif.sarif"
        sarif_path.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "properties": {"treeId": tree_id},
                            "tool": {"driver": {"name": "ruff"}},
                            "results": [
                                {
                                    "ruleId": "S602",
                                    "level": "error",
                                    "message": {"text": "Bad \x1b[31mmsg\x1b[0m"},
                                }
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        ev_sarif = trust.load_evidence(sarif_path, expected_tree_id=tree_id)
        check(
            "load_evidence accepts matching SARIF 2.1.0 and sanitizes text",
            ev_sarif["accepted"] is True
            and ev_sarif["format"] == "sarif"
            and ev_sarif["tools"] == ["ruff"]
            and "\x1b" not in (ev_sarif["sarifResults"][0]["message"] or ""),
        )
        ev_sarif_bad = trust.load_evidence(sarif_path, expected_tree_id=other_tree_id)
        check(
            "load_evidence rejects mismatched SARIF treeId",
            ev_sarif_bad["accepted"] is False and ev_sarif_bad["sarifResults"] == [],
        )

        # Conflicting treeIds across SARIF runs, duplicates, bad source, symlinks.
        sarif_conflict = root / "sarif_conflict.sarif"
        sarif_conflict.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {"properties": {"treeId": tree_id}, "results": []},
                        {"properties": {"treeId": other_tree_id}, "results": []},
                    ],
                }
            ),
            encoding="utf-8",
        )
        _expect_error(
            "SARIF with conflicting run treeIds raises TrustError",
            trust.load_evidence,
            sarif_conflict,
            expected_tree_id=tree_id,
            needle="conflicting treeId",
        )

        dup_ev = root / "dup_ev.json"
        dup_ev.write_text('{"treeId": "a", "treeId": "b"}', encoding="utf-8")
        _expect_error(
            "evidence rejects duplicate JSON keys",
            trust.load_evidence,
            dup_ev,
            expected_tree_id=tree_id,
        )

        bad_src_ev = root / "bad_src.json"
        bad_src_ev.write_text(
            json.dumps(
                {"treeId": tree_id, "findings": [_make_code_finding(source="model")]}
            ),
            encoding="utf-8",
        )
        _expect_error(
            "evidence rejects findings without source='code'",
            trust.load_evidence,
            bad_src_ev,
            expected_tree_id=tree_id,
        )

        sym_ev = root / "sym_ev.json"
        sym_ev.symlink_to(ev_ok_path)
        _expect_error(
            "evidence rejects symlink input",
            trust.load_evidence,
            sym_ev,
            expected_tree_id=tree_id,
        )

        # Trusted command execution guard.
        check(
            "can_run_repo_tools matches bool",
            trust.can_run_repo_tools(False) is False,
        )
        _expect_error(
            "run_trusted_command refuses untrusted PR execution",
            trust.run_trusted_command,
            ["git", "status"],
            cwd=repo,
            trusted=False,
            needle="untrusted PR",
        )
        cmd_out = trust.run_trusted_command(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=repo,
            trusted=True,
        )
        check(
            "run_trusted_command executes cleanly when trusted=True",
            cmd_out.strip() == b"true",
        )


def test_extended_trust_and_edge_branches() -> None:
    # _is_safe_git_fetch_url safety rules.
    for safe_url in (
        "https://github.com/org/repo.git",
        "ssh://git@github.com/org/repo.git",
        "git@github.com:org/repo.git",
    ):
        check(
            f"_is_safe_git_fetch_url accepts {safe_url}",
            trust._is_safe_git_fetch_url(safe_url) is True,
        )
    for bad_url in (
        "",
        "-upload-pack=evil",
        "https://user:token@github.com/org/repo.git",
        "ext::sh -c evil",
        "https://github.com/org/repo with space",
        "https://\x1b[31mevil",
        "file:///local/path",
    ):
        check(
            f"_is_safe_git_fetch_url rejects {checks.safe_error_text(bad_url)}",
            trust._is_safe_git_fetch_url(bad_url) is False,
        )

    with tempfile.TemporaryDirectory(prefix="vld8-trust-ext-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        _init_git_repo(repo)
        head_oid = _commit_files(
            repo,
            {".vld8.toml": "[head]\nok = true\n", "bad.toml": "broken = [\n"},
            "init",
        )
        tree_id = trust.compute_tree_id(repo)

        # Metadata serialization, author=None, missing/invalid fields, bad JSON.
        valid_meta = trust.PRMetadata(
            number=12,
            title="PR",
            body="Desc",
            url="https://github.com/org/repo/pull/12",
            author_login="alice",
            author_is_bot=False,
            head_ref_name="feat",
            head_ref_oid=head_oid,
            base_ref_name="main",
            is_cross_repository=False,
            trusted=True,
            untrusted_reasons=(),
        )
        as_dict = valid_meta.to_dict()
        check(
            "PRMetadata.to_dict uses camelCase keys",
            as_dict["schemaVersion"] == "1.0"
            and as_dict["headRefOid"] == head_oid
            and as_dict["isCrossRepository"] is False
            and as_dict["untrustedReasons"] == [],
        )

        with mock.patch(
            "vld8.checks._run_command",
            return_value=json.dumps(
                {
                    "number": 12,
                    "title": "Ghost author PR",
                    "body": "",
                    "url": "https://github.com/org/repo/pull/12",
                    "author": None,
                    "headRefName": "feat",
                    "headRefOid": head_oid,
                    "baseRefName": "main",
                    "isCrossRepository": False,
                }
            ).encode("utf-8"),
        ):
            ghost_meta = trust.fetch_pr_metadata(repo, 12)
            check(
                "author=None produces empty login cleanly",
                ghost_meta.author_login == "" and ghost_meta.author_is_bot is False,
            )

        for label, bad_raw in [
            ("non-json", b"{"),
            ("non-object json", b"[]"),
            ("missing field", json.dumps({"number": 12}).encode("utf-8")),
            (
                "bad author type",
                json.dumps(
                    {
                        "number": 12,
                        "title": "T",
                        "body": "",
                        "url": "https://github.com/org/repo/pull/12",
                        "author": "bad",
                        "headRefName": "feat",
                        "headRefOid": head_oid,
                        "baseRefName": "main",
                        "isCrossRepository": False,
                    }
                ).encode("utf-8"),
            ),
            (
                "ctrl login",
                json.dumps(
                    {
                        "number": 12,
                        "title": "T",
                        "body": "",
                        "url": "https://github.com/org/repo/pull/12",
                        "author": {"login": "alice\x1b"},
                        "headRefName": "feat",
                        "headRefOid": head_oid,
                        "baseRefName": "main",
                        "isCrossRepository": False,
                    }
                ).encode("utf-8"),
            ),
            (
                "nul title",
                json.dumps(
                    {
                        "number": 12,
                        "title": "T\x00x",
                        "body": "",
                        "url": "https://github.com/org/repo/pull/12",
                        "author": {"login": "alice"},
                        "headRefName": "feat",
                        "headRefOid": head_oid,
                        "baseRefName": "main",
                        "isCrossRepository": False,
                    }
                ).encode("utf-8"),
            ),
        ]:
            with mock.patch("vld8.checks._run_command", return_value=bad_raw):
                _expect_error(
                    f"fetch_pr_metadata rejects {label}",
                    trust.fetch_pr_metadata,
                    repo,
                    12,
                )

        # _resolve_gh_repo_url prefers sshUrl for git@ origin and url for https origin.
        def _gh_repo_view(argv: list[str], **_kwargs: Any) -> bytes:
            if "get-url" in argv:
                return b"git@github.com:org/repo.git\n"
            return json.dumps(
                {
                    "url": "https://github.com/org/repo",
                    "sshUrl": "git@github.com:org/repo.git",
                }
            ).encode("utf-8")

        with mock.patch("vld8.checks._run_command", side_effect=_gh_repo_view):
            check(
                "_resolve_gh_repo_url picks sshUrl when origin uses SSH",
                trust._resolve_gh_repo_url(repo) == "git@github.com:org/repo.git",
            )
        with mock.patch(
            "vld8.checks._run_command",
            return_value=json.dumps({"url": "https://github.com/org/repo"}).encode(
                "utf-8"
            ),
        ):
            check(
                "_resolve_gh_repo_url falls back to https url",
                trust._resolve_gh_repo_url(repo) == "https://github.com/org/repo",
            )

        # checkout_pr_worktree origin direct hit + gh-url fallback + trusted submodule.
        origin_bare = root / "org_direct.git"
        _git(root, "init", "-q", "--bare", str(origin_bare))
        _git(repo, "remote", "add", "origin", str(origin_bare))
        _git(repo, "push", "-q", "origin", f"{head_oid}:refs/pull/12/head")
        with trust.checkout_pr_worktree(repo, valid_meta) as wt_orig:
            check(
                "checkout_pr_worktree succeeds directly via origin",
                wt_orig.available is True and wt_orig.fetch_source == "origin",
            )

        with (
            mock.patch(
                "vld8.trust._try_fetch_pr_ref",
                side_effect=[(False, "no origin"), (True, None)],
            ),
            mock.patch(
                "vld8.trust._resolve_gh_repo_url",
                return_value="https://github.com/org/repo",
            ),
        ):
            ok_gh, src_gh, _ = trust._fetch_pr_head(repo, 12, head_oid)
            check(
                "_fetch_pr_head falls back to gh-url cleanly",
                ok_gh is True and src_gh == "gh-url",
            )

        # Trusted submodule failure is non-fatal (recorded in reason).
        sub_mod_repo = root / "sub_mod_repo"
        _init_git_repo(sub_mod_repo)
        sub_oid = _commit_files(sub_mod_repo, {"lib.py": "v = 1\n"}, "sub")
        (repo / ".gitmodules").write_text(
            '[submodule "ext"]\n\tpath = ext\n\turl = file:///nonexistent/sub.git\n',
            encoding="utf-8",
        )
        _git(repo, "add", ".gitmodules")
        _git(repo, "commit", "-qm", "add broken gitmodules")
        gm_oid = _git(repo, "rev-parse", "HEAD")
        _git(repo, "push", "-q", "origin", f"{gm_oid}:refs/pull/13/head")
        meta_sub = trust.PRMetadata(
            number=13,
            title="Sub",
            body="",
            url="https://github.com/org/repo/pull/13",
            author_login="alice",
            author_is_bot=False,
            head_ref_name="feat",
            head_ref_oid=gm_oid,
            base_ref_name="main",
            is_cross_repository=False,
            trusted=True,
            untrusted_reasons=(),
        )
        orig_run = trust._run_git_or_gh

        def _submodule_runner(should_fail: bool) -> Any:
            def _runner(argv: list[str], *, cwd: Path, **kwargs: Any) -> bytes:
                if "submodule" in argv:
                    if "status" in argv:
                        return b"-" + sub_oid.encode("utf-8") + b" ext\n"
                    if "update" in argv:
                        if should_fail:
                            raise trust.TrustError("submodule fetch failed")
                        return b""
                return orig_run(argv, cwd=cwd, **kwargs)

            return _runner

        with (
            mock.patch(
                "vld8.trust._try_fetch_pr_ref",
                return_value=(True, None),
            ),
            mock.patch.object(
                trust,
                "_run_git_or_gh",
                side_effect=_submodule_runner(True),
            ),
        ):
            with trust.checkout_pr_worktree(repo, meta_sub) as wt_sub:
                check(
                    "submodule init failure is non-fatal and recorded in reason",
                    wt_sub.available is True
                    and wt_sub.submodules_initialized is False
                    and "submodule init skipped" in (wt_sub.reason or ""),
                )

        with (
            mock.patch(
                "vld8.trust._try_fetch_pr_ref",
                return_value=(True, None),
            ),
            mock.patch.object(
                trust,
                "_run_git_or_gh",
                side_effect=_submodule_runner(False),
            ),
        ):
            with trust.checkout_pr_worktree(repo, meta_sub) as wt_sub_ok:
                check(
                    "trusted non-fork PR with submodules sets submodules_initialized",
                    wt_sub_ok.available is True
                    and wt_sub_ok.submodules_initialized is True
                    and wt_sub_ok.reason is None,
                )

        # State/atomic/config/evidence edge error paths.
        _expect_error(
            "resolve_state_dir rejects empty state-dir",
            trust.resolve_state_dir,
            repo,
            "   ",
        )
        file_as_dir = root / "not-a-dir"
        file_as_dir.write_text("x", encoding="utf-8")
        _expect_error(
            "prepare_run_dir rejects regular file as state-dir",
            trust.prepare_run_dir,
            file_as_dir,
            tree_id,
            run_id="r1",
        )
        _expect_error(
            "atomic_write_text rejects directory target",
            trust.atomic_write_text,
            root,
            "abc",
        )
        _expect_error(
            "atomic_write_text rejects NUL in path",
            trust.atomic_write_text,
            root / "bad\x00.txt",
            "abc",
        )
        _expect_error(
            "atomic_write_text rejects non-str",
            trust.atomic_write_text,
            root / "x.txt",
            123,  # type: ignore[arg-type]
        )

        # load_trusted_config requires explicit base_ref XOR external_config.
        _expect_error(
            "load_trusted_config rejects omitted base_ref and external_config",
            trust.load_trusted_config,
            repo,
        )
        ext_ok_cfg = root / "ext_ok_cfg.toml"
        ext_ok_cfg.write_text("[ext]\nok = true\n", encoding="utf-8")
        _expect_error(
            "load_trusted_config rejects passing both base_ref and external_config",
            trust.load_trusted_config,
            repo,
            base_ref="HEAD",
            external_config=ext_ok_cfg,
        )
        head_cfg, head_prov = trust.load_trusted_config(repo, base_ref="HEAD")
        check(
            "load_trusted_config reads HEAD tree when base_ref='HEAD' is explicit",
            head_cfg == {"head": {"ok": True}} and head_prov["source"] == "base-ref",
        )
        _expect_error(
            "load_trusted_config rejects invalid TOML in base_ref",
            trust.load_trusted_config,
            repo,
            base_ref="HEAD",
            config_rel_path="bad.toml",
        )
        bad_ext_toml = root / "bad_ext.toml"
        bad_ext_toml.write_text("bad = [\n", encoding="utf-8")
        _expect_error(
            "load_trusted_config rejects invalid external TOML",
            trust.load_trusted_config,
            repo,
            external_config=bad_ext_toml,
        )

        # Evidence error cases + top-level SARIF properties.treeId.
        sarif_top = root / "sarif_top.sarif"
        sarif_top.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "properties": {"treeId": tree_id},
                    "runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": []}],
                }
            ),
            encoding="utf-8",
        )
        ev_top = trust.load_evidence(sarif_top, expected_tree_id=tree_id)
        check(
            "load_evidence reads top-level SARIF properties.treeId",
            ev_top["accepted"] is True and ev_top["tools"] == ["semgrep"],
        )

        no_tree_ev = root / "no_tree.json"
        no_tree_ev.write_text('{"exclusions": ["a"]}', encoding="utf-8")
        ev_missing_tree = trust.load_evidence(no_tree_ev, expected_tree_id=tree_id)
        check(
            "load_evidence rejects missing treeId without raising",
            ev_missing_tree["accepted"] is False
            and ev_missing_tree["treeId"] is None
            and ev_missing_tree["exclusions"] == [],
        )

        for label, bad_payload in [
            ("unknown keys", {"treeId": tree_id, "extra": 1}),
            ("bad schemaVersion", {"schemaVersion": "9.9", "treeId": tree_id}),
            ("bad tools", {"treeId": tree_id, "tools": "ruff"}),
            ("empty tool", {"treeId": tree_id, "tools": [""]}),
            ("ctrl exclusion", {"treeId": tree_id, "exclusions": ["bad\x1b"]}),
            ("bad finding", {"treeId": tree_id, "findings": [{}]}),
            ("sarif version", {"version": "1.0", "runs": []}),
            ("sarif non-list runs", {"version": "2.1.0", "runs": {}}),
            ("sarif bad run", {"version": "2.1.0", "runs": ["bad"]}),
            (
                "sarif bad result",
                {"version": "2.1.0", "runs": [{"results": ["bad"]}]},
            ),
            (
                "sarif non-str treeId",
                {"version": "2.1.0", "runs": [{"properties": {"treeId": 42}}]},
            ),
        ]:
            bp = root / "bad_ev_case.json"
            bp.write_text(json.dumps(bad_payload), encoding="utf-8")
            _expect_error(
                f"load_evidence rejects {label}",
                trust.load_evidence,
                bp,
                expected_tree_id=tree_id,
            )

        _expect_error(
            "run_trusted_command wraps ChecksError into TrustError",
            trust.run_trusted_command,
            ["git", "rev-parse", "--verify", "nonexistent-ref"],
            cwd=repo,
            trusted=True,
        )

        # Hardening assertions (#128).
        cred_url_payload = json.dumps(
            {
                "number": 12,
                "title": "Cred URL",
                "body": "",
                "url": "https://user:pass@github.com/org/repo/pull/12",
                "author": {"login": "alice"},
                "headRefName": "feat",
                "headRefOid": head_oid,
                "baseRefName": "main",
                "isCrossRepository": False,
            }
        ).encode("utf-8")
        with mock.patch("vld8.checks._run_command", return_value=cred_url_payload):
            _expect_error(
                "fetch_pr_metadata rejects userinfo in PR URL",
                trust.fetch_pr_metadata,
                repo,
                12,
            )

        for bad_fetch in [
            "ssh://-oProxyCommand=evil/repo.git",
            "ssh://-user@github.com/org/repo.git",
            "git@github.com:-evil",
            "git@github.com:org/../repo.git",
        ]:
            check(
                f"_is_safe_git_fetch_url rejects {bad_fetch}",
                not trust._is_safe_git_fetch_url(bad_fetch),
            )

        ok_flag, _ = trust._try_fetch_pr_ref(repo, "-evil", 12, head_oid)
        check("_try_fetch_pr_ref rejects leading-dash remote", not ok_flag)

        bad_pr_meta = trust.PRMetadata(
            number=0,
            title="Zero PR",
            body="",
            url="https://github.com/org/repo/pull/12",
            author_login="alice",
            author_is_bot=False,
            head_ref_name="feat",
            head_ref_oid=head_oid,
            base_ref_name="main",
            is_cross_repository=False,
            trusted=True,
            untrusted_reasons=(),
        )
        try:
            with trust.checkout_pr_worktree(repo, bad_pr_meta):
                check("checkout_pr_worktree rejects non-positive PR number", False)
        except trust.TrustError:
            check("checkout_pr_worktree rejects non-positive PR number", True)

        outside_dir = root / "outside_target"
        outside_dir.mkdir()
        (outside_dir / "cfg.toml").write_text("[ok]\nx = 1\n", encoding="utf-8")
        repo_sym_parent = repo / "symlink_out"
        repo_sym_parent.symlink_to(outside_dir)
        _expect_error(
            "resolve_state_dir rejects symlink-parent path inside repo",
            trust.resolve_state_dir,
            repo,
            repo_sym_parent / "state",
        )
        _expect_error(
            "load_trusted_config rejects symlink-parent path inside repo",
            trust.load_trusted_config,
            repo,
            external_config=repo_sym_parent / "cfg.toml",
        )

        _expect_error(
            "atomic_write_json rejects NaN",
            trust.atomic_write_json,
            root / "nan.json",
            {"val": float("nan")},
        )

        partial_sarif = root / "partial.sarif"
        partial_sarif.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "properties": {"treeId": tree_id},
                            "tool": {"driver": {"name": "ruff"}},
                            "results": [],
                        },
                        {
                            "tool": {"driver": {"name": "semgrep"}},
                            "results": [],
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        ev_partial = trust.load_evidence(partial_sarif, expected_tree_id=tree_id)
        check(
            "load_evidence rejects partially stamped multi-run SARIF",
            ev_partial["accepted"] is False and ev_partial["treeId"] is None,
        )

        for label, bad_payload in [
            ("non-str vld8 treeId", {"treeId": 123, "exclusions": []}),
            (
                "oversized exclusion",
                {
                    "treeId": tree_id,
                    "exclusions": ["e" * (findings.MAX_IDENTIFIER_LENGTH + 1)],
                },
            ),
        ]:
            bp = root / "bad_ev_hardened.json"
            bp.write_text(json.dumps(bad_payload), encoding="utf-8")
            _expect_error(
                f"load_evidence rejects {label}",
                trust.load_evidence,
                bp,
                expected_tree_id=tree_id,
            )

        # Round 1 review fixes (#157 / #128).
        check(
            "can_run_repo_tools rejects non-bool truthy values",
            trust.can_run_repo_tools("false") is False
            and trust.can_run_repo_tools(1) is False
            and trust.can_run_repo_tools(True) is True,
        )
        _expect_error(
            "run_trusted_command rejects bare string argv",
            trust.run_trusted_command,
            "git",  # type: ignore[arg-type]
            cwd=repo,
            trusted=True,
        )
        _expect_error(
            "run_trusted_command rejects non-bool truthy trusted arg",
            trust.run_trusted_command,
            ["git", "--version"],
            cwd=repo,
            trusted="false",  # type: ignore[arg-type]
        )

        # SARIF executionSuccessful=false & malformed invocations / fields.
        failed_sarif = root / "failed_inv.sarif"
        failed_sarif.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "properties": {"treeId": tree_id},
                            "tool": {"driver": {"name": "ruff"}},
                            "invocations": [{"executionSuccessful": False}],
                            "results": [],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        ev_failed_inv = trust.load_evidence(failed_sarif, expected_tree_id=tree_id)
        check(
            "load_evidence rejects SARIF invocation with executionSuccessful=false",
            ev_failed_inv["accepted"] is False
            and "executionSuccessful=false" in (ev_failed_inv["reason"] or ""),
        )

        blank_driver_sarif = root / "blank_driver.sarif"
        blank_driver_sarif.write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [
                        {
                            "properties": {"treeId": tree_id},
                            "tool": {"driver": {"name": "   "}},
                            "invocations": [{"executionSuccessful": True}],
                            "results": [],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        ev_blank_driver = trust.load_evidence(
            blank_driver_sarif, expected_tree_id=tree_id
        )
        check(
            "SARIF blank driver.name is ignored cleanly",
            ev_blank_driver["accepted"] is True and ev_blank_driver["tools"] == [],
        )

        for label, bad_payload in [
            (
                "sarif non-list invocations",
                {"version": "2.1.0", "runs": [{"invocations": {}}]},
            ),
            (
                "sarif non-bool executionSuccessful",
                {
                    "version": "2.1.0",
                    "runs": [{"invocations": [{"executionSuccessful": "false"}]}],
                },
            ),
            (
                "sarif non-str ruleId",
                {"version": "2.1.0", "runs": [{"results": [{"ruleId": 123}]}]},
            ),
            (
                "sarif non-str level",
                {"version": "2.1.0", "runs": [{"results": [{"level": ["warn"]}]}]},
            ),
        ]:
            bp_s = root / "bad_sarif_r1.sarif"
            bp_s.write_text(json.dumps(bad_payload), encoding="utf-8")
            _expect_error(
                f"load_evidence rejects {label}",
                trust.load_evidence,
                bp_s,
                expected_tree_id=tree_id,
            )

        ansi_keys_ev = root / "ansi_keys.json"
        ansi_keys_ev.write_text(
            json.dumps(
                {
                    "treeId": tree_id,
                    "\x1b[31mINJECT\x1b[0m": 1,
                    "k2": 2,
                    "k3": 3,
                    "k4": 4,
                    "k5": 5,
                    "k6": 6,
                }
            ),
            encoding="utf-8",
        )
        try:
            trust.load_evidence(ansi_keys_ev, expected_tree_id=tree_id)
            check("load_evidence sanitizes and bounds unknown JSON keys", False)
        except trust.TrustError as exc:
            msg = str(exc)
            check(
                "load_evidence sanitizes and bounds unknown JSON keys",
                "\x1b" not in msg and "(+1 more)" in msg,
            )

        # Allow <git-common-dir>/vld8/runs/... on standard clones.
        std_state_dir = trust.resolve_state_dir(repo)
        std_run_dir = trust.prepare_run_dir(std_state_dir, tree_id, run_id="std1")
        _commit_files(repo, {"pyproject.toml": "[tool.x]\nv = 1\n"}, "add toolcfg")
        std_cfg = trust.extract_base_tool_config(
            repo, "HEAD", "pyproject.toml", std_run_dir / "toolcfg"
        )
        check(
            "extract_base_tool_config allows <git-common-dir>/vld8/runs/... on clones",
            std_cfg is not None and std_cfg.is_file(),
        )
        _expect_error(
            "extract_base_tool_config still rejects .git/hooks",
            trust.extract_base_tool_config,
            repo,
            "HEAD",
            "pyproject.toml",
            repo / ".git" / "hooks",
        )
        sym_to_runs = repo / "sym_to_runs"
        sym_to_runs.symlink_to(std_run_dir)
        _expect_error(
            "extract_base_tool_config rejects repo symlink into .git/vld8/runs",
            trust.extract_base_tool_config,
            repo,
            "HEAD",
            "pyproject.toml",
            sym_to_runs / "toolcfg",
        )

        # prepare_run_dir state_dir validation + deep RecursionError guards.
        _expect_error(
            "prepare_run_dir rejects blank state_dir",
            trust.prepare_run_dir,
            "   ",
            tree_id,
            run_id="r1",
        )
        _commit_files(
            repo,
            {"deep.toml": "x = " + ("[" * 5000) + ("]" * 5000) + "\n"},
            "deep toml",
        )
        _expect_error(
            "load_trusted_config wraps TOML RecursionError into TrustError",
            trust.load_trusted_config,
            repo,
            base_ref="HEAD",
            config_rel_path="deep.toml",
        )
        cyclic: dict[str, Any] = {}
        cyclic["self"] = cyclic
        _expect_error(
            "atomic_write_json wraps cyclic JSON error into TrustError",
            trust.atomic_write_json,
            root / "cyclic.json",
            cyclic,
        )
        with mock.patch("vld8.trust.json.dumps", side_effect=RecursionError("depth")):
            _expect_error(
                "atomic_write_json wraps JSON RecursionError into TrustError",
                trust.atomic_write_json,
                root / "deep_json.json",
                {"a": 1},
            )

        # Oversized file in base_ref raises TrustError cleanly via load_trusted_file.
        _commit_files(
            repo,
            {"huge.txt": "a" * (trust.MAX_CONFIG_BYTES + 16)},
            "oversized base file",
        )
        _expect_error(
            "load_trusted_file raises TrustError on oversized base-ref file",
            trust.load_trusted_file,
            repo,
            base_ref="HEAD",
            rel_path="huge.txt",
        )
        raw_head_toml, raw_prov = trust.load_trusted_file(
            repo, base_ref="HEAD", rel_path=".vld8.toml"
        )
        check(
            "load_trusted_file reads base-ref bytes cleanly",
            raw_head_toml is not None and raw_prov["source"] == "base-ref",
        )

        # PR title rejects controls; PR body escapes ANSI while keeping newlines.
        with mock.patch(
            "vld8.checks._run_command",
            return_value=json.dumps(
                {
                    "number": 12,
                    "title": "Bad\nTitle",
                    "body": "Body",
                    "url": "https://github.com/org/repo/pull/12",
                    "author": {"login": "alice"},
                    "headRefName": "feat",
                    "headRefOid": head_oid,
                    "baseRefName": "main",
                    "isCrossRepository": False,
                }
            ).encode("utf-8"),
        ):
            _expect_error(
                "fetch_pr_metadata rejects newline in title",
                trust.fetch_pr_metadata,
                repo,
                12,
            )

        with mock.patch(
            "vld8.checks._run_command",
            return_value=json.dumps(
                {
                    "number": 12,
                    "title": "Clean title",
                    "body": "Line 1\x1b[31mRED\x1b[0m\n\tLine 2\x07",
                    "url": "https://github.com/org/repo/pull/12",
                    "author": {"login": "alice"},
                    "headRefName": "feat",
                    "headRefOid": head_oid,
                    "baseRefName": "main",
                    "isCrossRepository": False,
                }
            ).encode("utf-8"),
        ):
            san_meta = trust.fetch_pr_metadata(repo, 12)
            san_dict = san_meta.to_dict()
            check(
                "fetch_pr_metadata escapes ANSI/controls in body and keeps newlines",
                "\x1b" not in san_dict["body"]
                and "\x07" not in san_dict["body"]
                and "\\x07" in san_dict["body"]
                and "\n\tLine 2" in san_dict["body"],
            )

        # checkout_pr_worktree removes tmp_root even if git worktree remove times out.
        orig_subproc_run = trust.subprocess.run

        def _timeout_remove(argv: list[str], **kwargs: Any) -> Any:
            if len(argv) >= 5 and argv[3] == "worktree" and argv[4] == "remove":
                raise trust.subprocess.TimeoutExpired(argv, 1.0)
            return orig_subproc_run(argv, **kwargs)

        timed_out_wt: Path | None = None
        with mock.patch("vld8.trust.subprocess.run", side_effect=_timeout_remove):
            with trust.checkout_pr_worktree(repo, valid_meta) as wt_to:
                timed_out_wt = wt_to.path
                check("worktree created before timeout probe", wt_to.available)
        check(
            "checkout_pr_worktree removes tempdir even when worktree remove times out",
            timed_out_wt is not None and not timed_out_wt.parent.exists(),
        )

        # GIT_DIR override in env must not hijack resolve_state_dir / compute_tree_id.
        expected_cur_tree = trust.compute_tree_id(repo, "HEAD")
        other_repo = root / "other_git_env_repo"
        _init_git_repo(other_repo)
        _commit_files(other_repo, {"other.txt": "hi\n"}, "other")
        prev_git_dir = os.environ.get("GIT_DIR")
        os.environ["GIT_DIR"] = str(other_repo / ".git")
        try:
            env_state = trust.resolve_state_dir(repo)
            env_tree = trust.compute_tree_id(repo, "HEAD")
            check(
                "trust git calls ignore caller GIT_DIR override",
                env_state == (repo.resolve() / ".git" / "vld8")
                and env_tree == expected_cur_tree,
            )
        finally:
            if prev_git_dir is None:
                os.environ.pop("GIT_DIR", None)
            else:
                os.environ["GIT_DIR"] = prev_git_dir


def main() -> int:
    os.environ.pop("GIT_DIR", None)
    test_state_dir_run_dir_and_atomic_writes()
    test_pr_metadata_fork_bot_and_worktree()
    test_config_evidence_and_trusted_execution()
    test_extended_trust_and_edge_branches()

    passed = sum(1 for _, ok in _results if ok)
    total = len(_results)
    for name, ok in _results:
        print(("PASS " if ok else "FAIL ") + name)
    print(f"\ntest_prepare_trust: {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
