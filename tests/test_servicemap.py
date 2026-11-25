#!/usr/bin/env python3
"""Regression suite for service map schema 1.2 validation and offline drift checking.

Dependency-free (no pytest): run from the repo root with

    python tests/test_servicemap.py

Exits non-zero if any check fails.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_SPEC = importlib.util.spec_from_file_location(
    "validate_servicemap",
    ROOT / "generate-servicemap" / "validate_servicemap.py",
)
assert _SPEC and _SPEC.loader
SM = importlib.util.module_from_spec(_SPEC)
sys.modules["validate_servicemap"] = SM
_SPEC.loader.exec_module(SM)

_results: list[tuple[str, bool]] = []


def check(name: str, cond: object) -> None:
    _results.append((name, bool(cond)))


def run_validate_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "vld8", "map", "validate", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def _base_v12_map(repo_name: str = "sample-repo", *, multi_repo: bool = False) -> dict:
    repos = [
        {
            "name": repo_name,
            "monorepo": False,
            "last_crawled": "2026-11-24T12:00:00Z",
        }
    ]
    if multi_repo:
        repos.append(
            {
                "name": "other-repo",
                "monorepo": False,
                "last_crawled": "2026-11-24T12:00:00Z",
            }
        )
    return {
        "schema_version": "1.2.0",
        "generated_at": "2026-11-24T12:00:00Z",
        "repositories": repos,
        "components": [
            {
                "id": "svc-api",
                "name": "api",
                "type": "service",
                "source_repo": repo_name,
                "path": "services/api",
                "confidence": 0.95,
                "discovery_method": "entrypoint",
                "last_crawled": "2026-11-24T12:00:00Z",
                "stub": False,
            },
            {
                "id": "app-worker",
                "name": "worker",
                "type": "app",
                "source_repo": repo_name,
                "path": "apps/worker",
                "confidence": 0.9,
                "discovery_method": "cli",
                "last_crawled": "2026-11-24T12:00:00Z",
                "stub": False,
            },
            {
                "id": "infra-box",
                "name": "box",
                "type": "infrastructure",
                "source_repo": repo_name,
                "path": "infra/box",
                "confidence": 0.9,
                "discovery_method": "container",
                "last_crawled": "2026-11-24T12:00:00Z",
                "stub": False,
                "iac_tool": "terraform",
                "provider": "aws",
                "resources": [],
            },
        ],
        "connections": [],
        "metadata": {
            "total_components": 3,
            "total_connections": 0,
            "total_stubs": 0,
            "component_counts": {"service": 1, "app": 1, "infrastructure": 1},
            "low_confidence_components": [],
            "shared_datastores": [],
            "unauthenticated_public_endpoints": [],
            "unmonitored_services": [],
            "repo_staleness": [
                {
                    "repo": r["name"],
                    "last_crawled": "2026-11-24T12:00:00Z",
                    "components": 3 if r["name"] == repo_name else 0,
                    "age_days": 0,
                }
                for r in repos
            ],
        },
    }


def _make_process_conn(**overrides) -> dict:
    conn = {
        "id": "conn-api-to-worker",
        "source": "svc-api",
        "target": "app-worker",
        "type": "process",
        "async": False,
        "program": "worker-cli",
        "as_user": "service-user",
        "via": "exec",
        "environment": "constructed",
        "passes": {"argv": ["--job", "sync"], "stdin": "payload"},
        "mounts": [{"source": "state/in", "target": "work/in", "read_only": True}],
        "confidence": 0.9,
        "discovery_method": "subprocess.run in api/run.py",
    }
    conn.update(overrides)
    return conn


def _make_ipc_conn(**overrides) -> dict:
    conn = {
        "id": "conn-api-to-worker-ipc",
        "source": "svc-api",
        "target": "app-worker",
        "type": "ipc",
        "async": False,
        "channel": "unix_socket",
        "channel_auth": "uid_peercred",
        "confidence": 0.85,
        "discovery_method": "socket bind in worker/sock.py",
    }
    conn.update(overrides)
    return conn


def _make_file_conn(**overrides) -> dict:
    conn = {
        "id": "conn-api-to-worker-file",
        "source": "svc-api",
        "target": "app-worker",
        "type": "file",
        "async": True,
        "path_expr": "state/queue/*.json",
        "mode": "read_write",
        "confidence": 0.8,
        "discovery_method": "queue dir watcher",
    }
    conn.update(overrides)
    return conn


def test_backward_compat() -> None:
    v10 = {
        "schema_version": "1.0.0",
        "generated_at": "2026-04-22T12:00:00Z",
        "repository": {"name": "legacy-app", "monorepo": False},
        "components": [
            {
                "id": "svc-web",
                "name": "web",
                "type": "service",
                "path": "src",
                "confidence": 0.9,
                "discovery_method": "main",
                "last_crawled": "2026-04-22T12:00:00Z",
                "stub": False,
            }
        ],
        "connections": [],
        "metadata": {
            "total_components": 1,
            "total_connections": 0,
            "total_stubs": 0,
            "component_counts": {"service": 1},
            "low_confidence_components": [],
            "shared_datastores": [],
            "unauthenticated_public_endpoints": [],
            "unmonitored_services": [],
        },
    }
    res10 = SM.validate_map(v10)
    check("1.0.0 synthetic map validates with no errors", not res10.errors)

    v11 = _base_v12_map()
    v11["schema_version"] = "1.1.0"
    res11 = SM.validate_map(v11)
    check("1.1.0 synthetic map validates with no errors", not res11.errors)

    # Validate local fixture maps if present on disk (test/ is gitignored).
    for fixture in sorted((ROOT / "test").glob("*servicemap.json")):
        proc = run_validate_cli(str(fixture))
        check(
            f"local fixture {fixture.name} passes with no finding warnings",
            proc.returncode == 0
            and "keep findings out of the service map" not in proc.stdout,
        )


def test_schema_v12_valid_and_malformed() -> None:
    valid_map = _base_v12_map()
    valid_map["connections"] = [
        _make_process_conn(),
        _make_ipc_conn(),
        _make_file_conn(),
        {
            "id": "conn-api-to-worker-http",
            "source": "svc-api",
            "target": "app-worker",
            "type": "http",
            "via": "gh",
            "async": False,
            "confidence": 0.9,
            "discovery_method": "cli call",
        },
        {
            "id": "conn-infra-to-api",
            "source": "infra-box",
            "target": "svc-api",
            "type": "infrastructure",
            "async": False,
            "mounts": [{"source": "data", "target": "app/data"}],
            "confidence": 0.9,
            "discovery_method": "compose mount",
        },
    ]
    valid_map["metadata"]["total_connections"] = len(valid_map["connections"])
    res = SM.validate_map(valid_map)
    check(
        f"1.2.0 map with all new types validates cleanly {res.errors}",
        not res.errors and not res.warnings,
    )

    for via in ("sudo", "launchd", "exec", "shell"):
        m = _base_v12_map()
        m["connections"] = [_make_process_conn(via=via)]
        check(f"process via={via} accepted", not SM.validate_map(m).errors)

    for chan in ("unix_socket", "stdio", "pipe", "signal"):
        m = _base_v12_map()
        m["connections"] = [_make_ipc_conn(channel=chan)]
        check(f"ipc channel={chan} accepted", not SM.validate_map(m).errors)

    for mode in ("read", "write", "read_write", "append", "lock", "watch"):
        m = _base_v12_map()
        m["connections"] = [_make_file_conn(mode=mode)]
        check(f"file mode={mode} accepted", not SM.validate_map(m).errors)

    # Malformed variants
    bad_cases: list[tuple[str, dict]] = []

    for missing in ("program", "as_user", "via", "environment", "passes"):
        m = _base_v12_map()
        c = _make_process_conn()
        c.pop(missing)
        m["connections"] = [c]
        bad_cases.append((f"process missing {missing}", m))

    m = _base_v12_map()
    m["connections"] = [_make_process_conn(via="ssh")]
    bad_cases.append(("process invalid via", m))

    m = _base_v12_map()
    m["connections"] = [_make_process_conn(environment="empty")]
    bad_cases.append(("process invalid environment", m))

    m = _base_v12_map()
    m["connections"] = [_make_process_conn(passes={"argv": [123]})]
    bad_cases.append(("process passes.argv non-string", m))

    m = _base_v12_map()
    m["connections"] = [_make_process_conn(passes={"extra": "nope"})]
    bad_cases.append(("process passes unknown key", m))

    m = _base_v12_map()
    m["connections"] = [
        _make_process_conn(mounts=[{"source": "a", "target": "b", "read_only": "yes"}])
    ]
    bad_cases.append(("process mounts bad read_only", m))

    m = _base_v12_map()
    m["connections"] = [
        _make_process_conn(mounts=[{"source": "a", "target": "b", "extra": 1}])
    ]
    bad_cases.append(("process mounts unknown key", m))

    m = _base_v12_map()
    m["connections"] = [_make_ipc_conn(channel="dbus")]
    bad_cases.append(("ipc invalid channel", m))

    m = _base_v12_map()
    c = _make_ipc_conn()
    c.pop("channel_auth")
    m["connections"] = [c]
    bad_cases.append(("ipc missing channel_auth", m))

    m = _base_v12_map()
    m["connections"] = [_make_file_conn(mode="truncate")]
    bad_cases.append(("file invalid mode", m))

    m = _base_v12_map()
    m["connections"] = [_make_file_conn(path_expr="")]
    bad_cases.append(("file empty path_expr", m))

    m = _base_v12_map()
    m["connections"] = [
        {
            "id": "conn-http-bad-via",
            "source": "svc-api",
            "target": "app-worker",
            "type": "http",
            "via": "",
            "async": False,
            "confidence": 0.9,
            "discovery_method": "cli",
        }
    ]
    bad_cases.append(("http empty via", m))

    # Malformed evidence entries
    good_ev = {
        "repo": "sample-repo",
        "file": "services/api/app.py",
        "lines": [1, 3],
        "sha256": "0" * 64,
    }
    bad_evidence = [
        ("evidence not a list", "not-a-list"),
        ("evidence file absolute", [{**good_ev, "file": "/etc/passwd"}]),
        ("evidence file traversal", [{**good_ev, "file": "../secret.txt"}]),
        ("evidence file backslash", [{**good_ev, "file": "a\\b.py"}]),
        ("evidence file drive prefix", [{**good_ev, "file": "C:foo.py"}]),
        ("evidence file null byte", [{**good_ev, "file": "a\x00b.py"}]),
        ("evidence lines reversed", [{**good_ev, "lines": [5, 2]}]),
        ("evidence lines zero", [{**good_ev, "lines": [0, 2]}]),
        ("evidence lines bool", [{**good_ev, "lines": [True, 2]}]),
        ("evidence sha256 short", [{**good_ev, "sha256": "abc"}]),
        ("evidence sha256 uppercase", [{**good_ev, "sha256": "A" * 64}]),
    ]
    for label, ev_val in bad_evidence:
        m = _base_v12_map()
        m["components"][0]["evidence"] = ev_val
        bad_cases.append((label, m))

    # Confidence, timestamp, root type hardening
    m = _base_v12_map()
    m["components"][0]["confidence"] = True
    bad_cases.append(("confidence rejects bool", m))

    m = _base_v12_map()
    m["components"][0]["confidence"] = float("nan")
    bad_cases.append(("confidence rejects NaN", m))

    m = _base_v12_map()
    m["generated_at"] = "2026-11-24Z"
    bad_cases.append(("timestamp rejects date-only Z", m))

    for label, payload in bad_cases:
        res = SM.validate_map(payload)
        check(f"malformed rejected: {label}", bool(res.errors))

    check(
        "validate_map rejects non-dict root",
        bool(SM.validate_map(["not", "dict"]).errors),
    )

    # Lowercase z with time separator works on 3.10+
    m = _base_v12_map()
    m["generated_at"] = "2026-11-24T12:00:00z"
    check("timestamp accepts lowercase z with T", not SM.validate_map(m).errors)


def test_findings_warning_and_terminal_escaping() -> None:
    m = _base_v12_map()
    m["components"][0]["notes"] = "CRITICAL: unauthenticated admin route CVE-2026-12345"
    res = SM.validate_map(m)
    check(
        "findings in notes trigger warning",
        any("keep findings out" in w for w in res.warnings),
    )

    m2 = _base_v12_map()
    m2["components"][0]["description"] = "Handles user orders and emits metrics"
    res2 = SM.validate_map(m2)
    check("normal description produces no finding warning", not res2.warnings)

    m3 = _base_v12_map()
    m3["components"][0]["id"] = "svc-\x1b[31mred\nforged"
    m3["components"][0]["type"] = "bogus"
    res3 = SM.validate_map(m3)
    joined = "\n".join(res3.errors)
    check("ANSI escapes stripped from errors", "\x1b" not in joined)
    check(
        "newline escaped in untrusted component ID",
        "\\x0a" in joined and "forged" in joined,
    )


def test_offline_drift_and_security() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-sm-test-") as tmp:
        tmp_path = Path(tmp)
        repo = tmp_path / "sample-repo"
        src_dir = repo / "services" / "api"
        src_dir.mkdir(parents=True)
        app_py = src_dir / "app.py"
        lines_v1 = [
            "def health():",
            "    return 'ok'",
            "",
            "def run_job():",
            "    return 42",
        ]
        # Write with CRLF to confirm LF/CRLF invariance in hash_lines
        app_py.write_bytes(("\r\n".join(lines_v1) + "\r\n").encode("utf-8"))

        worker_py = repo / "apps" / "worker" / "run.py"
        worker_py.parent.mkdir(parents=True)
        worker_lines = ["def main():", "    pass"]
        worker_py.write_text("\n".join(worker_lines) + "\n", encoding="utf-8")

        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.email=t@example.invalid",
                "-c",
                "user.name=t",
                "commit",
                "-qm",
                "init",
            ],
            cwd=repo,
            check=True,
        )

        sha_app = SM.hash_lines(lines_v1[3:5])  # lines [4, 5]
        sha_worker = SM.hash_lines(worker_lines[0:2])  # lines [1, 2]

        def build_ev_map(*, multi_repo: bool = False) -> dict:
            m = _base_v12_map("sample-repo", multi_repo=multi_repo)
            m["components"][0]["evidence"] = [
                {
                    "repo": "sample-repo",
                    "file": "services/api/app.py",
                    "lines": [4, 5],
                    "sha256": sha_app,
                }
            ]
            m["connections"] = [
                _make_process_conn(
                    evidence=[
                        {
                            "repo": "sample-repo",
                            "file": "apps/worker/run.py",
                            "lines": [1, 2],
                            "sha256": sha_worker,
                        }
                    ]
                )
            ]
            m["metadata"]["total_connections"] = 1
            if multi_repo:
                m["components"].append(
                    {
                        "id": "svc-remote",
                        "name": "remote",
                        "type": "service",
                        "source_repo": "other-repo",
                        "path": "src",
                        "confidence": 0.9,
                        "discovery_method": "api",
                        "last_crawled": "2026-11-24T12:00:00Z",
                        "stub": False,
                        "evidence": [
                            {
                                "repo": "other-repo",
                                "file": "src/main.py",
                                "lines": [1, 2],
                                "sha256": "a" * 64,
                            }
                        ],
                    }
                )
                m["metadata"]["total_components"] = 4
                m["metadata"]["component_counts"]["service"] = 2
            return m

        map_file = tmp_path / "servicemap.json"
        map_file.write_text(json.dumps(build_ev_map()), encoding="utf-8")

        # 1. Exact match via CLI + strict + determinism
        proc1 = run_validate_cli(
            str(map_file), "--check-evidence", "--repo", str(repo), "--strict"
        )
        proc2 = run_validate_cli(
            str(map_file), "--check-evidence", "--repo", str(repo), "--strict"
        )
        check(
            "exact evidence matches with exit 0 under --strict",
            proc1.returncode == 0
            and "verified=2 moved=0 changed=0 missing=0" in proc1.stdout,
        )
        check(
            "evidence check output is byte-identical across runs",
            proc1.stdout == proc2.stdout,
        )

        # 2. --strict without --check-evidence fails
        no_ce = run_validate_cli(str(map_file), "--strict")
        check("--strict without --check-evidence is rejected", no_ce.returncode != 0)

        # 3. Prepended lines -> MOVED, exit 0 even with --strict
        moved_lines = ["# comment 1", "# comment 2", *lines_v1]
        app_py.write_text("\n".join(moved_lines) + "\n", encoding="utf-8")
        proc_moved = run_validate_cli(
            str(map_file), "--check-evidence", "--repo", str(repo), "--strict"
        )
        check(
            "prepended lines reported as MOVED and succeed under --strict",
            proc_moved.returncode == 0
            and "verified=1 moved=1 changed=0" in proc_moved.stdout
            and "lines [4, 5] -> [6, 7]" in proc_moved.stdout,
        )

        # 4. Out-of-bounds citation that moved earlier in file -> MOVED
        short_moved = [
            *lines_v1[3:5]
        ]  # now at lines [1, 2], while cited [4, 5] > len(2)
        app_py.write_text("\n".join(short_moved) + "\n", encoding="utf-8")
        proc_oob_moved = run_validate_cli(
            str(map_file), "--check-evidence", "--repo", str(repo), "--strict"
        )
        check(
            "moved lines where old range exceeds new file length still detect move",
            proc_oob_moved.returncode == 0
            and "lines [4, 5] -> [1, 2]" in proc_oob_moved.stdout,
        )

        # 5. Modified cited lines -> warning by default, error under --strict
        app_py.write_text(
            "\n".join([*lines_v1[:4], "    return 99"]) + "\n", encoding="utf-8"
        )
        proc_changed_warn = run_validate_cli(
            str(map_file), "--check-evidence", "--repo", str(repo)
        )
        proc_changed_strict = run_validate_cli(
            str(map_file), "--check-evidence", "--repo", str(repo), "--strict"
        )
        check(
            "changed lines warn (exit 0) without --strict",
            proc_changed_warn.returncode == 0
            and "changed=1" in proc_changed_warn.stdout,
        )
        check(
            "changed lines fail (exit 1) with --strict",
            proc_changed_strict.returncode == 1
            and "ERRORS:" in proc_changed_strict.stdout,
        )

        # 6. Missing cited file -> warning by default, error under --strict
        app_py.unlink()
        proc_miss_warn = run_validate_cli(
            str(map_file), "--check-evidence", "--repo", str(repo)
        )
        proc_miss_strict = run_validate_cli(
            str(map_file), "--check-evidence", "--repo", str(repo), "--strict"
        )
        check(
            "missing file warns (exit 0) without --strict",
            proc_miss_warn.returncode == 0 and "missing=1" in proc_miss_warn.stdout,
        )
        check(
            "missing file fails (exit 1) with --strict",
            proc_miss_strict.returncode == 1 and "ERRORS:" in proc_miss_strict.stdout,
        )

        # 7. Symlink escaping repo root is ALWAYS an ERROR (even without --strict)
        outside = tmp_path / "secret_outside.txt"
        outside.write_text("do-not-read\n" * 6, encoding="utf-8")
        app_py.symlink_to(outside)
        proc_sym = run_validate_cli(
            str(map_file), "--check-evidence", "--repo", str(repo)
        )
        check(
            "symlink escaping repo root rejected as ERROR without --strict",
            proc_sym.returncode == 1 and "escapes repository root" in proc_sym.stdout,
        )
        app_py.unlink()

        # 8. Oversized file bound is respected
        app_py.write_bytes(b"x\n" * (SM.MAX_EVIDENCE_FILE_BYTES // 2 + 100))
        proc_big = run_validate_cli(
            str(map_file), "--check-evidence", "--repo", str(repo), "--strict"
        )
        check(
            "oversized evidence file rejected cleanly",
            proc_big.returncode == 1 and "oversized" in proc_big.stdout,
        )
        app_py.write_text("\n".join(lines_v1) + "\n", encoding="utf-8")

        # 9. Multi-repo map reports other repo as unverifiable (even with --strict)
        multi_file = tmp_path / "multi-servicemap.json"
        multi_file.write_text(
            json.dumps(build_ev_map(multi_repo=True)), encoding="utf-8"
        )
        proc_multi = run_validate_cli(
            str(multi_file), "--check-evidence", "--repo", str(repo), "--strict"
        )
        check(
            "multi-repo citation for other repo is unverifiable under --strict",
            proc_multi.returncode == 0
            and "verified=2" in proc_multi.stdout
            and "unverifiable=1" in proc_multi.stdout,
        )

        # Ambiguous multi-repo checkout falls back safely; --repo-name resolves it
        renamed_repo = tmp_path / "checkout-copy"
        repo.rename(renamed_repo)
        proc_ambig = run_validate_cli(
            str(multi_file), "--check-evidence", "--repo", str(renamed_repo)
        )
        proc_explicit = run_validate_cli(
            str(multi_file),
            "--check-evidence",
            "--repo",
            str(renamed_repo),
            "--repo-name",
            "sample-repo",
        )
        check(
            "ambiguous multi-repo checkout marks citations unverifiable with note",
            proc_ambig.returncode == 0
            and "unverifiable=3" in proc_ambig.stdout
            and "--repo-name" in proc_ambig.stdout,
        )
        check(
            "--repo-name overrides repo identity cleanly",
            proc_explicit.returncode == 0 and "verified=2" in proc_explicit.stdout,
        )


def test_docs_and_skill_alignment() -> None:
    schema_md = (ROOT / "references" / "schema.md").read_text(encoding="utf-8")
    skill_md = (ROOT / "generate-servicemap" / "SKILL.md").read_text(encoding="utf-8")
    readme_md = (ROOT / "README.md").read_text(encoding="utf-8")

    check(
        "references/schema.md bumped to 1.2.0", "**Schema Version**: 1.2.0" in schema_md
    )
    for token in (
        'type: "process"',
        'type: "ipc"',
        'type: "file"',
        "evidence[]",
        "via",
    ):
        check(f"schema.md documents {token}", token in schema_md)

    for token in (
        "1.2.0",
        "process",
        "ipc",
        "file",
        "evidence[]",
        "--check-evidence",
        "Never put findings",
    ):
        check(f"SKILL.md includes {token}", token in skill_md)

    check("README.md documents --check-evidence", "--check-evidence" in readme_md)


def test_api_and_cli_edge_cases() -> None:
    SM.errors.clear()
    check(
        "legacy check_iso_timestamp rejects date-only Z",
        not SM.check_iso_timestamp("2026-11-24Z", "ts"),
    )
    check(
        "legacy check_iso_timestamp accepts full ISO Z",
        SM.check_iso_timestamp("2026-11-24T12:00:00Z", "ts"),
    )
    SM.errors.clear()
    SM.check_confidence(True, "ctx")
    check("legacy check_confidence rejects bool", bool(SM.errors))

    res_no_repo = SM.validate_map(_base_v12_map(), check_evidence=True)
    check(
        "validate_map with check_evidence=True requires repo_path",
        any("--repo is required" in e for e in res_no_repo.errors),
    )

    with tempfile.TemporaryDirectory(prefix="vld8-sm-api-") as tmp:
        tmp_path = Path(tmp)
        res_bad_dir = SM.validate_map(
            _base_v12_map(), check_evidence=True, repo_path=tmp_path / "missing-dir"
        )
        check(
            "validate_map rejects missing repo_path directory",
            any("not a directory" in e for e in res_bad_dir.errors),
        )

        # Exercise SM.main() paths directly in-process for clean CLI coverage
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc_missing = SM.main([str(tmp_path / "nope.json")])
            rc_dir = SM.main([str(tmp_path)])
            bad_json = tmp_path / "bad.json"
            bad_json.write_text("{not json", encoding="utf-8")
            rc_bad_json = SM.main([str(bad_json)])
            list_json = tmp_path / "list.json"
            list_json.write_text("[]", encoding="utf-8")
            rc_list = SM.main([str(list_json)])

        check("SM.main missing file exits 2", rc_missing == 2)
        check("SM.main directory exits 2", rc_dir == 2)
        check("SM.main invalid JSON exits 2", rc_bad_json == 2)
        check("SM.main non-object JSON exits 1", rc_list == 1)

        repo = tmp_path / "sample-repo"
        (repo / "src").mkdir(parents=True)
        src = repo / "src" / "a.py"
        src.write_text("line1\nline2\nline3\n", encoding="utf-8")
        ev_map = _base_v12_map("sample-repo")
        ev_map["components"][0]["evidence"] = [
            {
                "repo": "sample-repo",
                "file": "src/a.py",
                "lines": [1, 2],
                "sha256": SM.hash_lines(["line1", "line2"]),
            }
        ]
        ev_file = tmp_path / "servicemap.json"
        ev_file.write_text(json.dumps(ev_map), encoding="utf-8")
        out_ok = io.StringIO()
        with contextlib.redirect_stdout(out_ok):
            rc_ok = SM.main([str(ev_file), "--check-evidence", "--repo", str(repo)])
        check(
            "SM.main --check-evidence verified exits 0",
            rc_ok == 0 and "verified=1" in out_ok.getvalue(),
        )

        # Moved, changed, missing, and non-regular file via SM.main()
        src.write_text("prefix\nline1\nline2\nline3\n", encoding="utf-8")
        out_moved = io.StringIO()
        with contextlib.redirect_stdout(out_moved):
            rc_moved = SM.main(
                [str(ev_file), "--check-evidence", "--repo", str(repo), "--strict"]
            )
        check(
            "SM.main --check-evidence detects move under --strict",
            rc_moved == 0 and "MOVED:" in out_moved.getvalue(),
        )

        src.write_text("other\nchanged\n", encoding="utf-8")
        out_changed = io.StringIO()
        with contextlib.redirect_stdout(out_changed):
            rc_changed = SM.main(
                [str(ev_file), "--check-evidence", "--repo", str(repo), "--strict"]
            )
        check(
            "SM.main --check-evidence reports changed under --strict",
            rc_changed == 1 and "changed=1" in out_changed.getvalue(),
        )

        src.unlink()
        src.mkdir()  # directory at cited path -> nonregular
        out_nonreg = io.StringIO()
        with contextlib.redirect_stdout(out_nonreg):
            rc_nonreg = SM.main(
                [str(ev_file), "--check-evidence", "--repo", str(repo), "--strict"]
            )
        check(
            "SM.main --check-evidence rejects non-regular file under --strict",
            rc_nonreg == 1 and "nonregular" in out_nonreg.getvalue(),
        )
        src.rmdir()

        # In-process missing, symlink escape, oversized file, and origin remote
        res_missing = SM.validate_map(
            ev_map, check_evidence=True, repo_path=repo, strict=False
        )
        check(
            "validate_map warns on missing cited file without --strict",
            not res_missing.errors and res_missing.evidence_counts["missing"] == 1,
        )

        outside = tmp_path / "outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        src.symlink_to(outside)
        res_sym_file = SM.validate_map(
            ev_map, check_evidence=True, repo_path=repo, strict=False
        )
        check(
            "validate_map treats symlink file escape as error",
            bool(res_sym_file.errors) and res_sym_file.evidence_counts["error"] == 1,
        )
        src.unlink()

        outside_dir = tmp_path / "outside-dir"
        outside_dir.mkdir()
        (outside_dir / "a.py").write_text("line1\nline2\n", encoding="utf-8")
        (repo / "src").rmdir()
        (repo / "src").symlink_to(outside_dir)
        res_sym_dir = SM.validate_map(
            ev_map, check_evidence=True, repo_path=repo, strict=False
        )
        check(
            "validate_map treats symlinked directory escape as error",
            bool(res_sym_dir.errors) and res_sym_dir.evidence_counts["error"] == 1,
        )
        (repo / "src").unlink()
        (repo / "src").mkdir()

        src.write_bytes(b"a\n" * (SM.MAX_EVIDENCE_FILE_BYTES // 2 + 100))
        res_big = SM.validate_map(
            ev_map, check_evidence=True, repo_path=repo, strict=False
        )
        check(
            "validate_map bounds oversized cited files",
            res_big.evidence_counts["error"] == 1 and bool(res_big.warnings),
        )
        src.write_text("line1\nline2\nline3\n", encoding="utf-8")

        # git origin remote resolution when checkout directory is renamed
        renamed = tmp_path / "renamed-dir"
        repo.rename(renamed)
        subprocess.run(["git", "init", "-q"], cwd=renamed, check=True)
        subprocess.run(
            [
                "git",
                "remote",
                "add",
                "origin",
                "https://example.invalid/org/sample-repo.git",
            ],
            cwd=renamed,
            check=True,
        )
        multi = _base_v12_map("sample-repo", multi_repo=True)
        multi["components"][0]["evidence"] = [
            {
                "repo": "other-repo",
                "file": "src/a.py",
                "lines": [1, 2],
                "sha256": "b" * 64,
            }
        ]
        res_remote = SM.validate_map(
            multi, check_evidence=True, repo_path=renamed, strict=True
        )
        check(
            "git origin remote resolves repo name for multi-repo map",
            not res_remote.errors and res_remote.evidence_counts["unverifiable"] == 1,
        )

        # 1.0 map through SM.main + component/connection/metadata validation coverage
        v10_file = tmp_path / "v10.json"
        v10_data = {
            "schema_version": "1.0.0",
            "generated_at": "2026-04-22T12:00:00Z",
            "repository": {"name": "legacy-app", "monorepo": False},
            "components": [
                {
                    "id": "svc-a",
                    "name": "a",
                    "type": "service",
                    "path": "a",
                    "confidence": 0.4,
                    "discovery_method": "m",
                    "last_crawled": "2026-04-22T12:00:00Z",
                    "stub": False,
                    "endpoints": [
                        {
                            "method": "GET",
                            "path": "/x",
                            "public": True,
                            "confidence": 0.9,
                            "authentication": {"mechanism": "custom"},
                            "authorization": {"type": "custom"},
                        }
                    ],
                },
                {
                    "id": "svc-a",
                    "name": "dup",
                    "type": "service",
                    "confidence": 0.9,
                    "discovery_method": "m",
                    "last_crawled": "2026-04-22T12:00:00Z",
                    "stub": True,
                    "stale": True,
                },
                {
                    "id": "datastore-bad",
                    "name": "db",
                    "type": "datastore",
                    "path": "db",
                    "confidence": 0.9,
                    "discovery_method": "m",
                    "last_crawled": "2026-04-22T12:00:00Z",
                    "stub": False,
                },
                {
                    "id": "ext-bad",
                    "name": "ext",
                    "type": "external",
                    "confidence": 0.9,
                    "discovery_method": "m",
                    "last_crawled": "2026-04-22T12:00:00Z",
                    "stub": False,
                },
            ],
            "connections": [
                {
                    "id": "c1",
                    "source": "missing-src",
                    "target": "missing-dst",
                    "type": "bogus",
                    "async": False,
                    "confidence": 2.0,
                    "discovery_method": "m",
                }
            ],
            "metadata": {
                "total_components": 99,
                "total_connections": 99,
                "total_stubs": 99,
                "component_counts": {"service": 99},
                "low_confidence_components": [],
                "shared_datastores": [],
                "unauthenticated_public_endpoints": [],
                "unmonitored_services": [],
            },
        }
        v10_file.write_text(json.dumps(v10_data), encoding="utf-8")
        out_v10 = io.StringIO()
        with contextlib.redirect_stdout(out_v10):
            rc_v10 = SM.main([str(v10_file)])
        v10_out = out_v10.getvalue()
        check(
            "SM.main catches duplicate IDs, missing fields, and count mismatches",
            rc_v10 == 1
            and "duplicate component ID" in v10_out
            and "stub=true requires stub_reason" in v10_out
            and "stale=true requires stale_since" in v10_out
            and "datastore missing required field" in v10_out
            and "external component missing required field" in v10_out,
        )

        # 1.0 --check-evidence exercises 1.0 _declared_repos branch
        v10_ev = _base_v12_map("legacy-app")
        v10_ev.pop("repositories")
        v10_ev["schema_version"] = "1.0.0"
        v10_ev["repository"] = {"name": "legacy-app", "monorepo": False}
        v10_ev["components"][0]["evidence"] = [
            {
                "repo": "legacy-app",
                "file": "src/a.py",
                "lines": [1, 2],
                "sha256": "c" * 64,
            }
        ]
        res_v10_ev = SM.validate_map(
            v10_ev, check_evidence=True, repo_path=renamed, strict=False
        )
        check(
            "1.0 map --check-evidence resolves single repository",
            res_v10_ev.evidence_checked and res_v10_ev.evidence_counts["changed"] == 1,
        )

        # Schema edge cases: mounts, evidence items, endpoints, repos, metadata
        edge_cases: list[tuple[str, dict]] = []
        for label, mounts_val in (
            ("mounts not a list", "bad"),
            ("mounts entry not a dict", ["bad"]),
            ("mounts missing source", [{"target": "t"}]),
        ):
            m = _base_v12_map()
            m["connections"] = [_make_process_conn(mounts=mounts_val)]
            edge_cases.append((label, m))

        for label, ev_val in (
            ("evidence item not dict", ["bad"]),
            (
                "evidence item missing repo",
                [{"file": "a.py", "lines": [1, 1], "sha256": "0" * 64}],
            ),
        ):
            m = _base_v12_map()
            m["components"][0]["evidence"] = ev_val
            edge_cases.append((label, m))

        m_ep = _base_v12_map()
        m_ep["components"][0]["endpoints"] = [
            "bad-ep",
            {"authentication": "bad-auth", "authorization": "bad-authz"},
        ]
        edge_cases.append(("endpoints malformed items", m_ep))

        m_ep_list = _base_v12_map()
        m_ep_list["components"][0]["endpoints"] = "not-list"
        edge_cases.append(("endpoints not list", m_ep_list))

        m_sr = _base_v12_map()
        m_sr["components"][0]["source_repo"] = "unknown-repo"
        edge_cases.append(("component source_repo mismatch", m_sr))

        m_dup_repo = _base_v12_map()
        m_dup_repo["repositories"].append(dict(m_dup_repo["repositories"][0]))
        edge_cases.append(("duplicate repository name", m_dup_repo))

        m_empty_repo = _base_v12_map()
        m_empty_repo["repositories"] = []
        edge_cases.append(("empty repositories list", m_empty_repo))

        m_bad_meta = _base_v12_map()
        m_bad_meta["metadata"]["repo_staleness"] = ["bad", {}]
        m_bad_meta["metadata"]["component_counts"] = "bad"
        edge_cases.append(("malformed repo_staleness and component_counts", m_bad_meta))

        # Unhashable (list) enum/type values must never raise TypeError
        m_list_comp_type = _base_v12_map()
        m_list_comp_type["components"][0]["type"] = ["service"]
        edge_cases.append(("unhashable component type list", m_list_comp_type))

        m_list_auth = _base_v12_map()
        m_list_auth["components"][0]["endpoints"] = [
            {
                "method": "GET",
                "path": "/x",
                "public": True,
                "confidence": 0.9,
                "authentication": {"mechanism": ["jwt"]},
                "authorization": {"type": ["rbac"]},
            }
        ]
        edge_cases.append(("unhashable endpoint auth enum list", m_list_auth))

        m_list_conn_type = _base_v12_map()
        m_list_conn_type["connections"] = [_make_process_conn(type=["process"])]
        edge_cases.append(("unhashable connection type list", m_list_conn_type))

        m_list_via = _base_v12_map()
        m_list_via["connections"] = [_make_process_conn(via=["exec"])]
        edge_cases.append(("unhashable process via list", m_list_via))

        m_list_env = _base_v12_map()
        m_list_env["connections"] = [_make_process_conn(environment=["inherited"])]
        edge_cases.append(("unhashable process environment list", m_list_env))

        m_list_chan = _base_v12_map()
        m_list_chan["connections"] = [_make_ipc_conn(channel=["pipe"])]
        edge_cases.append(("unhashable ipc channel list", m_list_chan))

        m_list_mode = _base_v12_map()
        m_list_mode["connections"] = [_make_file_conn(mode=["read"])]
        edge_cases.append(("unhashable file mode list", m_list_mode))

        # Null or empty required identity / version / type fields
        for bad_sv in ("", None):
            m_sv = _base_v12_map()
            m_sv["schema_version"] = bad_sv
            edge_cases.append((f"schema_version={bad_sv!r}", m_sv))

        m_null_ctype = _base_v12_map()
        m_null_ctype["components"][0]["type"] = None
        edge_cases.append(("component type null", m_null_ctype))

        m_null_conn = _base_v12_map()
        m_null_conn["connections"] = [
            {
                "id": "",
                "source": None,
                "target": None,
                "type": None,
                "async": False,
                "confidence": 0.5,
                "discovery_method": "m",
            }
        ]
        edge_cases.append(("connection empty id and null endpoints/type", m_null_conn))

        # evidence[].repo must match a declared repository
        m_bad_ev_repo = _base_v12_map()
        m_bad_ev_repo["components"][0]["evidence"] = [
            {
                "repo": "typo-repo",
                "file": "src/a.py",
                "lines": [1, 2],
                "sha256": "0" * 64,
            }
        ]
        edge_cases.append(("evidence.repo not in repositories[]", m_bad_ev_repo))

        for label, payload in edge_cases:
            check(f"edge case rejected: {label}", bool(SM.validate_map(payload).errors))

        # Empty --repo and --repo-name flags are rejected
        check(
            "empty --repo flag rejected",
            run_validate_cli(str(ev_file), "--check-evidence", "--repo", "").returncode
            == 2,
        )
        check(
            "empty --repo-name flag rejected",
            run_validate_cli(
                str(ev_file), "--check-evidence", "--repo-name", ""
            ).returncode
            == 2,
        )


def main() -> int:
    # Copy-on-read test of legacy validate(data) global state API
    SM.validate({"bad": True})
    check("legacy validate() populates module errors", bool(SM.errors))
    SM.validate(_base_v12_map())
    check("legacy validate() resets module errors on clean map", not SM.errors)

    test_backward_compat()
    test_schema_v12_valid_and_malformed()
    test_findings_warning_and_terminal_escaping()
    test_offline_drift_and_security()
    test_docs_and_skill_alignment()
    test_api_and_cli_edge_cases()

    for name, ok in _results:
        print(("PASS " if ok else "FAIL ") + name)
    fails = [name for name, ok in _results if not ok]
    if fails:
        print(f"\nFAILURES: {len(fails)}")
        return 1
    print(f"\nAll {len(_results)} checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
