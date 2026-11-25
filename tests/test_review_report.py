#!/usr/bin/env python3
"""Comprehensive tests for vld8 review report (vld8/report.py and CLI).

Dependency-free (no pytest): run from the repo root with

    python tests/test_review_report.py
"""

from __future__ import annotations

import copy
import io
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vld8 import cli, findings, report  # noqa: E402

_results: list[tuple[str, bool]] = []


def check(name: str, cond: object) -> None:
    _results.append((name, bool(cond)))


def run_cli(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "vld8", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def _fp(
    check_id: str,
    quote: str,
    *,
    package: str | None = None,
    version: str | None = None,
) -> str:
    return findings.compute_fingerprint(
        check_id, quote, package=package, version=version
    )


def _cfp(check_id: str, fix_file: str, fix_region: str) -> str:
    return findings.compute_class_fingerprint(check_id, fix_file, fix_region)


def _write_repo_file(repo: Path, rel: str, content: str | bytes) -> Path:
    target = repo / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        target.write_bytes(content)
    else:
        target.write_text(content, encoding="utf-8")
    return target


def _make_finding(
    *,
    file: str = "app/main.py",
    line_start: int = 1,
    line_end: int = 1,
    quote: str = "x = 1",
    lens: str = "code",
    check_id: str = "py-check-1",
    category: str | None = "correctness",
    claim: str = "Issue found.",
    evidence: str = "Observed problematic code.",
    severity: str = "ISSUE",
    basis: str | None = "written rule",
    blocking: bool = True,
    source: str = "model",
    package: str | None = None,
    version: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "file": file,
        "lineStart": line_start,
        "lineEnd": line_end,
        "quote": quote,
        "lens": lens,
        "checkId": check_id,
        "claim": claim,
        "evidence": evidence,
        "severity": severity,
        "blocking": blocking,
        "source": source,
        "fingerprint": extra.pop(
            "fingerprint",
            _fp(check_id, quote, package=package, version=version),
        ),
    }
    if category is not None:
        item["category"] = category
    if basis is not None:
        item["basis"] = basis
    if package is not None:
        item["package"] = package
    if version is not None:
        item["version"] = version
    item.update(extra)
    return item


def _make_doc(
    items: list[dict[str, Any]],
    *,
    lens: str | None = None,
    tree_id: str | None = "tree123",
    dismissals: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "schemaVersion": "1.0",
        "findings": items,
    }
    if lens is not None:
        doc["lens"] = lens
    if tree_id is not None:
        doc["treeId"] = tree_id
    if dismissals is not None:
        doc["dismissals"] = dismissals
    return doc


def _write_json(path: Path, data: Any) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_cli_and_help() -> None:
    p_help = run_cli("review", "report", "--help")
    check("`vld8 review report --help` exits 0", p_help.returncode == 0)
    for flag in ("--findings", "--prepare", "--prior", "--repo", "--format", "--out"):
        check(f"help documents {flag}", flag in p_help.stdout)

    p_rev_help = run_cli("review", "--help")
    check("`vld8 review --help` exits 0", p_rev_help.returncode == 0)

    # Preserved existing commands & passthrough.
    check("`vld8 --version` still exits 0", run_cli("--version").returncode == 0)
    check(
        "`vld8 mcp analyze --help` still exits 0",
        run_cli("mcp", "analyze", "--help").returncode == 0,
    )
    check(
        "`vld8 map validate --help` still exits 0",
        run_cli("map", "validate", "--help").returncode == 0,
    )
    check(
        "`vld8 map schema` still exits 0",
        run_cli("map", "schema").returncode == 0,
    )

    p_no_args = run_cli("review", "report")
    check("missing --findings exits 2", p_no_args.returncode == 2)

    err_buf = io.StringIO()
    bad_fmt_code = report.run_report(findings_path=None, fmt="xml", stderr=err_buf)
    check(
        "run_report rejects invalid format with exit 2",
        bad_fmt_code == 2 and "unsupported --format" in err_buf.getvalue(),
    )

    parser = cli.build_parser()
    ns = parser.parse_args(
        [
            "review",
            "report",
            "--findings",
            "m.json",
            "--prepare",
            "p.json",
            "--prior",
            "old.json",
            "--repo",
            ".",
            "--format",
            "sarif",
            "--out",
            "out.sarif",
        ]
    )
    check(
        "CLI parser binds review report args cleanly",
        ns.findings == "m.json"
        and ns.prepare == "p.json"
        and ns.prior == "old.json"
        and ns.format == "sarif"
        and ns.out == "out.sarif",
    )


def test_prepare_loading_and_resilience() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-prep-test-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        repo.mkdir()
        _write_repo_file(repo, "src/app.py", "def run():\n    return 1\n")

        valid_prep = {
            "schemaVersion": "1.0",
            "lens": "code",
            "treeId": "abc123",
            "partial": True,
            "candidates": [
                {
                    "candidateId": "cand-1",
                    "file": "src/app.py",
                    "lineStart": 1,
                    "lineEnd": None,
                    "checkId": "py-check-1",
                    "rule": "Rule text",
                    "reason": "Triggered",
                    "quote": "def run():",
                }
            ],
            "codeFindings": [
                _make_finding(
                    file="src/app.py",
                    line_start=1,
                    line_end=2,
                    quote="def run():\n    return 1",
                    source="code",
                    check_id="osv-pkg",
                    package="pyyaml",
                    version="5.3",
                    proof={"kind": "osv", "status": "verified"},
                )
            ],
            "unruled": [
                "budget reached on foo",
                {"candidateId": "cand-99", "count": 2, "ratio": 0.5, "flag": True},
            ],
            "coverage": {"checks": [{"id": "py-check-1", "blindSpots": ["eval"]}]},
        }
        prep_path = _write_json(root / "prepare.json", valid_prep)
        loaded = report.load_prepare_file(prep_path)
        check("load_prepare_file accepts valid contract", loaded["partial"] is True)

        # Missing/bad --prepare file errors
        for bad_target, label in [
            (root / "missing.json", "missing prepare"),
            (root, "directory as prepare"),
        ]:
            try:
                report.load_prepare_file(bad_target)
                check(f"prepare rejects {label}", False)
            except findings.FindingsError:
                check(f"prepare rejects {label}", True)

        if hasattr(os, "mkfifo"):
            fifo = root / "pipe.json"
            os.mkfifo(fifo)
            try:
                report.load_prepare_file(fifo)
                check("prepare rejects FIFO non-regular file", False)
            except findings.FindingsError:
                check("prepare rejects FIFO non-regular file", True)

        bad_utf8 = root / "bad_utf8.json"
        bad_utf8.write_bytes(b"\xff\xfe")
        try:
            report.load_prepare_file(bad_utf8)
            check("prepare rejects bad UTF-8", False)
        except findings.FindingsError:
            check("prepare rejects bad UTF-8", True)

        oversized = root / "big.json"
        oversized.write_text('{"schemaVersion":"1.0"}', encoding="utf-8")
        try:
            report.load_prepare_file(oversized, max_bytes=10)
            check("prepare rejects oversized file", False)
        except findings.FindingsError:
            check("prepare rejects oversized file", True)

        for raw_text, label in [
            ("{bad", "malformed JSON"),
            ("[]", "non-object JSON root"),
            ('{"a":1,"a":2}', "duplicate keys"),
            ('{"x":NaN}', "NaN constant"),
            ('{"x":Infinity}', "Infinity constant"),
        ]:
            p = root / "bad.json"
            p.write_text(raw_text, encoding="utf-8")
            try:
                report.load_prepare_file(p)
                check(f"prepare rejects {label}", False)
            except findings.FindingsError:
                check(f"prepare rejects {label}", True)

        # Schema-level validation rejections
        bad_docs: list[tuple[Any, str]] = [
            (["not-dict"], "non-dict"),
            ({"unknownKey": 1}, "unknown root key"),
            ({"schemaVersion": "2.0"}, "wrong schemaVersion"),
            ({"lens": "bogus"}, "invalid lens"),
            ({"treeId": "../bad"}, "invalid treeId"),
            ({"partial": "yes"}, "non-bool partial"),
            ({"candidates": "bad"}, "non-list candidates"),
            (
                {"candidates": [{}] * (report.MAX_CANDIDATES_COUNT + 1)},
                "oversized candidates",
            ),
            ({"candidates": ["not-obj"]}, "non-dict candidate"),
            ({"candidates": [{}]}, "missing candidateId"),
            (
                {"candidates": [{"candidateId": "c1"}, {"candidateId": "c1"}]},
                "duplicate candidateId",
            ),
            (
                {"candidates": [{"candidateId": "c1", "extra": 1}]},
                "unknown candidate key",
            ),
            (
                {"candidates": [{"candidateId": "c1", "lineStart": 5, "lineEnd": 3}]},
                "candidate lineEnd < lineStart",
            ),
            (
                {"candidates": [{"candidateId": "c1", "classProposal": "bad"}]},
                "bad classProposal type",
            ),
            (
                {
                    "candidates": [
                        {
                            "candidateId": "c1",
                            "classProposal": {
                                "rule": "r",
                                "sites": [
                                    {"file": "a.py", "lineStart": 1, "lineEnd": 1}
                                ],
                                "fixSite": {
                                    "file": "a.py",
                                    "lineStart": 1,
                                    "lineEnd": 1,
                                },
                                "closes": {"closed": 0, "total": 1},
                                "classFingerprint": "not-sha",
                            },
                        }
                    ]
                },
                "bad classProposal.classFingerprint",
            ),
            ({"codeFindings": "bad"}, "non-list codeFindings"),
            (
                {"codeFindings": [{}] * (findings.MAX_FINDINGS_COUNT + 1)},
                "oversized codeFindings",
            ),
            (
                {"codeFindings": [_make_finding(source="model")]},
                "codeFindings requires source=='code'",
            ),
            (
                {
                    "lens": "code",
                    "codeFindings": [
                        _make_finding(lens="security", severity="HIGH", source="code")
                    ],
                },
                "codeFindings lens mismatch",
            ),
            ({"unruled": "bad"}, "non-list unruled"),
            (
                {"unruled": ["x"] * (report.MAX_UNRULED_COUNT + 1)},
                "oversized unruled",
            ),
            ({"unruled": [123]}, "invalid unruled item type"),
            ({"unruled": ["   "]}, "blank unruled string"),
            ({"coverage": "bad"}, "scalar coverage"),
            ({"coverage": {"x": float("nan")}}, "non-finite float in coverage"),
            ({"coverage": {"x": "a\x00b"}}, "NUL in coverage"),
            ({"coverage": {"x": "a\ud800b"}}, "surrogate in coverage"),
            ({"coverage": {"": 1}}, "empty key in coverage"),
            ({"coverage": {"k" * 200: 1}}, "oversized key in coverage"),
            ({"coverage": {"k\n": 1}}, "control char key in coverage"),
            (
                {"coverage": {"a": {"b": {"c": {"d": {"e": {"f": {"g": 1}}}}}}}},
                "excessive nesting in coverage",
            ),
        ]
        for doc, label in bad_docs:
            check(
                f"validate_prepare_doc rejects {label}",
                bool(report.validate_prepare_doc(doc)),
            )

        # Huge node count in coverage (stays under MAX_UNRULED_COUNT per container)
        per_bucket = 100
        buckets = (report.MAX_COVERAGE_NODES // (per_bucket * 10)) + 2
        huge_cov = {
            f"g{g}": [[1] * per_bucket for _ in range(10)] for g in range(buckets)
        }
        cov_errs = report.validate_prepare_doc({"coverage": huge_cov})
        check(
            "validate_prepare_doc rejects oversized coverage nodes",
            any("nodes" in err and "max" in err for err in cov_errs),
        )

        # Resilience: missing/invalid --findings STILL emits codeFindings.
        bad_json_f = root / "bad_findings.json"
        bad_json_f.write_text("{corrupt", encoding="utf-8")
        bad_schema_f = _write_json(root / "bad_schema.json", {"schemaVersion": "1.0"})

        for f_arg, label in [
            (None, "omitted --findings"),
            (root / "nonexistent.json", "missing --findings file"),
            (bad_json_f, "malformed --findings JSON"),
            (bad_schema_f, "invalid --findings schema"),
        ]:
            for fmt in ("md", "json", "sarif"):
                out_buf = io.StringIO()
                err_buf = io.StringIO()
                code = report.run_report(
                    findings_path=f_arg,
                    prepare_path=prep_path,
                    repo_path=repo,
                    fmt=fmt,
                    stdout=out_buf,
                    stderr=err_buf,
                )
                txt = out_buf.getvalue()
                check(
                    f"resilience ({label}, {fmt}): exit 2 and codeFinding listed",
                    code == 2 and "osv-pkg" in txt and "src/app.py" in txt,
                )

        # Resilience: bad --prepare or bad --prior still runs --findings and exits 2
        good_f = _write_json(
            root / "good_model.json",
            _make_doc(
                [
                    _make_finding(
                        file="src/app.py",
                        line_start=1,
                        line_end=2,
                        quote="def run():\n    return 1",
                        severity="CONCERN",
                        basis=None,
                        blocking=False,
                    )
                ]
            ),
        )
        r_bad_prep = report.build_report(
            findings_path=good_f,
            prepare_path=root / "missing_prep.json",
            repo_path=repo,
        )
        check(
            "bad --prepare returns exit 2 while still rendering model findings",
            r_bad_prep["exitCode"] == 2 and len(r_bad_prep["findings"]) == 1,
        )
        r_bad_prior = report.build_report(
            findings_path=good_f, prior_path=root / "missing_prior.json", repo_path=repo
        )
        check(
            "bad --prior returns exit 2 while still rendering model findings",
            r_bad_prior["exitCode"] == 2 and len(r_bad_prior["findings"]) == 1,
        )

        # Cross-document lens and treeId mismatch
        mismatch_prep = _write_json(
            root / "mismatch_prep.json",
            {"schemaVersion": "1.0", "lens": "security", "treeId": "other"},
        )
        scoped_f = _write_json(
            root / "scoped.json",
            _make_doc([], lens="code", tree_id="tree123"),
        )
        r_mismatch = report.build_report(
            findings_path=scoped_f, prepare_path=mismatch_prep, repo_path=repo
        )
        errs_joined = "\n".join(r_mismatch["errors"]["validationErrors"])
        check(
            "cross-doc lens and treeId mismatches flagged",
            r_mismatch["exitCode"] == 2
            and "lens mismatch" in errs_joined
            and "treeId mismatch" in errs_joined,
        )


def test_citations_and_security() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-cit-test-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        repo.mkdir()
        outside = root / "secret.txt"
        outside.write_text("TOP_SECRET_OUTSIDE\n", encoding="utf-8")

        _write_repo_file(
            repo,
            "src/sample.py",
            "    def fn(arg):   \r\n"
            "        if arg:\r\n"
            "            eval(arg)\r\n"
            "        return 0\r\n"
            "    tail = 'other_line'\r\n",
        )
        _write_repo_file(repo, "src/empty.py", "")
        _write_repo_file(
            repo,
            "src/latin1.py",
            b"# \xff\xfe bad utf8 comment\nval = compute()\n",
        )
        _write_repo_file(repo, "src/bin.dat", b"abc\x00def\n")
        _write_repo_file(
            repo,
            "src/fix.py",
            "def safe():\n    pass\n",
        )
        _write_repo_file(
            repo,
            "src/big.py",
            b"x = 1\n" * (1_000_000),  # ~6 MiB > 5 MiB limit
        )

        # Symlinks (escaping file, escaping dir, internal symlink)
        (repo / "escape.py").symlink_to(outside)
        outside_dir = root / "outside_dir"
        outside_dir.mkdir()
        (outside_dir / "leak.py").write_text("secret = 1\n", encoding="utf-8")
        (repo / "dir_link").symlink_to(outside_dir)
        (repo / "internal_link.py").symlink_to(repo / "src" / "sample.py")
        (repo / "subdir").mkdir()

        # Valid citation edge cases:
        # 1) dedented + trailing whitespace + CRLF full range
        # 2) single-line partial snippet inside [1, 4]
        # 3) multi-line contiguous indented excerpt inside [1, 4]
        # 4) multi-line mid-line substring
        # 5) non-UTF-8 earlier line doesn't break UTF-8 line 2
        # 6) class.fixSite without quote + class.sites with quote
        good_items = [
            _make_finding(
                file="src/sample.py",
                line_start=1,
                line_end=3,
                quote="def fn(arg):\n    if arg:\n        eval(arg)",
                check_id="cit-dedent",
                severity="CONCERN",
                basis=None,
                blocking=False,
            ),
            _make_finding(
                file="src/sample.py",
                line_start=1,
                line_end=4,
                quote="eval(arg)",
                check_id="cit-partial-1line",
                severity="CONCERN",
                basis=None,
                blocking=False,
            ),
            _make_finding(
                file="src/sample.py",
                line_start=1,
                line_end=4,
                quote="if arg:\n    eval(arg)",
                check_id="cit-subrange",
                severity="CONCERN",
                basis=None,
                blocking=False,
            ),
            _make_finding(
                file="src/sample.py",
                line_start=1,
                line_end=3,
                quote="fn(arg):\n        if arg:",
                check_id="cit-midline-multi",
                severity="CONCERN",
                basis=None,
                blocking=False,
            ),
            _make_finding(
                file="src/latin1.py",
                line_start=2,
                line_end=2,
                quote="val = compute()",
                check_id="cit-nonutf8-safe",
                severity="CONCERN",
                basis=None,
                blocking=False,
                classFingerprint=_cfp("cit-nonutf8-safe", "src/fix.py", "def safe():"),
                **{
                    "class": {
                        "rule": "Use helper",
                        "sites": [
                            {
                                "file": "src/sample.py",
                                "lineStart": 3,
                                "lineEnd": 3,
                                "quote": "eval(arg)",
                            }
                        ],
                        "fixSite": {
                            "file": "src/fix.py",
                            "lineStart": 1,
                            "lineEnd": 2,
                        },
                        "closes": {"closed": 0, "total": 1},
                    }
                },
            ),
        ]
        good_f = _write_json(root / "good_cits.json", _make_doc(good_items))
        res_good = report.build_report(findings_path=good_f, repo_path=repo)
        check(
            "all valid citation edge cases verify cleanly",
            res_good["exitCode"] == 0
            and len(res_good["findings"]) == len(good_items)
            and res_good["errors"]["badCitations"] == [],
        )

        # Invalid citations + accounting interaction
        bad_items = [
            _make_finding(
                file="src/missing.py",
                line_start=1,
                line_end=1,
                quote="x",
                check_id="bad-missing",
                candidateIds=["cand-bad"],
            ),
            _make_finding(
                file="src/sample.py",
                line_start=1,
                line_end=99,
                quote="eval(arg)",
                check_id="bad-oob",
            ),
            _make_finding(
                file="src/empty.py",
                line_start=1,
                line_end=1,
                quote="x",
                check_id="bad-empty-file",
            ),
            _make_finding(
                file="src/sample.py",
                line_start=1,
                line_end=2,
                quote="other_line",
                check_id="bad-wrong-lines",
            ),
            _make_finding(
                file="src/sample.py",
                line_start=1,
                line_end=4,
                quote="fabricated_call()\nmore_fake()",
                check_id="bad-fabricated-multi",
            ),
            _make_finding(
                file="escape.py",
                line_start=1,
                line_end=1,
                quote="TOP_SECRET_OUTSIDE",
                check_id="bad-symlink-file",
            ),
            _make_finding(
                file="dir_link/leak.py",
                line_start=1,
                line_end=1,
                quote="secret = 1",
                check_id="bad-symlink-dir",
            ),
            _make_finding(
                file="internal_link.py",
                line_start=1,
                line_end=1,
                quote="def fn(arg):",
                check_id="bad-internal-symlink",
            ),
            _make_finding(
                file="subdir",
                line_start=1,
                line_end=1,
                quote="x",
                check_id="bad-dir-target",
            ),
            _make_finding(
                file="src/big.py",
                line_start=1,
                line_end=1,
                quote="x = 1",
                check_id="bad-oversized",
            ),
            _make_finding(
                file="src/bin.dat",
                line_start=1,
                line_end=1,
                quote="abc",
                check_id="bad-nul-byte",
            ),
            _make_finding(
                file="src/sample.py",
                line_start=1,
                line_end=1,
                quote="def fn(arg):",
                check_id="bad-fixsite",
                classFingerprint=_cfp("bad-fixsite", "src/fix.py", "def safe():"),
                **{
                    "class": {
                        "rule": "r",
                        "sites": [
                            {
                                "file": "src/sample.py",
                                "lineStart": 1,
                                "lineEnd": 1,
                                "quote": "WRONG_SITE_QUOTE",
                            }
                        ],
                        "fixSite": {
                            "file": "src/fix.py",
                            "lineStart": 1,
                            "lineEnd": 50,
                        },
                        "closes": {"closed": 0, "total": 1},
                    }
                },
            ),
        ]
        prep = _write_json(
            root / "prep.json",
            {"schemaVersion": "1.0", "candidates": [{"candidateId": "cand-bad"}]},
        )
        bad_f = _write_json(root / "bad_cits.json", _make_doc(bad_items))
        res_bad = report.build_report(
            findings_path=bad_f, prepare_path=prep, repo_path=repo
        )
        bad_checks = {c["checkId"] for c in res_bad["errors"]["badCitations"]}
        bad_locs = {c["location"] for c in res_bad["errors"]["badCitations"]}
        check(
            "every bad citation rejected, excluded, and fails accounting",
            res_bad["exitCode"] == 2
            and res_bad["verdict"] == "INCOMPLETE"
            and res_bad["findings"] == []
            and res_bad["errors"]["unaccountedCandidates"] == ["cand-bad"]
            and len(bad_checks) == len(bad_items)
            and {"primary", "class.fixSite", "class.sites[0]"} <= bad_locs,
        )

        # Invalid --repo paths
        for bad_repo, label in [
            (root / "no_repo", "missing --repo"),
            (outside, "file as --repo"),
            ("", "empty --repo"),
            ("bad\x00repo", "NUL in --repo"),
        ]:
            r_repo = report.build_report(
                findings_path=good_f, prepare_path=prep, repo_path=bad_repo
            )
            check(
                f"{label} returns exit 2 and excludes unverified model findings",
                r_repo["exitCode"] == 2 and r_repo["findings"] == [],
            )


def test_accounting_merge_rubric_prior_verdict_and_lens() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-merge-test-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        repo.mkdir()
        _write_repo_file(
            repo,
            "a.py",
            "line1 = 1\nline2 = 2\nline3 = 3\nline4 = 4\nline5 = 5\n",
        )
        _write_repo_file(
            repo,
            "b.py",
            "def f1():\n    pass\ndef f2():\n    pass\n",
        )
        _write_repo_file(repo, "fix.py", "def central_fix():\n    return True\n")

        # 1. Candidate accounting: class.sites, dismissals, conflicts, missing.
        prep_acc = _write_json(
            root / "prep_acc.json",
            {
                "schemaVersion": "1.0",
                "candidates": [
                    {"candidateId": "c-rule"},
                    {"candidateId": "c-site"},
                    {"candidateId": "c-dismiss"},
                    {"candidateId": "c-conflict"},
                    {"candidateId": "c-missing"},
                ],
            },
        )
        model_acc = _write_json(
            root / "model_acc.json",
            _make_doc(
                [
                    _make_finding(
                        file="a.py",
                        line_start=1,
                        line_end=1,
                        quote="line1 = 1",
                        candidateIds=["c-rule", "c-conflict", "c-unknown-f"],
                        severity="CONCERN",
                        basis=None,
                        blocking=False,
                        classFingerprint=_cfp(
                            "py-check-1", "fix.py", "def central_fix():"
                        ),
                        **{
                            "class": {
                                "rule": "r",
                                "sites": [
                                    {
                                        "file": "a.py",
                                        "lineStart": 2,
                                        "lineEnd": 2,
                                        "candidateId": "c-site",
                                    }
                                ],
                                "fixSite": {
                                    "file": "fix.py",
                                    "lineStart": 1,
                                    "lineEnd": 2,
                                },
                                "closes": {"closed": 0, "total": 1},
                            }
                        },
                    )
                ],
                dismissals=[
                    {"candidateId": "c-dismiss", "reason": "Safe constant"},
                    {"candidateId": "c-conflict", "reason": "Also dismissed"},
                    {"candidateId": "c-unknown-d", "reason": "Typo"},
                ],
            ),
        )
        r_acc = report.build_report(
            findings_path=model_acc, prepare_path=prep_acc, repo_path=repo
        )
        check(
            "accounting catches unaccounted, conflicting, and unknown candidates",
            r_acc["exitCode"] == 2
            and r_acc["errors"]["unaccountedCandidates"] == ["c-missing"]
            and r_acc["errors"]["conflictingCandidates"] == ["c-conflict"]
            and r_acc["errors"]["unknownCandidates"] == ["c-unknown-d", "c-unknown-f"],
        )

        # 2. Merge: Pass 1/2/3, dispute, classProposal, and downgrades.
        cf1 = _make_finding(
            file="a.py",
            line_start=1,
            line_end=1,
            quote="line1 = 1",
            check_id="chk-pass1",
            source="code",
            claim="Code claim 1",
            evidence="Code evidence 1",
            severity="ISSUE",
            basis="written rule",
            blocking=True,
            package="requests",
            version="2.0.0",
            proof={"kind": "rule", "status": "verified"},
            candidateIds=["cand-p1"],
        )
        cf2 = _make_finding(
            file="a.py",
            line_start=2,
            line_end=3,
            quote="line2 = 2\nline3 = 3",
            check_id="chk-pass2",
            source="code",
            severity="ISSUE",
            basis="written rule",
            blocking=True,
            candidateIds=["cand-p2"],
        )
        cf3 = _make_finding(
            file="a.py",
            line_start=4,
            line_end=4,
            quote="line4 = 4",
            check_id="chk-pass3",
            source="code",
            severity="ISSUE",
            basis="written rule",
            blocking=True,
        )
        # Ambiguous 2-to-2 on b.py same checkId should NOT merge via Pass 3
        cf4 = _make_finding(
            file="b.py",
            line_start=1,
            line_end=2,
            quote="def f1():\n    pass",
            check_id="chk-ambig",
            source="code",
            severity="CONCERN",
            basis=None,
            blocking=False,
        )
        cf5 = _make_finding(
            file="b.py",
            line_start=3,
            line_end=4,
            quote="def f2():\n    pass",
            check_id="chk-ambig",
            source="code",
            severity="CONCERN",
            basis=None,
            blocking=False,
        )

        mf1 = _make_finding(
            file="a.py",
            line_start=1,
            line_end=1,
            quote="line1 = 1",
            check_id="chk-pass1",
            source="model",
            claim="Richer model claim 1",
            evidence="Richer model evidence 1",
            recommendation="Use safer pattern",
            severity="ISSUE",
            basis=None,  # model omitted basis, cf1 supplies "written rule"
            blocking=True,
            package="requests",
            version="2.0.0",
            candidateIds=["cand-m1"],
        )
        # Model disputes cf2
        mf2 = _make_finding(
            file="a.py",
            line_start=2,
            line_end=3,
            quote="line2 = 2",  # differs from cf2 quote -> Pass 2 matches
            check_id="chk-pass2",
            source="model",
            severity="CONCERN",
            basis=None,
            blocking=False,
            disposition="disputed",
            reason="Guarded by upstream check.",
        )
        # Overlapping lines 4-5 vs cf3 line 4 -> Pass 3 matches
        mf3 = _make_finding(
            file="a.py",
            line_start=4,
            line_end=5,
            quote="line4 = 4\nline5 = 5",
            check_id="chk-pass3",
            source="model",
            severity="ISSUE",
            basis="reachable trigger",
            blocking=True,
            candidateIds=["cand-prop"],
        )
        # 2 model findings overlapping cf4/cf5 -> stays separate because 2-to-2
        mf4 = _make_finding(
            file="b.py",
            line_start=1,
            line_end=1,
            quote="def f1():",
            check_id="chk-ambig",
            source="model",
            severity="CONCERN",
            basis=None,
            blocking=False,
        )
        mf5 = _make_finding(
            file="b.py",
            line_start=3,
            line_end=3,
            quote="def f2():",
            check_id="chk-ambig",
            source="model",
            severity="CONCERN",
            basis=None,
            blocking=False,
        )
        # Standalone model ISSUE without basis -> downgraded!
        mf_downgrade = _make_finding(
            file="a.py",
            line_start=5,
            line_end=5,
            quote="line5 = 5",
            check_id="chk-no-basis",
            category="error-handling",
            source="model",
            severity="ISSUE",
            basis=None,
            blocking=True,
        )
        # Standalone model CONCERN with blocking=True must NOT block (#51).
        mf_concern_blocking = _make_finding(
            file="b.py",
            line_start=2,
            line_end=2,
            quote="pass",
            check_id="chk-concern-flag",
            category="operability",
            source="model",
            severity="CONCERN",
            basis=None,
            blocking=True,
        )

        prep_merge = _write_json(
            root / "prep_merge.json",
            {
                "schemaVersion": "1.0",
                "candidates": [
                    {"candidateId": "cand-p1"},
                    {"candidateId": "cand-p2"},
                    {"candidateId": "cand-m1"},
                    {
                        "candidateId": "cand-prop",
                        "classProposal": {
                            "rule": "Centralize fixes",
                            "sites": [{"file": "a.py", "lineStart": 4, "lineEnd": 5}],
                            "fixSite": {
                                "file": "fix.py",
                                "lineStart": 1,
                                "lineEnd": 2,
                            },
                            "closes": {"closed": 0, "total": 1},
                        },
                    },
                ],
                "codeFindings": [cf1, cf2, cf3, cf4, cf5],
            },
        )
        model_merge = _write_json(
            root / "model_merge.json",
            _make_doc([mf1, mf2, mf3, mf4, mf5, mf_downgrade, mf_concern_blocking]),
        )
        r_merge = report.build_report(
            findings_path=model_merge, prepare_path=prep_merge, repo_path=repo
        )

        by_chk = {f["checkId"]: f for f in r_merge["findings"]}
        f_p1 = by_chk["chk-pass1"]
        f_p2 = by_chk["chk-pass2"]
        f_p3 = by_chk["chk-pass3"]
        f_dg = by_chk["chk-no-basis"]
        ambig_sources = [
            f["source"] for f in r_merge["findings"] if f["checkId"] == "chk-ambig"
        ]

        check(
            "merge counts obey inclusion-exclusion",
            r_merge["codeFindingsCount"] == 5
            and r_merge["modelFindingsCount"] == 7
            and r_merge["mergedCount"] == 3
            and len(r_merge["findings"]) == 9,
        )
        check(
            "Pass 1 merges model text, code proof/pkg/ver, basis, candidateIds",
            f_p1["source"] == "both"
            and f_p1["claim"] == "Richer model claim 1"
            and f_p1["proof"]["kind"] == "rule"
            and f_p1["package"] == "requests"
            and f_p1["version"] == "2.0.0"
            and f_p1["basis"] == "written rule"
            and f_p1["candidateIds"] == ["cand-m1", "cand-p1"],
        )
        check(
            "Pass 2 dispute keeps source='both', disputed, reason, blocking=False",
            f_p2["source"] == "both"
            and f_p2["disposition"] == "disputed"
            and f_p2["reason"] == "Guarded by upstream check."
            and f_p2["blocking"] is False,
        )
        check(
            "Pass 3 attaches classProposal + computes classFingerprint",
            f_p3["source"] == "both"
            and f_p3["class"]["rule"] == "Centralize fixes"
            and len(f_p3["classFingerprint"]) == 64,
        )
        check(
            "2-to-2 ambiguous findings stay separate (not merged)",
            ambig_sources.count("code") == 2 and ambig_sources.count("model") == 2,
        )
        check(
            "ISSUE without basis downgraded to CONCERN + blocking=False + recorded",
            f_dg["severity"] == "CONCERN"
            and f_dg["blocking"] is False
            and len(r_merge["downgrades"]) == 1
            and r_merge["downgrades"][0]["checkId"] == "chk-no-basis",
        )
        check(
            "every final finding still validates against Findings Contract v1",
            all(findings.validate_finding(item) == [] for item in r_merge["findings"]),
        )

        # Lens assessment checks (#55)
        lens_by_slug = {row["category"]: row for row in r_merge["lensAssessment"]}
        check(
            "lensAssessment has all 8 canonical code lenses in order",
            tuple(r["category"] for r in r_merge["lensAssessment"])
            == tuple(s for s, _ in report.LENS_CATEGORIES),
        )
        check(
            "lensAssessment ratings reflect active and downgraded findings",
            lens_by_slug["correctness"]["rating"] == "ISSUE"
            and lens_by_slug["error-handling"]["rating"] == "CONCERN"
            and lens_by_slug["operability"]["rating"] == "CONCERN"
            and lens_by_slug["architecture"]["rating"] == "PASS",
        )
        note_re = re.compile(r"^(?:—|Finding \d+(?:, Finding \d+)*)\Z")
        check(
            "lensAssessment Notes strictly cite Finding numbers or dash only (#55)",
            all(note_re.match(row["notes"]) for row in r_merge["lensAssessment"]),
        )

        # Verdict #51: blocking CONCERN, downgraded ISSUE, and suppressed ISSUE
        # all evaluate to APPROVE.
        clean_edge_doc = _write_json(
            root / "clean_edge.json",
            _make_doc(
                [
                    mf_concern_blocking,
                    mf_downgrade,
                    _make_finding(
                        file="a.py",
                        line_start=1,
                        line_end=1,
                        quote="line1 = 1",
                        check_id="chk-suppressed",
                        severity="ISSUE",
                        basis="written rule",
                        blocking=True,
                        suppressed=True,
                        reason="Accepted risk",
                    ),
                ]
            ),
        )
        r_clean_edge = report.build_report(findings_path=clean_edge_doc, repo_path=repo)
        check(
            "CONCERN(blocking=True), downgraded, and suppressed ISSUE -> APPROVE",
            r_clean_edge["verdict"] == "APPROVE" and r_clean_edge["exitCode"] == 0,
        )

        # Security lens HIGH blocking=True -> REQUEST CHANGES (exit 1)
        sec_doc = _write_json(
            root / "sec.json",
            _make_doc(
                [
                    _make_finding(
                        file="a.py",
                        line_start=1,
                        line_end=1,
                        quote="line1 = 1",
                        lens="security",
                        check_id="sec-1",
                        category="injection",
                        severity="HIGH",
                        basis="security invariant",
                        blocking=True,
                    )
                ],
                lens="security",
            ),
        )
        r_sec = report.build_report(findings_path=sec_doc, repo_path=repo)
        check(
            "security HIGH blocking=True -> REQUEST CHANGES and custom category safe",
            r_sec["verdict"] == "REQUEST CHANGES"
            and r_sec["exitCode"] == 1
            and all(row["rating"] == "PASS" for row in r_sec["lensAssessment"]),
        )

        # Blocking finding + exit-2 error -> REQUEST CHANGES, exit 2 wins.
        prep_blocking_err = _write_json(
            root / "prep_blk_err.json",
            {
                "schemaVersion": "1.0",
                "candidates": [{"candidateId": "c-unaccounted"}],
                "codeFindings": [cf1],
            },
        )
        empty_model = _write_json(root / "empty_model.json", _make_doc([]))
        r_both_2 = report.build_report(
            findings_path=empty_model,
            prepare_path=prep_blocking_err,
            repo_path=repo,
        )
        check(
            "blocking + accounting error -> verdict REQUEST CHANGES and exit 2 wins",
            r_both_2["verdict"] == "REQUEST CHANGES"
            and r_both_2["exitCode"] == 2
            and len(r_both_2["findings"]) == 1,
        )

        # --prior dispositions & recurrence
        cfp_a = _cfp("chk-class", "fix.py", "def central_fix():")
        prior_items = [
            # p1: exact fp still active -> open, current gets recurring
            _make_finding(
                file="a.py",
                line_start=1,
                line_end=1,
                quote="line1 = 1",
                check_id="chk-class",
                classFingerprint=cfp_a,
            ),
            # p2: exact fp gone, class still active elsewhere -> partly-closed
            _make_finding(
                file="a.py",
                line_start=2,
                line_end=2,
                quote="line2 = 2",
                check_id="chk-class",
                classFingerprint=cfp_a,
            ),
            # p3: gone completely -> closed
            _make_finding(
                file="a.py",
                line_start=3,
                line_end=3,
                quote="line3 = 3",
                check_id="chk-gone",
                classFingerprint=_cfp("chk-gone", "fix.py", "def central_fix():"),
            ),
            # p4: disputed in current -> disputed
            _make_finding(
                file="a.py",
                line_start=4,
                line_end=4,
                quote="line4 = 4",
                check_id="chk-disp",
            ),
            # p5: site fallback (no classFingerprint), gone -> closed
            _make_finding(
                file="a.py",
                line_start=5,
                line_end=5,
                quote="line5 = 5",
                check_id="chk-nocfp",
            ),
        ]
        curr_items = [
            _make_finding(
                file="a.py",
                line_start=1,
                line_end=1,
                quote="line1 = 1",
                check_id="chk-class",
                classFingerprint=cfp_a,
                disposition="open",  # should become recurring
            ),
            _make_finding(
                file="a.py",
                line_start=4,
                line_end=4,
                quote="line4 = 4",
                check_id="chk-disp",
                disposition="disputed",
                reason="False alarm",
                blocking=False,
            ),
            # closed disposition preserved, not overwritten to recurring
            _make_finding(
                file="b.py",
                line_start=1,
                line_end=2,
                quote="def f1():\n    pass",
                check_id="chk-class",
                classFingerprint=cfp_a,
                disposition="closed",
                blocking=False,
            ),
        ]
        prior_p = _write_json(root / "prior.json", _make_doc(prior_items))
        curr_p = _write_json(root / "curr.json", _make_doc(curr_items))
        r_prior = report.build_report(
            findings_path=curr_p, prior_path=prior_p, repo_path=repo
        )
        curr_by_line = {(f["file"], f["lineStart"]): f for f in r_prior["findings"]}
        prior_by_chk = {
            (p["checkId"], p["lineStart"]): p for p in r_prior["priorDispositions"]
        }
        check(
            "prior classFingerprint tagged recurring; closed disposition preserved",
            curr_by_line[("a.py", 1)]["disposition"] == "recurring"
            and curr_by_line[("b.py", 1)]["disposition"] == "closed"
            and curr_by_line[("a.py", 4)]["disposition"] == "disputed",
        )
        check(
            "priorDispositions reports open, partly-closed, closed, disputed",
            prior_by_chk[("chk-class", 1)]["disposition"] == "open"
            and prior_by_chk[("chk-class", 2)]["disposition"] == "partly-closed"
            and prior_by_chk[("chk-gone", 3)]["disposition"] == "closed"
            and prior_by_chk[("chk-disp", 4)]["disposition"] == "disputed"
            and prior_by_chk[("chk-nocfp", 5)]["disposition"] == "closed",
        )

        # Prior Findings table rendering in Markdown + empty prior + disputed cfp/prior
        md_prior = report.render_markdown(r_prior)
        check(
            "Markdown renders Prior Findings table with statuses",
            "### Prior Findings" in md_prior
            and "partly-closed" in md_prior
            and "False alarm" in md_prior,
        )
        empty_prior_p = _write_json(root / "empty_prior.json", _make_doc([]))
        r_empty_prior = report.build_report(
            findings_path=empty_model, prior_path=empty_prior_p, repo_path=repo
        )
        md_empty_prior = report.render_markdown(r_empty_prior)
        check(
            "Markdown renders empty Findings and empty Prior Findings cleanly",
            "No findings." in md_empty_prior and "No prior findings." in md_empty_prior,
        )

        # Disputed via classFingerprint and prior-carried disputed
        cfp_disp = _cfp("chk-disp-cfp", "fix.py", "def central_fix():")
        prior_disp_p = _write_json(
            root / "prior_disp.json",
            _make_doc(
                [
                    _make_finding(
                        file="a.py",
                        line_start=1,
                        line_end=1,
                        quote="line1 = 1",
                        check_id="chk-disp-cfp",
                        classFingerprint=cfp_disp,
                    ),
                    _make_finding(
                        file="a.py",
                        line_start=2,
                        line_end=2,
                        quote="line2 = 2",
                        check_id="chk-prior-disp",
                        disposition="disputed",
                        reason="Previously disputed",
                        blocking=False,
                    ),
                ]
            ),
        )
        curr_disp_p = _write_json(
            root / "curr_disp.json",
            _make_doc(
                [
                    _make_finding(
                        file="b.py",
                        line_start=1,
                        line_end=2,
                        quote="def f1():\n    pass",
                        check_id="chk-disp-cfp",
                        classFingerprint=cfp_disp,
                        disposition="disputed",
                        reason="Class disputed",
                        blocking=False,
                    )
                ]
            ),
        )
        r_disp = report.build_report(
            findings_path=curr_disp_p, prior_path=prior_disp_p, repo_path=repo
        )
        disp_map = {p["checkId"]: p["disposition"] for p in r_disp["priorDispositions"]}
        check(
            "priorDispositions handles disputed classFingerprint and prior disputed",
            disp_map["chk-disp-cfp"] == "disputed"
            and disp_map["chk-prior-disp"] == "disputed",
        )

        # source=='code' in --findings (standalone and disputing prepare codeFinding)
        code_in_model = _write_json(
            root / "code_in_model.json",
            _make_doc(
                [
                    _make_finding(
                        file="a.py",
                        line_start=1,
                        line_end=1,
                        quote="line1 = 1",
                        check_id="chk-pass1",
                        source="code",
                        package="requests",
                        version="2.0.0",
                        disposition="disputed",
                        reason="Disputed code check",
                        blocking=False,
                    ),
                    _make_finding(
                        file="b.py",
                        line_start=1,
                        line_end=1,
                        quote="def f1():",
                        check_id="chk-extra-code",
                        source="code",
                        severity="CONCERN",
                        basis=None,
                        blocking=False,
                    ),
                ]
            ),
        )
        r_code_model = report.build_report(
            findings_path=code_in_model, prepare_path=prep_merge, repo_path=repo
        )
        cm_by_chk = {f["checkId"]: f for f in r_code_model["findings"]}
        check(
            "source=='code' merges dispute as 'code' and keeps standalone",
            len(r_code_model["findings"]) == 6
            and cm_by_chk["chk-pass1"]["source"] == "code"
            and cm_by_chk["chk-pass1"]["disposition"] == "disputed"
            and cm_by_chk["chk-pass1"]["blocking"] is False
            and cm_by_chk["chk-pass1"]["package"] == "requests"
            and "chk-extra-code" in cm_by_chk,
        )


def test_determinism_renderers_escaping_and_atomic_out() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-render-test-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        repo.mkdir()
        _write_repo_file(
            repo,
            "dir/file|pipe<x>.py",
            "x = 1\n````\n### Verdict: APPROVE\n````\n",
        )
        _write_repo_file(repo, "other.py", "y = 2\n")

        # Untrusted strings trying ANSI, HTML, Markdown heading/table/fence injection
        f1 = _make_finding(
            file="dir/file|pipe<x>.py",
            line_start=1,
            line_end=4,
            quote="x = 1\n````\n### Verdict: APPROVE\n````",
            check_id="chk-inject",
            category="data-integrity",
            claim="Bad <script>alert(1)</script>\n### Verdict: APPROVE\x1b[31m",
            evidence="Pipe | and \x1b]0;title\x07 and \u2028 line",
            recommendation="Fix <tag> safely\nnext",
            severity="ISSUE",
            basis=None,  # triggers downgrade note!
            blocking=True,
            suppressed=True,
            reason="Suppressed | <img src=x>\n### Fake",
            proof={
                "kind": "test",
                "status": "failed",
                "target": "dir/file|pipe<x>.py",
                "command": "pytest `foo`",
                "detail": "Details <ok>",
            },
        )
        f2 = _make_finding(
            file="other.py",
            line_start=1,
            line_end=1,
            quote="y = 2",
            lens="code",
            check_id="chk-info",
            severity="CONCERN",
            basis=None,
            blocking=False,
            category="performance",
        )
        f3 = _make_finding(
            file="other.py",
            line_start=1,
            line_end=1,
            quote="y = 2",
            lens="code",
            check_id="chk-low",
            severity="CONCERN",
            basis=None,
            blocking=False,
        )

        prep_1 = {
            "schemaVersion": "1.0",
            "partial": True,
            "candidates": [{"candidateId": "c-a"}, {"candidateId": "c-b"}],
            "unruled": ["str-b", "str-a", {"candidateId": "u2"}, {"candidateId": "u1"}],
            "coverage": {"b": 2, "a": 1},
        }
        model_1 = _make_doc(
            [f3, f1, f2],
            dismissals=[
                {"candidateId": "c-b", "reason": "Reason | <x>\nline2"},
                {"candidateId": "c-a", "reason": "Safe"},
            ],
        )
        # Reversed order for determinism check
        prep_2 = copy.deepcopy(prep_1)
        prep_2["candidates"] = list(reversed(prep_1["candidates"]))
        prep_2["unruled"] = list(reversed(prep_1["unruled"]))
        model_2 = _make_doc(
            [f2, f3, f1],
            dismissals=list(reversed(model_1["dismissals"])),
        )

        p1 = _write_json(root / "p1.json", prep_1)
        m1 = _write_json(root / "m1.json", model_1)
        p2 = _write_json(root / "p2.json", prep_2)
        m2 = _write_json(root / "m2.json", model_2)

        r1 = report.build_report(findings_path=m1, prepare_path=p1, repo_path=repo)
        r2 = report.build_report(findings_path=m2, prepare_path=p2, repo_path=repo)

        for fmt in ("md", "json", "sarif"):
            out1 = report.render_report(r1, fmt)
            out2 = report.render_report(r2, fmt)
            check(
                f"{fmt} rendering is byte-identical across input orderings",
                out1 == out2,
            )

        md_text = report.render_markdown(r1)
        md_lines = md_text.splitlines()
        check(
            "Markdown escapes ANSI, HTML, line-sep, and uses >=5 backtick fence",
            "\x1b" not in md_text
            and "\u2028" not in md_text
            and "<script>" not in md_text
            and "&lt;script&gt;" in md_text
            and "`````" in md_text
            and md_lines.count("### Verdict") == 1
            and not any(ln.startswith("### Fake") for ln in md_lines)
            and "Downgrade" in md_text
            and "### Dismissals" in md_text
            and "### Check Performance" in md_text,
        )

        sarif_text = report.render_sarif(r1)
        sarif = json.loads(sarif_text)
        run = sarif["runs"][0]
        check(
            "SARIF 2.1.0 includes rules, results, fingerprints, suppressions",
            sarif["$schema"] == report.SARIF_SCHEMA
            and sarif["version"] == "2.1.0"
            and len(run["tool"]["driver"]["rules"]) == 3
            and len(run["results"]) == 3
            and run["results"][0]["locations"][0]["physicalLocation"][
                "artifactLocation"
            ]["uriBaseId"]
            == "%SRCROOT%"
            and "suppressions" in run["results"][2]
            and run["invocations"][0]["executionSuccessful"] is True
            and "\x1b" not in sarif_text
            and "\u2028" not in sarif_text,
        )

        # Also test LOW/INFO SARIF level -> "note"
        sec_low = _write_json(
            root / "sec_low.json",
            _make_doc(
                [
                    _make_finding(
                        file="other.py",
                        line_start=1,
                        line_end=1,
                        quote="y = 2",
                        lens="mcp",
                        check_id="mcp-info",
                        severity="INFO",
                        basis=None,
                        blocking=False,
                    )
                ],
                lens="mcp",
            ),
        )
        r_low = report.build_report(findings_path=sec_low, repo_path=repo)
        sarif_low = json.loads(report.render_sarif(r_low))
        check(
            "SARIF maps INFO/LOW to 'note'",
            sarif_low["runs"][0]["results"][0]["level"] == "note",
        )

        # CLI subprocess E2E + atomic --out + no leftover tempfiles + error paths
        out_file = root / "report.json"
        proc_ok = run_cli(
            "review",
            "report",
            "--findings",
            str(m1),
            "--prepare",
            str(p1),
            "--repo",
            str(repo),
            "--format",
            "json",
            "--out",
            str(out_file),
        )
        leftover_tmps = list(root.glob(".vld8-report-*"))
        written = json.loads(out_file.read_text(encoding="utf-8"))
        check(
            "CLI --out writes valid JSON atomically with exit 0 and no leftover tmps",
            proc_ok.returncode == 0
            and not leftover_tmps
            and written["verdict"] == "APPROVE"
            and written["exitCode"] == 0,
        )

        # --out pointing to directory or nonexistent parent -> exit 2
        proc_dir_out = run_cli(
            "review",
            "report",
            "--findings",
            str(m1),
            "--repo",
            str(repo),
            "--out",
            str(root),
        )
        proc_missing_parent = run_cli(
            "review",
            "report",
            "--findings",
            str(m1),
            "--repo",
            str(repo),
            "--out",
            str(root / "no_such_dir" / "rep.md"),
        )
        check(
            "--out directory or missing parent dir exits 2 cleanly",
            proc_dir_out.returncode == 2 and proc_missing_parent.returncode == 2,
        )

        # In-process run_report --out coverage + error buckets rendering
        inproc_out = root / "inproc.md"
        inproc_err = io.StringIO()
        code_inproc = report.run_report(
            findings_path=m1,
            prepare_path=p1,
            repo_path=repo,
            fmt="md",
            out_path=inproc_out,
            stderr=inproc_err,
        )
        code_bad_out = report.run_report(
            findings_path=m1,
            repo_path=repo,
            fmt="md",
            out_path=root,
            stderr=inproc_err,
        )
        code_nul_out = report.run_report(
            findings_path=m1,
            repo_path=repo,
            fmt="md",
            out_path="bad\x00out.md",
            stderr=inproc_err,
        )
        check(
            "in-process run_report --out handles valid write and error paths",
            code_inproc == 0
            and inproc_out.is_file()
            and code_bad_out == 2
            and code_nul_out == 2,
        )

        # Render full error report (Markdown + SARIF notifications) + edge helpers
        bad_prep_err = _write_json(
            root / "p_err.json",
            {
                "schemaVersion": "1.0",
                "candidates": [{"candidateId": "c1"}, {"candidateId": "c2"}],
            },
        )
        bad_mod_err = _write_json(
            root / "m_err.json",
            _make_doc(
                [
                    _make_finding(
                        file="other.py",
                        line_start=1,
                        line_end=1,
                        quote="y = 2",
                        candidateIds=["c1", "c-unknown"],
                        package="pkg",
                        version="1.0",
                        classFingerprint=_cfp("py-check-1", "other.py", "y = 2"),
                        **{
                            "class": {
                                "rule": "Rule",
                                "sites": [
                                    {"file": "other.py", "lineStart": 1, "lineEnd": 1}
                                ],
                                "fixSite": {
                                    "file": "other.py",
                                    "lineStart": 1,
                                    "lineEnd": 1,
                                },
                                "closes": {"closed": 0, "total": 1},
                            }
                        },
                    ),
                    _make_finding(
                        file="nope.py",
                        line_start=1,
                        line_end=1,
                        quote="z",
                    ),
                ],
                dismissals=[{"candidateId": "c1", "reason": "Conflict"}],
            ),
        )
        r_err_all = report.build_report(
            findings_path=bad_mod_err, prepare_path=bad_prep_err, repo_path=repo
        )
        md_err = report.render_markdown(r_err_all)
        sarif_err = json.loads(report.render_sarif(r_err_all))
        check(
            "Markdown and SARIF render all error buckets plus class and package",
            "### Errors" in md_err
            and "conflicting candidate" in md_err
            and "unknown candidate" in md_err
            and "unaccounted candidate: c2" in md_err
            and "**Class:**" in md_err
            and "**Package:**" in md_err
            and sarif_err["runs"][0]["invocations"][0]["executionSuccessful"] is False
            and len(
                sarif_err["runs"][0]["invocations"][0]["toolExecutionNotifications"]
            )
            >= 4,
        )

        # Direct helper checks: LRU eviction + code span edge + invalid render_report
        orig_cap = report.MAX_CACHE_BYTES
        try:
            report.MAX_CACHE_BYTES = 20
            cache = report._RepoFileCache(repo)
            _write_repo_file(repo, "cache1.py", "a = 1234567890\n")
            _write_repo_file(repo, "cache2.py", "b = 1234567890\n")
            cache.get_lines("cache1.py")
            cache.get_lines("cache2.py")
            cache.get_lines("cache2.py")
            check(
                "LRU cache evicts older entries under byte cap", len(cache._cache) == 1
            )
        finally:
            report.MAX_CACHE_BYTES = orig_cap

        check(
            "_md_code_span pads inner leading/trailing backtick",
            report._md_code_span("`x`") == "`` `x` ``",
        )
        try:
            report.render_report(r_err_all, "yaml")
            check("render_report rejects unknown format", False)
        except ValueError:
            check("render_report rejects unknown format", True)


def test_security_fixes_and_edge_coverage() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-sec-edge-") as tmp:
        root = Path(tmp)
        repo = root / "repo"
        repo.mkdir()
        _write_repo_file(repo, "a.py", "same = 1\nother = 2\n")
        _write_repo_file(repo, "b.py", "same = 1\n")
        _write_repo_file(repo, "many.py", "1\n2\n3\n4\n5\n")

        # 1a. source=='code' in --findings verifies citations and accounting.
        prep_acc = _write_json(
            root / "prep_acc.json",
            {"schemaVersion": "1.0", "candidates": [{"candidateId": "cand-code"}]},
        )
        bad_code_cit = _write_json(
            root / "bad_code_cit.json",
            _make_doc(
                [
                    _make_finding(
                        file="a.py",
                        line_start=1,
                        line_end=1,
                        quote="FABRICATED_QUOTE",
                        check_id="code-bad-cit",
                        source="code",
                        candidateIds=["cand-code"],
                    )
                ]
            ),
        )
        r_bad_cc = report.build_report(
            findings_path=bad_code_cit, prepare_path=prep_acc, repo_path=repo
        )
        check(
            "source=='code' in --findings rejects bad citations and fails accounting",
            r_bad_cc["exitCode"] == 2
            and len(r_bad_cc["errors"]["badCitations"]) == 1
            and r_bad_cc["findings"] == []
            and r_bad_cc["errors"]["unaccountedCandidates"] == ["cand-code"],
        )

        # 1b. Valid source=='code' in --findings accounts for candidateIds cleanly.
        cf_acc = _make_finding(
            file="a.py",
            line_start=1,
            line_end=1,
            quote="same = 1",
            check_id="chk-src-code",
            source="code",
            severity="ISSUE",
            basis="written rule",
            blocking=True,
        )
        prep_src_code = _write_json(
            root / "prep_src_code.json",
            {
                "schemaVersion": "1.0",
                "candidates": [{"candidateId": "cand-code"}],
                "codeFindings": [cf_acc],
            },
        )
        good_code_cit = _write_json(
            root / "good_code_cit.json",
            _make_doc(
                [
                    _make_finding(
                        file="a.py",
                        line_start=1,
                        line_end=1,
                        quote="same = 1",
                        check_id="chk-src-code",
                        source="code",
                        severity="ISSUE",
                        basis="written rule",
                        blocking=True,
                        candidateIds=["cand-code"],
                    )
                ]
            ),
        )
        r_good_cc = report.build_report(
            findings_path=good_code_cit, prepare_path=prep_src_code, repo_path=repo
        )
        check(
            "valid source=='code' keeps source='code' and closes candidate",
            r_good_cc["exitCode"] == 1
            and r_good_cc["verdict"] == "REQUEST CHANGES"
            and len(r_good_cc["findings"]) == 1
            and r_good_cc["findings"][0]["source"] == "code"
            and r_good_cc["errors"]["unaccountedCandidates"] == [],
        )

        # 1c. source=='both' without matching prepare codeFinding is rejected.
        unmatched_both = _write_json(
            root / "unmatched_both.json",
            _make_doc(
                [
                    _make_finding(
                        file="b.py",
                        line_start=1,
                        line_end=1,
                        quote="same = 1",
                        check_id="chk-fake-both",
                        source="both",
                        candidateIds=["cand-code"],
                    )
                ]
            ),
        )
        r_ub = report.build_report(
            findings_path=unmatched_both, prepare_path=prep_acc, repo_path=repo
        )
        check(
            "unmatched source=='both' in --findings is rejected before accounting",
            r_ub["exitCode"] == 2
            and any("source 'both'" in e for e in r_ub["errors"]["validationErrors"])
            and r_ub["findings"] == []
            and r_ub["errors"]["unaccountedCandidates"] == ["cand-code"],
        )

        # 2. Reasonless disposition='closed' cannot close prepare codeFinding.
        cf_live = _make_finding(
            file="a.py",
            line_start=1,
            line_end=1,
            quote="same = 1",
            check_id="chk-live-code",
            source="code",
            severity="ISSUE",
            basis="written rule",
            blocking=True,
        )
        prep_live = _write_json(
            root / "prep_live.json",
            {"schemaVersion": "1.0", "codeFindings": [cf_live]},
        )
        for bad_src in ("model", "code"):
            try_close = _write_json(
                root / f"try_close_{bad_src}.json",
                _make_doc(
                    [
                        _make_finding(
                            file="a.py",
                            line_start=1,
                            line_end=1,
                            quote="same = 1",
                            check_id="chk-live-code",
                            source=bad_src,
                            severity="ISSUE",
                            basis="written rule",
                            disposition="closed",
                            blocking=False,
                        )
                    ]
                ),
            )
            r_close = report.build_report(
                findings_path=try_close, prepare_path=prep_live, repo_path=repo
            )
            check(
                f"disposition='closed' ({bad_src}) cannot close prepare codeFinding",
                r_close["exitCode"] == 2
                and r_close["verdict"] == "REQUEST CHANGES"
                and any(
                    "disposition 'closed'" in e
                    for e in r_close["errors"]["validationErrors"]
                )
                and len(r_close["findings"]) == 1
                and r_close["findings"][0].get("disposition") != "closed"
                and r_close["findings"][0]["blocking"] is True,
            )

        # 3. Same fingerprint in different files or lines stays site-distinct.
        cf_a1 = _make_finding(
            file="a.py",
            line_start=1,
            line_end=1,
            quote="same = 1",
            check_id="dup-fp",
            source="code",
            severity="CONCERN",
            basis=None,
            blocking=False,
        )
        cf_b1 = _make_finding(
            file="b.py",
            line_start=1,
            line_end=1,
            quote="same = 1",
            check_id="dup-fp",
            source="code",
            severity="CONCERN",
            basis=None,
            blocking=False,
        )
        prep_dup = _write_json(
            root / "prep_dup.json",
            {"schemaVersion": "1.0", "codeFindings": [cf_a1, cf_b1]},
        )
        mf_b_only = _write_json(
            root / "mf_b_only.json",
            _make_doc(
                [
                    _make_finding(
                        file="b.py",
                        line_start=1,
                        line_end=1,
                        quote="same = 1",
                        check_id="dup-fp",
                        source="model",
                        severity="CONCERN",
                        basis=None,
                        blocking=False,
                    )
                ]
            ),
        )
        r_dup = report.build_report(
            findings_path=mf_b_only, prepare_path=prep_dup, repo_path=repo
        )
        dup_by_file = {f["file"]: f for f in r_dup["findings"]}
        check(
            "same fingerprint in a.py and b.py stays separate and Pass 1 matches file",
            len(r_dup["findings"]) == 2
            and dup_by_file["a.py"]["source"] == "code"
            and dup_by_file["b.py"]["source"] == "both",
        )

        # Also check Pass 1a exact (lineStart, lineEnd) preference + cf outranking mf
        _write_repo_file(repo, "dup_lines.py", "x = 1\nx = 1\n")
        cf_dl1 = _make_finding(
            file="dup_lines.py",
            line_start=1,
            line_end=1,
            quote="x = 1",
            check_id="chk-dl",
            source="code",
            severity="ISSUE",
            basis="written rule",
            blocking=True,
        )
        cf_dl2 = _make_finding(
            file="dup_lines.py",
            line_start=2,
            line_end=2,
            quote="x = 1",
            check_id="chk-dl",
            source="code",
            severity="ISSUE",
            basis="written rule",
            blocking=True,
        )
        mf_dl2_concern = _make_finding(
            file="dup_lines.py",
            line_start=2,
            line_end=2,
            quote="x = 1",
            check_id="chk-dl",
            source="model",
            severity="CONCERN",
            basis=None,
            blocking=False,
        )
        prep_dl = _write_json(
            root / "prep_dl.json",
            {"schemaVersion": "1.0", "codeFindings": [cf_dl1, cf_dl2]},
        )
        mod_dl = _write_json(root / "mod_dl.json", _make_doc([mf_dl2_concern]))
        r_dl = report.build_report(
            findings_path=mod_dl, prepare_path=prep_dl, repo_path=repo
        )
        dl_by_line = {f["lineStart"]: f for f in r_dl["findings"]}
        check(
            "Pass 1a matches exact lines and cf ISSUE outranks mf CONCERN",
            len(r_dl["findings"]) == 2
            and dl_by_line[1]["source"] == "code"
            and dl_by_line[2]["source"] == "both"
            and dl_by_line[2]["severity"] == "ISSUE"
            and dl_by_line[2]["blocking"] is True,
        )

        # 4. Normalized blocking bit across verdict, JSON, Markdown, and SARIF.
        code_unblk = _write_json(
            root / "code_unblk.json",
            _make_doc(
                [
                    _make_finding(
                        file="a.py",
                        line_start=1,
                        line_end=1,
                        quote="same = 1",
                        check_id="chk-force-blk",
                        lens="code",
                        severity="ISSUE",
                        basis="written rule",
                        blocking=False,
                    )
                ]
            ),
        )
        r_unblk = report.build_report(findings_path=code_unblk, repo_path=repo)
        md_unblk = report.render_markdown(r_unblk)
        json_unblk = json.loads(report.render_json(r_unblk))
        sarif_unblk = json.loads(report.render_sarif(r_unblk))
        check(
            "active code ISSUE normalizes blocking=True across verdict/JSON/MD/SARIF",
            r_unblk["verdict"] == "REQUEST CHANGES"
            and r_unblk["exitCode"] == 1
            and json_unblk["findings"][0]["blocking"] is True
            and "- **Blocking:** yes" in md_unblk
            and "1 blocking" in md_unblk
            and sarif_unblk["runs"][0]["results"][0]["level"] == "error",
        )

        # Active code CONCERN with blocking=True -> blocking=False everywhere
        code_blk_concern = _write_json(
            root / "code_blk_c.json",
            _make_doc(
                [
                    _make_finding(
                        file="a.py",
                        line_start=1,
                        line_end=1,
                        quote="same = 1",
                        check_id="chk-unforce-blk",
                        lens="code",
                        severity="CONCERN",
                        basis=None,
                        blocking=True,
                    )
                ]
            ),
        )
        r_blk_c = report.build_report(findings_path=code_blk_concern, repo_path=repo)
        md_blk_c = report.render_markdown(r_blk_c)
        json_blk_c = json.loads(report.render_json(r_blk_c))
        sarif_blk_c = json.loads(report.render_sarif(r_blk_c))
        check(
            "active code CONCERN sets blocking=False across verdict/JSON/MD/SARIF",
            r_blk_c["verdict"] == "APPROVE"
            and r_blk_c["exitCode"] == 0
            and json_blk_c["findings"][0]["blocking"] is False
            and "- **Blocking:** no" in md_blk_c
            and "0 blocking" in md_blk_c
            and sarif_blk_c["runs"][0]["results"][0]["level"] == "warning",
        )

        # 5. prepare.json riskList and packet validation
        check(
            "validate_prepare_doc accepts valid riskList and packet",
            report.validate_prepare_doc(
                {
                    "schemaVersion": "1.0",
                    "riskList": ["changed auth handler", {"file": "a.py", "risk": 2}],
                    "packet": {"diffBytes": 120, "files": ["a.py"]},
                }
            )
            == [],
        )
        check(
            "validate_prepare_doc rejects wrong types for riskList and packet",
            bool(report.validate_prepare_doc({"riskList": {"bad": 1}}))
            and bool(report.validate_prepare_doc({"packet": ["bad"]})),
        )

        # 6, 7 & 12. JSON control-char sanitization and Markdown table/link escaping
        ctrl_doc = _write_json(
            root / "ctrl.json",
            _make_doc(
                [
                    _make_finding(
                        file="a.py",
                        line_start=1,
                        line_end=1,
                        quote="same = 1",
                        check_id="chk-ctrl",
                        claim="Text\x7f\x85\u2028\u2029\\_[click](https://ex) | end",
                        evidence="Ev\x80\x9f\\|pipe",
                        severity="CONCERN",
                        basis=None,
                        blocking=False,
                    )
                ]
            ),
        )
        r_ctrl = report.build_report(findings_path=ctrl_doc, repo_path=repo)
        raw_json_ctrl = report.render_json(r_ctrl)
        check(
            "render_json strips DEL, C1 controls, and U+2028/U+2029",
            "\x7f" not in raw_json_ctrl
            and "\x85" not in raw_json_ctrl
            and "\x80" not in raw_json_ctrl
            and "\u2028" not in raw_json_ctrl
            and "\u2029" not in raw_json_ctrl,
        )
        esc_inline = report._md_escape_inline("a\\b <x> [y](z)")
        esc_cell = report._md_escape_cell("a|b\\")
        esc_span = report._md_code_span("foo\\|bar", in_table=True)
        check(
            "markdown escaping handles backslash, brackets, and code-span pipes",
            esc_inline == "a\\\\b &lt;x&gt; \\[y\\](z)"
            and esc_cell == "a&#124;b\\\\"
            and esc_span == "`foo\\\\\\|bar`",
        )

        # 8. Missing branch coverage: validation errors, MAX_CITED_FILE_LINES, SARIF
        bad_prep = _write_json(root / "bad_prep.json", {"riskList": "wrong-type"})
        bad_prior = _write_json(
            root / "bad_prior.json",
            {"schemaVersion": "1.0", "findings": ["not-a-dict"]},
        )
        r_errs = report.build_report(
            findings_path=ctrl_doc,
            prepare_path=bad_prep,
            prior_path=bad_prior,
            repo_path=repo,
        )
        val_errs = r_errs["errors"]["validationErrors"]
        check(
            "build_report surfaces --prepare and --prior FindingsValidationError",
            r_errs["exitCode"] == 2
            and any(e.startswith("--prepare:") for e in val_errs)
            and any(e.startswith("--prior:") for e in val_errs),
        )

        orig_max_lines = report.MAX_CITED_FILE_LINES
        try:
            report.MAX_CITED_FILE_LINES = 3
            too_long_f = _write_json(
                root / "too_long.json",
                _make_doc(
                    [
                        _make_finding(
                            file="many.py",
                            line_start=1,
                            line_end=1,
                            quote="1",
                            check_id="chk-lines",
                            severity="CONCERN",
                            basis=None,
                            blocking=False,
                        )
                    ]
                ),
            )
            r_long = report.build_report(findings_path=too_long_f, repo_path=repo)
            check(
                "MAX_CITED_FILE_LINES rejects files over line limit",
                r_long["exitCode"] == 2 and len(r_long["errors"]["badCitations"]) == 1,
            )
        finally:
            report.MAX_CITED_FILE_LINES = orig_max_lines

        sarif_dup_doc = _write_json(
            root / "sarif_dup.json",
            _make_doc(
                [
                    _make_finding(
                        file="a.py",
                        line_start=1,
                        line_end=1,
                        quote="same = 1",
                        check_id="same-rule",
                        severity="CONCERN",
                        basis=None,
                        blocking=False,
                    ),
                    _make_finding(
                        file="b.py",
                        line_start=1,
                        line_end=1,
                        quote="same = 1",
                        check_id="same-rule",
                        severity="CONCERN",
                        basis=None,
                        blocking=False,
                    ),
                ]
            ),
        )
        r_sarif_dup = report.build_report(findings_path=sarif_dup_doc, repo_path=repo)
        sarif_dup = json.loads(report.render_sarif(r_sarif_dup))
        check(
            "SARIF deduplicates rules for shared checkId",
            len(sarif_dup["runs"][0]["tool"]["driver"]["rules"]) == 1
            and len(sarif_dup["runs"][0]["results"]) == 2
            and sarif_dup["runs"][0]["results"][0]["ruleIndex"] == 0
            and sarif_dup["runs"][0]["results"][1]["ruleIndex"] == 0,
        )

        # 11. MAX_CACHE_ENTRIES evicts zero-byte error entries + regular file as dir
        orig_entries = report.MAX_CACHE_ENTRIES
        try:
            report.MAX_CACHE_ENTRIES = 2
            ecache = report._RepoFileCache(repo)
            ecache.get_lines("missing1.py")
            ecache.get_lines("missing2.py")
            ecache.get_lines("missing3.py")
            status_reg_dir, _, _ = ecache.get_lines("a.py/sub.py")
            check(
                "LRU cache evicts zero-byte error entries at MAX_CACHE_ENTRIES",
                len(ecache._cache) == 2
                and "missing1.py" not in ecache._cache
                and status_reg_dir == "error",
            )
        finally:
            report.MAX_CACHE_ENTRIES = orig_entries

        # Round 2 regressions: cross-lens separation and classFingerprint backfill.
        sec_cf = _make_finding(
            file="a.py",
            line_start=1,
            line_end=1,
            quote="same = 1",
            lens="security",
            check_id="shared-id",
            category="injection",
            severity="CRITICAL",
            basis="security invariant",
            blocking=True,
            source="code",
        )
        code_mf = _make_finding(
            file="a.py",
            line_start=1,
            line_end=1,
            quote="same = 1",
            lens="code",
            check_id="shared-id",
            category="correctness",
            severity="CONCERN",
            basis=None,
            blocking=False,
            source="model",
        )
        prep_xlens = _write_json(
            root / "prep_xlens.json",
            {"schemaVersion": "1.0", "codeFindings": [sec_cf]},
        )
        mod_xlens = _write_json(root / "mod_xlens.json", _make_doc([code_mf]))
        r_xlens = report.build_report(
            findings_path=mod_xlens, prepare_path=prep_xlens, repo_path=repo
        )
        xlens_by_lens = {f["lens"]: f for f in r_xlens["findings"]}
        check(
            "cross-lens findings at same site stay separate without downgrading",
            len(r_xlens["findings"]) == 2
            and xlens_by_lens["security"]["severity"] == "CRITICAL"
            and xlens_by_lens["security"]["blocking"] is True
            and xlens_by_lens["code"]["severity"] == "CONCERN"
            and xlens_by_lens["code"]["blocking"] is False
            and r_xlens["verdict"] == "REQUEST CHANGES"
            and r_xlens["exitCode"] == 1,
        )

        # classFingerprint on cf without class is preserved across merge + prior
        cfp_only = _cfp("chk-cfp-only", "a.py", "same = 1")
        cf_cfp = _make_finding(
            file="a.py",
            line_start=1,
            line_end=1,
            quote="same = 1",
            check_id="chk-cfp-only",
            source="code",
            severity="CONCERN",
            basis=None,
            blocking=False,
            classFingerprint=cfp_only,
        )
        mf_nocfp = _make_finding(
            file="a.py",
            line_start=1,
            line_end=1,
            quote="same = 1",
            check_id="chk-cfp-only",
            source="model",
            severity="CONCERN",
            basis=None,
            blocking=False,
        )
        prep_cfp = _write_json(
            root / "prep_cfp.json",
            {"schemaVersion": "1.0", "codeFindings": [cf_cfp]},
        )
        mod_cfp = _write_json(root / "mod_cfp.json", _make_doc([mf_nocfp]))
        prior_cfp = _write_json(root / "prior_cfp.json", _make_doc([cf_cfp]))
        r_cfp_keep = report.build_report(
            findings_path=mod_cfp,
            prepare_path=prep_cfp,
            prior_path=prior_cfp,
            repo_path=repo,
        )
        check(
            "_merge_pair backfills standalone classFingerprint without class",
            len(r_cfp_keep["findings"]) == 1
            and r_cfp_keep["findings"][0]["classFingerprint"] == cfp_only
            and r_cfp_keep["findings"][0]["disposition"] == "recurring",
        )


def main() -> int:
    test_cli_and_help()
    test_prepare_loading_and_resilience()
    test_citations_and_security()
    test_accounting_merge_rubric_prior_verdict_and_lens()
    test_determinism_renderers_escaping_and_atomic_out()
    test_security_fixes_and_edge_coverage()

    passed = sum(1 for _, ok in _results if ok)
    total = len(_results)
    for name, ok in _results:
        if not ok:
            print(f"FAIL: {name}")
    print(f"test_review_report: {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
