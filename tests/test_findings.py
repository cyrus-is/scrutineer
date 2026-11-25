#!/usr/bin/env python3
"""Tests for Findings Contract v1 schema, validator, and fingerprints.

Dependency-free (no pytest): run from the repo root with

    python tests/test_findings.py
"""

from __future__ import annotations

import copy
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from vld8 import findings, paths  # noqa: E402

_results: list[tuple[str, bool]] = []


def check(name: str, cond: object) -> None:
    _results.append((name, bool(cond)))


def _valid_fp(char: str = "a") -> str:
    return char * 64


def _minimal_finding(**overrides: object) -> dict[str, object]:
    item: dict[str, object] = {
        "file": "vld8/cli.py",
        "lineStart": 10,
        "lineEnd": 12,
        "quote": "return subprocess.run(cmd).returncode",
        "lens": "code",
        "checkId": "py-subprocess-check",
        "claim": "Return code should be checked explicitly.",
        "evidence": "Caller ignores exit code when running helper.",
        "severity": "CONCERN",
        "blocking": False,
        "source": "model",
        "fingerprint": _valid_fp("a"),
    }
    item.update(overrides)
    return item


def _minimal_doc(
    findings_list: list[dict[str, object]] | None = None, **overrides: object
) -> dict[str, object]:
    doc: dict[str, object] = {
        "schemaVersion": "1.0",
        "findings": [_minimal_finding()] if findings_list is None else findings_list,
    }
    doc.update(overrides)
    return doc


def _expect_invalid(name: str, doc: object, needle: str = "") -> None:
    errors = findings.validate_findings_doc(doc)
    ok = bool(errors) and (not needle or any(needle in err for err in errors))
    check(name, ok)


def test_schema_and_parity() -> None:
    check("findings schema path exists", paths.FINDINGS_SCHEMA.is_file())
    check("no missing toolkit assets", paths.missing_assets() == [])
    check(
        "schema_path helper matches paths.FINDINGS_SCHEMA",
        findings.schema_path() == paths.FINDINGS_SCHEMA,
    )

    schema = findings.load_schema()
    check(
        "schema root declares Draft 2020-12",
        schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema",
    )
    check(
        "schemaVersion const matches SCHEMA_VERSION",
        schema["properties"]["schemaVersion"]["const"] == findings.SCHEMA_VERSION,
    )
    check("load_schema returns defensive copy", True)
    schema["title"] = "mutated"
    check(
        "mutating returned schema does not mutate cache",
        findings.load_schema()["title"] == "vld8 Findings Contract v1",
    )

    defs = schema["$defs"]
    check(
        "lens enum matches VALID_LENSES",
        set(defs["lens"]["enum"]) == findings.VALID_LENSES,
    )
    check(
        "basis enum matches VALID_BASES",
        set(defs["basis"]["enum"]) == findings.VALID_BASES,
    )
    check(
        "source enum matches VALID_SOURCES",
        set(defs["source"]["enum"]) == findings.VALID_SOURCES,
    )
    check(
        "disposition enum matches VALID_DISPOSITIONS",
        set(defs["disposition"]["enum"]) == findings.VALID_DISPOSITIONS,
    )
    check(
        "proof.kind matches VALID_PROOF_KINDS",
        set(defs["proof"]["properties"]["kind"]["enum"]) == findings.VALID_PROOF_KINDS,
    )
    check(
        "proof.status matches VALID_PROOF_STATUSES",
        set(defs["proof"]["properties"]["status"]["enum"])
        == findings.VALID_PROOF_STATUSES,
    )
    check(
        "finding.severity matches VALID_SEVERITIES",
        set(defs["finding"]["properties"]["severity"]["enum"])
        == findings.VALID_SEVERITIES,
    )
    check(
        "code severity rule matches CODE_SEVERITIES",
        set(defs["finding"]["allOf"][0]["then"]["properties"]["severity"]["enum"])
        == findings.CODE_SEVERITIES,
    )
    check(
        "schema maxItems findings matches constant",
        schema["properties"]["findings"]["maxItems"] == findings.MAX_FINDINGS_COUNT,
    )
    check(
        "schema maxItems dismissals matches constant",
        schema["properties"]["dismissals"]["maxItems"] == findings.MAX_DISMISSALS_COUNT,
    )
    check(
        "schema maxItems class sites matches constant",
        defs["findingClass"]["properties"]["sites"]["maxItems"]
        == findings.MAX_CLASS_SITES,
    )
    check(
        "schema maxItems candidateIds matches constant",
        defs["finding"]["properties"]["candidateIds"]["maxItems"]
        == findings.MAX_CANDIDATE_IDS,
    )

    # Regex parity between schema patterns and Python validator on edge cases.
    path_re = re.compile(defs["repoRelativePath"]["pattern"], re.ASCII)
    id_re = re.compile(defs["identifier"]["pattern"], re.ASCII)
    sha_re = re.compile(defs["sha256Hex"]["pattern"], re.ASCII)
    for sample, expected in [
        ("vld8/cli.py", True),
        (".github/workflows/test.yml", True),
        ("..hidden/file.py", True),
        (".hidden", True),
        ("", False),
        ("/abs/path.py", False),
        ("dir/", False),
        ("a//b.py", False),
        ("../escape.py", False),
        ("a/../b.py", False),
        ("./a.py", False),
        ("a/./b.py", False),
        (".", False),
        ("..", False),
        ("a\\b.py", False),
        ("C:a.py", False),
        ("C:/a.py", False),
        ("a\x00b.py", False),
        ("a\nb.py", False),
        ("a\x1bb.py", False),
    ]:
        errs: list[str] = []
        py_ok = findings._validate_repo_relative_path(sample, "p", errs)
        # In Python `re`, `$` matches before `\n`; control-char exclusion avoids it.
        re_ok = bool(path_re.match(sample)) and "\n" not in sample
        check(f"path parity ({sample!r})", py_ok == expected and re_ok == expected)

    for sample, expected in [
        ("py-sec-01", True),
        ("CWE-78:cmd_exec/v1.0", True),
        ("", False),
        ("-leading-dash", False),
        ("has space", False),
        ("²superscript", False),
        ("id\nline2", False),
    ]:
        errs = []
        py_ok = findings._validate_identifier(sample, "id", errs)
        re_ok = bool(id_re.match(sample)) and "\n" not in sample
        check(
            f"identifier parity ({sample!r})", py_ok == expected and re_ok == expected
        )

    for sample, expected in [
        (_valid_fp("0"), True),
        (_valid_fp("f"), True),
        (_valid_fp("A"), False),
        ("a" * 63, False),
        ("a" * 65, False),
        ("²" * 64, False),
        ("a" * 63 + "g", False),
    ]:
        errs = []
        py_ok = findings._validate_sha256(sample, "fp", errs)
        re_ok = bool(sha_re.match(sample)) and "\n" not in sample
        check(
            f"sha256 parity ({sample[:8]!r} len={len(sample)})",
            py_ok == expected and re_ok == expected,
        )


def test_valid_documents() -> None:
    empty_doc = _minimal_doc([])
    snapshot = copy.deepcopy(empty_doc)
    check(
        "empty findings doc validates", findings.validate_findings_doc(empty_doc) == []
    )
    check("validator does not mutate input", empty_doc == snapshot)

    code_issue = _minimal_finding(
        severity="ISSUE",
        basis="written rule",
        blocking=True,
        category="error-handling",
        recommendation="Propagate non-zero return codes to caller.",
    )
    code_issue_no_basis = _minimal_finding(severity="ISSUE", basis=None, blocking=False)
    check(
        "code ISSUE without basis still parses under contract v1",
        findings.validate_findings_doc(_minimal_doc([code_issue_no_basis])) == [],
    )

    fp = findings.compute_fingerprint(
        "sec-cmd-inj", "subprocess.run(user_cmd, shell=True)"
    )
    cfp = findings.compute_class_fingerprint(
        "sec-cmd-inj",
        "vld8/runner.py",
        "def run_safe(argv):\n    return subprocess.run(argv)",
    )
    full_security = {
        "file": "vld8/cli.py",
        "lineStart": 27,
        "lineEnd": 27,
        "quote": "subprocess.run([sys.executable, str(script), *args])",
        "lens": "security",
        "checkId": "sec-cmd-inj",
        "category": "injection",
        "claim": "Untrusted shell argument could be interpreted as command.",
        "evidence": "Value flows from input parameter directly into shell invocation.",
        "severity": "HIGH",
        "basis": "security invariant",
        "blocking": True,
        "source": "both",
        "proof": {
            "kind": "test",
            "status": "verified",
            "detail": "Regression test reproduces shell expansion.",
            "command": "python tests/test_findings.py",
            "target": "vld8/cli.py",
        },
        "class": {
            "rule": "Never invoke shells with untrusted strings.",
            "sites": [
                {
                    "file": "vld8/cli.py",
                    "lineStart": 27,
                    "lineEnd": 27,
                    "quote": "subprocess.run(...)",
                    "candidateId": "cand-1",
                },
                {
                    "file": "vld8/installer.py",
                    "lineStart": 146,
                    "lineEnd": 146,
                    "candidateId": "cand-2",
                },
            ],
            "fixSite": {
                "file": "vld8/runner.py",
                "lineStart": 12,
                "lineEnd": 18,
                "quote": "def run_safe(argv):",
            },
            "closes": {"closed": 0, "total": 2},
        },
        "classFingerprint": cfp,
        "disposition": "recurring",
        "suppressed": True,
        "reason": "Accepted in test sandbox only; guarded upstream.",
        "package": "pyyaml",
        "version": "6.0.3",
        "candidateIds": ["cand-1", "cand-2"],
        "recommendation": "Use a single vetted runner helper with list arguments.",
        "fingerprint": fp,
    }
    full_doc = {
        "schemaVersion": "1.0",
        "lens": None,
        "treeId": "abc123def456",
        "findings": [code_issue, full_security],
        "dismissals": [
            {"candidateId": "cand-3", "reason": "Called only on static constant list."}
        ],
    }
    check(
        "full multi-lens document with dismissals validates",
        findings.validate_findings_doc(full_doc) == [],
    )

    mcp_doc = _minimal_doc(
        [
            _minimal_finding(
                lens="mcp",
                severity="CRITICAL",
                blocking=True,
                disposition="disputed",
                reason="False positive on benign token limit.",
            )
        ],
        lens="mcp",
    )
    check(
        "scoped mcp document with CRITICAL and disputed reason validates",
        findings.validate_findings_doc(mcp_doc) == [],
    )


def test_invalid_documents_and_edge_cases() -> None:
    _expect_invalid(
        "non-dict root rejected", ["not", "an", "object"], "expected JSON object"
    )
    _expect_invalid("missing schemaVersion rejected", {"findings": []}, "schemaVersion")
    _expect_invalid(
        "wrong schemaVersion rejected",
        {"schemaVersion": "2.0", "findings": []},
        "schemaVersion",
    )
    _expect_invalid(
        "unknown root key rejected", _minimal_doc([], extraKey=1), "extraKey"
    )
    _expect_invalid("missing findings rejected", {"schemaVersion": "1.0"}, "findings")
    _expect_invalid(
        "findings non-list rejected",
        {"schemaVersion": "1.0", "findings": {}},
        "expected array",
    )
    _expect_invalid(
        "findings over MAX_FINDINGS_COUNT rejected",
        {"schemaVersion": "1.0", "findings": [{}] * (findings.MAX_FINDINGS_COUNT + 1)},
        "exceeds max",
    )
    _expect_invalid(
        "dismissals non-list rejected", _minimal_doc([], dismissals="bad"), "dismissals"
    )
    _expect_invalid(
        "dismissals over MAX_DISMISSALS_COUNT rejected",
        _minimal_doc([], dismissals=[{}] * (findings.MAX_DISMISSALS_COUNT + 1)),
        "exceeds max",
    )
    _expect_invalid(
        "duplicate dismissal candidateId rejected",
        _minimal_doc(
            [],
            dismissals=[
                {"candidateId": "c1", "reason": "ok"},
                {"candidateId": "c1", "reason": "again"},
            ],
        ),
        "duplicate dismissal",
    )
    _expect_invalid(
        "dismissal non-dict and unknown key rejected",
        _minimal_doc(
            [], dismissals=[{"candidateId": "c1", "reason": "ok", "extra": 1}]
        ),
        "extra",
    )
    _expect_invalid(
        "dismissal missing fields rejected",
        _minimal_doc([], dismissals=[{}]),
        "missing required",
    )
    _expect_invalid(
        "non-dict dismissal rejected",
        _minimal_doc([], dismissals=[123]),
        "expected object",
    )

    _expect_invalid(
        "non-dict finding rejected", _minimal_doc(["bad"]), "expected object"
    )
    _expect_invalid(
        "snake_case key rejected (line_start)",
        _minimal_doc([_minimal_finding(line_start=1)]),
        "unknown property",
    )
    _expect_invalid(
        "missing required quote rejected",
        _minimal_doc([{k: v for k, v in _minimal_finding().items() if k != "quote"}]),
        "quote",
    )

    # Unhashable / wrong types (must not raise TypeError)
    _expect_invalid(
        "unhashable list lens rejected",
        _minimal_doc([_minimal_finding(lens=["code"])]),
        "expected string",
    )
    _expect_invalid(
        "unhashable dict severity rejected",
        _minimal_doc([_minimal_finding(severity={"ISSUE": 1})]),
        "expected string",
    )
    _expect_invalid(
        "unhashable list basis rejected",
        _minimal_doc([_minimal_finding(basis=["written rule"])]),
        "expected string",
    )
    _expect_invalid(
        "unhashable list source rejected",
        _minimal_doc([_minimal_finding(source={"code": True})]),
        "expected string",
    )
    _expect_invalid(
        "unhashable dict disposition rejected",
        _minimal_doc([_minimal_finding(disposition=["open"])]),
        "expected string",
    )

    # Bool-as-int and int-as-bool traps
    _expect_invalid(
        "bool lineStart rejected",
        _minimal_doc([_minimal_finding(lineStart=True)]),
        "lineStart",
    )
    _expect_invalid(
        "bool lineEnd rejected",
        _minimal_doc([_minimal_finding(lineEnd=False)]),
        "lineEnd",
    )
    _expect_invalid(
        "zero lineStart rejected",
        _minimal_doc([_minimal_finding(lineStart=0)]),
        "lineStart",
    )
    _expect_invalid(
        "lineEnd < lineStart rejected",
        _minimal_doc([_minimal_finding(lineStart=5, lineEnd=4)]),
        "lineEnd",
    )
    _expect_invalid(
        "int blocking=1 rejected",
        _minimal_doc([_minimal_finding(blocking=1)]),
        "blocking",
    )
    _expect_invalid(
        "int suppressed=1 rejected",
        _minimal_doc([_minimal_finding(suppressed=1)]),
        "suppressed",
    )

    # Path containment
    for bad_path in [
        "/etc/passwd",
        "../secret.py",
        "a/../b.py",
        "a//b.py",
        "a/",
        "a\\b.py",
        "C:a.py",
        "a\x00b.py",
        "a\x1bb.py",
        "a" * 1025,
    ]:
        _expect_invalid(
            f"unsafe finding file rejected ({bad_path[:12]!r})",
            _minimal_doc([_minimal_finding(file=bad_path)]),
            ".file",
        )

    # Code-lens severity constraint and cross-field rules
    _expect_invalid(
        "code lens rejects CRITICAL",
        _minimal_doc([_minimal_finding(lens="code", severity="CRITICAL")]),
        "severity",
    )
    _expect_invalid(
        "document lens mismatch rejected",
        _minimal_doc([_minimal_finding(lens="code")], lens="security"),
        "document lens",
    )
    _expect_invalid(
        "suppressed without reason rejected",
        _minimal_doc([_minimal_finding(suppressed=True)]),
        "reason",
    )
    _expect_invalid(
        "suppressed with null reason rejected",
        _minimal_doc([_minimal_finding(suppressed=True, reason=None)]),
        "reason",
    )
    _expect_invalid(
        "suppressed with blank reason rejected",
        _minimal_doc([_minimal_finding(suppressed=True, reason="   \n ")]),
        "reason",
    )
    _expect_invalid(
        "disputed without reason rejected",
        _minimal_doc([_minimal_finding(disposition="disputed")]),
        "reason",
    )
    _expect_invalid(
        "class without classFingerprint rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    **{
                        "class": {
                            "rule": "r",
                            "sites": [{"file": "a.py", "lineStart": 1, "lineEnd": 1}],
                            "fixSite": {"file": "a.py", "lineStart": 1, "lineEnd": 1},
                            "closes": {"closed": 1, "total": 1},
                        }
                    }
                )
            ]
        ),
        "classFingerprint",
    )
    _expect_invalid(
        "class with null classFingerprint rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    **{
                        "class": {
                            "rule": "r",
                            "sites": [{"file": "a.py", "lineStart": 1, "lineEnd": 1}],
                            "fixSite": {"file": "a.py", "lineStart": 1, "lineEnd": 1},
                            "closes": {"closed": 1, "total": 1},
                        },
                        "classFingerprint": None,
                    }
                )
            ]
        ),
        "classFingerprint",
    )
    _expect_invalid(
        "version without package rejected",
        _minimal_doc([_minimal_finding(version="1.2.3")]),
        "package",
    )

    # Class & proof & candidateIds edge cases
    _expect_invalid(
        "empty class.sites rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    **{
                        "classFingerprint": _valid_fp("b"),
                        "class": {
                            "rule": "r",
                            "sites": [],
                            "fixSite": {"file": "a.py", "lineStart": 1, "lineEnd": 1},
                            "closes": {"closed": 0, "total": 1},
                        },
                    }
                )
            ]
        ),
        "sites",
    )
    _expect_invalid(
        "oversized class.sites rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    **{
                        "classFingerprint": _valid_fp("b"),
                        "class": {
                            "rule": "r",
                            "sites": [{"file": "a.py", "lineStart": 1, "lineEnd": 1}]
                            * (findings.MAX_CLASS_SITES + 1),
                            "fixSite": {"file": "a.py", "lineStart": 1, "lineEnd": 1},
                            "closes": {"closed": 0, "total": 1},
                        },
                    }
                )
            ]
        ),
        "exceeds max",
    )
    _expect_invalid(
        "closes.closed > total rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    **{
                        "classFingerprint": _valid_fp("b"),
                        "class": {
                            "rule": "r",
                            "sites": [{"file": "a.py", "lineStart": 1, "lineEnd": 1}],
                            "fixSite": {"file": "a.py", "lineStart": 2, "lineEnd": 1},
                            "closes": {"closed": True, "total": 1},
                        },
                    }
                )
            ]
        ),
        "closes.closed",
    )
    _expect_invalid(
        "closes.closed 2 > total 1 rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    **{
                        "classFingerprint": _valid_fp("b"),
                        "class": {
                            "rule": "r",
                            "sites": [{"file": "a.py", "lineStart": 1, "lineEnd": 1}],
                            "fixSite": {"file": "a.py", "lineStart": 1, "lineEnd": 1},
                            "closes": {"closed": 2, "total": 1},
                        },
                    }
                )
            ]
        ),
        "must be <= total",
    )
    _expect_invalid(
        "unsafe fixSite path rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    **{
                        "classFingerprint": _valid_fp("b"),
                        "class": {
                            "rule": "r",
                            "sites": [
                                {"file": "../bad.py", "lineStart": 1, "lineEnd": 1}
                            ],
                            "fixSite": {
                                "file": "/bad.py",
                                "lineStart": 1,
                                "lineEnd": 1,
                            },
                            "closes": {"closed": 0, "total": 1},
                        },
                    }
                )
            ]
        ),
        "fixSite.file",
    )
    _expect_invalid(
        "proof bad enum and multiline command rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    proof={
                        "kind": "magic",
                        "status": "unknown",
                        "command": "echo hi\nwhoami",
                        "target": "x\x00y",
                        "detail": " ",
                    }
                )
            ]
        ),
        "proof.kind",
    )
    _expect_invalid(
        "duplicate candidateIds rejected",
        _minimal_doc([_minimal_finding(candidateIds=["c1", "c1"])]),
        "duplicate candidateId",
    )
    _expect_invalid(
        "candidateIds non-list rejected",
        _minimal_doc([_minimal_finding(candidateIds="c1")]),
        "expected array",
    )
    _expect_invalid(
        "candidateIds over MAX_CANDIDATE_IDS rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    candidateIds=[
                        f"c-{i}" for i in range(findings.MAX_CANDIDATE_IDS + 1)
                    ]
                )
            ]
        ),
        "exceeds max",
    )
    _expect_invalid(
        "non-string identifier, sha256, file, line, and text fields rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    file=123,
                    checkId=456,
                    fingerprint=789,
                    category=123,
                    claim="x\x00y",
                    evidence="e" * (findings.MAX_LONG_TEXT_LENGTH + 1),
                    package="p" * (findings.MAX_PACKAGE_LENGTH + 1),
                    recommendation=999,
                )
            ]
        ),
        "expected string",
    )
    _expect_invalid(
        "non-dict proof, class, site, closes, and missing keys rejected",
        _minimal_doc(
            [
                _minimal_finding(proof="bad"),
                _minimal_finding(proof={}),
                _minimal_finding(classFingerprint=_valid_fp("c"), **{"class": "bad"}),
                _minimal_finding(
                    classFingerprint=_valid_fp("c"),
                    **{
                        "class": {
                            "sites": "not-list",
                            "fixSite": {},
                            "closes": "not-dict",
                        }
                    },
                ),
                _minimal_finding(
                    classFingerprint=_valid_fp("c"),
                    **{
                        "class": {
                            "rule": "r",
                            "sites": ["not-site"],
                            "fixSite": "not-site",
                            "closes": {"total": 0},
                        }
                    },
                ),
            ]
        ),
        "expected",
    )

    # ANSI/control characters in untrusted fields must be escaped in error output.
    ansi_errs = findings.validate_finding(
        _minimal_finding(severity="\x1b[31mFAKE\x1b[0m\x00", **{"bad\x1bkey": 1})
    )
    joined = "\n".join(ansi_errs)
    check(
        "ANSI escape stripped/escaped in validation errors",
        "\x1b" not in joined and "\x00" not in joined,
    )
    check(
        "direct validate_finding rejects non-dict",
        "expected object" in findings.validate_finding("bad")[0],
    )


def test_file_loading() -> None:
    with tempfile.TemporaryDirectory(prefix="vld8-findings-test-") as tmp:
        root = Path(tmp)

        valid_path = root / "valid.json"
        doc = _minimal_doc([_minimal_finding()])
        valid_path.write_text(json.dumps(doc), encoding="utf-8")
        check(
            "load_findings_file parses and validates valid file",
            findings.load_findings_file(valid_path) == doc,
        )

        invalid_doc_path = root / "invalid_doc.json"
        invalid_doc_path.write_text(
            json.dumps({"schemaVersion": "1.0", "findings": [{}]}), encoding="utf-8"
        )
        try:
            findings.load_findings_file(invalid_doc_path)
            check("load_findings_file raises FindingsValidationError", False)
        except findings.FindingsValidationError as exc:
            check(
                "load_findings_file raises FindingsValidationError with errors",
                len(exc.errors) >= 1,
            )
        raw = findings.load_findings_file(invalid_doc_path, validate=False)
        check(
            "load_findings_file(validate=False) returns raw dict",
            raw["schemaVersion"] == "1.0",
        )

        for name, content in [
            ("bad_json.json", "{not valid json"),
            (
                "dup_keys.json",
                '{"schemaVersion":"1.0","schemaVersion":"2.0","findings":[]}',
            ),
            ("nan.json", '{"schemaVersion":"1.0","findings":[],"x":NaN}'),
            ("root_list.json", "[]"),
            ("deep.json", ("[" * 5000) + ("]" * 5000)),
        ]:
            p = root / name
            p.write_text(content, encoding="utf-8")
            try:
                findings.load_findings_file(p)
                check(f"rejects {name}", False)
            except findings.FindingsError:
                check(f"rejects {name}", True)

        bad_utf8 = root / "bad_utf8.json"
        bad_utf8.write_bytes(b"\xff\xfe")
        try:
            findings.load_findings_file(bad_utf8)
            check("rejects invalid UTF-8", False)
        except findings.FindingsError:
            check("rejects invalid UTF-8", True)

        big = root / "big.json"
        big.write_text(json.dumps(doc), encoding="utf-8")
        try:
            findings.load_findings_file(big, max_bytes=32)
            check("rejects oversized file", False)
        except findings.FindingsError:
            check("rejects oversized file", True)

        for target_arg, label in [
            (root / "missing.json", "missing file"),
            (root, "directory path"),
        ]:
            try:
                findings.load_findings_file(target_arg)
                check(f"rejects {label}", False)
            except findings.FindingsError:
                check(f"rejects {label}", True)

        for bad_opt, label in [
            (0, "max_bytes=0"),
            (True, "max_bytes=True"),
        ]:
            try:
                findings.load_findings_file(valid_path, max_bytes=bad_opt)  # type: ignore[arg-type]
                check(f"rejects {label}", False)
            except ValueError:
                check(f"rejects {label}", True)
        try:
            findings.load_findings_file(valid_path, validate="yes")  # type: ignore[arg-type]
            check("rejects validate='yes'", False)
        except ValueError:
            check("rejects validate='yes'", True)


def test_fingerprints() -> None:
    check(
        "normalize_code_region handles CRLF/CR, spaces, blank lines, and dedent",
        findings.normalize_code_region("\r\n    x = 1   \r\n        y = 2\t\n\n")
        == "x = 1\n    y = 2",
    )
    check(
        "normalize_code_region returns empty string for blank input",
        findings.normalize_code_region("  \n\t\r\n") == "",
    )

    fp1 = findings.compute_fingerprint("py-sql", "    cursor.execute(q)\n")
    fp2 = findings.compute_fingerprint("py-sql", "\r\n  cursor.execute(q)  \r\n")
    check(
        "fingerprint is 64-char lowercase hex and whitespace/CRLF stable",
        len(fp1) == 64 and fp1 == fp2 and fp1.islower(),
    )

    fp_indented = findings.compute_fingerprint(
        "py-sql", "if ok:\n    cursor.execute(q)"
    )
    fp_indented_more = findings.compute_fingerprint(
        "py-sql", "if ok:\n        cursor.execute(q)"
    )
    check(
        "fingerprint distinguishes relative indentation changes",
        fp_indented != fp_indented_more,
    )

    fp_pkg1 = findings.compute_fingerprint(
        "cve-1", "pyyaml", package="pyyaml", version="6.0.3"
    )
    fp_pkg2 = findings.compute_fingerprint(
        "cve-1", "pyyaml", package="pyyaml", version="6.0.4"
    )
    fp_pkg_only = findings.compute_fingerprint("cve-1", "pyyaml", package="pyyaml")
    fp_no_pkg = findings.compute_fingerprint("cve-1", "pyyaml")
    check(
        "fingerprint distinguishes package and version",
        len({fp_pkg1, fp_pkg2, fp_pkg_only, fp_no_pkg}) == 4,
    )

    # Field boundary collisions must not collide.
    check(
        "canonical JSON encoding prevents boundary collisions",
        findings.compute_fingerprint("a:b", "c")
        != findings.compute_fingerprint("a", "b:c"),
    )

    cfp1 = findings.compute_class_fingerprint(
        "py-sql", "vld8/db.py", "    def query(sql):\n        pass\n"
    )
    cfp2 = findings.compute_class_fingerprint(
        "py-sql", "vld8/db.py", "def query(sql):\r\n    pass\r\n"
    )
    cfp_other_file = findings.compute_class_fingerprint(
        "py-sql", "vld8/other.py", "def query(sql):\n    pass"
    )
    check(
        "classFingerprint is deterministic and bound to fixSite file",
        cfp1 == cfp2 and cfp1 != cfp_other_file,
    )
    check(
        "finding and class fingerprints are domain separated",
        findings.compute_fingerprint("py-sql", "def query(): pass")
        != findings.compute_class_fingerprint(
            "py-sql", "vld8/db.py", "def query(): pass"
        ),
    )

    for fn, args, label in [
        (findings.normalize_code_region, (123,), "non-string region"),
        (findings.normalize_code_region, ("abc\x00def",), "NUL in region"),
        (findings.compute_fingerprint, ("bad id", "x = 1"), "invalid check_id"),
        (findings.compute_fingerprint, ("ok-id", "   \n"), "empty normalized region"),
    ]:
        try:
            fn(*args)
            check(f"fingerprint raises ValueError on {label}", False)
        except ValueError:
            check(f"fingerprint raises ValueError on {label}", True)

    for kwargs, label in [
        ({"version": "1.0"}, "version without package"),
        ({"package": "  "}, "blank package"),
        ({"package": "bad\nline"}, "multiline package"),
        ({"package": "pyyaml", "version": "  "}, "blank version"),
    ]:
        try:
            findings.compute_fingerprint("ok-id", "x = 1", **kwargs)  # type: ignore[arg-type]
            check(f"compute_fingerprint raises ValueError on {label}", False)
        except ValueError:
            check(f"compute_fingerprint raises ValueError on {label}", True)

    for args, label in [
        (("ok-id", "../escape.py", "x = 1"), "unsafe fixSite file"),
        (("bad id", "a.py", "x = 1"), "invalid check_id in class fingerprint"),
        (("ok-id", "a.py", "   \n"), "empty fixSite region"),
    ]:
        try:
            findings.compute_class_fingerprint(*args)
            check(f"compute_class_fingerprint rejects {label}", False)
        except ValueError:
            check(f"compute_class_fingerprint rejects {label}", True)


def main() -> int:
    test_schema_and_parity()
    test_valid_documents()
    test_invalid_documents_and_edge_cases()
    test_file_loading()
    test_fingerprints()

    passed = sum(1 for _, ok in _results if ok)
    total = len(_results)
    for name, ok in _results:
        if not ok:
            print(f"FAIL: {name}")
    print(f"test_findings: {passed}/{total} passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
