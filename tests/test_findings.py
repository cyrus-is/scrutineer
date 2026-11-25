#!/usr/bin/env python3
"""Tests for Findings Contract v1 schema, validator, and fingerprints.

Dependency-free (no pytest): run from the repo root with

    python tests/test_findings.py
"""

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
        "SECURITY_SEVERITIES and CODE_SEVERITIES partition VALID_SEVERITIES",
        findings.CODE_SEVERITIES.isdisjoint(findings.SECURITY_SEVERITIES)
        and (findings.CODE_SEVERITIES | findings.SECURITY_SEVERITIES)
        == findings.VALID_SEVERITIES,
    )
    check(
        "CODE_CATEGORIES contains the 8 code-lens evaluation categories",
        len(findings.CODE_CATEGORIES) == 8
        and {"production-reliability", "correctness", "security-invariant"}
        & findings.CODE_CATEGORIES
        == {"production-reliability", "correctness"},
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
    check(
        "schema text maxLength parity matches constants",
        defs["nonBlankText"]["maxLength"] == findings.MAX_SHORT_TEXT_LENGTH
        and defs["nonBlankLongText"]["maxLength"] == findings.MAX_LONG_TEXT_LENGTH
        and defs["nonBlankLine"]["maxLength"] == findings.MAX_LINE_LENGTH
        and defs["repoRelativePath"]["maxLength"] == findings.MAX_PATH_LENGTH
        and defs["identifier"]["maxLength"] == findings.MAX_IDENTIFIER_LENGTH
        and defs["treeId"]["maxLength"] == findings.MAX_IDENTIFIER_LENGTH
        and defs["finding"]["properties"]["quote"]["$ref"] == "#/$defs/nonBlankLongText"
        and defs["finding"]["properties"]["evidence"]["$ref"]
        == "#/$defs/nonBlankLongText"
        and defs["siteRef"]["properties"]["quote"]["anyOf"][1]["$ref"]
        == "#/$defs/nonBlankLongText",
    )

    # Regex parity between schema patterns and Python validator without re.ASCII
    # (matching jsonschema's default Python `re` compilation).
    path_re = re.compile(defs["repoRelativePath"]["pattern"])
    id_re = re.compile(defs["identifier"]["pattern"])
    tree_re = re.compile(defs["treeId"]["pattern"])
    sha_re = re.compile(defs["sha256Hex"]["pattern"])
    line_re = re.compile(defs["nonBlankLine"]["pattern"])
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
        ("a.py\n", False),
        ("a\x1bb.py", False),
        ("a\x9bb.py", False),
        ("a\u2028b.py", False),
    ]:
        errs: list[str] = []
        py_ok = findings._validate_repo_relative_path(sample, "p", errs)
        re_ok = path_re.match(sample) is not None
        check(f"path parity ({sample!r})", py_ok == expected and re_ok == expected)

    for sample, expected in [
        ("py-sec-01", True),
        ("CWE-78:cmd_exec/v1.0", True),
        ("", False),
        ("-leading-dash", False),
        ("has space", False),
        ("²superscript", False),
        ("id\nline2", False),
        ("py-sec-01\n", False),
    ]:
        errs = []
        py_ok = findings._validate_identifier(sample, "id", errs)
        re_ok = id_re.match(sample) is not None
        check(
            f"identifier parity ({sample!r})", py_ok == expected and re_ok == expected
        )

    for sample, expected in [
        ("abc123def456", True),
        ("tree_2026.11-v1", True),
        ("", False),
        ("a/b", False),
        ("a/../../outside", False),
        ("a..b", False),
        ("..", False),
        (".dot", False),
        ("-dash", False),
        ("tree:1", False),
        ("abc123\n", False),
        ("²abc", False),
    ]:
        errs = []
        py_ok = findings._validate_tree_id(sample, "treeId", errs)
        re_ok = tree_re.match(sample) is not None
        check(f"treeId parity ({sample!r})", py_ok == expected and re_ok == expected)

    for sample, expected in [
        (_valid_fp("0"), True),
        (_valid_fp("f"), True),
        (_valid_fp("A"), False),
        ("a" * 63, False),
        ("a" * 65, False),
        ("²" * 64, False),
        ("a" * 63 + "g", False),
        ("a" * 64 + "\n", False),
    ]:
        errs = []
        py_ok = findings._validate_sha256(sample, "fp", errs)
        re_ok = sha_re.match(sample) is not None
        check(
            f"sha256 parity ({sample[:8]!r} len={len(sample)})",
            py_ok == expected and re_ok == expected,
        )

    for sample, expected in [
        ("correctness", True),
        ("  pyyaml  ", True),
        ("", False),
        ("   \t ", False),
        ("cat\n", False),
        ("cat\nnext", False),
        ("cat\x00x", False),
        ("cat\x1bx", False),
        ("cat\x85x", False),
        ("cat\x9bx", False),
        ("cat\u2028x", False),
        ("cat\u2029x", False),
    ]:
        errs = []
        py_ok = findings._validate_non_blank_line(sample, "line", errs)
        re_ok = line_re.match(sample) is not None
        check(
            f"nonBlankLine parity ({sample!r})", py_ok == expected and re_ok == expected
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
    long_doc = _minimal_doc(
        [
            _minimal_finding(
                quote="q" * 5000,
                evidence="e" * 5000,
                **{
                    "classFingerprint": _valid_fp("d"),
                    "class": {
                        "rule": "Long quote must fit 16384 budget.",
                        "sites": [
                            {
                                "file": "vld8/cli.py",
                                "lineStart": 1,
                                "lineEnd": 1,
                                "quote": "s" * 5000,
                            }
                        ],
                        "fixSite": {
                            "file": "vld8/cli.py",
                            "lineStart": 1,
                            "lineEnd": 1,
                        },
                        "closes": {"closed": 0, "total": 1},
                    },
                },
            )
        ]
    )
    check(
        "5,000-char quote and evidence within 16,384 limit validate",
        findings.validate_findings_doc(long_doc) == [],
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

    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        Draft202012Validator = None  # optional dev-only cross-check

    if Draft202012Validator is not None:
        Draft202012Validator.check_schema(findings.load_schema())
        validator = Draft202012Validator(findings.load_schema())
        for sample_doc, label in [
            (empty_doc, "empty_doc"),
            (long_doc, "long_doc"),
            (full_doc, "full_doc"),
            (mcp_doc, "mcp_doc"),
        ]:
            check(
                f"jsonschema accepts {label}",
                list(validator.iter_errors(sample_doc)) == [],
            )
        trailing_nl = _minimal_doc([_minimal_finding(file="a.py\n")])
        check(
            "jsonschema rejects trailing newline in path",
            bool(list(validator.iter_errors(trailing_nl))),
        )
        lens_mismatch = _minimal_doc([_minimal_finding(lens="code")], lens="security")
        check(
            "jsonschema enforces root.lens match via allOf",
            bool(list(validator.iter_errors(lens_mismatch))),
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
        "fixSite lineEnd < lineStart rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    **{
                        "classFingerprint": _valid_fp("b"),
                        "class": {
                            "rule": "r",
                            "sites": [{"file": "a.py", "lineStart": 1, "lineEnd": 1}],
                            "fixSite": {"file": "a.py", "lineStart": 2, "lineEnd": 1},
                            "closes": {"closed": 0, "total": 1},
                        },
                    }
                )
            ]
        ),
        "class.fixSite.lineEnd: 1 must be >= lineStart (2)",
    )
    _expect_invalid(
        "closes.closed bool rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    **{
                        "classFingerprint": _valid_fp("b"),
                        "class": {
                            "rule": "r",
                            "sites": [{"file": "a.py", "lineStart": 1, "lineEnd": 1}],
                            "fixSite": {"file": "a.py", "lineStart": 1, "lineEnd": 1},
                            "closes": {"closed": True, "total": 1},
                        },
                    }
                )
            ]
        ),
        "closes.closed: expected integer >= 0",
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
                                {"file": "src/a.py", "lineStart": 1, "lineEnd": 1}
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
        "unsafe class site path rejected",
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
                                "file": "src/fix.py",
                                "lineStart": 1,
                                "lineEnd": 1,
                            },
                            "closes": {"closed": 0, "total": 1},
                        },
                    }
                )
            ]
        ),
        "class.sites[0].file",
    )
    for bad_proof, needle, label in [
        ({"kind": "magic", "status": "verified"}, "proof.kind", "bad proof.kind"),
        ({"kind": "test", "status": "unknown"}, "proof.status", "bad proof.status"),
        (
            {"kind": "test", "status": "verified", "command": "echo hi\nwhoami"},
            "proof.command",
            "multiline proof.command",
        ),
        (
            {"kind": "test", "status": "verified", "target": "x\x00y"},
            "proof.target",
            "NUL proof.target",
        ),
        (
            {"kind": "test", "status": "verified", "detail": " "},
            "proof.detail",
            "blank proof.detail",
        ),
    ]:
        _expect_invalid(
            f"proof rejects {label}",
            _minimal_doc([_minimal_finding(proof=bad_proof)]),
            needle,
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
    for overrides, needle, label in [
        ({"file": 123}, "findings[0].file: expected string", "non-string file"),
        (
            {"checkId": 456},
            "findings[0].checkId: expected string",
            "non-string checkId",
        ),
        (
            {"fingerprint": 789},
            "findings[0].fingerprint: expected string",
            "non-string fingerprint",
        ),
        (
            {"category": 123},
            "findings[0].category: expected string",
            "non-string category",
        ),
        (
            {"recommendation": 999},
            "findings[0].recommendation: expected string",
            "non-string recommendation",
        ),
        ({"claim": "x\x00y"}, "findings[0].claim: NUL byte", "NUL in claim"),
        (
            {"evidence": "e" * (findings.MAX_LONG_TEXT_LENGTH + 1)},
            "findings[0].evidence: length",
            "oversized evidence",
        ),
        (
            {"package": "p" * (findings.MAX_PACKAGE_LENGTH + 1)},
            "findings[0].package: length",
            "oversized package",
        ),
        (
            {"file": "a\ud800b.py"},
            "findings[0].file: unpaired UTF-16 surrogates",
            "surrogate in file",
        ),
        (
            {"category": "cat\ud800"},
            "findings[0].category: unpaired UTF-16 surrogates",
            "surrogate in category",
        ),
        (
            {"quote": "q\ud800"},
            "findings[0].quote: unpaired UTF-16 surrogates",
            "surrogate in quote",
        ),
        (
            {"category": "cat\x9b"},
            "findings[0].category: control characters",
            "C1 control in category",
        ),
        (
            {"file": "a\u2028b.py"},
            "findings[0].file: control characters",
            "U+2028 in file",
        ),
    ]:
        _expect_invalid(
            f"finding rejects {label}",
            _minimal_doc([_minimal_finding(**overrides)]),
            needle,
        )
    _expect_invalid(
        "siteRef missing required file rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    classFingerprint=_valid_fp("c"),
                    **{
                        "class": {
                            "rule": "r",
                            "sites": [{"lineStart": 1, "lineEnd": 1}],
                            "fixSite": {"file": "a.py", "lineStart": 1, "lineEnd": 1},
                            "closes": {"closed": 0, "total": 1},
                        }
                    },
                )
            ]
        ),
        "class.sites[0].file: missing required property",
    )
    _expect_invalid(
        "class missing required rule rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    classFingerprint=_valid_fp("c"),
                    **{
                        "class": {
                            "sites": [{"file": "a.py", "lineStart": 1, "lineEnd": 1}],
                            "fixSite": {"file": "a.py", "lineStart": 1, "lineEnd": 1},
                            "closes": {"closed": 0, "total": 1},
                        }
                    },
                )
            ]
        ),
        "class.rule: missing required property",
    )
    _expect_invalid(
        "closes missing required closed rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    classFingerprint=_valid_fp("c"),
                    **{
                        "class": {
                            "rule": "r",
                            "sites": [{"file": "a.py", "lineStart": 1, "lineEnd": 1}],
                            "fixSite": {"file": "a.py", "lineStart": 1, "lineEnd": 1},
                            "closes": {"total": 1},
                        }
                    },
                )
            ]
        ),
        "class.closes.closed: missing required property",
    )
    _expect_invalid(
        "non-dict proof rejected",
        _minimal_doc([_minimal_finding(proof="bad")]),
        "proof: expected object",
    )
    _expect_invalid(
        "empty proof missing kind and status rejected",
        _minimal_doc([_minimal_finding(proof={})]),
        "proof.kind: missing required property",
    )
    _expect_invalid(
        "non-dict class rejected",
        _minimal_doc(
            [_minimal_finding(classFingerprint=_valid_fp("c"), **{"class": "bad"})]
        ),
        "class: expected object",
    )
    _expect_invalid(
        "non-list class.sites rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    classFingerprint=_valid_fp("c"),
                    **{
                        "class": {
                            "rule": "r",
                            "sites": "not-list",
                            "fixSite": {"file": "a.py", "lineStart": 1, "lineEnd": 1},
                            "closes": {"closed": 0, "total": 1},
                        }
                    },
                )
            ]
        ),
        "class.sites: expected array",
    )
    _expect_invalid(
        "non-dict class.closes rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    classFingerprint=_valid_fp("c"),
                    **{
                        "class": {
                            "rule": "r",
                            "sites": [{"file": "a.py", "lineStart": 1, "lineEnd": 1}],
                            "fixSite": {"file": "a.py", "lineStart": 1, "lineEnd": 1},
                            "closes": "not-dict",
                        }
                    },
                )
            ]
        ),
        "class.closes: expected object",
    )
    _expect_invalid(
        "non-dict siteRef in class.sites rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    classFingerprint=_valid_fp("c"),
                    **{
                        "class": {
                            "rule": "r",
                            "sites": ["not-site"],
                            "fixSite": {"file": "a.py", "lineStart": 1, "lineEnd": 1},
                            "closes": {"closed": 0, "total": 1},
                        }
                    },
                )
            ]
        ),
        "class.sites[0]: expected object",
    )
    _expect_invalid(
        "non-dict class.fixSite rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    classFingerprint=_valid_fp("c"),
                    **{
                        "class": {
                            "rule": "r",
                            "sites": [{"file": "a.py", "lineStart": 1, "lineEnd": 1}],
                            "fixSite": "not-site",
                            "closes": {"closed": 0, "total": 1},
                        }
                    },
                )
            ]
        ),
        "class.fixSite: expected object",
    )
    _expect_invalid(
        "invalid closes.total=0 rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    classFingerprint=_valid_fp("c"),
                    **{
                        "class": {
                            "rule": "r",
                            "sites": [{"file": "a.py", "lineStart": 1, "lineEnd": 1}],
                            "fixSite": {"file": "a.py", "lineStart": 1, "lineEnd": 1},
                            "closes": {"closed": 0, "total": 0},
                        }
                    },
                )
            ]
        ),
        "class.closes.total: expected integer >= 1",
    )
    _expect_invalid(
        "closes.total smaller than len(sites) rejected",
        _minimal_doc(
            [
                _minimal_finding(
                    classFingerprint=_valid_fp("c"),
                    **{
                        "class": {
                            "rule": "r",
                            "sites": [
                                {"file": "a.py", "lineStart": 1, "lineEnd": 1},
                                {"file": "b.py", "lineStart": 2, "lineEnd": 2},
                            ],
                            "fixSite": {"file": "a.py", "lineStart": 1, "lineEnd": 1},
                            "closes": {"closed": 0, "total": 1},
                        }
                    },
                )
            ]
        ),
        "must be >= len(sites)",
    )
    _expect_invalid(
        "non-string treeId rejected",
        _minimal_doc([], treeId=123),
        "treeId: expected string",
    )
    stripped_label = findings._safe_label("\x1b[31m\x1b[0m" * 60 + "z" * 20)
    check(
        "safe_label bounds length after ANSI stripping",
        len(stripped_label) <= 64
        and stripped_label.endswith("...")
        and "\x1b" not in stripped_label,
    )
    try:
        findings.load_findings_file("bad\x00.json")
        check("load_findings_file rejects embedded NUL path as FindingsError", False)
    except findings.FindingsError as exc:
        check(
            "load_findings_file rejects embedded NUL path as FindingsError",
            "\x00" not in str(exc),
        )
    try:
        findings.load_findings_file("x" * 500)
        check("load_findings_file bounds long path in FindingsError", False)
    except findings.FindingsError as exc:
        check(
            "load_findings_file bounds long path in FindingsError",
            len(str(exc)) < 200,
        )

    # ANSI/control characters in untrusted fields must be escaped in error output.
    ansi_errs = findings.validate_finding(
        _minimal_finding(
            severity="\x1b[31mFAKE\x1b[0m\x00" + ("x" * 300),
            **{"bad\x1bkey": 1},
        )
    )
    joined = "\n".join(ansi_errs)
    check(
        "ANSI escape stripped/escaped in validation errors",
        "\x1b" not in joined and "\x00" not in joined,
    )
    check(
        "safe_label truncates long strings cleanly and bounds container repr",
        findings._safe_label("y" * 2000).endswith("...")
        and len(findings._safe_label(list(range(500)))) <= 64,
    )
    _expect_invalid(
        "treeId path traversal rejected",
        _minimal_doc([], treeId="a/../../outside"),
        "treeId",
    )
    try:
        findings.load_findings_file("missing-\x1b[31mfile.json")
        check("load_findings_file escapes control chars in filename errors", False)
    except findings.FindingsError as exc:
        check(
            "load_findings_file escapes control chars in filename errors",
            "\x1b" not in str(exc),
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

        safe_out = findings._safe_label("a\ud800b\udfffc\u2028d\u2029e")
        safe_out.encode("utf-8")
        check(
            "_safe_label escapes surrogates and Unicode line/paragraph separators",
            all(tag in safe_out for tag in ("\\ud800", "\\udfff", "\\u2028", "\\u2029"))
            and "\ud800" not in safe_out
            and "\udfff" not in safe_out
            and "\u2028" not in safe_out
            and "\u2029" not in safe_out,
        )

        surrogate_key_file = root / "surrogate_key.json"
        surrogate_key_file.write_text(
            '{"schemaVersion":"1.0","findings":[],"bad\\ud800":1}',
            encoding="utf-8",
        )
        try:
            findings.load_findings_file(surrogate_key_file)
            check("rejects surrogate unknown key cleanly", False)
        except findings.FindingsValidationError as exc:
            msg = str(exc)
            msg.encode("utf-8")
            check(
                "surrogate unknown key error is UTF-8 safe and escaped",
                "\\ud800" in msg and "\ud800" not in msg,
            )

        dup_surrogate_file = root / "dup_surrogate.json"
        dup_surrogate_file.write_text(
            '{"schemaVersion":"1.0","findings":[],"k\\ud800":1,"k\\ud800":2}',
            encoding="utf-8",
        )
        try:
            findings.load_findings_file(dup_surrogate_file)
            check("rejects duplicate surrogate key cleanly", False)
        except findings.FindingsError as exc:
            msg = str(exc)
            msg.encode("utf-8")
            check(
                "duplicate surrogate key error is UTF-8 safe and escaped",
                "\\ud800" in msg and "\ud800" not in msg,
            )

        for sep, tag, label in [
            ("\u2028", "\\u2028", "U+2028"),
            ("\u2029", "\\u2029", "U+2029"),
        ]:
            errs = findings.validate_findings_doc(
                {"schemaVersion": "1.0", "findings": [], f"bad{sep}key": 1}
            )
            check(
                f"unknown key error escapes {label}",
                len(errs) == 1 and tag in errs[0] and sep not in errs[0],
            )


def test_fingerprints() -> None:
    check(
        "normalize_code_region handles CRLF/CR, spaces, blank lines, and dedent",
        findings.normalize_code_region("\r\n    x = 1   \r\n        y = 2\t\n\n")
        == "x = 1\n    y = 2",
    )
    check(
        "normalize_code_region trims many leading blank lines in linear time",
        findings.normalize_code_region(("\n" * 50_000) + "  x = 1\n" + ("\n" * 50_000))
        == "x = 1",
    )
    check(
        "compute_fingerprint handles non-ASCII UTF-8 code regions",
        len(findings.compute_fingerprint("py-i18n", 'msg = "héllo — 世界"')) == 64,
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
        (findings.normalize_code_region, ("abc\ud800def",), "surrogate in region"),
        (
            findings.compute_fingerprint,
            ("ok-id", "x\ud800"),
            "surrogate in compute_fingerprint",
        ),
        (
            findings.compute_class_fingerprint,
            ("ok-id", "a.py", "x\ud800"),
            "surrogate in compute_class_fingerprint",
        ),
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
