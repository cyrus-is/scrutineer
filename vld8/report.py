"""Review report builder, verifier, merger, and renderer (vld8 review report).

Implements Findings Contract v1 verification, candidate accounting, citation
verification against a local repository checkout, rubric enforcement, deterministic
code/model merging, prior disposition tracking, verdict/lens assessment, and
Markdown / JSON / SARIF 2.1.0 rendering using only the Python standard library.
"""

from __future__ import annotations

import copy
import json
import math
import os
import re
import stat
import tempfile
from collections import OrderedDict
from pathlib import Path
from typing import Any

from . import __version__, findings

SCHEMA_VERSION = findings.SCHEMA_VERSION
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
VALID_FORMATS = frozenset({"md", "json", "sarif"})

MAX_CANDIDATES_COUNT = 10_000
MAX_UNRULED_COUNT = 10_000
MAX_COVERAGE_NODES = 10_000
MAX_COVERAGE_DEPTH = 6
MAX_CITED_FILE_BYTES = 5 * 1024 * 1024
MAX_CITED_FILE_LINES = 200_000
MAX_CACHE_BYTES = 64 * 1024 * 1024

LENS_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("production-reliability", "Production Reliability"),
    ("correctness", "Correctness"),
    ("data-integrity", "Data Integrity"),
    ("error-handling", "Error Handling"),
    ("architecture", "Architecture"),
    ("operability", "Operability"),
    ("performance", "Performance"),
    ("maintainability", "Maintainability"),
)

SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "ISSUE": 2,
    "MEDIUM": 3,
    "CONCERN": 4,
    "LOW": 5,
    "INFO": 6,
}

_PREPARE_DOC_KEYS = frozenset(
    {
        "schemaVersion",
        "lens",
        "treeId",
        "partial",
        "candidates",
        "codeFindings",
        "unruled",
        "coverage",
    }
)
_CANDIDATE_KEYS = frozenset(
    {
        "candidateId",
        "file",
        "lineStart",
        "lineEnd",
        "checkId",
        "rule",
        "reason",
        "quote",
        "classProposal",
    }
)
_CLASS_PROPOSAL_EXTRA_KEYS = frozenset({"classFingerprint"})

_ANSI_FULL_RE = re.compile(
    r"\x1b(?:"
    r"\[[0-?]*[ -/]*[@-~]"
    r"|\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|[PX^_][^\x1b]*\x1b\\"
    r"|[@-Z\\-_]"
    r")"
)


def _sanitize_text(value: Any, *, allow_newlines: bool = False) -> str:
    """Strip ANSI escapes and escape control/surrogate chars safely."""
    text = value if isinstance(value, str) else str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _ANSI_FULL_RE.sub(" ", text)
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if allow_newlines and ch in ("\n", "\t"):
            out.append(ch)
        elif ch in ("\n", "\t"):
            out.append(" ")
        elif code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            out.append(f"\\x{code:02x}")
        elif 0xD800 <= code <= 0xDFFF or code in (0x2028, 0x2029):
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    return "".join(out)


def _md_escape_inline(value: Any) -> str:
    """Sanitize untrusted text for single-line Markdown prose."""
    cleaned = _sanitize_text(value, allow_newlines=False)
    return cleaned.replace("<", "&lt;").replace(">", "&gt;")


def _md_escape_cell(value: Any) -> str:
    """Sanitize untrusted text for a Markdown table cell."""
    return _md_escape_inline(value).replace("|", "\\|")


def _md_code_span(value: Any, *, in_table: bool = False) -> str:
    """Wrap text in a backtick inline span safe against inner backticks."""
    cleaned = _sanitize_text(value, allow_newlines=False)
    if in_table:
        cleaned = cleaned.replace("|", "\\|")
    max_ticks = max((len(m.group(0)) for m in re.finditer(r"`+", cleaned)), default=0)
    fence = "`" * (max_ticks + 1)
    if cleaned.startswith("`") or cleaned.endswith("`"):
        return f"{fence} {cleaned} {fence}"
    return f"{fence}{cleaned}{fence}"


def _md_fence(value: Any, lang: str = "") -> str:
    """Wrap code in a fenced block with more backticks than any inner run."""
    cleaned = _sanitize_text(value, allow_newlines=True).rstrip("\n")
    max_ticks = max((len(m.group(0)) for m in re.finditer(r"`+", cleaned)), default=0)
    fence = "`" * max(3, max_ticks + 1)
    safe_lang = re.sub(r"[^A-Za-z0-9_+-]", "", lang)
    return f"{fence}{safe_lang}\n{cleaned}\n{fence}"


def _read_bounded_json_dict(
    path: str | Path,
    *,
    label: str,
    max_bytes: int = findings.MAX_FINDINGS_BYTES,
) -> dict[str, Any]:
    """Safely open, size-check, UTF-8 decode, and parse a JSON object file."""
    target = Path(path)
    safe_name = findings._safe_label(target.name or str(target))
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(target), flags)
    except (OSError, ValueError) as exc:
        detail = findings._safe_label(getattr(exc, "strerror", None) or str(exc))
        raise findings.FindingsError(
            f"cannot open {label} file {safe_name}: {detail}"
        ) from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise findings.FindingsError(
                f"{label} path is not a regular file: {safe_name}"
            )
        if st.st_size > max_bytes:
            raise findings.FindingsError(
                f"{label} file {safe_name} ({st.st_size} bytes) "
                f"exceeds max {max_bytes} bytes"
            )
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw = handle.read(max_bytes + 1)
    except OSError as exc:
        detail = findings._safe_label(exc.strerror or str(exc))
        raise findings.FindingsError(
            f"cannot read {label} file {safe_name}: {detail}"
        ) from exc
    finally:
        if fd != -1:
            os.close(fd)

    if len(raw) > max_bytes:
        raise findings.FindingsError(
            f"{label} file {safe_name} exceeds max {max_bytes} bytes"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise findings.FindingsError(
            f"{label} file {safe_name} is not valid UTF-8: {exc}"
        ) from exc

    try:
        data = json.loads(
            text,
            object_pairs_hook=findings._reject_duplicate_keys,
            parse_constant=findings._reject_json_constant,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise findings.FindingsError(f"invalid JSON in {safe_name}: {exc}") from exc

    if not isinstance(data, dict):
        raise findings.FindingsError(f"{label} file {safe_name} must contain an object")
    return data


def _validate_bounded_value(
    value: Any,
    prefix: str,
    errors: list[str],
    *,
    depth: int = 0,
    budget: list[int] | None = None,
) -> None:
    """Validate bounded JSON data for coverage/unruled payloads."""
    if budget is None:
        budget = [0]
    budget[0] += 1
    if budget[0] > MAX_COVERAGE_NODES:
        if budget[0] == MAX_COVERAGE_NODES + 1:
            errors.append(f"{prefix}: structure exceeds max {MAX_COVERAGE_NODES} nodes")
        return
    if depth > MAX_COVERAGE_DEPTH:
        errors.append(f"{prefix}: nesting depth exceeds max {MAX_COVERAGE_DEPTH}")
        return

    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            errors.append(f"{prefix}: non-finite float is not allowed")
        return
    if isinstance(value, str):
        if len(value) > findings.MAX_LONG_TEXT_LENGTH:
            errors.append(
                f"{prefix}: string length {len(value)} exceeds max "
                f"{findings.MAX_LONG_TEXT_LENGTH}"
            )
        elif "\x00" in value:
            errors.append(f"{prefix}: NUL byte is not allowed")
        elif findings._has_surrogate(value):
            errors.append(f"{prefix}: unpaired UTF-16 surrogates are not allowed")
        return
    if isinstance(value, list):
        if len(value) > MAX_UNRULED_COUNT:
            errors.append(
                f"{prefix}: array length {len(value)} exceeds max {MAX_UNRULED_COUNT}"
            )
            return
        for idx, item in enumerate(value):
            _validate_bounded_value(
                item, f"{prefix}[{idx}]", errors, depth=depth + 1, budget=budget
            )
        return
    if isinstance(value, dict):
        if len(value) > MAX_UNRULED_COUNT:
            errors.append(
                f"{prefix}: object key count {len(value)} exceeds max "
                f"{MAX_UNRULED_COUNT}"
            )
            return
        for key, val in value.items():
            if not isinstance(key, str) or not key:
                errors.append(f"{prefix}: object keys must be non-empty strings")
                continue
            if len(key) > findings.MAX_IDENTIFIER_LENGTH:
                errors.append(
                    f"{prefix}.{findings._safe_label(key)}: key exceeds max length"
                )
                continue
            if findings._has_control_char(key) or findings._has_surrogate(key):
                errors.append(
                    f"{prefix}.{findings._safe_label(key)}: unsafe characters in key"
                )
                continue
            _validate_bounded_value(
                val,
                f"{prefix}.{findings._safe_label(key)}",
                errors,
                depth=depth + 1,
                budget=budget,
            )
        return
    errors.append(f"{prefix}: unsupported type {type(value).__name__}")


def _validate_class_proposal(value: Any, prefix: str, errors: list[str]) -> None:
    """Validate candidate.classProposal matching Findings Contract v1 class shape."""
    if not isinstance(value, dict):
        errors.append(f"{prefix}: expected object, got {type(value).__name__}")
        return
    allowed = findings._CLASS_KEYS | _CLASS_PROPOSAL_EXTRA_KEYS
    findings._check_unknown_keys(value, allowed, prefix, errors)
    inner = {k: v for k, v in value.items() if k != "classFingerprint"}
    findings._validate_finding_class(inner, prefix, errors)
    if "classFingerprint" in value and value["classFingerprint"] is not None:
        findings._validate_sha256(
            value["classFingerprint"], f"{prefix}.classFingerprint", errors
        )


def _validate_candidate(
    value: Any,
    prefix: str,
    seen_ids: set[str],
    errors: list[str],
) -> None:
    if not isinstance(value, dict):
        errors.append(f"{prefix}: expected object, got {type(value).__name__}")
        return
    findings._check_unknown_keys(value, _CANDIDATE_KEYS, prefix, errors)
    if "candidateId" not in value:
        errors.append(f"{prefix}.candidateId: missing required property")
    elif findings._validate_identifier(
        value["candidateId"], f"{prefix}.candidateId", errors
    ):
        cid = value["candidateId"]
        if cid in seen_ids:
            errors.append(
                f"{prefix}.candidateId: duplicate candidateId "
                f"{findings._safe_label(cid)}"
            )
        seen_ids.add(cid)

    if "file" in value and value["file"] is not None:
        findings._validate_repo_relative_path(value["file"], f"{prefix}.file", errors)
    range_subset = {
        k: value[k]
        for k in ("lineStart", "lineEnd")
        if k in value and value[k] is not None
    }
    if range_subset:
        findings._validate_line_range(range_subset, prefix, errors)
    if "checkId" in value and value["checkId"] is not None:
        findings._validate_identifier(value["checkId"], f"{prefix}.checkId", errors)
    if "rule" in value and value["rule"] is not None:
        findings._validate_non_blank_text(value["rule"], f"{prefix}.rule", errors)
    if "reason" in value and value["reason"] is not None:
        findings._validate_non_blank_text(value["reason"], f"{prefix}.reason", errors)
    if "quote" in value and value["quote"] is not None:
        findings._validate_non_blank_text(
            value["quote"],
            f"{prefix}.quote",
            errors,
            max_len=findings.MAX_LONG_TEXT_LENGTH,
        )
    if "classProposal" in value and value["classProposal"] is not None:
        _validate_class_proposal(
            value["classProposal"], f"{prefix}.classProposal", errors
        )


def validate_prepare_doc(data: Any) -> list[str]:
    """Validate a parsed prepare.json document against the prepare contract."""
    if not isinstance(data, dict):
        return [f"prepare: expected JSON object, got {type(data).__name__}"]

    errors: list[str] = []
    findings._check_unknown_keys(data, _PREPARE_DOC_KEYS, "prepare", errors)

    if "schemaVersion" in data and data["schemaVersion"] != SCHEMA_VERSION:
        errors.append(
            f"prepare.schemaVersion: expected {SCHEMA_VERSION!r}, "
            f"got {findings._safe_label(data['schemaVersion'])}"
        )

    prep_lens: str | None = None
    if "lens" in data and data["lens"] is not None:
        if findings._validate_enum(
            data["lens"], "prepare.lens", findings.VALID_LENSES, errors
        ):
            prep_lens = data["lens"]

    if "treeId" in data and data["treeId"] is not None:
        findings._validate_tree_id(data["treeId"], "prepare.treeId", errors)

    if "partial" in data and not isinstance(data["partial"], bool):
        errors.append(
            f"prepare.partial: expected boolean, got {type(data['partial']).__name__}"
        )

    if "candidates" in data:
        candidates = data["candidates"]
        if not isinstance(candidates, list):
            errors.append(
                f"prepare.candidates: expected array, got {type(candidates).__name__}"
            )
        elif len(candidates) > MAX_CANDIDATES_COUNT:
            errors.append(
                f"prepare.candidates: length {len(candidates)} exceeds max "
                f"{MAX_CANDIDATES_COUNT}"
            )
        else:
            seen_ids: set[str] = set()
            for idx, item in enumerate(candidates):
                _validate_candidate(item, f"candidates[{idx}]", seen_ids, errors)

    if "codeFindings" in data:
        code_findings = data["codeFindings"]
        if not isinstance(code_findings, list):
            errors.append(
                "prepare.codeFindings: expected array, got "
                f"{type(code_findings).__name__}"
            )
        elif len(code_findings) > findings.MAX_FINDINGS_COUNT:
            errors.append(
                f"prepare.codeFindings: length {len(code_findings)} exceeds max "
                f"{findings.MAX_FINDINGS_COUNT}"
            )
        else:
            for idx, item in enumerate(code_findings):
                item_errs = findings.validate_finding(
                    item,
                    prefix=f"codeFindings[{idx}]",
                    expected_lens=prep_lens,
                )
                errors.extend(item_errs)
                if isinstance(item, dict) and item.get("source") != "code":
                    errors.append(
                        f"codeFindings[{idx}].source: must be 'code' in prepare.json"
                    )

    if "unruled" in data:
        unruled = data["unruled"]
        if not isinstance(unruled, list):
            errors.append(
                f"prepare.unruled: expected array, got {type(unruled).__name__}"
            )
        elif len(unruled) > MAX_UNRULED_COUNT:
            errors.append(
                f"prepare.unruled: length {len(unruled)} exceeds max "
                f"{MAX_UNRULED_COUNT}"
            )
        else:
            budget = [0]
            for idx, item in enumerate(unruled):
                if isinstance(item, str):
                    findings._validate_non_blank_text(item, f"unruled[{idx}]", errors)
                elif isinstance(item, dict):
                    _validate_bounded_value(
                        item, f"unruled[{idx}]", errors, budget=budget
                    )
                else:
                    errors.append(
                        f"unruled[{idx}]: expected string or object, "
                        f"got {type(item).__name__}"
                    )

    if "coverage" in data and data["coverage"] is not None:
        cov = data["coverage"]
        if not isinstance(cov, (dict, list)):
            errors.append(
                f"prepare.coverage: expected object or array, got {type(cov).__name__}"
            )
        else:
            _validate_bounded_value(cov, "prepare.coverage", errors)

    return errors


def load_prepare_file(
    path: str | Path,
    *,
    max_bytes: int = findings.MAX_FINDINGS_BYTES,
) -> dict[str, Any]:
    """Safely load and validate a prepare.json file."""
    data = _read_bounded_json_dict(path, label="prepare", max_bytes=max_bytes)
    errors = validate_prepare_doc(data)
    if errors:
        raise findings.FindingsValidationError(errors)
    return data


def _split_lines_deterministic(text: str) -> list[str]:
    """Split text on LF/CRLF/CR only so Unicode line separators stay on-line."""
    if not text:
        return []
    unified = text.replace("\r\n", "\n").replace("\r", "\n")
    if unified.endswith("\n"):
        unified = unified[:-1]
    return unified.split("\n")


class _RepoFileCache:
    """Bounded repo-contained file reader & citation verifier.

    Enforces strict symlink policy: every path component inside ``repo_root``
    must be a non-symlink, ``O_NOFOLLOW`` is passed when supported, the resolved
    path must stay relative to ``repo_root``, and the open fd must refer to a
    regular file within ``MAX_CITED_FILE_BYTES``.
    """

    def __init__(self, repo_root: Path) -> None:
        self.repo_root = repo_root.resolve()
        self._cache: OrderedDict[str, tuple[str, list[str] | None, str | None, int]] = (
            OrderedDict()
        )
        self._cached_bytes = 0

    def _remember(
        self,
        rel_file: str,
        status: str,
        lines: list[str] | None,
        reason: str | None,
        size: int,
    ) -> tuple[str, list[str] | None, str | None]:
        while self._cache and self._cached_bytes + size > MAX_CACHE_BYTES:
            _, (_, _, _, evicted_size) = self._cache.popitem(last=False)
            self._cached_bytes -= evicted_size
        if size <= MAX_CACHE_BYTES:
            self._cache[rel_file] = (status, lines, reason, size)
            self._cached_bytes += size
        return (status, lines, reason)

    def get_lines(self, rel_file: str) -> tuple[str, list[str] | None, str | None]:
        if rel_file in self._cache:
            status, lines, reason, size = self._cache.pop(rel_file)
            self._cache[rel_file] = (status, lines, reason, size)
            return (status, lines, reason)

        cur = self.repo_root
        for part in rel_file.split("/"):
            cur = cur / part
            try:
                st = cur.lstat()
            except FileNotFoundError:
                return self._remember(
                    rel_file, "error", None, f"cited file not found: {rel_file}", 0
                )
            except OSError as exc:
                detail = findings._safe_label(exc.strerror or str(exc))
                return self._remember(
                    rel_file, "error", None, f"cannot stat {rel_file}: {detail}", 0
                )
            if stat.S_ISLNK(st.st_mode):
                return self._remember(
                    rel_file,
                    "error",
                    None,
                    f"cited path traverses symlink: {rel_file}",
                    0,
                )

        try:
            resolved = cur.resolve()
        except (OSError, RuntimeError) as exc:
            detail = findings._safe_label(str(exc))
            return self._remember(
                rel_file, "error", None, f"cannot resolve {rel_file}: {detail}", 0
            )
        if not resolved.is_relative_to(self.repo_root):
            return self._remember(
                rel_file,
                "error",
                None,
                f"cited path escapes repository root: {rel_file}",
                0,
            )

        flags = (
            os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            fd = os.open(str(cur), flags)
        except OSError as exc:
            detail = findings._safe_label(exc.strerror or str(exc))
            return self._remember(
                rel_file, "error", None, f"cannot open {rel_file}: {detail}", 0
            )

        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                return self._remember(
                    rel_file,
                    "error",
                    None,
                    f"cited path is not a regular file: {rel_file}",
                    0,
                )
            if st.st_size > MAX_CITED_FILE_BYTES:
                return self._remember(
                    rel_file,
                    "error",
                    None,
                    f"cited file {rel_file} exceeds max {MAX_CITED_FILE_BYTES} bytes",
                    0,
                )
            with os.fdopen(fd, "rb") as handle:
                fd = -1
                raw = handle.read(MAX_CITED_FILE_BYTES + 1)
        except OSError as exc:
            detail = findings._safe_label(exc.strerror or str(exc))
            return self._remember(
                rel_file, "error", None, f"cannot read {rel_file}: {detail}", 0
            )
        finally:
            if fd != -1:
                os.close(fd)

        if len(raw) > MAX_CITED_FILE_BYTES:
            return self._remember(
                rel_file,
                "error",
                None,
                f"cited file {rel_file} exceeds max {MAX_CITED_FILE_BYTES} bytes",
                0,
            )

        text = raw.decode("utf-8", errors="replace")
        lines = _split_lines_deterministic(text)
        if len(lines) > MAX_CITED_FILE_LINES:
            return self._remember(
                rel_file,
                "error",
                None,
                f"cited file {rel_file} exceeds max {MAX_CITED_FILE_LINES} lines",
                0,
            )
        return self._remember(rel_file, "ok", lines, None, len(raw))

    def read_region(self, rel_file: str, line_start: int, line_end: int) -> str | None:
        """Read normalized line slice if valid, or None on error."""
        status, lines, _ = self.get_lines(rel_file)
        if status != "ok" or lines is None:
            return None
        if line_start < 1 or line_end < line_start or line_end > len(lines):
            return None
        slice_text = "\n".join(lines[line_start - 1 : line_end])
        if "\x00" in slice_text:
            return None
        return slice_text

    def verify_site_ref(
        self,
        site: dict[str, Any],
        *,
        require_quote: bool,
    ) -> str | None:
        """Return None if valid, else human-readable failure reason."""
        rel_file = site["file"]
        line_start = site["lineStart"]
        line_end = site["lineEnd"]
        quote = site.get("quote")

        status, lines, err_reason = self.get_lines(rel_file)
        if status != "ok" or lines is None:
            return err_reason or f"cannot read {rel_file}"
        if line_start < 1 or line_end < line_start or line_end > len(lines):
            return (
                f"line range {line_start}-{line_end} out of bounds "
                f"(file has {len(lines)} lines)"
            )
        if quote is None:
            return "missing required quote" if require_quote else None
        return _verify_quote_in_lines(lines, line_start, line_end, quote)

    def verify_finding_citations(
        self,
        finding: dict[str, Any],
        finding_index: int,
    ) -> list[dict[str, Any]]:
        """Verify primary citation, class.fixSite, and every class.sites[] entry."""
        failures: list[dict[str, Any]] = []
        check_id = finding["checkId"]

        primary_err = self.verify_site_ref(finding, require_quote=True)
        if primary_err is not None:
            failures.append(
                {
                    "findingIndex": finding_index,
                    "checkId": check_id,
                    "location": "primary",
                    "file": finding["file"],
                    "lineStart": finding["lineStart"],
                    "lineEnd": finding["lineEnd"],
                    "reason": primary_err,
                }
            )

        cls = finding.get("class")
        if isinstance(cls, dict):
            fix_site = cls["fixSite"]
            fix_err = self.verify_site_ref(fix_site, require_quote=False)
            if fix_err is not None:
                failures.append(
                    {
                        "findingIndex": finding_index,
                        "checkId": check_id,
                        "location": "class.fixSite",
                        "file": fix_site["file"],
                        "lineStart": fix_site["lineStart"],
                        "lineEnd": fix_site["lineEnd"],
                        "reason": fix_err,
                    }
                )
            for idx, site in enumerate(cls["sites"]):
                site_err = self.verify_site_ref(site, require_quote=False)
                if site_err is not None:
                    failures.append(
                        {
                            "findingIndex": finding_index,
                            "checkId": check_id,
                            "location": f"class.sites[{idx}]",
                            "file": site["file"],
                            "lineStart": site["lineStart"],
                            "lineEnd": site["lineEnd"],
                            "reason": site_err,
                        }
                    )
        return failures


def _verify_quote_in_lines(
    lines: list[str],
    line_start: int,
    line_end: int,
    quote: str,
) -> str | None:
    """Verify normalized quote matches cited lines[line_start-1 : line_end]."""
    try:
        norm_quote = findings.normalize_code_region(quote)
    except ValueError as exc:
        return f"invalid quote: {exc}"
    if not norm_quote:
        return "quote must not be empty or whitespace-only"

    cited = lines[line_start - 1 : line_end]
    cited_raw = "\n".join(cited)
    if "\x00" in cited_raw:
        return "cited source lines contain NUL byte"

    norm_cited = findings.normalize_code_region(cited_raw)
    if norm_cited == norm_quote:
        return None

    quote_lines = norm_quote.split("\n")
    if len(quote_lines) == 1:
        needle = quote_lines[0]
        if any(needle in ln.rstrip(" \t") for ln in cited):
            return None
        return f"quote not found in cited lines {line_start}-{line_end}"

    trimmed_cited = "\n".join(ln.rstrip(" \t") for ln in cited)
    if norm_quote in trimmed_cited:
        return None

    span = len(quote_lines)
    if span <= len(cited):
        for offset in range(len(cited) - span + 1):
            window = "\n".join(cited[offset : offset + span])
            if findings.normalize_code_region(window) == norm_quote:
                return None

    return f"quote does not match cited lines {line_start}-{line_end}"


def _is_active(finding: dict[str, Any]) -> bool:
    """Return True if a finding is neither suppressed nor closed/disputed."""
    return not finding.get("suppressed", False) and finding.get("disposition") not in {
        "closed",
        "disputed",
    }


def _is_blocking(finding: dict[str, Any]) -> bool:
    """Return True if an active finding triggers REQUEST CHANGES (#51, #126).

    Under ``code`` lens, only an active ``ISSUE`` with ``blocking=True`` blocks;
    a ``CONCERN`` never triggers ``REQUEST CHANGES`` even if ``blocking=True``.
    Under ``security``/``mcp`` lenses, any active finding with ``blocking=True``
    triggers ``REQUEST CHANGES``.
    """
    if not _is_active(finding):
        return False
    if not finding.get("blocking", False):
        return False
    if finding["lens"] == "code":
        return finding["severity"] == "ISSUE"
    return True


def _finding_sort_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    return (
        SEVERITY_RANK[finding["severity"]],
        not bool(finding["blocking"]),
        bool(finding.get("suppressed", False)),
        finding["file"],
        finding["lineStart"],
        finding["lineEnd"],
        finding["checkId"],
        finding["fingerprint"],
    )


def _extract_model_candidate_ids(finding: dict[str, Any]) -> set[str]:
    ids = set(finding.get("candidateIds", []))
    cls = finding.get("class")
    if isinstance(cls, dict):
        for site in cls.get("sites", []):
            cid = site.get("candidateId")
            if cid is not None:
                ids.add(cid)
    return ids


def _attach_class_proposal(
    finding: dict[str, Any],
    candidates_by_id: dict[str, dict[str, Any]],
    file_cache: _RepoFileCache | None,
) -> None:
    """Attach code's candidate classProposal when the finding has no class."""
    if finding.get("class") is not None:
        return
    for cid in sorted(finding.get("candidateIds", [])):
        cand = candidates_by_id.get(cid)
        if not cand or cand.get("classProposal") is None:
            continue
        proposal = copy.deepcopy(cand["classProposal"])
        cfp = proposal.pop("classFingerprint", None)
        if cfp is None:
            cfp = finding.get("classFingerprint")
        if cfp is None:
            fix_site = proposal["fixSite"]
            region = fix_site.get("quote")
            if region is None and file_cache is not None:
                region = file_cache.read_region(
                    fix_site["file"], fix_site["lineStart"], fix_site["lineEnd"]
                )
            if region is None or not findings.normalize_code_region(region):
                region = finding["quote"]
            cfp = findings.compute_class_fingerprint(
                finding["checkId"], fix_site["file"], region
            )
        finding["class"] = proposal
        finding["classFingerprint"] = cfp
        return


def _merge_pair(cf: dict[str, Any], mf: dict[str, Any]) -> dict[str, Any]:
    """Merge a matched code finding and model finding into source='both'."""
    merged = copy.deepcopy(mf)
    merged["source"] = "both"
    merged["fingerprint"] = cf["fingerprint"]

    if merged.get("category") is None and cf.get("category") is not None:
        merged["category"] = cf["category"]

    if merged.get("basis") is None and cf.get("basis") is not None:
        merged["basis"] = cf["basis"]

    if merged.get("proof") is None and cf.get("proof") is not None:
        merged["proof"] = copy.deepcopy(cf["proof"])

    if merged.get("class") is None and cf.get("class") is not None:
        merged["class"] = copy.deepcopy(cf["class"])
        merged["classFingerprint"] = cf.get("classFingerprint")

    if merged.get("recommendation") is None and cf.get("recommendation") is not None:
        merged["recommendation"] = cf["recommendation"]

    if merged.get("package") is None and cf.get("package") is not None:
        merged["package"] = cf["package"]
        merged["version"] = cf.get("version")
    elif (
        merged.get("package") == cf.get("package")
        and merged.get("version") is None
        and cf.get("version") is not None
    ):
        merged["version"] = cf["version"]

    merged_cids = sorted(
        set(cf.get("candidateIds", [])) | set(mf.get("candidateIds", []))
    )
    if merged_cids:
        merged["candidateIds"] = merged_cids

    suppressed = bool(mf.get("suppressed", False) or cf.get("suppressed", False))
    merged["suppressed"] = suppressed
    if merged.get("reason") is None and cf.get("reason") is not None:
        merged["reason"] = cf["reason"]

    if merged.get("disposition") is None and cf.get("disposition") is not None:
        merged["disposition"] = cf["disposition"]

    if merged.get("disposition") in ("disputed", "closed"):
        merged["blocking"] = False
    else:
        if cf["lens"] == mf["lens"] and (
            SEVERITY_RANK[cf["severity"]] < SEVERITY_RANK[mf["severity"]]
        ):
            merged["severity"] = cf["severity"]
            if cf.get("basis") is not None and merged.get("basis") is None:
                merged["basis"] = cf["basis"]
        merged["blocking"] = bool(cf.get("blocking") or mf.get("blocking"))

    return merged


def _ranges_overlap(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return a["lineStart"] <= b["lineEnd"] and b["lineStart"] <= a["lineEnd"]


def _merge_findings(
    prepare_code_findings: list[dict[str, Any]],
    model_findings: list[dict[str, Any]],
    model_code_findings: list[dict[str, Any]],
    candidates_by_id: dict[str, dict[str, Any]],
    file_cache: _RepoFileCache | None,
) -> tuple[list[dict[str, Any]], int, int, int]:
    """Merge code findings and verified model findings deterministically.

    Returns ``(merged_findings, code_count, model_count, both_count)`` where
    ``code_count`` counts findings backed by code (``source in ("code", "both")``),
    ``model_count`` counts findings backed by model (``source in ("model", "both")``),
    and ``both_count`` counts findings with ``source == "both"``.
    """
    code_by_fp: dict[str, int] = {}
    code_list: list[dict[str, Any]] = []
    for item in sorted(
        (copy.deepcopy(x) for x in prepare_code_findings),
        key=_finding_sort_key,
    ):
        if item["fingerprint"] not in code_by_fp:
            code_by_fp[item["fingerprint"]] = len(code_list)
            code_list.append(item)

    for extra in sorted(
        (copy.deepcopy(x) for x in model_code_findings),
        key=_finding_sort_key,
    ):
        fp = extra["fingerprint"]
        if fp in code_by_fp:
            idx = code_by_fp[fp]
            if (
                extra.get("disposition") is not None
                or extra.get("suppressed")
                or extra.get("class") is not None
            ):
                code_list[idx] = _merge_pair(code_list[idx], extra)
        else:
            code_by_fp[fp] = len(code_list)
            code_list.append(extra)
    code_list.sort(key=_finding_sort_key)

    model_list = sorted(
        (copy.deepcopy(item) for item in model_findings),
        key=_finding_sort_key,
    )

    used_code: set[int] = set()
    used_model: set[int] = set()
    pairs: list[tuple[int, int]] = []

    # Pass 1: exact fingerprint match.
    model_by_fp: dict[str, list[int]] = {}
    for mi, mf in enumerate(model_list):
        model_by_fp.setdefault(mf["fingerprint"], []).append(mi)
    for ci, cf in enumerate(code_list):
        matches = [
            mi for mi in model_by_fp.get(cf["fingerprint"], []) if mi not in used_model
        ]
        if matches:
            mi = matches[0]
            used_code.add(ci)
            used_model.add(mi)
            pairs.append((ci, mi))

    # Pass 2: exact (file, lineStart, lineEnd, checkId).
    model_by_site: dict[tuple[str, int, int, str], list[int]] = {}
    for mi, mf in enumerate(model_list):
        if mi in used_model:
            continue
        key = (mf["file"], mf["lineStart"], mf["lineEnd"], mf["checkId"])
        model_by_site.setdefault(key, []).append(mi)
    for ci, cf in enumerate(code_list):
        if ci in used_code:
            continue
        key = (cf["file"], cf["lineStart"], cf["lineEnd"], cf["checkId"])
        matches = [mi for mi in model_by_site.get(key, []) if mi not in used_model]
        if matches:
            mi = matches[0]
            used_code.add(ci)
            used_model.add(mi)
            pairs.append((ci, mi))

    # Pass 3: unambiguous 1-to-1 overlapping range on (file, checkId).
    code_by_fc: dict[tuple[str, str], list[int]] = {}
    for ci, cf in enumerate(code_list):
        if ci not in used_code:
            code_by_fc.setdefault((cf["file"], cf["checkId"]), []).append(ci)
    model_by_fc: dict[tuple[str, str], list[int]] = {}
    for mi, mf in enumerate(model_list):
        if mi not in used_model:
            model_by_fc.setdefault((mf["file"], mf["checkId"]), []).append(mi)
    for key in sorted(set(code_by_fc) & set(model_by_fc)):
        c_idxs = code_by_fc[key]
        m_idxs = model_by_fc[key]
        if len(c_idxs) == 1 and len(m_idxs) == 1:
            ci, mi = c_idxs[0], m_idxs[0]
            if _ranges_overlap(code_list[ci], model_list[mi]):
                used_code.add(ci)
                used_model.add(mi)
                pairs.append((ci, mi))

    merged_out: list[dict[str, Any]] = []
    for ci, mi in pairs:
        merged_out.append(_merge_pair(code_list[ci], model_list[mi]))
    for ci, cf in enumerate(code_list):
        if ci not in used_code:
            merged_out.append(cf)
    for mi, mf in enumerate(model_list):
        if mi not in used_model:
            merged_out.append(mf)

    for item in merged_out:
        if item.get("disposition") in ("disputed", "closed"):
            item["blocking"] = False
        _attach_class_proposal(item, candidates_by_id, file_cache)

    code_count = sum(1 for item in merged_out if item["source"] in ("code", "both"))
    model_count = sum(1 for item in merged_out if item["source"] in ("model", "both"))
    both_count = sum(1 for item in merged_out if item["source"] == "both")
    return merged_out, code_count, model_count, both_count


def _mark_recurring(
    current_findings: list[dict[str, Any]],
    prior_findings: list[dict[str, Any]],
) -> None:
    """Tag current findings as 'recurring' when classFingerprint matches prior."""
    prior_cfps = {
        pf["classFingerprint"]
        for pf in prior_findings
        if pf.get("classFingerprint") is not None
    }
    for item in current_findings:
        cfp = item.get("classFingerprint")
        if cfp is not None and cfp in prior_cfps:
            if item.get("disposition") in (None, "open"):
                item["disposition"] = "recurring"


def _compute_prior_dispositions(
    current_findings: list[dict[str, Any]],
    prior_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Summarize each prior finding's status across the current run.

    Status rules per prior finding (sorted deterministically):
    1. ``"disputed"`` if matched in current findings with ``disposition == "disputed"``
       (exact ``fingerprint`` match first, or ``classFingerprint`` match), or if the
       prior finding itself already carried ``"disputed"`` and no active current
       finding matches it.
    2. ``"open"`` if an active current finding shares its exact ``fingerprint``.
    3. ``"partly-closed"`` if its exact ``fingerprint`` is gone/inactive, yet an
       active current finding shares its ``classFingerprint``.
    4. ``"closed"`` otherwise.
    """
    sorted_prior = sorted(
        (copy.deepcopy(pf) for pf in prior_findings),
        key=_finding_sort_key,
    )
    dispositions: list[dict[str, Any]] = []
    for pf in sorted_prior:
        pf_fp = pf["fingerprint"]
        pf_cfp = pf.get("classFingerprint")
        pf_disp = pf.get("disposition")

        fp_matches = [f for f in current_findings if f["fingerprint"] == pf_fp]
        cfp_matches = (
            [f for f in current_findings if f.get("classFingerprint") == pf_cfp]
            if pf_cfp is not None
            else []
        )

        disputed_fp = [f for f in fp_matches if f.get("disposition") == "disputed"]
        active_fp = [f for f in fp_matches if _is_active(f)]
        active_cfp = [f for f in cfp_matches if _is_active(f)]
        disputed_cfp = [f for f in cfp_matches if f.get("disposition") == "disputed"]

        reason: str | None = None
        if disputed_fp:
            status = "disputed"
            reason = disputed_fp[0].get("reason")
            matched = sorted({f["fingerprint"] for f in disputed_fp})
        elif active_fp:
            status = "open"
            matched = sorted({f["fingerprint"] for f in active_fp})
        elif active_cfp:
            status = "partly-closed"
            matched = sorted({f["fingerprint"] for f in active_cfp})
        elif disputed_cfp:
            status = "disputed"
            reason = disputed_cfp[0].get("reason")
            matched = sorted({f["fingerprint"] for f in disputed_cfp})
        elif pf_disp == "disputed":
            status = "disputed"
            reason = pf.get("reason")
            matched = []
        else:
            status = "closed"
            matched = []

        entry: dict[str, Any] = {
            "fingerprint": pf_fp,
            "classFingerprint": pf_cfp,
            "checkId": pf["checkId"],
            "file": pf["file"],
            "lineStart": pf["lineStart"],
            "lineEnd": pf["lineEnd"],
            "priorDisposition": pf_disp,
            "disposition": status,
            "matchedFingerprints": matched,
        }
        if reason is not None:
            entry["reason"] = reason
        dispositions.append(entry)

    return dispositions


def _apply_rubric_downgrades(
    findings_list: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[int]]:
    """Downgrade ISSUEs lacking a rubric basis to CONCERN (blocking=False)."""
    downgraded_ids: set[int] = set()
    for item in findings_list:
        if item["severity"] == "ISSUE" and item.get("basis") is None:
            item["severity"] = "CONCERN"
            item["blocking"] = False
            downgraded_ids.add(id(item))
    return findings_list, downgraded_ids


def _build_downgrade_records(
    sorted_findings: list[dict[str, Any]],
    downgraded_ids: set[int],
) -> tuple[list[dict[str, Any]], set[int]]:
    records: list[dict[str, Any]] = []
    downgraded_numbers: set[int] = set()
    for idx, item in enumerate(sorted_findings, start=1):
        if id(item) in downgraded_ids:
            downgraded_numbers.add(idx)
            records.append(
                {
                    "findingNumber": idx,
                    "fingerprint": item["fingerprint"],
                    "checkId": item["checkId"],
                    "file": item["file"],
                    "lineStart": item["lineStart"],
                    "lineEnd": item["lineEnd"],
                    "fromSeverity": "ISSUE",
                    "toSeverity": "CONCERN",
                    "toBlocking": False,
                    "reason": (
                        "ISSUE has no evidence basis; downgraded to CONCERN "
                        "per rubric rule"
                    ),
                }
            )
    return records, downgraded_numbers


def _compute_lens_assessment(
    sorted_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Compute the 8-row Lens Assessment table citing only Finding numbers or '—'."""
    rows: list[dict[str, Any]] = []
    for slug, display_name in LENS_CATEGORIES:
        active_items: list[tuple[int, dict[str, Any]]] = [
            (idx, item)
            for idx, item in enumerate(sorted_findings, start=1)
            if _is_active(item) and item.get("category") == slug
        ]
        if any(
            item["severity"] in {"ISSUE", "CRITICAL", "HIGH"}
            for _, item in active_items
        ):
            rating = "ISSUE"
        elif active_items:
            rating = "CONCERN"
        else:
            rating = "PASS"
        nums = [idx for idx, _ in active_items]
        notes = ", ".join(f"Finding {num}" for num in nums) if nums else "—"
        rows.append(
            {
                "category": slug,
                "lens": display_name,
                "rating": rating,
                "findingNumbers": nums,
                "notes": notes,
            }
        )
    return rows


def _unruled_sort_key(item: Any) -> tuple[int, str, str]:
    if isinstance(item, str):
        return (0, item, "")
    cid = str(item.get("candidateId") or "")
    return (1, cid, json.dumps(item, sort_keys=True, ensure_ascii=False))


def _has_errors(errors: dict[str, list[Any]]) -> bool:
    return any(bool(items) for items in errors.values())


def _compute_verdict_and_exit(
    sorted_findings: list[dict[str, Any]],
    errors: dict[str, list[Any]],
) -> tuple[str, int]:
    has_blocking = any(_is_blocking(item) for item in sorted_findings)
    has_err = _has_errors(errors)
    if has_blocking:
        verdict = "REQUEST CHANGES"
    elif has_err:
        verdict = "INCOMPLETE"
    else:
        verdict = "APPROVE"

    if has_err:
        exit_code = 2
    elif has_blocking:
        exit_code = 1
    else:
        exit_code = 0
    return verdict, exit_code


def build_report(
    *,
    findings_path: str | Path | None,
    prepare_path: str | Path | None = None,
    prior_path: str | Path | None = None,
    repo_path: str | Path = ".",
) -> dict[str, Any]:
    """Load inputs, verify citations/accounting/rubric, merge, and build report."""
    errors: dict[str, list[Any]] = {
        "inputErrors": [],
        "validationErrors": [],
        "badCitations": [],
        "unaccountedCandidates": [],
        "conflictingCandidates": [],
        "unknownCandidates": [],
    }

    # 1. Load --prepare independently so codeFindings survive --findings errors.
    prepare_doc: dict[str, Any] | None = None
    prepare_code_findings: list[dict[str, Any]] = []
    candidates_by_id: dict[str, dict[str, Any]] = {}
    partial = False
    unruled: list[Any] = []
    coverage: Any = None

    if prepare_path is not None:
        try:
            prepare_doc = load_prepare_file(prepare_path)
            prepare_code_findings = list(prepare_doc.get("codeFindings", []))
            for cand in prepare_doc.get("candidates", []):
                candidates_by_id[cand["candidateId"]] = cand
            partial = bool(prepare_doc.get("partial", False))
            unruled = sorted(prepare_doc.get("unruled", []), key=_unruled_sort_key)
            coverage = prepare_doc.get("coverage")
        except findings.FindingsValidationError as exc:
            errors["validationErrors"].extend(f"--prepare: {err}" for err in exc.errors)
        except findings.FindingsError as exc:
            errors["inputErrors"].append(f"--prepare: {exc}")

    # 2. Load --findings independently.
    model_doc: dict[str, Any] | None = None
    if findings_path is None:
        errors["inputErrors"].append("--findings: path is required")
    else:
        try:
            model_doc = findings.load_findings_file(findings_path)
        except findings.FindingsValidationError as exc:
            errors["validationErrors"].extend(
                f"--findings: {err}" for err in exc.errors
            )
        except findings.FindingsError as exc:
            errors["inputErrors"].append(f"--findings: {exc}")

    # 3. Load --prior independently.
    prior_doc: dict[str, Any] | None = None
    if prior_path is not None:
        try:
            prior_doc = findings.load_findings_file(prior_path)
        except findings.FindingsValidationError as exc:
            errors["validationErrors"].extend(f"--prior: {err}" for err in exc.errors)
        except findings.FindingsError as exc:
            errors["inputErrors"].append(f"--prior: {exc}")

    # 4. Cross-document consistency checks when both prepare and findings loaded.
    if prepare_doc is not None and model_doc is not None:
        prep_lens = prepare_doc.get("lens")
        mod_lens = model_doc.get("lens")
        if prep_lens is not None and mod_lens is not None and prep_lens != mod_lens:
            errors["validationErrors"].append(
                f"lens mismatch: --prepare has {prep_lens!r}, "
                f"--findings has {mod_lens!r}"
            )
        prep_tree = prepare_doc.get("treeId")
        mod_tree = model_doc.get("treeId")
        if prep_tree is not None and mod_tree is not None and prep_tree != mod_tree:
            errors["validationErrors"].append(
                f"treeId mismatch: --prepare has {prep_tree!r}, "
                f"--findings has {mod_tree!r}"
            )

    # 5. Validate --repo directory & verify non-"code" citations from --findings.
    file_cache: _RepoFileCache | None = None
    repo_valid = False
    try:
        repo_str = os.fspath(repo_path)
        if not repo_str.strip() or "\x00" in repo_str:
            raise OSError("empty or invalid --repo path")
        resolved_repo = Path(repo_str).resolve()
        if not resolved_repo.is_dir():
            errors["inputErrors"].append(
                f"--repo is not an existing directory: {findings._safe_label(repo_str)}"
            )
        else:
            file_cache = _RepoFileCache(resolved_repo)
            repo_valid = True
    except (OSError, ValueError, TypeError) as exc:
        errors["inputErrors"].append(
            f"--repo cannot be resolved: {findings._safe_label(str(exc))}"
        )

    verified_model_findings: list[dict[str, Any]] = []
    model_code_findings: list[dict[str, Any]] = []
    dismissals: list[dict[str, Any]] = []
    if model_doc is not None:
        dismissals = sorted(
            (copy.deepcopy(d) for d in model_doc.get("dismissals", [])),
            key=lambda d: (d["candidateId"], d["reason"]),
        )
        for idx, item in enumerate(model_doc.get("findings", [])):
            if item["source"] == "code":
                model_code_findings.append(item)
                continue
            if not repo_valid or file_cache is None:
                errors["badCitations"].append(
                    {
                        "findingIndex": idx,
                        "checkId": item["checkId"],
                        "location": "primary",
                        "file": item["file"],
                        "lineStart": item["lineStart"],
                        "lineEnd": item["lineEnd"],
                        "reason": "cannot verify citation: --repo is unavailable",
                    }
                )
                continue
            cit_errs = file_cache.verify_finding_citations(item, idx)
            if cit_errs:
                errors["badCitations"].extend(cit_errs)
            else:
                verified_model_findings.append(item)

    errors["badCitations"].sort(
        key=lambda e: (
            e["findingIndex"],
            e["location"],
            e["file"],
            e["lineStart"],
            e["lineEnd"],
            e["reason"],
        )
    )

    # 6. Candidate accounting when --prepare and --findings both loaded cleanly.
    if prepare_doc is not None and model_doc is not None:
        declared_ids = set(candidates_by_id)
        ruled_ids: set[str] = set()
        for item in verified_model_findings:
            ruled_ids |= _extract_model_candidate_ids(item)
        dismissed_ids = {d["candidateId"] for d in dismissals}
        errors["conflictingCandidates"] = sorted(ruled_ids & dismissed_ids)
        errors["unknownCandidates"] = sorted((ruled_ids | dismissed_ids) - declared_ids)
        errors["unaccountedCandidates"] = sorted(
            declared_ids - (ruled_ids | dismissed_ids)
        )

    # 7. Merge code & model findings, apply prior, downgrade, sort deterministically.
    merged_findings, code_count, model_count, both_count = _merge_findings(
        prepare_code_findings,
        verified_model_findings,
        model_code_findings,
        candidates_by_id,
        file_cache,
    )

    if prior_doc is not None:
        _mark_recurring(merged_findings, prior_doc["findings"])

    merged_findings, downgraded_ids = _apply_rubric_downgrades(merged_findings)
    sorted_findings = sorted(merged_findings, key=_finding_sort_key)
    downgrades, downgraded_numbers = _build_downgrade_records(
        sorted_findings, downgraded_ids
    )

    if prior_doc is not None:
        prior_dispositions = _compute_prior_dispositions(
            sorted_findings, prior_doc["findings"]
        )
    else:
        prior_dispositions = []

    lens_assessment = _compute_lens_assessment(sorted_findings)
    verdict, exit_code = _compute_verdict_and_exit(sorted_findings, errors)

    doc_lens = (
        model_doc.get("lens")
        if model_doc is not None and model_doc.get("lens") is not None
        else (prepare_doc.get("lens") if prepare_doc is not None else None)
    )
    doc_tree_id = (
        model_doc.get("treeId")
        if model_doc is not None and model_doc.get("treeId") is not None
        else (prepare_doc.get("treeId") if prepare_doc is not None else None)
    )

    report: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "lens": doc_lens,
        "treeId": doc_tree_id,
        "verdict": verdict,
        "exitCode": exit_code,
        "findings": sorted_findings,
        "codeFindingsCount": code_count,
        "modelFindingsCount": model_count,
        "mergedCount": both_count,
        "downgrades": downgrades,
        "dismissals": dismissals,
        "priorDispositions": prior_dispositions,
        "lensAssessment": lens_assessment,
        "errors": errors,
        "partial": partial,
        "unruled": unruled,
        "coverage": coverage,
        "_meta": {
            "hasPrior": prior_doc is not None,
            "hasPrepare": prepare_doc is not None,
            "downgradedNumbers": sorted(downgraded_numbers),
        },
    }
    return report


def public_json_payload(report: dict[str, Any]) -> dict[str, Any]:
    """Return the public camelCase JSON report dict (without internal metadata)."""
    return {k: v for k, v in report.items() if k != "_meta"}


def render_json(report: dict[str, Any]) -> str:
    """Render report as deterministic, formatted camelCase JSON."""
    return json.dumps(public_json_payload(report), indent=2, ensure_ascii=False) + "\n"


def _error_messages(errors: dict[str, list[Any]]) -> list[str]:
    """Flatten structured error buckets into sanitized diagnostic strings."""
    msgs: list[str] = []
    for err in errors.get("inputErrors", []):
        msgs.append(_sanitize_text(err))
    for err in errors.get("validationErrors", []):
        msgs.append(_sanitize_text(err))
    for cit in errors.get("badCitations", []):
        msgs.append(
            "bad citation at findings"
            f"[{cit['findingIndex']}] ({_sanitize_text(cit['checkId'])}, "
            f"{_sanitize_text(cit['location'])} {_sanitize_text(cit['file'])}:"
            f"{cit['lineStart']}-{cit['lineEnd']}): {_sanitize_text(cit['reason'])}"
        )
    for cid in errors.get("unaccountedCandidates", []):
        msgs.append(f"unaccounted candidate: {_sanitize_text(cid)}")
    for cid in errors.get("conflictingCandidates", []):
        msgs.append(
            f"conflicting candidate (both ruled and dismissed): {_sanitize_text(cid)}"
        )
    for cid in errors.get("unknownCandidates", []):
        msgs.append(f"unknown candidate (not in --prepare): {_sanitize_text(cid)}")
    return msgs


def _format_site_range(site: dict[str, Any]) -> str:
    start, end = site["lineStart"], site["lineEnd"]
    span = f"{start}" if start == end else f"{start}-{end}"
    return f"{site['file']}:{span}"


def render_markdown(report: dict[str, Any]) -> str:
    """Render report as escaped, GitHub-safe Markdown."""
    meta = report.get("_meta", {})
    downgraded_nums = set(meta.get("downgradedNumbers", []))
    errors = report["errors"]
    findings_list = report["findings"]
    active_count = sum(1 for f in findings_list if _is_active(f))
    blocking_count = sum(1 for f in findings_list if _is_blocking(f))

    lines: list[str] = [
        "### Verdict",
        "",
        f"**Verdict:** {_md_escape_inline(report['verdict'])} "
        f"(exit code {report['exitCode']})",
        "",
    ]

    if _has_errors(errors):
        lines.extend(["### Errors", ""])
        for msg in _error_messages(errors):
            lines.append(f"- {_md_escape_inline(msg)}")
        lines.append("")

    lines.extend(
        [
            "### Summary",
            "",
            f"- **Findings:** {len(findings_list)} total "
            f"({active_count} active, {blocking_count} blocking)",
            f"- **Sources:** {report['codeFindingsCount']} code-backed, "
            f"{report['modelFindingsCount']} model-backed, "
            f"{report['mergedCount']} merged (`both`)",
            f"- **Downgrades:** {len(report['downgrades'])}",
            f"- **Dismissals:** {len(report['dismissals'])}",
        ]
    )
    if report["partial"]:
        lines.append("- **Coverage status:** partial (candidates capped by budget)")
    lines.append("")

    lines.extend(["### Findings", ""])
    if not findings_list:
        lines.append("No findings.")
        lines.append("")
    else:
        for idx, item in enumerate(findings_list, start=1):
            loc = _md_code_span(_format_site_range(item))
            cid = _md_code_span(item["checkId"])
            lines.append(f"#### Finding {idx}: {loc} ({cid})")
            lines.append("")
            cat = item.get("category")
            lens_str = (
                f"{item['lens']} ({_md_escape_inline(cat)})"
                if cat is not None
                else item["lens"]
            )
            disp = item.get("disposition") or "open"
            if item.get("suppressed"):
                disp = f"{disp} (suppressed)"
            lines.append(f"- **Source:** {item['source']}")
            lines.append(f"- **Lens:** {lens_str}")
            lines.append(f"- **Severity:** {item['severity']}")
            lines.append(f"- **Basis:** {item.get('basis') or 'none'}")
            lines.append(f"- **Blocking:** {'yes' if item['blocking'] else 'no'}")
            lines.append(f"- **Disposition:** {_md_escape_inline(disp)}")
            if idx in downgraded_nums:
                lines.append(
                    "- **Downgrade:** Original rating was ISSUE without basis; "
                    "downgraded to CONCERN (non-blocking)."
                )
            if item.get("reason") is not None:
                lines.append(f"- **Reason:** {_md_escape_inline(item['reason'])}")
            lines.append(f"- **Claim:** {_md_escape_inline(item['claim'])}")
            lines.append(f"- **Evidence:** {_md_escape_inline(item['evidence'])}")
            proof = item.get("proof")
            if isinstance(proof, dict):
                p_parts = [f"{proof['kind']} ({proof['status']})"]
                if proof.get("target") is not None:
                    p_parts.append(f"target {_md_code_span(proof['target'])}")
                if proof.get("command") is not None:
                    p_parts.append(f"command {_md_code_span(proof['command'])}")
                if proof.get("detail") is not None:
                    p_parts.append(_md_escape_inline(proof["detail"]))
                lines.append(f"- **Proof:** {'; '.join(p_parts)}")
            cls = item.get("class")
            if isinstance(cls, dict):
                fix_loc = _md_code_span(_format_site_range(cls["fixSite"]))
                closes = cls["closes"]
                lines.append(
                    f"- **Class:** {_md_escape_inline(cls['rule'])} — "
                    f"fix site {fix_loc}, closes {closes['closed']}/{closes['total']}"
                )
            if item.get("package") is not None:
                pkg = _md_code_span(item["package"])
                ver = (
                    f" {_md_code_span(item['version'])}"
                    if item.get("version") is not None
                    else ""
                )
                lines.append(f"- **Package:** {pkg}{ver}")
            if item.get("recommendation") is not None:
                lines.append(
                    f"- **Recommendation:** {_md_escape_inline(item['recommendation'])}"
                )
            lines.append("- **Quote:**")
            lines.append("")
            lines.append(_md_fence(item["quote"]))
            lines.append("")

    if report["dismissals"]:
        lines.extend(["### Dismissals", ""])
        lines.append("| Candidate | Reason |")
        lines.append("|---|---|")
        for d in report["dismissals"]:
            lines.append(
                f"| {_md_code_span(d['candidateId'], in_table=True)} | "
                f"{_md_escape_cell(d['reason'])} |"
            )
        lines.append("")

    if meta.get("hasPrior"):
        lines.extend(["### Prior Findings", ""])
        if not report["priorDispositions"]:
            lines.append("No prior findings.")
        else:
            lines.append("| Site | Check | Prior | Status | Notes |")
            lines.append("|---|---|---|---|---|")
            for p in report["priorDispositions"]:
                site = _md_code_span(_format_site_range(p), in_table=True)
                chk = _md_code_span(p["checkId"], in_table=True)
                prior_d = _md_escape_cell(p.get("priorDisposition") or "open")
                status = _md_escape_cell(p["disposition"])
                note = _md_escape_cell(p.get("reason") or "—")
                lines.append(f"| {site} | {chk} | {prior_d} | {status} | {note} |")
        lines.append("")

    lines.extend(["### Lens Assessment", ""])
    lines.append("| Lens | Rating | Notes |")
    lines.append("|---|---|---|")
    for row in report["lensAssessment"]:
        lines.append(f"| {row['lens']} | {row['rating']} | {row['notes']} |")
    lines.append("")

    if report["partial"] or report["unruled"] or report["coverage"] is not None:
        lines.extend(["### Check Performance", ""])
        if report["partial"]:
            lines.append("- **Partial run:** yes")
        if report["unruled"]:
            lines.append(f"- **Unruled items ({len(report['unruled'])}):**")
            for u in report["unruled"]:
                rendered = (
                    u
                    if isinstance(u, str)
                    else json.dumps(u, sort_keys=True, ensure_ascii=False)
                )
                lines.append(f"  - {_md_escape_inline(rendered)}")
        if report["coverage"] is not None:
            cov_json = json.dumps(
                report["coverage"], indent=2, sort_keys=True, ensure_ascii=False
            )
            lines.append("- **Coverage:**")
            lines.append("")
            lines.append(_md_fence(cov_json, lang="json"))
        lines.append("")

    return "\n".join(lines)


def _sarif_level(finding: dict[str, Any]) -> str:
    if _is_blocking(finding) or finding["severity"] in {
        "ISSUE",
        "CRITICAL",
        "HIGH",
    }:
        return "error"
    if finding["severity"] in {"CONCERN", "MEDIUM"}:
        return "warning"
    return "note"


def render_sarif(report: dict[str, Any]) -> str:
    """Render report as SARIF 2.1.0 JSON with safe control-char sanitization."""
    meta = report.get("_meta", {})
    downgraded_nums = set(meta.get("downgradedNumbers", []))
    findings_list = report["findings"]

    rules: list[dict[str, Any]] = []
    rule_index_by_id: dict[str, int] = {}
    for item in sorted(findings_list, key=lambda f: f["checkId"]):
        cid = item["checkId"]
        if cid in rule_index_by_id:
            continue
        rule_index_by_id[cid] = len(rules)
        rules.append(
            {
                "id": cid,
                "shortDescription": {"text": _sanitize_text(item["claim"])},
                "properties": {"lens": item["lens"]},
            }
        )

    results: list[dict[str, Any]] = []
    for idx, item in enumerate(findings_list, start=1):
        msg_parts = [_sanitize_text(item["claim"])]
        if idx in downgraded_nums:
            msg_parts.append(
                "Note: Original rating was ISSUE without basis; downgraded to CONCERN."
            )
        msg_parts.append(f"Evidence: {_sanitize_text(item['evidence'])}")
        if item.get("recommendation") is not None:
            msg_parts.append(
                f"Recommendation: {_sanitize_text(item['recommendation'])}"
            )

        partial_fps: dict[str, str] = {"vld8/finding/v1": item["fingerprint"]}
        if item.get("classFingerprint") is not None:
            partial_fps["vld8/class/v1"] = item["classFingerprint"]

        props: dict[str, Any] = {
            "lens": item["lens"],
            "source": item["source"],
            "basis": item.get("basis"),
            "blocking": item["blocking"],
            "disposition": item.get("disposition"),
        }
        if idx in downgraded_nums:
            props["downgradedFrom"] = "ISSUE"
        if item.get("reason") is not None:
            props["reason"] = _sanitize_text(item["reason"])

        result_obj: dict[str, Any] = {
            "ruleId": item["checkId"],
            "ruleIndex": rule_index_by_id[item["checkId"]],
            "level": _sarif_level(item),
            "message": {"text": " ".join(msg_parts)},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": _sanitize_text(item["file"]),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": item["lineStart"],
                            "endLine": item["lineEnd"],
                            "snippet": {
                                "text": _sanitize_text(
                                    item["quote"], allow_newlines=True
                                )
                            },
                        },
                    }
                }
            ],
            "partialFingerprints": partial_fps,
            "properties": props,
        }
        if item.get("suppressed"):
            result_obj["suppressions"] = [
                {
                    "kind": "external",
                    "justification": _sanitize_text(item.get("reason") or ""),
                }
            ]
        results.append(result_obj)

    notifications = [
        {"level": "error", "message": {"text": msg}}
        for msg in _error_messages(report["errors"])
    ]
    has_err = _has_errors(report["errors"])

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "vld8",
                        "semanticVersion": str(__version__),
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": not has_err,
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "properties": {
                    "verdict": report["verdict"],
                    "exitCode": report["exitCode"],
                },
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2, ensure_ascii=False) + "\n"


def render_report(report: dict[str, Any], fmt: str) -> str:
    """Render report dictionary in ``md``, ``json``, or ``sarif`` format."""
    if fmt == "md":
        return render_markdown(report)
    if fmt == "json":
        return render_json(report)
    if fmt == "sarif":
        return render_sarif(report)
    raise ValueError(f"unsupported format: {fmt!r}")


def _atomic_write(out_path: Path, text: str) -> None:
    """Write ``text`` atomically to ``out_path`` via a sibling tempfile."""
    raw_str = os.fspath(out_path)
    if "\x00" in raw_str or not raw_str.strip():
        raise OSError("invalid output path")
    if out_path.exists() and out_path.is_dir():
        raise IsADirectoryError(f"output path is a directory: {out_path}")
    tmp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=out_path.parent,
            prefix=".vld8-report-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            tmp_name = handle.name
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, out_path)
        tmp_name = None
    finally:
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def run_report(
    *,
    findings_path: str | Path | None,
    prepare_path: str | Path | None = None,
    prior_path: str | Path | None = None,
    repo_path: str | Path = ".",
    fmt: str = "md",
    out_path: str | Path | None = None,
    stdout: Any = None,
    stderr: Any = None,
) -> int:
    """Execute ``vld8 review report`` end-to-end and return exit code (0/1/2)."""
    import sys

    out_stream = sys.stdout if stdout is None else stdout
    err_stream = sys.stderr if stderr is None else stderr

    if fmt not in VALID_FORMATS:
        print(
            f"ERROR: unsupported --format {findings._safe_label(fmt)}; "
            "expected md, json, or sarif",
            file=err_stream,
        )
        return 2

    report = build_report(
        findings_path=findings_path,
        prepare_path=prepare_path,
        prior_path=prior_path,
        repo_path=repo_path,
    )
    rendered = render_report(report, fmt)

    if out_path is not None:
        try:
            _atomic_write(Path(out_path), rendered)
        except OSError as exc:
            detail = findings._safe_label(exc.strerror or str(exc))
            print(
                f"ERROR: cannot write report to "
                f"{findings._safe_label(str(out_path))}: {detail}",
                file=err_stream,
            )
            return 2
    else:
        out_stream.write(rendered)
        if hasattr(out_stream, "flush"):
            out_stream.flush()

    if report["exitCode"] == 2:
        for msg in _error_messages(report["errors"]):
            print(f"ERROR: {msg}", file=err_stream)

    return int(report["exitCode"])
