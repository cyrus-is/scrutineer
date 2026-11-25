"""Findings contract v1 loader, validator, and deterministic fingerprints.

Implements validation and fingerprinting for ``vld8/schemas/findings-v1.json``
using only the Python standard library.
"""

import copy
import functools
import hashlib
import json
import os
import re
import reprlib
import stat
import textwrap
from pathlib import Path
from typing import Any

from . import paths

SCHEMA_VERSION = "1.0"
SCHEMA_PATH = paths.FINDINGS_SCHEMA

MAX_FINDINGS_BYTES = 10 * 1024 * 1024
MAX_FINDINGS_COUNT = 10_000
MAX_DISMISSALS_COUNT = 10_000
MAX_CLASS_SITES = 500
MAX_CANDIDATE_IDS = 256
MAX_PATH_LENGTH = 1024
MAX_IDENTIFIER_LENGTH = 128
MAX_LINE_LENGTH = 1024
MAX_PACKAGE_LENGTH = 256
MAX_VERSION_LENGTH = 128
MAX_CATEGORY_LENGTH = 128
MAX_SHORT_TEXT_LENGTH = 4096
MAX_LONG_TEXT_LENGTH = 16384

VALID_LENSES = frozenset({"code", "security", "mcp"})
CODE_CATEGORIES = frozenset(
    {
        "production-reliability",
        "correctness",
        "data-integrity",
        "error-handling",
        "architecture",
        "operability",
        "performance",
        "maintainability",
    }
)
CODE_SEVERITIES = frozenset({"ISSUE", "CONCERN"})
SECURITY_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})
VALID_SEVERITIES = CODE_SEVERITIES | SECURITY_SEVERITIES
VALID_BASES = frozenset(
    {
        "written rule",
        "confirmed map rule",
        "stated requirement",
        "followed contract",
        "reachable trigger",
        "security invariant",
    }
)
VALID_SOURCES = frozenset({"code", "model", "both"})
VALID_DISPOSITIONS = frozenset(
    {"open", "closed", "partly-closed", "disputed", "recurring"}
)
VALID_PROOF_KINDS = frozenset(
    {"test", "probe", "query", "canary", "linter", "sarif", "osv", "rule"}
)
VALID_PROOF_STATUSES = frozenset({"verified", "unverified", "failed", "not-run"})

_DOC_KEYS = frozenset({"schemaVersion", "lens", "treeId", "findings", "dismissals"})
_PROOF_KEYS = frozenset({"kind", "status", "detail", "command", "target"})
_SITE_KEYS = frozenset({"file", "lineStart", "lineEnd", "quote", "candidateId"})
_CLASS_KEYS = frozenset({"rule", "sites", "fixSite", "closes"})
_CLOSES_KEYS = frozenset({"closed", "total"})
_DISMISSAL_KEYS = frozenset({"candidateId", "reason"})
_FINDING_REQUIRED_KEYS = (
    "file",
    "lineStart",
    "lineEnd",
    "quote",
    "lens",
    "checkId",
    "claim",
    "evidence",
    "severity",
    "blocking",
    "source",
    "fingerprint",
)
_FINDING_OPTIONAL_KEYS = frozenset(
    {
        "category",
        "basis",
        "proof",
        "class",
        "classFingerprint",
        "disposition",
        "suppressed",
        "reason",
        "package",
        "version",
        "candidateIds",
        "recommendation",
    }
)
_FINDING_KEYS = frozenset(_FINDING_REQUIRED_KEYS) | _FINDING_OPTIONAL_KEYS

_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z", re.ASCII)
_TREE_ID_RE = re.compile(r"^(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z", re.ASCII)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}\Z", re.ASCII)
_DRIVE_PREFIX_RE = re.compile(r"^[A-Za-z]:", re.ASCII)
_ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))")

_BOUNDED_REPR = reprlib.Repr()
_BOUNDED_REPR.maxlevel = 2
_BOUNDED_REPR.maxdict = 4
_BOUNDED_REPR.maxlist = 4
_BOUNDED_REPR.maxtuple = 4
_BOUNDED_REPR.maxset = 4
_BOUNDED_REPR.maxfrozenset = 4
_BOUNDED_REPR.maxstring = 128
_BOUNDED_REPR.maxother = 128


class FindingsError(ValueError):
    """Raised when a findings file or schema cannot be read or parsed."""


class FindingsValidationError(FindingsError):
    """Raised when a parsed findings document fails contract validation."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = list(errors)
        preview = "; ".join(self.errors[:3])
        if len(self.errors) > 3:
            preview += f" (+{len(self.errors) - 3} more)"
        super().__init__(f"invalid findings document: {preview}")


def schema_path() -> Path:
    """Return the path to the bundled findings-v1 JSON Schema."""
    return SCHEMA_PATH


@functools.lru_cache(maxsize=1)
def _load_schema_cached() -> dict[str, Any]:
    path = schema_path()
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FindingsError(f"cannot read findings schema {path.name}: {exc}") from exc
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FindingsError(f"invalid findings schema JSON: {exc}") from exc
    if not isinstance(loaded, dict):
        raise FindingsError("findings schema root must be a JSON object")
    return loaded


def load_schema() -> dict[str, Any]:
    """Return a deep copy of the bundled findings-v1 JSON Schema."""
    return copy.deepcopy(_load_schema_cached())


def _safe_label(value: Any, *, max_len: int = 64) -> str:
    """Render untrusted input safely in O(1) without terminal control escapes."""
    if isinstance(value, str):
        truncated = len(value) > max_len * 4
        text = value[: max_len * 4]
    else:
        truncated = False
        text = _BOUNDED_REPR.repr(value)
    text = _ANSI_RE.sub(" ", text)
    cleaned: list[str] = []
    for ch in text:
        code = ord(ch)
        if code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            cleaned.append(f"\\x{code:02x}")
        elif 0xD800 <= code <= 0xDFFF or code in (0x2028, 0x2029):
            cleaned.append(f"\\u{code:04x}")
        else:
            cleaned.append(ch)
    out = "".join(cleaned)
    if truncated or len(out) > max_len:
        return out[: max_len - 3] + "..."
    return out


def _is_strict_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _has_control_char(value: str) -> bool:
    return any(
        ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F or ch in ("\u2028", "\u2029")
        for ch in value
    )


def _has_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in value)


def _validate_identifier(value: Any, label: str, errors: list[str]) -> bool:
    if not isinstance(value, str):
        errors.append(f"{label}: expected string, got {type(value).__name__}")
        return False
    if not _IDENTIFIER_RE.match(value):
        errors.append(
            f"{label}: must be 1..{MAX_IDENTIFIER_LENGTH} ASCII identifier chars "
            f"(got {_safe_label(value)})"
        )
        return False
    return True


def _validate_tree_id(value: Any, label: str, errors: list[str]) -> bool:
    if not isinstance(value, str):
        errors.append(f"{label}: expected string, got {type(value).__name__}")
        return False
    if not _TREE_ID_RE.match(value):
        errors.append(
            f"{label}: must be a safe single-segment tree identifier "
            f"(got {_safe_label(value)})"
        )
        return False
    return True


def _validate_sha256(value: Any, label: str, errors: list[str]) -> bool:
    if not isinstance(value, str):
        errors.append(f"{label}: expected string, got {type(value).__name__}")
        return False
    if not _SHA256_RE.match(value):
        errors.append(
            f"{label}: must be a 64-character lowercase hex SHA-256 digest "
            f"(got {_safe_label(value)})"
        )
        return False
    return True


def _validate_non_blank_line(
    value: Any,
    label: str,
    errors: list[str],
    *,
    max_len: int = MAX_LINE_LENGTH,
) -> bool:
    if not isinstance(value, str):
        errors.append(f"{label}: expected string, got {type(value).__name__}")
        return False
    if len(value) > max_len:
        errors.append(f"{label}: length {len(value)} exceeds max {max_len}")
        return False
    if _has_control_char(value):
        errors.append(f"{label}: control characters are not allowed")
        return False
    if _has_surrogate(value):
        errors.append(f"{label}: unpaired UTF-16 surrogates are not allowed")
        return False
    if not value.strip():
        errors.append(f"{label}: must not be empty or whitespace-only")
        return False
    return True


def _validate_non_blank_text(
    value: Any,
    label: str,
    errors: list[str],
    *,
    max_len: int = MAX_SHORT_TEXT_LENGTH,
) -> bool:
    if not isinstance(value, str):
        errors.append(f"{label}: expected string, got {type(value).__name__}")
        return False
    if len(value) > max_len:
        errors.append(f"{label}: length {len(value)} exceeds max {max_len}")
        return False
    if "\x00" in value:
        errors.append(f"{label}: NUL byte is not allowed")
        return False
    if _has_surrogate(value):
        errors.append(f"{label}: unpaired UTF-16 surrogates are not allowed")
        return False
    if not value.strip():
        errors.append(f"{label}: must not be empty or whitespace-only")
        return False
    return True


def _validate_repo_relative_path(value: Any, label: str, errors: list[str]) -> bool:
    if not isinstance(value, str):
        errors.append(f"{label}: expected string, got {type(value).__name__}")
        return False
    if not value:
        errors.append(f"{label}: must not be empty")
        return False
    if len(value) > MAX_PATH_LENGTH:
        errors.append(
            f"{label}: path length {len(value)} exceeds max {MAX_PATH_LENGTH}"
        )
        return False
    if _has_control_char(value):
        errors.append(f"{label}: control characters are not allowed in paths")
        return False
    if _has_surrogate(value):
        errors.append(f"{label}: unpaired UTF-16 surrogates are not allowed in paths")
        return False
    if "\\" in value:
        errors.append(f"{label}: backslashes are not allowed in repo-relative paths")
        return False
    if value.startswith("/") or value.endswith("/"):
        errors.append(f"{label}: path must be relative with no leading or trailing '/'")
        return False
    if _DRIVE_PREFIX_RE.match(value):
        errors.append(f"{label}: drive prefixes are not allowed in repo-relative paths")
        return False
    segments = value.split("/")
    if any(seg in {"", ".", ".."} for seg in segments):
        errors.append(f"{label}: path must not contain empty, '.', or '..' segments")
        return False
    return True


def _validate_enum(
    value: Any,
    label: str,
    valid: frozenset[str],
    errors: list[str],
) -> bool:
    if not isinstance(value, str):
        errors.append(f"{label}: expected string, got {type(value).__name__}")
        return False
    if value not in valid:
        allowed = ", ".join(sorted(valid))
        errors.append(
            f"{label}: invalid value {_safe_label(value)}; expected one of: {allowed}"
        )
        return False
    return True


def _check_unknown_keys(
    obj: dict[str, Any],
    allowed: frozenset[str],
    prefix: str,
    errors: list[str],
) -> None:
    extra = sorted(k for k in obj if k not in allowed)
    for key in extra:
        errors.append(f"{prefix}.{_safe_label(key)}: unknown property")


def _validate_line_range(
    obj: dict[str, Any],
    prefix: str,
    errors: list[str],
) -> None:
    start = obj.get("lineStart")
    end = obj.get("lineEnd")
    start_ok = _is_strict_int(start) and start >= 1
    end_ok = _is_strict_int(end) and end >= 1
    if "lineStart" in obj and not start_ok:
        errors.append(f"{prefix}.lineStart: expected integer >= 1")
    if "lineEnd" in obj and not end_ok:
        errors.append(f"{prefix}.lineEnd: expected integer >= 1")
    if start_ok and end_ok and end < start:
        errors.append(f"{prefix}.lineEnd: {end} must be >= lineStart ({start})")


def _validate_site_ref(value: Any, prefix: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{prefix}: expected object, got {type(value).__name__}")
        return
    _check_unknown_keys(value, _SITE_KEYS, prefix, errors)
    for req in ("file", "lineStart", "lineEnd"):
        if req not in value:
            errors.append(f"{prefix}.{req}: missing required property")
    if "file" in value:
        _validate_repo_relative_path(value["file"], f"{prefix}.file", errors)
    _validate_line_range(value, prefix, errors)
    if "quote" in value and value["quote"] is not None:
        _validate_non_blank_text(
            value["quote"], f"{prefix}.quote", errors, max_len=MAX_LONG_TEXT_LENGTH
        )
    if "candidateId" in value and value["candidateId"] is not None:
        _validate_identifier(value["candidateId"], f"{prefix}.candidateId", errors)


def _validate_proof(value: Any, prefix: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{prefix}: expected object, got {type(value).__name__}")
        return
    _check_unknown_keys(value, _PROOF_KEYS, prefix, errors)
    for req in ("kind", "status"):
        if req not in value:
            errors.append(f"{prefix}.{req}: missing required property")
    if "kind" in value:
        _validate_enum(value["kind"], f"{prefix}.kind", VALID_PROOF_KINDS, errors)
    if "status" in value:
        _validate_enum(
            value["status"], f"{prefix}.status", VALID_PROOF_STATUSES, errors
        )
    if "detail" in value and value["detail"] is not None:
        _validate_non_blank_text(value["detail"], f"{prefix}.detail", errors)
    if "command" in value and value["command"] is not None:
        _validate_non_blank_line(value["command"], f"{prefix}.command", errors)
    if "target" in value and value["target"] is not None:
        _validate_non_blank_line(value["target"], f"{prefix}.target", errors)


def _validate_finding_class(value: Any, prefix: str, errors: list[str]) -> None:
    if not isinstance(value, dict):
        errors.append(f"{prefix}: expected object, got {type(value).__name__}")
        return
    _check_unknown_keys(value, _CLASS_KEYS, prefix, errors)
    for req in ("rule", "sites", "fixSite", "closes"):
        if req not in value:
            errors.append(f"{prefix}.{req}: missing required property")
    if "rule" in value:
        _validate_non_blank_text(value["rule"], f"{prefix}.rule", errors)
    sites_len: int | None = None
    if "sites" in value:
        sites = value["sites"]
        if not isinstance(sites, list):
            errors.append(f"{prefix}.sites: expected array, got {type(sites).__name__}")
        elif not sites:
            errors.append(f"{prefix}.sites: must contain at least 1 site")
        elif len(sites) > MAX_CLASS_SITES:
            errors.append(
                f"{prefix}.sites: length {len(sites)} exceeds max {MAX_CLASS_SITES}"
            )
        else:
            sites_len = len(sites)
            for idx, site in enumerate(sites):
                _validate_site_ref(site, f"{prefix}.sites[{idx}]", errors)
    if "fixSite" in value:
        _validate_site_ref(value["fixSite"], f"{prefix}.fixSite", errors)
    if "closes" in value:
        closes = value["closes"]
        if not isinstance(closes, dict):
            errors.append(
                f"{prefix}.closes: expected object, got {type(closes).__name__}"
            )
        else:
            _check_unknown_keys(closes, _CLOSES_KEYS, f"{prefix}.closes", errors)
            for req in ("closed", "total"):
                if req not in closes:
                    errors.append(f"{prefix}.closes.{req}: missing required property")
            closed = closes.get("closed")
            total = closes.get("total")
            closed_ok = _is_strict_int(closed) and closed >= 0
            total_ok = _is_strict_int(total) and total >= 1
            if "closed" in closes and not closed_ok:
                errors.append(f"{prefix}.closes.closed: expected integer >= 0")
            if "total" in closes and not total_ok:
                errors.append(f"{prefix}.closes.total: expected integer >= 1")
            if closed_ok and total_ok and closed > total:
                errors.append(
                    f"{prefix}.closes.closed: {closed} must be <= total ({total})"
                )
            if total_ok and sites_len is not None and total < sites_len:
                errors.append(
                    f"{prefix}.closes.total: {total} must be >= "
                    f"len(sites) ({sites_len})"
                )


def _validate_dismissal(
    value: Any,
    prefix: str,
    seen_ids: set[str],
    errors: list[str],
) -> None:
    if not isinstance(value, dict):
        errors.append(f"{prefix}: expected object, got {type(value).__name__}")
        return
    _check_unknown_keys(value, _DISMISSAL_KEYS, prefix, errors)
    for req in ("candidateId", "reason"):
        if req not in value:
            errors.append(f"{prefix}.{req}: missing required property")
    if "candidateId" in value and _validate_identifier(
        value["candidateId"], f"{prefix}.candidateId", errors
    ):
        cid = value["candidateId"]
        if cid in seen_ids:
            errors.append(
                f"{prefix}.candidateId: duplicate dismissal for {_safe_label(cid)}"
            )
        seen_ids.add(cid)
    if "reason" in value:
        _validate_non_blank_text(value["reason"], f"{prefix}.reason", errors)


def normalize_code_region(text: str) -> str:
    """Normalize a code region deterministically for fingerprinting.

    Converts CRLF/CR line endings to LF, strips trailing spaces/tabs per line,
    removes leading and trailing blank lines, and applies ``textwrap.dedent``.
    """
    if not isinstance(text, str):
        raise ValueError(f"code_region must be a string, got {type(text).__name__}")
    if "\x00" in text:
        raise ValueError("code_region must not contain NUL bytes")
    if _has_surrogate(text):
        raise ValueError("code_region must not contain unpaired UTF-16 surrogates")
    unified = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip(" \t") for line in unified.split("\n")]
    start = 0
    end = len(lines)
    while start < end and lines[start] == "":
        start += 1
    while end > start and lines[end - 1] == "":
        end -= 1
    if start == end:
        return ""
    return textwrap.dedent("\n".join(lines[start:end]))


def _sha256_canonical(payload: list[str]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def compute_fingerprint(
    check_id: str,
    code_region: str,
    *,
    package: str | None = None,
    version: str | None = None,
) -> str:
    """Compute a deterministic SHA-256 fingerprint for a finding site."""
    if not isinstance(check_id, str) or not _IDENTIFIER_RE.match(check_id):
        raise ValueError(
            f"check_id must be 1..{MAX_IDENTIFIER_LENGTH} ASCII identifier chars"
        )
    normalized = normalize_code_region(code_region)
    if not normalized:
        raise ValueError("code_region must not be empty or whitespace-only")

    payload: list[str] = ["v1", "finding", check_id, normalized]
    if version is not None and package is None:
        raise ValueError("package is required when version is provided")
    if package is not None:
        errs: list[str] = []
        if not _validate_non_blank_line(
            package, "package", errs, max_len=MAX_PACKAGE_LENGTH
        ):
            raise ValueError(errs[0])
        payload.append(package.strip())
    if version is not None:
        errs = []
        if not _validate_non_blank_line(
            version, "version", errs, max_len=MAX_VERSION_LENGTH
        ):
            raise ValueError(errs[0])
        payload.append(version.strip())
    return _sha256_canonical(payload)


def compute_class_fingerprint(
    check_id: str,
    fix_site_file: str,
    fix_site_region: str,
) -> str:
    """Compute a deterministic SHA-256 fingerprint for a finding class fix site."""
    if not isinstance(check_id, str) or not _IDENTIFIER_RE.match(check_id):
        raise ValueError(
            f"check_id must be 1..{MAX_IDENTIFIER_LENGTH} ASCII identifier chars"
        )
    errs: list[str] = []
    if not _validate_repo_relative_path(fix_site_file, "fix_site_file", errs):
        raise ValueError(errs[0])
    normalized = normalize_code_region(fix_site_region)
    if not normalized:
        raise ValueError("fix_site_region must not be empty or whitespace-only")
    return _sha256_canonical(["v1", "class", check_id, fix_site_file, normalized])


def validate_finding(
    finding: Any,
    *,
    prefix: str = "finding",
    expected_lens: str | None = None,
) -> list[str]:
    """Validate a single finding dict against Findings Contract v1."""
    errors: list[str] = []
    if not isinstance(finding, dict):
        return [f"{prefix}: expected object, got {type(finding).__name__}"]

    _check_unknown_keys(finding, _FINDING_KEYS, prefix, errors)
    for req in _FINDING_REQUIRED_KEYS:
        if req not in finding:
            errors.append(f"{prefix}.{req}: missing required property")

    if "file" in finding:
        _validate_repo_relative_path(finding["file"], f"{prefix}.file", errors)
    _validate_line_range(finding, prefix, errors)
    if "quote" in finding:
        _validate_non_blank_text(
            finding["quote"], f"{prefix}.quote", errors, max_len=MAX_LONG_TEXT_LENGTH
        )

    lens_val: str | None = None
    if "lens" in finding and _validate_enum(
        finding["lens"], f"{prefix}.lens", VALID_LENSES, errors
    ):
        lens_val = finding["lens"]
        if expected_lens is not None and lens_val != expected_lens:
            errors.append(
                f"{prefix}.lens: expected {_safe_label(expected_lens)} to match "
                f"document lens, got {_safe_label(lens_val)}"
            )

    if "checkId" in finding:
        _validate_identifier(finding["checkId"], f"{prefix}.checkId", errors)
    if "category" in finding and finding["category"] is not None:
        _validate_non_blank_line(
            finding["category"],
            f"{prefix}.category",
            errors,
            max_len=MAX_CATEGORY_LENGTH,
        )
    if "claim" in finding:
        _validate_non_blank_text(finding["claim"], f"{prefix}.claim", errors)
    if "evidence" in finding:
        _validate_non_blank_text(
            finding["evidence"],
            f"{prefix}.evidence",
            errors,
            max_len=MAX_LONG_TEXT_LENGTH,
        )

    if "severity" in finding:
        allowed_sev = CODE_SEVERITIES if lens_val == "code" else VALID_SEVERITIES
        _validate_enum(finding["severity"], f"{prefix}.severity", allowed_sev, errors)

    if "basis" in finding and finding["basis"] is not None:
        _validate_enum(finding["basis"], f"{prefix}.basis", VALID_BASES, errors)

    if "blocking" in finding and not isinstance(finding["blocking"], bool):
        kind = type(finding["blocking"]).__name__
        errors.append(f"{prefix}.blocking: expected boolean, got {kind}")

    if "source" in finding:
        _validate_enum(finding["source"], f"{prefix}.source", VALID_SOURCES, errors)

    if "proof" in finding and finding["proof"] is not None:
        _validate_proof(finding["proof"], f"{prefix}.proof", errors)

    has_class = isinstance(finding.get("class"), dict)
    if "class" in finding and finding["class"] is not None:
        _validate_finding_class(finding["class"], f"{prefix}.class", errors)

    if "classFingerprint" in finding and finding["classFingerprint"] is not None:
        _validate_sha256(
            finding["classFingerprint"], f"{prefix}.classFingerprint", errors
        )
    elif has_class:
        errors.append(
            f"{prefix}.classFingerprint: required and non-null when class is present"
        )

    disp_val: str | None = None
    if "disposition" in finding and finding["disposition"] is not None:
        if _validate_enum(
            finding["disposition"], f"{prefix}.disposition", VALID_DISPOSITIONS, errors
        ):
            disp_val = finding["disposition"]

    suppressed_val = False
    if "suppressed" in finding:
        if not isinstance(finding["suppressed"], bool):
            errors.append(
                f"{prefix}.suppressed: expected boolean, "
                f"got {type(finding['suppressed']).__name__}"
            )
        else:
            suppressed_val = finding["suppressed"]

    reason_present = "reason" in finding and finding["reason"] is not None
    if reason_present:
        _validate_non_blank_text(finding["reason"], f"{prefix}.reason", errors)
    if suppressed_val and not reason_present:
        errors.append(f"{prefix}.reason: required when suppressed is true")
    if disp_val == "disputed" and not reason_present:
        errors.append(f"{prefix}.reason: required when disposition is 'disputed'")

    pkg_val = finding.get("package")
    if "package" in finding and pkg_val is not None:
        _validate_non_blank_line(
            pkg_val, f"{prefix}.package", errors, max_len=MAX_PACKAGE_LENGTH
        )
    if "version" in finding and finding["version"] is not None:
        _validate_non_blank_line(
            finding["version"], f"{prefix}.version", errors, max_len=MAX_VERSION_LENGTH
        )
        if pkg_val is None:
            errors.append(f"{prefix}.package: required when version is specified")

    if "candidateIds" in finding:
        cids = finding["candidateIds"]
        if not isinstance(cids, list):
            errors.append(
                f"{prefix}.candidateIds: expected array, got {type(cids).__name__}"
            )
        elif len(cids) > MAX_CANDIDATE_IDS:
            errors.append(
                f"{prefix}.candidateIds: length {len(cids)} exceeds max "
                f"{MAX_CANDIDATE_IDS}"
            )
        else:
            seen_cids: set[str] = set()
            for idx, cid in enumerate(cids):
                if _validate_identifier(cid, f"{prefix}.candidateIds[{idx}]", errors):
                    if cid in seen_cids:
                        errors.append(
                            f"{prefix}.candidateIds[{idx}]: duplicate candidateId "
                            f"{_safe_label(cid)}"
                        )
                    seen_cids.add(cid)

    if "recommendation" in finding and finding["recommendation"] is not None:
        _validate_non_blank_text(
            finding["recommendation"], f"{prefix}.recommendation", errors
        )

    if "fingerprint" in finding:
        _validate_sha256(finding["fingerprint"], f"{prefix}.fingerprint", errors)

    return errors


def validate_findings_doc(data: Any) -> list[str]:
    """Validate a parsed findings document against Findings Contract v1."""
    if not isinstance(data, dict):
        return [f"root: expected JSON object, got {type(data).__name__}"]

    errors: list[str] = []
    _check_unknown_keys(data, _DOC_KEYS, "root", errors)

    if "schemaVersion" not in data:
        errors.append("root.schemaVersion: missing required property")
    elif data["schemaVersion"] != SCHEMA_VERSION:
        errors.append(
            f"root.schemaVersion: expected {SCHEMA_VERSION!r}, "
            f"got {_safe_label(data['schemaVersion'])}"
        )

    doc_lens: str | None = None
    if "lens" in data and data["lens"] is not None:
        if _validate_enum(data["lens"], "root.lens", VALID_LENSES, errors):
            doc_lens = data["lens"]

    if "treeId" in data and data["treeId"] is not None:
        _validate_tree_id(data["treeId"], "root.treeId", errors)

    if "findings" not in data:
        errors.append("root.findings: missing required property")
    else:
        findings = data["findings"]
        if not isinstance(findings, list):
            errors.append(
                f"root.findings: expected array, got {type(findings).__name__}"
            )
        elif len(findings) > MAX_FINDINGS_COUNT:
            errors.append(
                f"root.findings: length {len(findings)} exceeds max "
                f"{MAX_FINDINGS_COUNT}"
            )
        else:
            for idx, item in enumerate(findings):
                errors.extend(
                    validate_finding(
                        item, prefix=f"findings[{idx}]", expected_lens=doc_lens
                    )
                )

    if "dismissals" in data:
        dismissals = data["dismissals"]
        if not isinstance(dismissals, list):
            errors.append(
                f"root.dismissals: expected array, got {type(dismissals).__name__}"
            )
        elif len(dismissals) > MAX_DISMISSALS_COUNT:
            errors.append(
                f"root.dismissals: length {len(dismissals)} exceeds max "
                f"{MAX_DISMISSALS_COUNT}"
            )
        else:
            seen_ids: set[str] = set()
            for idx, dismissal in enumerate(dismissals):
                _validate_dismissal(dismissal, f"dismissals[{idx}]", seen_ids, errors)

    return errors


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key {_safe_label(key)}")
        obj[key] = value
    return obj


def _reject_json_constant(token: str) -> Any:
    raise ValueError(f"non-standard JSON constant {_safe_label(token)} is not allowed")


def load_findings_file(
    path: str | Path,
    *,
    validate: bool = True,
    max_bytes: int = MAX_FINDINGS_BYTES,
) -> dict[str, Any]:
    """Read, size-check, parse, and optionally validate a findings JSON file."""
    if not _is_strict_int(max_bytes) or max_bytes < 1:
        raise ValueError("max_bytes must be a positive integer")
    if not isinstance(validate, bool):
        raise ValueError("validate must be a boolean")

    target = Path(path)
    safe_name = _safe_label(target.name)
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(target), flags)
    except (OSError, ValueError) as exc:
        detail = _safe_label(getattr(exc, "strerror", None) or str(exc))
        raise FindingsError(f"cannot open findings file {safe_name}: {detail}") from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise FindingsError(f"findings path is not a regular file: {safe_name}")
        if st.st_size > max_bytes:
            raise FindingsError(
                f"findings file {safe_name} ({st.st_size} bytes) "
                f"exceeds max {max_bytes} bytes"
            )
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw = handle.read(max_bytes + 1)
    except OSError as exc:
        detail = _safe_label(exc.strerror or str(exc))
        raise FindingsError(f"cannot read findings file {safe_name}: {detail}") from exc
    finally:
        if fd != -1:
            os.close(fd)

    if len(raw) > max_bytes:
        raise FindingsError(f"findings file {safe_name} exceeds max {max_bytes} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FindingsError(
            f"findings file {safe_name} is not valid UTF-8: {exc}"
        ) from exc

    try:
        data = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise FindingsError(f"invalid JSON in {safe_name}: {exc}") from exc

    if not isinstance(data, dict):
        raise FindingsError(f"findings file {safe_name} must contain a JSON object")

    if validate:
        errors = validate_findings_doc(data)
        if errors:
            raise FindingsValidationError(errors)

    return data
