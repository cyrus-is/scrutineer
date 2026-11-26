"""Context packet builder for ``vld8 review prepare`` (#52, #56, #127, #128).

Collects repository rules files, intent sources (``--spec``, PR body, changed
design/plan docs, optional linked issues), and tree-matched ``--evidence`` under
a deterministic character budget with fence-safe Markdown quoting helpers using
only the Python standard library plus :mod:`vld8.checks`, :mod:`vld8.findings`,
:mod:`vld8.report`, and :mod:`vld8.trust`.
"""

import hashlib
import json
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import checks, findings, report, trust

SCHEMA_VERSION = "1.0"

RULES_FILENAMES: tuple[str, ...] = (
    "CLAUDE.md",
    "AGENTS.md",
    "ENGINEERING.md",
    "CONTRIBUTING.md",
)
_RULES_NAME_SET = frozenset(RULES_FILENAMES)

DEFAULT_PACKET_BUDGET_CHARS = 64_000
MIN_PACKET_BUDGET_CHARS = 1024
MAX_PACKET_BUDGET_CHARS = 512_000
MAX_SECTION_TEXT_CHARS = findings.MAX_LONG_TEXT_LENGTH
MAX_RULE_FILE_BYTES = 256 * 1024
_MAX_ALLOWED_FILE_BYTES = 2 * 1024 * 1024

MAX_CHANGED_PATHS = 5_000
MAX_RULES_DIRS = 2_000
_GIT_LS_TREE_BATCH_SIZE = 400
MAX_RULES_FILES = 64
MAX_INTENT_SOURCES = 32
MAX_DESIGN_DOCS = 16
MAX_LINKED_ISSUES = 16
MAX_EVIDENCE_FILES = 16
MAX_EVIDENCE_TOOLS = 256
MAX_EVIDENCE_EXCLUSIONS = 2_000
MAX_SARIF_PACKET_RESULTS = 200
MAX_WARNINGS = 128

_TRUNC_SUFFIX = "\n[truncated]"
_FENCED_BLOCK_RE = re.compile(r"```.*?```", re.DOTALL)
_ISSUE_REF_RE = re.compile(
    r"(?:^|[\s(\[,;])#([1-9][0-9]{0,7})(?![0-9A-Za-z_-])", re.ASCII
)
_DESIGN_DIR_PREFIXES: tuple[tuple[str, ...], ...] = (
    ("docs", "plans"),
    ("docs", "design"),
    ("docs", "adr"),
    ("docs", "adrs"),
    ("docs", "rfc"),
    ("docs", "rfcs"),
    ("docs", "specs"),
    ("adr",),
    ("rfcs",),
    ("specs",),
)
_DESIGN_STEMS = frozenset({"design", "spec", "roadmap"})
_DESIGN_PREFIXES = ("design-", "spec-", "adr-", "rfc-")


class PacketError(ValueError):
    """Raised when rules, intent, evidence, or packet budget validation fails."""


@dataclass(frozen=True)
class PacketBuildResult:
    """Deterministic budgeted context packet and accepted code findings."""

    packet: dict[str, Any]
    code_findings: list[dict[str, Any]]
    unruled: list[dict[str, Any]]


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _validate_max_file_bytes(max_file_bytes: Any) -> int:
    if (
        not findings._is_strict_int(max_file_bytes)
        or max_file_bytes < 1
        or max_file_bytes > _MAX_ALLOWED_FILE_BYTES
    ):
        raise PacketError(
            f"max_file_bytes must be an integer between 1 and {_MAX_ALLOWED_FILE_BYTES}"
        )
    return max_file_bytes


def _validate_single_git_ref_no_colon(ref: Any, *, label: str) -> str:
    try:
        clean_ref = trust._validate_single_git_ref(ref, label=label)
    except trust.TrustError as exc:
        raise PacketError(str(exc)) from exc
    if ":" in clean_ref:
        raise PacketError(
            f"{label}: expected single git ref without ':' "
            f"(got {checks.safe_error_text(clean_ref)})"
        )
    return clean_ref


def _validate_changed_paths(changed_paths: Sequence[str]) -> list[str]:
    if isinstance(changed_paths, (str, bytes)) or not isinstance(
        changed_paths, Sequence
    ):
        raise PacketError("changed_paths must be a sequence of repo-relative paths")
    if len(changed_paths) > MAX_CHANGED_PATHS:
        raise PacketError(
            f"changed_paths count {len(changed_paths)} exceeds max {MAX_CHANGED_PATHS}"
        )
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw_path in changed_paths:
        try:
            rel = checks.validate_repo_relative_path(raw_path)
        except checks.ChecksError as exc:
            raise PacketError(str(exc)) from exc
        if rel not in seen:
            seen.add(rel)
            cleaned.append(rel)
    return cleaned


def _pr_meta_is_trusted(pr_meta: trust.PRMetadata) -> bool:
    return (
        trust.can_run_repo_tools(pr_meta.trusted)
        and pr_meta.is_cross_repository is False
        and pr_meta.author_is_bot is False
    )


def _resolve_effective_trusted(
    trusted: bool | None,
    pr_meta: trust.PRMetadata | None,
) -> bool:
    if trusted is not None and not isinstance(trusted, bool):
        raise PacketError("trusted must be a boolean or None")
    if pr_meta is not None and not isinstance(pr_meta, trust.PRMetadata):
        raise PacketError("pr_meta must be a PRMetadata instance or None")
    if pr_meta is None:
        return True if trusted is None else trusted
    pr_trusted = _pr_meta_is_trusted(pr_meta)
    if trusted is True and not pr_trusted:
        raise PacketError(
            "trusted=True cannot be used with an untrusted, fork, or bot PR"
        )
    if trusted is False:
        return False
    return pr_trusted


def _decode_and_sanitize_text(raw: bytes) -> tuple[str, str]:
    text = report._sanitize_text(
        raw.decode("utf-8", errors="replace"), allow_newlines=True
    )
    return text, _sha256_text(text)


def _append_warning(warnings: list[str], msg: str) -> None:
    if len(warnings) < MAX_WARNINGS:
        clean = report._sanitize_text(msg, allow_newlines=False)
        if len(clean) > 512:
            clean = clean[:509] + "..."
        warnings.append(clean)


def format_quoted_block(text: str, *, info: str = "") -> str:
    """Wrap sanitized untrusted text in a dynamically sized backtick fence."""
    if not isinstance(text, str):
        raise PacketError(f"quoted text must be str, got {type(text).__name__}")
    if not isinstance(info, str):
        raise PacketError(f"fence info must be str, got {type(info).__name__}")
    clean_text = report._sanitize_text(text, allow_newlines=True)
    clean_info = (
        checks.safe_error_text(info, max_len=64).strip().replace("`", "")
        if info
        else ""
    )
    max_run = 0
    for match in re.finditer(r"`+", clean_text):
        run_len = len(match.group(0))
        if run_len > max_run:
            max_run = run_len
    fence = "`" * max(3, max_run + 1)
    header = f"{fence}{clean_info}" if clean_info else fence
    if not clean_text:
        return f"{header}\n{fence}"
    body = clean_text if clean_text.endswith("\n") else f"{clean_text}\n"
    return f"{header}\n{body}{fence}"


def _lookup_git_tree_blobs(
    repo_root: Path,
    tree_ref: str,
    candidate_paths: Sequence[str],
) -> dict[str, tuple[str, int]]:
    """Batch-lookup regular non-symlink blobs in ``tree_ref`` via ``git ls-tree``."""
    if not candidate_paths:
        return {}
    pathspecs = [f":(literal){rel}" for rel in candidate_paths]
    try:
        ls_raw = trust._run_git_or_gh(
            [
                "git",
                "-C",
                str(repo_root),
                "ls-tree",
                "--full-tree",
                "-r",
                "-z",
                "-l",
                tree_ref,
                "--",
                *pathspecs,
            ],
            cwd=repo_root,
        )
    except trust.TrustError as exc:
        raise PacketError(str(exc)) from exc

    wanted = set(candidate_paths)
    found: dict[str, tuple[str, int]] = {}
    for rec in ls_raw.split(b"\x00"):
        if not rec:
            continue
        meta, sep, path_bytes = rec.partition(b"\t")
        if not sep:
            continue
        entry_path = path_bytes.decode("utf-8", "surrogateescape")
        if entry_path not in wanted:
            continue
        parts = meta.decode("ascii", "replace").split()
        if len(parts) != 4:
            continue
        mode, obj_type, oid, size_str = parts
        if (
            mode not in ("100644", "100755")
            or obj_type != "blob"
            or not checks._GIT_OID_RE.match(oid)
            or not size_str.isdigit()
        ):
            continue
        found[entry_path] = (oid, int(size_str))
    return found


def collect_rules_files(
    repo_root: str | Path,
    changed_paths: Sequence[str] = (),
    *,
    base_ref: str | None = None,
    trusted: bool = True,
    max_file_bytes: int = MAX_RULE_FILE_BYTES,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Collect root and changed-subtree rules files in deterministic order."""
    if not isinstance(trusted, bool):
        raise PacketError("trusted must be a boolean")
    file_cap = _validate_max_file_bytes(max_file_bytes)
    try:
        resolved_repo, _ = checks.resolve_repo_root(repo_root)
    except checks.ChecksError as exc:
        raise PacketError(str(exc)) from exc
    clean_paths = _validate_changed_paths(changed_paths)

    warnings: list[str] = []
    clean_base: str | None = None
    if base_ref is not None:
        clean_base = _validate_single_git_ref_no_colon(base_ref, label="baseRef")
        try:
            trust.compute_tree_id(resolved_repo, clean_base)
        except trust.TrustError as exc:
            raise PacketError(str(exc)) from exc
    elif not trusted:
        _append_warning(
            warnings,
            "skipped working-tree rules files because PR/tree is untrusted",
        )
        return [], warnings

    dirs: set[str] = {""}
    for rel in clean_paths:
        parts = rel.split("/")
        for depth in range(1, len(parts)):
            dirs.add("/".join(parts[:depth]))

    ordered_dirs = sorted(dirs, key=lambda d: (0 if not d else d.count("/") + 1, d))
    if len(ordered_dirs) > MAX_RULES_DIRS:
        ordered_dirs = ordered_dirs[:MAX_RULES_DIRS]
        _append_warning(
            warnings,
            f"rules directory scan capped at {MAX_RULES_DIRS} directories",
        )

    candidates: list[tuple[str, str]] = [
        (scope_dir, f"{scope_dir}/{fname}" if scope_dir else fname)
        for scope_dir in ordered_dirs
        for fname in RULES_FILENAMES
    ]
    entries: list[dict[str, Any]] = []
    capped = False

    if clean_base is not None:
        for start in range(0, len(candidates), _GIT_LS_TREE_BATCH_SIZE):
            batch = candidates[start : start + _GIT_LS_TREE_BATCH_SIZE]
            blobs = _lookup_git_tree_blobs(
                resolved_repo,
                clean_base,
                [rel for _, rel in batch],
            )
            for scope_dir, rel_path in batch:
                blob_info = blobs.get(rel_path)
                if blob_info is None:
                    continue
                oid, blob_size = blob_info
                if blob_size > file_cap:
                    _append_warning(
                        warnings,
                        f"skipped rules file {checks.safe_error_text(rel_path)} "
                        f"({blob_size} bytes): exceeds max {file_cap} bytes",
                    )
                    continue
                if len(entries) >= MAX_RULES_FILES:
                    capped = True
                    break
                try:
                    raw = trust._run_git_or_gh(
                        ["git", "-C", str(resolved_repo), "cat-file", "blob", oid],
                        cwd=resolved_repo,
                        max_stdout_bytes=file_cap,
                    )
                except trust.TrustError as exc:
                    _append_warning(warnings, f"skipped rules file {rel_path}: {exc}")
                    continue
                content, digest = _decode_and_sanitize_text(raw)
                entries.append(
                    {
                        "path": rel_path,
                        "scope": scope_dir or "root",
                        "source": "base-ref",
                        "ref": clean_base,
                        "sha256": digest,
                        "totalChars": len(content),
                        "content": content,
                    }
                )
            if capped:
                break
    else:
        for scope_dir, rel_path in candidates:
            try:
                raw = checks._read_repo_regular_file(
                    resolved_repo,
                    rel_path,
                    max_bytes=file_cap,
                    raise_on_oversized=True,
                )
            except checks.ChecksError as exc:
                _append_warning(warnings, f"skipped rules file {rel_path}: {exc}")
                continue
            if raw is None:
                continue
            if len(entries) >= MAX_RULES_FILES:
                capped = True
                break
            content, digest = _decode_and_sanitize_text(raw)
            entries.append(
                {
                    "path": rel_path,
                    "scope": scope_dir or "root",
                    "source": "working-tree",
                    "ref": None,
                    "sha256": digest,
                    "totalChars": len(content),
                    "content": content,
                }
            )

    if capped:
        _append_warning(
            warnings,
            f"rules file discovery capped at {MAX_RULES_FILES} files",
        )
    return entries, warnings


def extract_linked_issue_numbers(
    text: str,
    *,
    exclude_number: int | None = None,
) -> list[int]:
    """Extract sorted unique GitHub issue numbers outside fenced code blocks."""
    if not isinstance(text, str):
        raise PacketError(f"text must be str, got {type(text).__name__}")
    scrubbed = _FENCED_BLOCK_RE.sub(" ", text)
    found: set[int] = set()
    for match in _ISSUE_REF_RE.finditer(scrubbed):
        num = int(match.group(1))
        if exclude_number is not None and num == exclude_number:
            continue
        found.add(num)
    return sorted(found)[:MAX_LINKED_ISSUES]


def is_design_doc_path(rel_path: str) -> bool:
    """Return True if ``rel_path`` points to a changed design, spec, or ADR doc."""
    if not isinstance(rel_path, str) or not rel_path:
        return False
    parts = [part for part in rel_path.split("/") if part]
    if not parts:
        return False
    basename = parts[-1]
    if basename in _RULES_NAME_SET:
        return False
    lower_name = basename.lower()
    if not lower_name.endswith((".md", ".txt")):
        return False
    lower_parts = tuple(part.lower() for part in parts[:-1])
    for prefix in _DESIGN_DIR_PREFIXES:
        if len(lower_parts) >= len(prefix) and lower_parts[: len(prefix)] == prefix:
            return True
    stem = lower_name.rsplit(".", 1)[0]
    return stem in _DESIGN_STEMS or stem.startswith(_DESIGN_PREFIXES)


def _read_spec_source(
    resolved_repo: Path,
    raw_repo_root: str | Path,
    spec_path: str | Path,
    *,
    trusted: bool,
    file_cap: int,
) -> dict[str, Any]:
    try:
        raw_str = trust._validate_path_string(spec_path, label="spec file")
    except trust.TrustError as exc:
        raise PacketError(str(exc)) from exc

    spec_candidate = Path(raw_str)
    try:
        trust._reject_symlink(spec_candidate, label="spec file")
        resolved_spec = trust._safe_resolve(spec_candidate, label="spec file")
    except trust.TrustError as exc:
        raise PacketError(str(exc)) from exc

    abs_spec = Path(os.path.abspath(spec_candidate))
    abs_repo = Path(os.path.abspath(raw_repo_root))
    in_repo = (
        resolved_spec.is_relative_to(resolved_repo)
        or abs_spec.is_relative_to(resolved_repo)
        or abs_spec.is_relative_to(abs_repo)
    )

    if in_repo:
        if not trusted:
            raise PacketError(
                "spec file must reside outside the reviewed repository for "
                "untrusted PRs"
            )
        if not resolved_spec.is_relative_to(resolved_repo):
            raise PacketError("spec file escapes repository root")
        rel_spec = resolved_spec.relative_to(resolved_repo).as_posix()
        try:
            clean_rel = checks.validate_repo_relative_path(rel_spec)
        except checks.ChecksError as exc:
            raise PacketError(str(exc)) from exc
        try:
            raw = checks._read_repo_regular_file(
                resolved_repo, clean_rel, max_bytes=file_cap, raise_on_oversized=True
            )
        except checks.ChecksError as exc:
            raise PacketError(f"spec file {exc}") from exc
        if raw is None:
            raise PacketError(f"spec file missing or symlinked: {clean_rel}")
        source_kind = "repo"
        display_path = clean_rel
    else:
        try:
            raw = checks._read_explicit_regular_file(
                spec_candidate, max_bytes=file_cap, label="spec file"
            )
        except checks.ChecksError as exc:
            raise PacketError(str(exc)) from exc
        source_kind = "external"
        display_path = checks.safe_error_text(
            spec_candidate.name or "spec", max_len=128
        )

    content, digest = _decode_and_sanitize_text(raw)
    return {
        "kind": "spec",
        "source": source_kind,
        "path": display_path,
        "trustLevel": "trusted",
        "sha256": digest,
        "totalChars": len(content),
        "content": content,
    }


def _fetch_issue_entry(
    resolved_repo: Path, issue_num: int, *, file_cap: int
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        raw_out = trust._run_git_or_gh(
            [
                "gh",
                "issue",
                "view",
                str(issue_num),
                "--json",
                "number,title,body",
            ],
            cwd=resolved_repo,
        )
        payload = trust._loads_strict_json_object(
            raw_out, source_label=f"gh issue view #{issue_num}"
        )
    except trust.TrustError as exc:
        return None, f"skipped linked issue #{issue_num}: {exc}"

    num_val = payload.get("number")
    title = payload.get("title")
    body = payload.get("body")
    if (
        not findings._is_strict_int(num_val)
        or num_val != issue_num
        or not isinstance(title, str)
        or not isinstance(body, str)
        or "\x00" in title
        or "\x00" in body
        or findings._has_surrogate(title)
        or findings._has_surrogate(body)
    ):
        return None, f"skipped linked issue #{issue_num}: invalid gh issue payload"

    clean_title = report._sanitize_text(title, allow_newlines=False)
    clean_body = report._sanitize_text(body, allow_newlines=True)
    if len(clean_body.encode("utf-8")) > file_cap:
        encoded = clean_body.encode("utf-8")[:file_cap]
        clean_body = encoded.decode("utf-8", errors="ignore")
    combined = (
        f"Title: {clean_title}\n\n{clean_body}"
        if clean_body.strip()
        else (f"Title: {clean_title}")
    )
    return (
        {
            "kind": "linked-issue",
            "source": f"issue:#{issue_num}",
            "path": None,
            "trustLevel": "untrusted",
            "sha256": _sha256_text(combined),
            "totalChars": len(combined),
            "content": combined,
        },
        None,
    )


def collect_intent_sources(
    repo_root: str | Path,
    *,
    spec_path: str | Path | None = None,
    pr_meta: trust.PRMetadata | None = None,
    changed_paths: Sequence[str] = (),
    target_ref: str | None = None,
    trusted: bool | None = None,
    fetch_linked_issues: bool = False,
    max_file_bytes: int = MAX_RULE_FILE_BYTES,
) -> tuple[list[dict[str, Any]], list[int], list[str]]:
    """Collect optional intent sources (spec, PR body, design docs, issues)."""
    effective_trusted = _resolve_effective_trusted(trusted, pr_meta)
    if not isinstance(fetch_linked_issues, bool):
        raise PacketError("fetch_linked_issues must be a boolean")
    file_cap = _validate_max_file_bytes(max_file_bytes)

    try:
        resolved_repo, _ = checks.resolve_repo_root(repo_root)
    except checks.ChecksError as exc:
        raise PacketError(str(exc)) from exc
    clean_paths = _validate_changed_paths(changed_paths)

    clean_target: str | None = None
    if target_ref is not None:
        clean_target = _validate_single_git_ref_no_colon(target_ref, label="targetRef")
        try:
            trust.compute_tree_id(resolved_repo, clean_target)
        except trust.TrustError as exc:
            raise PacketError(str(exc)) from exc

    entries: list[dict[str, Any]] = []
    warnings: list[str] = []
    repo_spec_rel: str | None = None

    if spec_path is not None:
        spec_entry = _read_spec_source(
            resolved_repo,
            repo_root,
            spec_path,
            trusted=effective_trusted,
            file_cap=file_cap,
        )
        if spec_entry["source"] == "repo":
            repo_spec_rel = spec_entry["path"]
        entries.append(spec_entry)

    linked_issues: list[int] = []
    if pr_meta is not None:
        linked_issues = extract_linked_issue_numbers(
            pr_meta.body, exclude_number=pr_meta.number
        )
        clean_title = report._sanitize_text(pr_meta.title, allow_newlines=False)
        clean_body = report._sanitize_text(pr_meta.body, allow_newlines=True)
        pr_text = (
            f"Title: {clean_title}\n\n{clean_body}"
            if clean_body.strip()
            else f"Title: {clean_title}"
        )
        if clean_title.strip() or clean_body.strip():
            entries.append(
                {
                    "kind": "pr-body",
                    "source": f"pr:#{pr_meta.number}",
                    "path": None,
                    "trustLevel": "trusted" if effective_trusted else "untrusted",
                    "sha256": _sha256_text(pr_text),
                    "totalChars": len(pr_text),
                    "content": pr_text,
                }
            )

    design_paths = sorted(
        p for p in clean_paths if is_design_doc_path(p) and p != repo_spec_rel
    )
    if len(design_paths) > MAX_DESIGN_DOCS:
        _append_warning(
            warnings,
            f"changed design docs capped at {MAX_DESIGN_DOCS} of {len(design_paths)}",
        )
        design_paths = design_paths[:MAX_DESIGN_DOCS]

    for rel_path in design_paths:
        if len(entries) >= MAX_INTENT_SOURCES:
            _append_warning(warnings, f"intent sources capped at {MAX_INTENT_SOURCES}")
            break
        raw_doc: bytes | None = None
        if clean_target is not None:
            try:
                raw_doc = checks._read_git_tree_regular_file(
                    resolved_repo,
                    clean_target,
                    rel_path,
                    max_bytes=file_cap,
                    raise_on_oversized=True,
                    env=trust._scrubbed_git_env(),
                )
            except checks.ChecksError as exc:
                _append_warning(warnings, f"skipped design doc {rel_path}: {exc}")
                continue
        else:
            try:
                raw_doc = checks._read_repo_regular_file(
                    resolved_repo,
                    rel_path,
                    max_bytes=file_cap,
                    raise_on_oversized=True,
                )
            except checks.ChecksError as exc:
                _append_warning(warnings, f"skipped design doc {rel_path}: {exc}")
                continue
        if raw_doc is None:
            continue
        doc_text, doc_sha = _decode_and_sanitize_text(raw_doc)
        entries.append(
            {
                "kind": "design-doc",
                "source": "diff",
                "path": rel_path,
                "trustLevel": "trusted" if effective_trusted else "untrusted",
                "sha256": doc_sha,
                "totalChars": len(doc_text),
                "content": doc_text,
            }
        )

    if fetch_linked_issues and linked_issues:
        for issue_num in linked_issues:
            if len(entries) >= MAX_INTENT_SOURCES:
                _append_warning(
                    warnings, f"intent sources capped at {MAX_INTENT_SOURCES}"
                )
                break
            entry, warn = _fetch_issue_entry(
                resolved_repo, issue_num, file_cap=file_cap
            )
            if warn:
                _append_warning(warnings, warn)
            if entry is not None:
                entries.append(entry)

    return entries, linked_issues, warnings


def collect_evidence(
    evidence_paths: str | Path | Sequence[str | Path] | None,
    *,
    expected_tree_id: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    """Load and merge ``--evidence`` payloads matching ``expected_tree_id``."""
    try:
        clean_expected = trust._validate_tree_id_value(expected_tree_id)
    except trust.TrustError as exc:
        raise PacketError(str(exc)) from exc

    if evidence_paths is None:
        raw_paths: list[str | Path] = []
    elif isinstance(evidence_paths, (str, Path)):
        raw_paths = [evidence_paths]
    elif isinstance(evidence_paths, Sequence) and not isinstance(evidence_paths, bytes):
        raw_paths = list(evidence_paths)
    else:
        raise PacketError("evidence_paths must be a path, sequence, or None")

    if len(raw_paths) > MAX_EVIDENCE_FILES:
        raise PacketError(
            f"evidence_paths count {len(raw_paths)} exceeds max {MAX_EVIDENCE_FILES}"
        )

    accepted_files: list[str] = []
    rejected_files: list[dict[str, Any]] = []
    tools_set: set[str] = set()
    exclusions: list[str] = []
    seen_exclusions: set[str] = set()
    code_findings: list[dict[str, Any]] = []
    seen_sites: set[tuple[str, str, int, int, str, str]] = set()
    findings_capped = False
    sarif_results: list[dict[str, Any]] = []
    warnings: list[str] = []

    for ev_item in raw_paths:
        try:
            raw_str = trust._validate_path_string(ev_item, label="evidence file")
            ev_res = trust.load_evidence(raw_str, expected_tree_id=clean_expected)
        except trust.TrustError as exc:
            raise PacketError(str(exc)) from exc

        safe_base = checks.safe_error_text(
            Path(raw_str).name or "evidence", max_len=128
        )
        if not ev_res["accepted"]:
            rejected_files.append(
                {
                    "file": safe_base,
                    "reason": checks.safe_error_text(
                        ev_res.get("reason") or "rejected", max_len=512
                    ),
                    "treeId": ev_res.get("treeId"),
                }
            )
            _append_warning(
                warnings,
                f"evidence ignored ({safe_base}): {ev_res.get('reason')}",
            )
            continue

        accepted_files.append(safe_base)
        for tool_name in ev_res.get("tools", []):
            tools_set.add(tool_name)
        for excl in ev_res.get("exclusions", []):
            if excl not in seen_exclusions:
                seen_exclusions.add(excl)
                if len(exclusions) < MAX_EVIDENCE_EXCLUSIONS:
                    exclusions.append(excl)
        for item in ev_res.get("findings", []):
            site_key = report._site_identity(item)
            if site_key in seen_sites:
                continue
            if len(code_findings) >= findings.MAX_FINDINGS_COUNT:
                if not findings_capped:
                    findings_capped = True
                    _append_warning(
                        warnings,
                        f"evidence findings capped at {findings.MAX_FINDINGS_COUNT}",
                    )
                break
            seen_sites.add(site_key)
            code_findings.append(item)
        sarif_results.extend(ev_res.get("sarifResults", []))

    sorted_tools = sorted(tools_set)
    total_tools = len(sorted_tools)
    tools_truncated = total_tools > MAX_EVIDENCE_TOOLS
    tools_out = sorted_tools[:MAX_EVIDENCE_TOOLS]
    if tools_truncated:
        _append_warning(
            warnings,
            f"evidence tools truncated to {MAX_EVIDENCE_TOOLS} of {total_tools}",
        )

    total_exclusions = len(seen_exclusions)
    exclusions_truncated = total_exclusions > MAX_EVIDENCE_EXCLUSIONS
    if exclusions_truncated:
        _append_warning(
            warnings,
            f"evidence exclusions truncated to {MAX_EVIDENCE_EXCLUSIONS} "
            f"of {total_exclusions}",
        )

    total_sarif = len(sarif_results)
    sarif_truncated = total_sarif > MAX_SARIF_PACKET_RESULTS
    if sarif_truncated:
        sarif_results = sarif_results[:MAX_SARIF_PACKET_RESULTS]
        _append_warning(
            warnings,
            f"evidence SARIF results truncated to {MAX_SARIF_PACKET_RESULTS} "
            f"of {total_sarif}",
        )

    evidence_summary = {
        "acceptedFiles": accepted_files,
        "rejectedFiles": rejected_files,
        "toolsCount": total_tools,
        "toolsTruncated": tools_truncated,
        "tools": tools_out,
        "exclusionsCount": total_exclusions,
        "exclusionsTruncated": exclusions_truncated,
        "exclusions": exclusions,
        "findingsCount": len(code_findings),
        "sarifResultsCount": total_sarif,
        "sarifTruncated": sarif_truncated,
        "sarifResults": sarif_results,
    }
    return evidence_summary, code_findings, warnings


def _allocate_budget(
    items: list[dict[str, Any]],
    *,
    item_kind: str,
    remaining: int,
    omitted: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int, bool]:
    out: list[dict[str, Any]] = []
    partial = False
    for entry in items:
        content = entry["content"]
        total_chars = len(content)
        cap = min(remaining, MAX_SECTION_TEXT_CHARS)
        truncated = False
        included = content

        if total_chars > cap:
            truncated = True
            partial = True
            reason = (
                "section-limit"
                if remaining >= MAX_SECTION_TEXT_CHARS
                else "budget-exceeded"
            )
            if cap > len(_TRUNC_SUFFIX):
                included = content[: cap - len(_TRUNC_SUFFIX)] + _TRUNC_SUFFIX
            else:
                included = ""
                if reason == "budget-exceeded":
                    remaining = 0
            if len(omitted) < MAX_WARNINGS:
                omitted.append(
                    {
                        "kind": item_kind,
                        "path": entry.get("path"),
                        "source": entry.get("source"),
                        "reason": reason,
                        "omittedChars": total_chars - len(included),
                    }
                )

        remaining -= len(included)
        trimmed = dict(entry)
        trimmed["content"] = included
        trimmed["includedChars"] = len(included)
        trimmed["truncated"] = truncated
        out.append(trimmed)
    return out, remaining, partial


def build_context_packet(
    repo_root: str | Path,
    *,
    tree_id: str,
    changed_paths: Sequence[str] = (),
    base_ref: str | None = None,
    target_ref: str | None = None,
    trusted: bool | None = None,
    spec_path: str | Path | None = None,
    pr_meta: trust.PRMetadata | None = None,
    evidence_paths: str | Path | Sequence[str | Path] | None = None,
    fetch_linked_issues: bool = False,
    budget_chars: int = DEFAULT_PACKET_BUDGET_CHARS,
) -> PacketBuildResult:
    """Build a bounded, deterministic context packet for ``vld8 review prepare``."""
    try:
        clean_tree_id = trust._validate_tree_id_value(tree_id)
    except trust.TrustError as exc:
        raise PacketError(str(exc)) from exc
    effective_trusted = _resolve_effective_trusted(trusted, pr_meta)
    if (
        not findings._is_strict_int(budget_chars)
        or budget_chars < MIN_PACKET_BUDGET_CHARS
        or budget_chars > MAX_PACKET_BUDGET_CHARS
    ):
        raise PacketError(
            f"budget_chars must be an integer between "
            f"{MIN_PACKET_BUDGET_CHARS} and {MAX_PACKET_BUDGET_CHARS}"
        )

    rules_raw, rules_warnings = collect_rules_files(
        repo_root,
        changed_paths,
        base_ref=base_ref,
        trusted=effective_trusted,
    )
    intent_raw, linked_issues, intent_warnings = collect_intent_sources(
        repo_root,
        spec_path=spec_path,
        pr_meta=pr_meta,
        changed_paths=changed_paths,
        target_ref=target_ref,
        trusted=effective_trusted,
        fetch_linked_issues=fetch_linked_issues,
    )
    evidence_summary, code_findings, evidence_warnings = collect_evidence(
        evidence_paths,
        expected_tree_id=clean_tree_id,
    )

    warnings: list[str] = []
    for msg in (*rules_warnings, *intent_warnings, *evidence_warnings):
        _append_warning(warnings, msg)

    omitted: list[dict[str, Any]] = []
    rules_budgeted, rem_after_rules, rules_partial = _allocate_budget(
        rules_raw,
        item_kind="rules",
        remaining=budget_chars,
        omitted=omitted,
    )
    intent_budgeted: list[dict[str, Any]] = []
    rem = rem_after_rules
    intent_partial = False
    for entry in intent_raw:
        allocated, rem, item_partial = _allocate_budget(
            [entry],
            item_kind=entry["kind"],
            remaining=rem,
            omitted=omitted,
        )
        intent_budgeted.extend(allocated)
        intent_partial = intent_partial or item_partial

    sources_used: list[str] = []
    if any(r["includedChars"] > 0 or r["totalChars"] == 0 for r in rules_budgeted):
        sources_used.append("rules")
    for kind in ("spec", "pr-body", "design-doc", "linked-issue"):
        if any(
            item["kind"] == kind
            and (item["includedChars"] > 0 or item["totalChars"] == 0)
            for item in intent_budgeted
        ):
            sources_used.append(kind)
    if evidence_summary["acceptedFiles"]:
        sources_used.append("evidence")

    used_chars = sum(item["includedChars"] for item in rules_budgeted) + sum(
        item["includedChars"] for item in intent_budgeted
    )
    packet: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "treeId": clean_tree_id,
        "budget": {
            "budgetChars": budget_chars,
            "usedChars": used_chars,
            "partial": bool(rules_partial or intent_partial),
        },
        "sourcesUsed": sources_used,
        "linkedIssues": linked_issues,
        "rulesFiles": rules_budgeted,
        "intentSources": intent_budgeted,
        "evidence": evidence_summary,
        "omitted": omitted,
        "warnings": warnings,
    }
    return PacketBuildResult(
        packet=packet,
        code_findings=code_findings,
        unruled=[],
    )


def build_packet_json_bytes(result: PacketBuildResult) -> bytes:
    """Serialize ``result.packet`` as deterministic UTF-8 JSON bytes."""
    return (
        json.dumps(
            result.packet,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
