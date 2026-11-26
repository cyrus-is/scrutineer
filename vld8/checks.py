"""Code-first check routing (``vld8 checks``) and diff sizing (``vld8 review size``).

Selects matching platform guidance blocks from installed toolkit YAML assets
without executing or trusting code/config inside ``--repo``, and sizes diffs or
pull requests using bounded ``git`` / ``gh`` invocations and optional service-map
partitioning.
"""

from __future__ import annotations

import fnmatch
import functools
import itertools
import json
import os
import re
import stat
import subprocess
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from . import findings, paths

SCHEMA_VERSION = "1.0"
VALID_LENSES = frozenset({"code", "security", "both"})

MAX_REF_LENGTH = 1024
MAX_COMMAND_TIMEOUT_S = 60.0
MAX_COMMAND_STDOUT_BYTES = 10 * 1024 * 1024
MAX_COMMAND_STDERR_BYTES = 1024 * 1024
MAX_PR_API_BYTES = 50 * 1024 * 1024
MAX_PR_LISTED_FILES = 3500
MAX_CONTENT_FILE_BYTES = 1024 * 1024
MAX_TEXT_CACHE_BYTES = 64 * 1024 * 1024
MAX_TEXT_CACHE_ENTRIES = 10_000
MAX_SERVICEMAP_BYTES = 10 * 1024 * 1024
MAX_GUIDANCE_BYTES = 10 * 1024 * 1024
MAX_GLOB_STARS = 8

LARGE_FILES_THRESHOLD = 150
MEDIUM_FILES_THRESHOLD = 50
LARGE_COMMITS_THRESHOLD = 20

CONTENT_EXTS = frozenset(
    {
        ".swift",
        ".m",
        ".mm",
        ".h",
        ".kt",
        ".java",
        ".py",
        ".go",
        ".rs",
        ".rb",
        ".php",
        ".cs",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".vue",
        ".mjs",
        ".cjs",
        ".mts",
        ".cts",
        ".dart",
        ".scala",
        ".ex",
        ".exs",
        ".c",
        ".cc",
        ".cpp",
        ".hpp",
        ".sh",
        ".yml",
        ".yaml",
        ".json",
        ".toml",
        ".tf",
        ".plist",
        ".entitlements",
        ".xcconfig",
        ".xcprivacy",
        ".pbxproj",
        ".resolved",
        ".gradle",
        ".kts",
    }
)

_NON_PLATFORM_SECTIONS = frozenset({"cross_cutting", "verification"})
_MILESTONE_RE = re.compile(r"^\d+\.\d+\Z", re.ASCII)
_GIT_OID_RE = re.compile(r"^[0-9a-f]{40,64}\Z")


class ChecksError(ValueError):
    """Raised when check selection or diff sizing input or execution fails."""


@dataclass(frozen=True)
class _FileStat:
    path: str
    additions: int
    deletions: int
    binary: bool = False


def safe_error_text(value: Any, *, max_len: int = 240) -> str:
    """Render untrusted strings safely without terminal escape or control chars."""
    return findings._safe_label(value, max_len=max_len)


def validate_repo_relative_path(path_str: Any) -> str:
    """Validate a strict repo-relative POSIX path."""
    errors: list[str] = []
    if not findings._validate_repo_relative_path(path_str, "path", errors):
        raise ChecksError(errors[0])
    return str(path_str)


def validate_git_ref_or_range(value: Any) -> str:
    """Validate a git ref or range, rejecting flag injection and control chars."""
    if not isinstance(value, str):
        raise ChecksError(f"ref/range: expected string, got {type(value).__name__}")
    if not value:
        raise ChecksError("ref/range: must not be empty")
    if len(value) > MAX_REF_LENGTH:
        raise ChecksError(
            f"ref/range: length {len(value)} exceeds max {MAX_REF_LENGTH}"
        )
    if value.startswith("-"):
        raise ChecksError(
            f"ref/range: must not start with '-' (got {safe_error_text(value)})"
        )
    if findings._has_control_char(value):
        raise ChecksError("ref/range: control characters are not allowed")
    if findings._has_surrogate(value):
        raise ChecksError("ref/range: unpaired UTF-16 surrogates are not allowed")
    if any(ch.isspace() for ch in value):
        raise ChecksError("ref/range: whitespace is not allowed")
    return value


def validate_pr_number(value: Any) -> int:
    """Validate a GitHub PR number (>= 1, non-bool int)."""
    if not findings._is_strict_int(value) or value < 1:
        raise ChecksError(
            f"pr: expected positive integer >= 1, got {safe_error_text(value)}"
        )
    return int(value)


def resolve_repo_root(repo: str | Path) -> tuple[Path, str]:
    """Validate ``--repo`` directory exists and return (resolved_path, safe_label)."""
    if isinstance(repo, Path):
        raw = str(repo)
    elif isinstance(repo, str):
        raw = repo
    else:
        raise ChecksError(f"repo: expected path, got {type(repo).__name__}")
    if not raw or findings._has_control_char(raw) or findings._has_surrogate(raw):
        raise ChecksError("repo: invalid directory path")
    candidate = Path(raw)
    try:
        if not candidate.exists():
            raise ChecksError(f"repo directory does not exist: {safe_error_text(raw)}")
        if not candidate.is_dir():
            raise ChecksError(f"repo path is not a directory: {safe_error_text(raw)}")
        resolved = candidate.resolve()
    except OSError as exc:
        raise ChecksError(
            f"cannot access repo directory {safe_error_text(raw)}: "
            f"{safe_error_text(exc)}"
        ) from exc
    label = (
        "."
        if raw == "."
        else safe_error_text(
            resolved.name or ".", max_len=findings.MAX_IDENTIFIER_LENGTH
        )
    )
    return resolved, label


def _as_bytes(data: bytes | str | None) -> bytes:
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    return data.encode("utf-8", "surrogateescape")


def _run_command(
    argv: list[str],
    *,
    cwd: Path,
    timeout: float = MAX_COMMAND_TIMEOUT_S,
    max_stdout_bytes: int = MAX_COMMAND_STDOUT_BYTES,
    max_stderr_bytes: int = MAX_COMMAND_STDERR_BYTES,
    env: dict[str, str] | None = None,
) -> bytes:
    """Run a subprocess with list argv only, bounded output, and safe errors."""
    if (
        not isinstance(argv, list)
        or not argv
        or not all(isinstance(part, str) for part in argv)
    ):
        raise ChecksError("command arguments must be a non-empty list of strings")
    if any("\x00" in part for part in argv):
        raise ChecksError("command arguments must not contain NUL bytes")
    cmd_name = safe_error_text(argv[0])
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd),
            env=env,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ChecksError(f"required command not found: {cmd_name}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ChecksError(f"{cmd_name} timed out after {timeout:.0f}s") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise ChecksError(f"{cmd_name} failed: {safe_error_text(exc)}") from exc

    stdout = _as_bytes(proc.stdout)
    stderr = _as_bytes(proc.stderr)
    if proc.returncode != 0:
        err_slice = stderr[:max_stderr_bytes].decode("utf-8", "replace").strip()
        detail = safe_error_text(err_slice, max_len=240) if err_slice else ""
        msg = f"{cmd_name} exited with status {proc.returncode}"
        if detail:
            msg = f"{msg}: {detail}"
        raise ChecksError(msg)
    if len(stdout) > max_stdout_bytes:
        raise ChecksError(
            f"{cmd_name} output ({len(stdout)} bytes) exceeds "
            f"max {max_stdout_bytes} bytes"
        )
    return stdout


def _read_fd_bounded(fd: int, *, max_bytes: int) -> bytes | None:
    """Validate an open fd is a regular file within ``max_bytes`` and read it."""
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        if st.st_size > max_bytes:
            return None
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw = handle.read(max_bytes + 1)
    except OSError:
        return None
    finally:
        if fd != -1:
            os.close(fd)
    if len(raw) > max_bytes:
        return None
    return raw


def _read_repo_regular_file(
    repo_root: Path,
    rel_path: str,
    *,
    max_bytes: int,
) -> bytes | None:
    """Safely read a regular non-symlink file inside ``repo_root``."""
    validate_repo_relative_path(rel_path)
    parts = rel_path.split("/")

    cur = repo_root
    for part in parts:
        cur = cur / part
        try:
            st = cur.lstat()
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode):
            return None

    try:
        resolved = cur.resolve()
    except OSError, RuntimeError:
        return None
    if not resolved.is_relative_to(repo_root):
        return None

    dir_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = (
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    )

    cur_fd = -1
    try:
        cur_fd = os.open(str(repo_root), dir_flags)
        for part in parts[:-1]:
            next_fd = os.open(part, dir_flags, dir_fd=cur_fd)
            os.close(cur_fd)
            cur_fd = next_fd
        leaf_fd = os.open(parts[-1], file_flags, dir_fd=cur_fd)
    except OSError:
        return None
    finally:
        if cur_fd != -1:
            os.close(cur_fd)

    return _read_fd_bounded(leaf_fd, max_bytes=max_bytes)


def _read_explicit_regular_file(
    file_path: Path,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    """Safely read an explicit non-symlink regular file with bounded size."""
    safe_name = safe_error_text(file_path.name or str(file_path))
    try:
        st = file_path.lstat()
    except FileNotFoundError as exc:
        raise ChecksError(f"{label} not found: {safe_name}") from exc
    except OSError as exc:
        raise ChecksError(
            f"cannot access {label} {safe_name}: {safe_error_text(exc)}"
        ) from exc
    if stat.S_ISLNK(st.st_mode):
        raise ChecksError(f"{label} must not be a symlink: {safe_name}")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(file_path), flags)
    except OSError as exc:
        raise ChecksError(
            f"cannot open {label} {safe_name}: {safe_error_text(exc)}"
        ) from exc

    try:
        f_st = os.fstat(fd)
        if not stat.S_ISREG(f_st.st_mode):
            raise ChecksError(f"{label} is not a regular file: {safe_name}")
        if f_st.st_size > max_bytes:
            raise ChecksError(
                f"{label} {safe_name} ({f_st.st_size} bytes) "
                f"exceeds max {max_bytes} bytes"
            )
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw = handle.read(max_bytes + 1)
    except OSError as exc:
        raise ChecksError(
            f"cannot read {label} {safe_name}: {safe_error_text(exc)}"
        ) from exc
    finally:
        if fd != -1:
            os.close(fd)

    if len(raw) > max_bytes:
        raise ChecksError(f"{label} {safe_name} exceeds max {max_bytes} bytes")
    return raw


@functools.lru_cache(maxsize=1024)
def _glob_regex(pattern: str) -> re.Pattern[str]:
    """Compile a guidance glob where ``**/`` matches zero or more directories.

    Matches ``generate.py``'s recursive glob expansion with ``re.IGNORECASE``
    semantics so case variants such as ``Dockerfile*`` and ``**/*.ts`` route
    consistently across filesystems.
    """
    parts = pattern.split("**/")
    if len(parts) - 1 > MAX_GLOB_STARS:
        raise ChecksError(
            f"glob pattern has too many '**/': {safe_error_text(pattern)}"
        )
    candidates = {
        parts[0]
        + "".join(
            ("**/" if keep else "") + p
            for keep, p in zip(keeps, parts[1:], strict=True)
        )
        for keeps in itertools.product((True, False), repeat=len(parts) - 1)
    }
    return re.compile(
        "|".join(f"(?:{fnmatch.translate(c)})" for c in sorted(candidates)),
        re.IGNORECASE,
    )


def glob_match(rel_path: str, pattern: str) -> bool:
    """Match a repo-relative POSIX path against a guidance glob pattern."""
    return _glob_regex(pattern).match(rel_path) is not None


def _apply_previews(
    node: Any,
    enabled: frozenset[str] = frozenset(),
) -> Any:
    """Filter preview-gated entries from loaded guidance YAML."""

    def gate(value: dict[str, Any], key: str) -> str | None:
        if key not in value:
            return None
        milestone = value[key]
        if not (isinstance(milestone, str) and _MILESTONE_RE.match(milestone)):
            raise ChecksError(f"guidance gate `{key}` must be a milestone string")
        return milestone

    def keep(value: Any) -> bool:
        if not isinstance(value, dict):
            return True
        on, off = gate(value, "preview"), gate(value, "replaced_in")
        if on is not None and on == off:
            raise ChecksError(f"guidance entry has conflicting gates for {on!r}")
        return (on is None or on in enabled) and (off is None or off not in enabled)

    if isinstance(node, dict):
        return {
            k: _apply_previews(v, enabled)
            for k, v in node.items()
            if k not in ("preview", "replaced_in") and keep(v)
        }
    if isinstance(node, list):
        return [_apply_previews(v, enabled) for v in node if keep(v)]
    return node


def _load_guidance(path: Path) -> dict[str, Any]:
    raw = _read_explicit_regular_file(
        path, max_bytes=MAX_GUIDANCE_BYTES, label="guidance file"
    )
    try:
        text = raw.decode("utf-8")
        loaded = yaml.safe_load(text)
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ChecksError(
            f"cannot parse guidance YAML {safe_error_text(path.name)}: "
            f"{safe_error_text(exc)}"
        ) from exc
    if not isinstance(loaded, dict):
        raise ChecksError(
            f"guidance YAML {safe_error_text(path.name)} must be a mapping"
        )
    filtered = _apply_previews(loaded, frozenset())
    if not isinstance(filtered, dict):
        raise ChecksError("filtered guidance must be a mapping")
    return filtered


def _diff_target_tree_ref(diff_range: str) -> str | None:
    """Return right-hand tree ref for range diffs, or None for working-tree diff."""
    if "..." in diff_range:
        _, rhs = diff_range.split("...", 1)
        target = rhs or "HEAD"
    elif ".." in diff_range:
        _, rhs = diff_range.split("..", 1)
        target = rhs or "HEAD"
    else:
        return None
    validate_git_ref_or_range(target)
    return target


def _read_git_tree_regular_file(
    repo_root: Path,
    tree_ref: str,
    rel_path: str,
    *,
    max_bytes: int,
    raise_on_oversized: bool = False,
    env: dict[str, str] | None = None,
) -> bytes | None:
    """Read a regular non-symlink blob from ``tree_ref`` bounded by ``max_bytes``."""
    validate_repo_relative_path(rel_path)
    ls_raw = _run_command(
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
            f":(literal){rel_path}",
        ],
        cwd=repo_root,
        env=env,
    )
    if not ls_raw:
        return None
    for rec in ls_raw.split(b"\x00"):
        if not rec:
            continue
        meta, sep, path_bytes = rec.partition(b"\t")
        if not sep:
            continue
        entry_path = path_bytes.decode("utf-8", "surrogateescape")
        if entry_path != rel_path:
            continue
        parts = meta.decode("ascii", "replace").split()
        if len(parts) != 4:
            return None
        mode, obj_type, oid, size_str = parts
        if (
            mode not in ("100644", "100755")
            or obj_type != "blob"
            or not _GIT_OID_RE.match(oid)
            or not size_str.isdigit()
        ):
            return None
        if int(size_str) > max_bytes:
            if raise_on_oversized:
                raise ChecksError(
                    f"git tree file {safe_error_text(rel_path)} "
                    f"({size_str} bytes) exceeds max {max_bytes} bytes"
                )
            return None
        return _run_command(
            ["git", "-C", str(repo_root), "cat-file", "blob", oid],
            cwd=repo_root,
            max_stdout_bytes=max_bytes,
            env=env,
        )
    return None


class _BoundedTextCache:
    """Bounded LRU text cache for working-tree or git-tree content reads."""

    def __init__(self, repo_root: Path, *, tree_ref: str | None = None) -> None:
        self.repo_root = repo_root.resolve()
        self.tree_ref = tree_ref
        self._cache: OrderedDict[str, tuple[str | None, int]] = OrderedDict()
        self._cached_bytes = 0

    def get_text(self, rel_path: str) -> str | None:
        if rel_path in self._cache:
            text, size = self._cache.pop(rel_path)
            self._cache[rel_path] = (text, size)
            return text
        if self.tree_ref is not None:
            raw = _read_git_tree_regular_file(
                self.repo_root,
                self.tree_ref,
                rel_path,
                max_bytes=MAX_CONTENT_FILE_BYTES,
            )
        else:
            raw = _read_repo_regular_file(
                self.repo_root, rel_path, max_bytes=MAX_CONTENT_FILE_BYTES
            )
        if raw is None:
            text: str | None = None
            size = 0
        else:
            text = raw.decode("utf-8", errors="ignore")
            size = len(raw)
        while self._cache and (
            len(self._cache) >= MAX_TEXT_CACHE_ENTRIES
            or self._cached_bytes + size > MAX_TEXT_CACHE_BYTES
        ):
            _, (_, evicted_size) = self._cache.popitem(last=False)
            self._cached_bytes -= evicted_size
        if size <= MAX_TEXT_CACHE_BYTES:
            self._cache[rel_path] = (text, size)
            self._cached_bytes += size
        return text


def _normalize_code_checks(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        norm: dict[str, Any] = {
            "id": item.get("id", ""),
            "title": item.get("title", ""),
            "pattern": item.get("pattern", ""),
            "failureMode": item.get("failure_mode", ""),
            "fix": item.get("fix", ""),
            "lens": item.get("lens", ""),
            "severity": item.get("severity", ""),
        }
        for opt in ("kind", "tier"):
            if opt in item:
                norm[opt] = item[opt]
        out.append(norm)
    return out


def _normalize_focus_areas(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        norm: dict[str, Any] = {
            "area": item.get("area", ""),
            "description": item.get("description", ""),
            "lens": item.get("lens", ""),
        }
        if "why" in item:
            norm["why"] = item["why"]
        out.append(norm)
    return out


def _normalize_change_type_signals(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        patterns = item.get("patterns", [])
        out.append(
            {
                "type": item.get("type", ""),
                "patterns": list(patterns) if isinstance(patterns, list) else [],
            }
        )
    return out


def _normalize_security_checks(items: Any) -> list[dict[str, Any]]:
    if not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        norm: dict[str, Any] = {
            "id": item.get("id", ""),
            "title": item.get("title", ""),
            "pattern": item.get("pattern", ""),
            "secureAlternative": item.get("secure_alternative", ""),
            "owasp": item.get("owasp", ""),
            "severityIfFound": item.get("severity_if_found", ""),
        }
        for opt in ("kind", "tier"):
            if opt in item:
                norm[opt] = item[opt]
        out.append(norm)
    return out


def _evaluate_block(
    *,
    lens: str,
    category: str,
    key: str,
    data: dict[str, Any],
    changed_paths: list[str],
    text_cache: _BoundedTextCache,
) -> dict[str, Any] | None:
    """Match one platform guidance block against ``changed_paths``.

    Follows ``generate.py``'s ``detect_mode`` semantics:
    - ``files`` (default): ``detect_files`` decides when non-empty;
      ``detect_content`` runs only when ``detect_files`` is empty.
    - ``all``: both ``detect_files`` and on-disk ``detect_content`` must match.
    - ``any``: either ``detect_files`` or on-disk ``detect_content`` matches.
    """
    globs = data.get("detect_files") or []
    contents = data.get("detect_content") or []
    mode = data.get("detect_mode", "files")
    raw_exts = data.get("detect_content_exts") or CONTENT_EXTS
    exts = frozenset(ext.lower() for ext in raw_exts)

    glob_matched = [
        rel for rel in changed_paths if any(glob_match(rel, g) for g in globs)
    ]

    if not contents:
        content_candidates: list[str] = []
    elif mode == "all":
        content_candidates = glob_matched
    elif mode == "any":
        content_candidates = changed_paths
    else:
        content_candidates = changed_paths if not globs else []

    content_matches: set[tuple[str, str]] = set()
    if content_candidates:
        compiled = [(pat, re.compile(pat, re.MULTILINE)) for pat in contents]
        for rel in content_candidates:
            if PurePosixPath(rel).suffix.lower() not in exts:
                continue
            text = text_cache.get_text(rel)
            if not text:
                continue
            for pat, regex in compiled:
                if regex.search(text):
                    content_matches.add((rel, pat))

    content_paths = {rel for rel, _ in content_matches}
    if mode == "all":
        hit = bool(globs) and bool(glob_matched) and bool(content_matches)
        matched_paths = sorted(content_paths)
    elif mode == "any":
        hit = bool(glob_matched) or bool(content_matches)
        matched_paths = sorted(set(glob_matched) | content_paths)
    elif globs:
        hit = bool(glob_matched)
        matched_paths = sorted(set(glob_matched))
    else:
        hit = bool(content_matches)
        matched_paths = sorted(content_paths)

    if not hit:
        return None

    matched_content = [
        {"path": rel, "pattern": pat} for rel, pat in sorted(content_matches)
    ]
    block: dict[str, Any] = {
        "lens": lens,
        "category": category,
        "key": key,
        "name": data.get("name", key),
        "matchedPaths": matched_paths,
        "matchedContent": matched_content,
    }
    if lens == "code":
        block["checks"] = _normalize_code_checks(data.get("preflight_checks"))
        block["focusAreas"] = _normalize_focus_areas(data.get("focus_areas"))
        block["changeTypeSignals"] = _normalize_change_type_signals(
            data.get("change_type_signals")
        )
    else:
        block["checks"] = _normalize_security_checks(data.get("checklist"))
    return block


def _git_changed_paths(repo_root: Path, diff_range: str) -> list[str]:
    validate_git_ref_or_range(diff_range)
    raw = _run_command(
        [
            "git",
            "-C",
            str(repo_root),
            "diff",
            "--name-only",
            "-z",
            diff_range,
            "--",
        ],
        cwd=repo_root,
    )
    if not raw:
        return []
    tokens = raw.split(b"\x00")
    if tokens and tokens[-1] == b"":
        tokens = tokens[:-1]
    paths_out = [
        validate_repo_relative_path(tok.decode("utf-8", "surrogateescape"))
        for tok in tokens
    ]
    return sorted(set(paths_out))


def select_checks(
    *,
    changed: list[str] | None = None,
    diff_range: str | None = None,
    lens: str = "both",
    repo: str | Path = ".",
) -> dict[str, Any]:
    """Select applicable peer-review and/or security guidance blocks."""
    if (changed is None) == (diff_range is None):
        raise ChecksError("exactly one of changed or diff_range must be provided")
    if lens not in VALID_LENSES:
        raise ChecksError(
            f"invalid lens {safe_error_text(lens)}; "
            f"expected one of: {', '.join(sorted(VALID_LENSES))}"
        )

    repo_root, repo_label = resolve_repo_root(repo)
    if changed is not None:
        if not changed:
            raise ChecksError("changed must include at least one path")
        mode = "changed"
        tree_ref: str | None = None
        changed_paths = sorted({validate_repo_relative_path(p) for p in changed})
    else:
        assert diff_range is not None
        mode = "diff"
        tree_ref = _diff_target_tree_ref(diff_range)
        changed_paths = _git_changed_paths(repo_root, diff_range)

    guidance_sources: list[tuple[str, Path]] = []
    if lens in ("code", "both"):
        guidance_sources.append(("code", paths.PEER_GUIDANCE))
    if lens in ("security", "both"):
        guidance_sources.append(("security", paths.SECURITY_GUIDANCE))

    text_cache = _BoundedTextCache(repo_root, tree_ref=tree_ref)
    blocks: list[dict[str, Any]] = []
    all_matched: set[str] = set()

    for active_lens, guidance_path in guidance_sources:
        guidance = _load_guidance(guidance_path)
        for category, platforms in guidance.items():
            if category in _NON_PLATFORM_SECTIONS or not isinstance(platforms, dict):
                continue
            for key, pdata in platforms.items():
                if not isinstance(pdata, dict):
                    continue
                block = _evaluate_block(
                    lens=active_lens,
                    category=category,
                    key=key,
                    data=pdata,
                    changed_paths=changed_paths,
                    text_cache=text_cache,
                )
                if block is not None:
                    blocks.append(block)
                    all_matched.update(block["matchedPaths"])

    blocks.sort(key=lambda b: (b["lens"], b["category"], b["key"]))
    unmatched_paths = sorted(p for p in changed_paths if p not in all_matched)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "lens": lens,
        "mode": mode,
        "repo": repo_label,
        "changedPaths": changed_paths,
        "unmatchedPaths": unmatched_paths,
        "blocks": blocks,
    }


def _parse_numstat_int(token: bytes, *, path_hint: str) -> int:
    try:
        value = int(token.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ChecksError(
            f"unexpected git numstat count for {safe_error_text(path_hint)}"
        ) from exc
    if value < 0:
        raise ChecksError(
            f"negative git numstat count for {safe_error_text(path_hint)}"
        )
    return value


def _parse_git_numstat_z(raw: bytes) -> list[_FileStat]:
    """Parse ``git diff --numstat -z`` output including rename/copy records."""
    if not raw:
        return []
    tokens = raw.split(b"\x00")
    if tokens and tokens[-1] == b"":
        tokens = tokens[:-1]

    entries: list[_FileStat] = []
    idx = 0
    total = len(tokens)
    while idx < total:
        rec = tokens[idx]
        parts = rec.split(b"\t", 2)
        if len(parts) != 3:
            raise ChecksError("malformed git diff --numstat -z record")
        add_tok, del_tok, path_tok = parts
        if path_tok == b"":
            if idx + 2 >= total:
                raise ChecksError("truncated rename record in git diff --numstat -z")
            old_path = tokens[idx + 1].decode("utf-8", "surrogateescape")
            new_path = tokens[idx + 2].decode("utf-8", "surrogateescape")
            validate_repo_relative_path(old_path)
            rel_path = validate_repo_relative_path(new_path)
            idx += 3
        else:
            rel_path = validate_repo_relative_path(
                path_tok.decode("utf-8", "surrogateescape")
            )
            idx += 1

        if add_tok == b"-" and del_tok == b"-":
            entries.append(
                _FileStat(path=rel_path, additions=0, deletions=0, binary=True)
            )
        else:
            additions = _parse_numstat_int(add_tok, path_hint=rel_path)
            deletions = _parse_numstat_int(del_tok, path_hint=rel_path)
            entries.append(
                _FileStat(
                    path=rel_path,
                    additions=additions,
                    deletions=deletions,
                    binary=False,
                )
            )
    return entries


def _git_diff_stats(repo_root: Path, diff_range: str) -> tuple[list[_FileStat], int]:
    validate_git_ref_or_range(diff_range)
    numstat_raw = _run_command(
        [
            "git",
            "-C",
            str(repo_root),
            "diff",
            "--numstat",
            "-z",
            diff_range,
            "--",
        ],
        cwd=repo_root,
    )
    entries = _parse_git_numstat_z(numstat_raw)

    rev_cmd = ["git", "-C", str(repo_root), "rev-list", "--count"]
    if "..." in diff_range:
        rev_cmd.extend(["--right-only", diff_range, "--"])
    elif ".." in diff_range:
        rev_cmd.extend([diff_range, "--"])
    else:
        rev_cmd.extend([f"{diff_range}..HEAD", "--"])

    count_raw = _run_command(rev_cmd, cwd=repo_root)
    count_str = count_raw.decode("utf-8", "replace").strip()
    try:
        commits = int(count_str)
    except ValueError as exc:
        raise ChecksError(
            f"unexpected git rev-list count: {safe_error_text(count_str)}"
        ) from exc
    if commits < 0:
        raise ChecksError("git rev-list returned negative commit count")
    return entries, commits


def _parse_concatenated_json_arrays(raw: bytes) -> list[dict[str, Any]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ChecksError(
            f"gh api output is not valid UTF-8: {safe_error_text(exc)}"
        ) from exc

    decoder = json.JSONDecoder()
    idx = 0
    length = len(text)
    items: list[dict[str, Any]] = []
    while idx < length:
        while idx < length and text[idx].isspace():
            idx += 1
        if idx >= length:
            break
        try:
            page, next_idx = decoder.raw_decode(text, idx)
        except json.JSONDecodeError as exc:
            raise ChecksError(
                f"invalid JSON from gh api: {safe_error_text(exc)}"
            ) from exc
        idx = next_idx
        if not isinstance(page, list):
            raise ChecksError("gh api PR files page must be a JSON array")
        if len(items) + len(page) > MAX_PR_LISTED_FILES:
            raise ChecksError(
                f"gh api PR files count exceeds max {MAX_PR_LISTED_FILES}"
            )
        for item in page:
            if not isinstance(item, dict):
                raise ChecksError("gh api PR file entry must be a JSON object")
            items.append(item)
    return items


def _gh_pr_stats(
    repo_root: Path,
    pr_number: int,
) -> tuple[int, int, int, int, list[_FileStat]]:
    validate_pr_number(pr_number)
    pr_str = str(pr_number)

    view_raw = _run_command(
        [
            "gh",
            "pr",
            "view",
            pr_str,
            "--json",
            "changedFiles,additions,deletions,commits",
        ],
        cwd=repo_root,
    )
    try:
        view_data = json.loads(view_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChecksError(
            f"invalid JSON from gh pr view: {safe_error_text(exc)}"
        ) from exc
    if not isinstance(view_data, dict):
        raise ChecksError("gh pr view output must be a JSON object")

    for req in ("changedFiles", "additions", "deletions", "commits"):
        if req not in view_data:
            raise ChecksError(f"gh pr view output missing {req}")

    total_files = view_data["changedFiles"]
    total_additions = view_data["additions"]
    total_deletions = view_data["deletions"]
    for field_name, val in (
        ("changedFiles", total_files),
        ("additions", total_additions),
        ("deletions", total_deletions),
    ):
        if not findings._is_strict_int(val) or val < 0:
            raise ChecksError(f"gh pr view {field_name} must be a non-negative integer")

    raw_commits = view_data["commits"]
    if isinstance(raw_commits, list):
        commits = len(raw_commits)
    elif findings._is_strict_int(raw_commits) and raw_commits >= 0:
        commits = int(raw_commits)
    else:
        raise ChecksError("gh pr view commits must be a list or integer")

    files_raw = _run_command(
        [
            "gh",
            "api",
            "--paginate",
            f"repos/{{owner}}/{{repo}}/pulls/{pr_str}/files?per_page=100",
        ],
        cwd=repo_root,
        max_stdout_bytes=MAX_PR_API_BYTES,
    )
    page_items = _parse_concatenated_json_arrays(files_raw)
    entries: list[_FileStat] = []
    for item in page_items:
        filename = validate_repo_relative_path(item.get("filename"))
        add = item.get("additions", 0)
        delete = item.get("deletions", 0)
        if not findings._is_strict_int(add) or add < 0:
            raise ChecksError(
                f"invalid PR file additions for {safe_error_text(filename)}"
            )
        if not findings._is_strict_int(delete) or delete < 0:
            raise ChecksError(
                f"invalid PR file deletions for {safe_error_text(filename)}"
            )
        entries.append(_FileStat(path=filename, additions=add, deletions=delete))

    return (
        int(total_files),
        int(total_additions),
        int(total_deletions),
        commits,
        entries,
    )


def _parse_service_map_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChecksError(f"invalid JSON in {label}: {safe_error_text(exc)}") from exc
    if not isinstance(data, dict):
        raise ChecksError(f"{label} root must be a JSON object")
    if "components" in data and not isinstance(data["components"], list):
        raise ChecksError(f"{label} components must be a JSON array")
    return data


def _load_service_map(
    repo_root: Path,
    service_map: str | Path | None,
) -> dict[str, Any] | None:
    if service_map is not None:
        sm_path = Path(service_map)
        raw = _read_explicit_regular_file(
            sm_path, max_bytes=MAX_SERVICEMAP_BYTES, label="service map"
        )
        return _parse_service_map_json(
            raw, safe_error_text(sm_path.name or str(sm_path))
        )

    raw = _read_repo_regular_file(
        repo_root, paths.SERVICEMAP_FILE, max_bytes=MAX_SERVICEMAP_BYTES
    )
    if raw is None:
        return None
    return _parse_service_map_json(raw, paths.SERVICEMAP_FILE)


def _extract_component_prefixes(
    service_map_data: dict[str, Any] | None,
) -> list[tuple[str, str]]:
    if not service_map_data:
        return []
    components = service_map_data.get("components", [])
    prefixes: list[tuple[str, str]] = []
    for comp in components:
        if not isinstance(comp, dict):
            continue
        if comp.get("stub") or comp.get("type") == "external":
            continue
        name = comp.get("name")
        comp_id = comp.get("id")
        if isinstance(name, str) and name.strip():
            raw_label = name
        elif isinstance(comp_id, str) and comp_id.strip():
            raw_label = comp_id
        else:
            continue

        if findings._has_control_char(raw_label):
            raise ChecksError("service map component label contains control characters")
        if findings._has_surrogate(raw_label):
            raise ChecksError(
                "service map component label contains unpaired UTF-16 surrogates"
            )
        label = raw_label.strip()
        if len(label) > findings.MAX_IDENTIFIER_LENGTH:
            raise ChecksError(
                f"service map component label exceeds max "
                f"{findings.MAX_IDENTIFIER_LENGTH} characters"
            )

        candidates: list[str] = []
        for single_key in ("path", "root_path"):
            val = comp.get(single_key)
            if isinstance(val, str):
                candidates.append(val)
        multi = comp.get("paths")
        if isinstance(multi, list):
            candidates.extend(x for x in multi if isinstance(x, str))

        for raw_prefix in candidates:
            cleaned = raw_prefix.strip().rstrip("/")
            if not cleaned or cleaned == ".":
                continue
            validate_repo_relative_path(cleaned)
            prefixes.append((cleaned, label))
    return prefixes


def _match_component(
    rel_path: str,
    prefixes: list[tuple[str, str]],
) -> str | None:
    best_len = -1
    best_label: str | None = None
    for prefix, label in prefixes:
        if rel_path == prefix or rel_path.startswith(prefix + "/"):
            plen = len(prefix)
            if plen > best_len or (
                plen == best_len and (best_label is None or label < best_label)
            ):
                best_len = plen
                best_label = label
    return best_label


def _default_partition_key(rel_path: str) -> str:
    parts = rel_path.split("/")
    return f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else parts[0]


def _build_partitions(
    entries: list[_FileStat],
    service_map_data: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if not entries:
        return []
    prefixes = _extract_component_prefixes(service_map_data)
    matched_components = (
        [_match_component(e.path, prefixes) for e in entries] if prefixes else []
    )
    use_service_map = any(m is not None for m in matched_components)
    matched_names = {m for m in matched_components if m is not None}
    fallback_name = "other"
    if fallback_name in matched_names:
        fallback_name = "unmapped"
        suffix = 2
        while fallback_name in matched_names:
            fallback_name = f"unmapped-{suffix}"
            suffix += 1

    buckets: dict[str, dict[str, Any]] = {}
    for idx, entry in enumerate(entries):
        if use_service_map:
            name = matched_components[idx] or fallback_name
        else:
            name = _default_partition_key(entry.path)
        bucket = buckets.get(name)
        if bucket is None:
            bucket = {"name": name, "files": 0, "additions": 0, "deletions": 0}
            buckets[name] = bucket
        bucket["files"] += 1
        bucket["additions"] += entry.additions
        bucket["deletions"] += entry.deletions

    return sorted(
        buckets.values(),
        key=lambda p: (-p["additions"], -p["files"], p["name"]),
    )


def _classify_size(files: int, commits: int) -> tuple[str, str, bool, list[str]]:
    if files > LARGE_FILES_THRESHOLD or commits > LARGE_COMMITS_THRESHOLD:
        reasons: list[str] = []
        if files > LARGE_FILES_THRESHOLD:
            reasons.append(f"files > {LARGE_FILES_THRESHOLD}")
        if commits > LARGE_COMMITS_THRESHOLD:
            reasons.append(f"commits > {LARGE_COMMITS_THRESHOLD}")
        return "large", "partition", True, reasons
    if files >= MEDIUM_FILES_THRESHOLD:
        return (
            "medium",
            "single-unit-sorted",
            False,
            [f"files >= {MEDIUM_FILES_THRESHOLD}"],
        )
    return "small", "single-unit", False, []


def size_review(
    *,
    diff_range: str | None = None,
    pr_number: int | None = None,
    repo: str | Path = ".",
    service_map: str | Path | None = None,
) -> dict[str, Any]:
    """Measure a diff or PR and recommend a review strategy and partitions."""
    if (diff_range is None) == (pr_number is None):
        raise ChecksError("exactly one of diff_range or pr_number must be provided")

    repo_root, _ = resolve_repo_root(repo)
    service_map_data = _load_service_map(repo_root, service_map)

    if diff_range is not None:
        mode = "diff"
        target = diff_range
        entries, commits = _git_diff_stats(repo_root, diff_range)
        files = len(entries)
        listed_files = files
        files_truncated = False
        binary_files = sum(1 for e in entries if e.binary)
        additions = sum(e.additions for e in entries)
        deletions = sum(e.deletions for e in entries)
    else:
        assert pr_number is not None
        mode = "pr"
        validate_pr_number(pr_number)
        target = str(pr_number)
        files, additions, deletions, commits, entries = _gh_pr_stats(
            repo_root, pr_number
        )
        listed_files = len(entries)
        files_truncated = files > listed_files
        binary_files = 0

    tier, strategy, partition_recommended, reasons = _classify_size(files, commits)
    partitions = _build_partitions(entries, service_map_data)

    return {
        "schemaVersion": SCHEMA_VERSION,
        "mode": mode,
        "target": target,
        "files": files,
        "listedFiles": listed_files,
        "filesTruncated": files_truncated,
        "binaryFiles": binary_files,
        "additions": additions,
        "deletions": deletions,
        "commits": commits,
        "tier": tier,
        "strategy": strategy,
        "partitionRecommended": partition_recommended,
        "reasons": reasons,
        "partitions": partitions,
    }
