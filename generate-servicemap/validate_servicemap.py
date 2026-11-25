#!/usr/bin/env python3
"""
Validate a servicemap.json file against the schema requirements.
Reports errors, warnings, optional offline evidence/drift verification,
and summary statistics.

Usage:
    python validate_servicemap.py <path-to-servicemap.json> \
        [--check-evidence [--repo PATH] [--repo-name NAME] [--strict]]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import stat
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

MAX_MAP_BYTES = 50 * 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 2 * 1024 * 1024
MAX_MOVE_SCAN_LINES = 50_000
MAX_MOVE_SCAN_SPAN = 500
MAX_MOVE_SCAN_WORK = 2_000_000

VALID_COMPONENT_TYPES = {
    "service",
    "app",
    "library",
    "infrastructure",
    "pipeline",
    "datastore",
    "external",
}
VALID_CONNECTION_TYPES = {
    "http",
    "grpc",
    "graphql",
    "websocket",
    "queue",
    "pubsub",
    "database",
    "cache",
    "storage",
    "library",
    "infrastructure",
    "event",
    "process",
    "ipc",
    "file",
}
VALID_PROCESS_VIA = {"sudo", "launchd", "exec", "shell"}
VALID_PROCESS_ENVIRONMENTS = {"inherited", "constructed"}
VALID_IPC_CHANNELS = {"unix_socket", "stdio", "pipe", "signal"}
VALID_FILE_MODES = {"read", "write", "read_write", "append", "lock", "watch"}
VALID_AUTH_MECHANISMS = {
    "jwt",
    "api_key",
    "oauth2",
    "session",
    "mtls",
    "basic",
    "none",
    "unknown",
}
VALID_AUTHZ_TYPES = {"rbac", "abac", "acl", "scope", "none", "unknown"}
ID_PREFIXES = {
    "service": "svc-",
    "app": "app-",
    "library": "lib-",
    "infrastructure": "infra-",
    "pipeline": "pipeline-",
    "datastore": "datastore-",
    "external": "ext-",
}

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DRIVE_PREFIX_RE = re.compile(r"^[A-Za-z]:")
ANSI_ESCAPE_RE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])"
)
FINDING_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("CVE reference", re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)),
    ("CWE reference", re.compile(r"\bCWE-\d+\b", re.IGNORECASE)),
    (
        "security/code finding phrasing",
        re.compile(
            r"\b(?:sql injection|command injection|path traversal|hardcoded secret"
            r"|security finding|vulnerability|unauthenticated access"
            r"|privilege escalation"
            r"|arbitrary code execution)\b",
            re.IGNORECASE,
        ),
    ),
    ("finding severity tag", re.compile(r"(?:^|\s)(?:CRITICAL|HIGH|ISSUE|CONCERN):")),
)

errors: list[str] = []
warnings: list[str] = []


@dataclass
class ValidationResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    evidence_checked: bool = False
    evidence_counts: dict[str, int] = field(default_factory=dict)
    evidence_details: list[str] = field(default_factory=list)


def sanitize_terminal(text: str) -> str:
    """Strip ANSI escape sequences and escape control characters."""
    cleaned = ANSI_ESCAPE_RE.sub("", text)
    out: list[str] = []
    for ch in cleaned:
        code = ord(ch)
        if code < 0x20 or 0x7F <= code <= 0x9F:
            out.append(f"\\x{code:02x}")
        else:
            out.append(ch)
    return "".join(out)


def _is_non_empty_str(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_safe_rel_posix(path_str: str) -> bool:
    if not path_str or "\x00" in path_str:
        return False
    if (
        path_str.startswith(("/", "\\"))
        or "\\" in path_str
        or DRIVE_PREFIX_RE.match(path_str)
    ):
        return False
    parts = path_str.split("/")
    return all(part not in ("", ".", "..") for part in parts)


def hash_lines(lines: list[str]) -> str:
    """Compute deterministic SHA-256 over LF-joined source lines."""
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def _parse_schema_version(sv: object) -> tuple[int, int, int] | None:
    """Return (major, minor, patch) tuple, or None if unparseable."""
    if not isinstance(sv, str) or not sv:
        return None
    parts = sv.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def _is_valid_iso_timestamp(value: object) -> tuple[bool, str]:
    if not isinstance(value, str):
        return False, f"must be a string, got {type(value).__name__}"
    # Keep 3.10 support for trailing Z while rejecting date-only "YYYY-MM-DDZ".

    if value.endswith(("Z", "z")) and any(sep in value for sep in ("T", "t", " ")):
        normalized = value[:-1] + "+00:00"
    else:
        normalized = value
    try:
        datetime.fromisoformat(normalized)
        return True, ""
    except ValueError:
        return False, f"is not a valid ISO 8601 timestamp: {sanitize_terminal(value)}"


def check_iso_timestamp(value: object, field_name: str) -> bool:
    ok, reason = _is_valid_iso_timestamp(value)
    if not ok:
        errors.append(f"ERROR: {sanitize_terminal(field_name)} {reason}")
    return ok


def _validate_confidence(value: object, context: str) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return f"confidence in {context} must be a number, got {type(value).__name__}"
    if not math.isfinite(value) or value < 0.0 or value > 1.0:
        return f"confidence in {context} must be 0.0–1.0, got {value}"
    return None


def check_confidence(value: object, context: str) -> None:
    err = _validate_confidence(value, context)
    if err is not None:
        errors.append(f"ERROR: {sanitize_terminal(err)}")


def _declared_repos(data: dict, is_v1_1_plus: bool) -> list[str]:
    if is_v1_1_plus:
        repos = data.get("repositories")
        if not isinstance(repos, list):
            return []
        return [
            r["name"]
            for r in repos
            if isinstance(r, dict) and _is_non_empty_str(r.get("name"))
        ]
    repo = data.get("repository")
    if isinstance(repo, dict) and _is_non_empty_str(repo.get("name")):
        return [repo["name"]]
    return []


def _git_origin_repo_name(repo_root: Path) -> str | None:
    if not (repo_root / ".git").exists():
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    url = proc.stdout.strip().rstrip("/")
    if not url:
        return None
    tail = url.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    if tail.endswith(".git"):
        tail = tail[:-4]
    return tail or None


def resolve_repo_name(
    data: dict,
    is_v1_1_plus: bool,
    repo_root: Path,
    explicit_name: str | None = None,
) -> str | None:
    if explicit_name is not None:
        stripped = explicit_name.strip()
        return stripped or None
    declared = _declared_repos(data, is_v1_1_plus)
    origin_name = _git_origin_repo_name(repo_root)
    if origin_name and origin_name in declared:
        return origin_name
    dir_name = repo_root.name
    if dir_name in declared:
        return dir_name
    if len(declared) == 1:
        return declared[0]
    return None


class _Validator:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.evidence_refs: list[tuple[str, dict]] = []

    def error(self, msg: str) -> None:
        self.errors.append(f"ERROR: {sanitize_terminal(msg)}")

    def warn(self, msg: str) -> None:
        self.warnings.append(f"WARN: {sanitize_terminal(msg)}")

    def check_iso_timestamp(self, value: object, field_name: str) -> bool:
        ok, reason = _is_valid_iso_timestamp(value)
        if not ok:
            self.error(f"{field_name} {reason}")
        return ok

    def check_confidence(self, value: object, context: str) -> None:
        err = _validate_confidence(value, context)
        if err is not None:
            self.error(err)

    def check_findings_text(self, item: dict, ctx: str) -> None:
        for field_name in ("notes", "description"):
            val = item.get(field_name)
            texts: list[str] = []
            if isinstance(val, str):
                texts.append(val)
            elif isinstance(val, list):
                texts.extend(x for x in val if isinstance(x, str))
            for text in texts:
                for label, pattern in FINDING_PATTERNS:
                    if pattern.search(text):
                        self.warn(
                            f"{ctx}.{field_name} looks like a finding ({label}); "
                            "keep findings out of the service map"
                        )
                        break

    def validate_mounts(self, mounts: object, ctx: str) -> None:
        if not isinstance(mounts, list):
            self.error(f"{ctx}.mounts must be a list")
            return
        allowed_keys = {"source", "target", "read_only"}
        for idx, mount in enumerate(mounts):
            mctx = f"{ctx}.mounts[{idx}]"
            if not isinstance(mount, dict):
                self.error(f"{mctx} must be an object")
                continue
            unknown = set(mount) - allowed_keys
            if unknown:
                self.error(f"{mctx} has unknown field(s): {', '.join(sorted(unknown))}")
            for req in ("source", "target"):
                if not _is_non_empty_str(mount.get(req)):
                    self.error(f"{mctx}.{req} must be a non-empty string")
            if "read_only" in mount and not isinstance(mount["read_only"], bool):
                self.error(f"{mctx}.read_only must be a boolean")

    def _check_enum(
        self,
        value: object,
        valid: set[str],
        label: str,
        *,
        warn_only: bool = False,
        kind_label: str = "value",
    ) -> bool:
        if not isinstance(value, str):
            self.error(f"{label} must be a string, got {type(value).__name__}")
            return False
        if value not in valid:
            if warn_only:
                self.warn(f"{label}: unknown {kind_label} '{value}'")
            else:
                self.error(f"{label} must be one of {sorted(valid)}, got '{value}'")
            return False
        return True

    def validate_evidence_list(
        self,
        evidence: object,
        ctx: str,
        *,
        known_repos: set[str] | None = None,
    ) -> None:
        if not isinstance(evidence, list):
            self.error(f"{ctx}.evidence must be a list")
            return
        for idx, entry in enumerate(evidence):
            ectx = f"{ctx}.evidence[{idx}]"
            if not isinstance(entry, dict):
                self.error(f"{ectx} must be an object")
                continue
            valid_entry = True
            repo_val = entry.get("repo")
            if not _is_non_empty_str(repo_val):
                self.error(f"{ectx}.repo must be a non-empty string")
                valid_entry = False
            elif known_repos is not None and repo_val not in known_repos:
                self.error(
                    f"{ectx}.repo '{repo_val}' does not match any declared repository"
                )
                valid_entry = False
            file_val = entry.get("file")
            if not isinstance(file_val, str) or not _is_safe_rel_posix(file_val):
                self.error(
                    f"{ectx}.file must be a safe repo-relative POSIX path "
                    "without '..' or leading '/'"
                )
                valid_entry = False
            lines_val = entry.get("lines")
            if (
                not isinstance(lines_val, list)
                or len(lines_val) != 2
                or not _is_strict_int(lines_val[0])
                or not _is_strict_int(lines_val[1])
                or lines_val[0] < 1
                or lines_val[1] < lines_val[0]
            ):
                self.error(f"{ectx}.lines must be [start, end] with 1 <= start <= end")
                valid_entry = False
            sha_val = entry.get("sha256")
            if not isinstance(sha_val, str) or not SHA256_RE.match(sha_val):
                self.error(f"{ectx}.sha256 must be a 64-character lowercase hex digest")
                valid_entry = False
            if valid_entry:
                self.evidence_refs.append((ectx, entry))

    def validate_component(
        self,
        comp: object,
        idx: int,
        all_ids: set[str],
        is_v1_1_plus: bool = False,
        known_repos: set[str] | None = None,
    ) -> None:
        ctx = f"components[{idx}]"
        if not isinstance(comp, dict):
            self.error(f"{ctx} must be an object")
            return

        required = [
            "id",
            "name",
            "type",
            "confidence",
            "discovery_method",
            "last_crawled",
            "stub",
        ]
        if is_v1_1_plus:
            required.append("source_repo")
        for fld in required:
            if fld not in comp:
                self.error(f"{ctx} missing required field: {fld}")

        raw_id = comp.get("id")
        comp_id = raw_id if isinstance(raw_id, str) and raw_id else f"<unknown-{idx}>"
        ctx = f"component '{comp_id}'"

        if isinstance(raw_id, str) and raw_id:
            if raw_id in all_ids:
                self.error(f"{ctx}: duplicate component ID")
            all_ids.add(raw_id)
        elif "id" in comp:
            self.error(f"{ctx}: id must be a non-empty string")

        comp_type = comp.get("type")
        if "type" in comp:
            self._check_enum(comp_type, VALID_COMPONENT_TYPES, f"{ctx} type")

        if (
            isinstance(comp_type, str)
            and comp_type in ID_PREFIXES
            and isinstance(raw_id, str)
        ):
            expected_prefix = ID_PREFIXES[comp_type]
            if not comp_id.startswith(expected_prefix):
                self.warn(
                    f"{ctx}: ID should start with '{expected_prefix}' "
                    f"for type '{comp_type}'"
                )

        if "confidence" in comp:
            self.check_confidence(comp["confidence"], ctx)

        if "last_crawled" in comp:
            self.check_iso_timestamp(comp["last_crawled"], f"{ctx}.last_crawled")

        if comp.get("stub"):
            if "stub_reason" not in comp:
                self.error(f"{ctx}: stub=true requires stub_reason")
            conf = comp.get("confidence", 1)
            if (
                not isinstance(conf, bool)
                and isinstance(conf, (int, float))
                and conf > 0.3
            ):
                self.warn(f"{ctx}: stub with confidence > 0.3 is unusual")

        if comp.get("stale") and "stale_since" not in comp:
            self.error(f"{ctx}: stale=true requires stale_since")

        if not comp.get("stub") and comp_type != "external" and not comp.get("path"):
            self.warn(f"{ctx}: non-stub, non-external component should have a path")

        if is_v1_1_plus and known_repos is not None and "source_repo" in comp:
            sr = comp["source_repo"]
            if sr is not None and (not isinstance(sr, str) or sr not in known_repos):
                self.error(f"{ctx}: source_repo '{sr}' does not match repositories[]")
            if sr is None and not comp.get("stub"):
                self.warn(f"{ctx}: source_repo is null but component is not a stub")

        if comp_type in ("service", "app"):
            endpoints = comp.get("endpoints", [])
            if not isinstance(endpoints, list):
                self.error(f"{ctx}.endpoints must be a list")
            else:
                for i, ep in enumerate(endpoints):
                    ep_ctx = f"{ctx}.endpoints[{i}]"
                    if not isinstance(ep, dict):
                        self.error(f"{ep_ctx} must be an object")
                        continue
                    for fld in ("method", "path", "public", "confidence"):
                        if fld not in ep:
                            self.error(f"{ep_ctx} missing required field: {fld}")
                    if "confidence" in ep:
                        self.check_confidence(ep["confidence"], ep_ctx)
                    if "authentication" in ep:
                        auth = ep["authentication"]
                        if isinstance(auth, dict):
                            mech = auth.get("mechanism")
                            if mech is not None and mech != "":
                                self._check_enum(
                                    mech,
                                    VALID_AUTH_MECHANISMS,
                                    ep_ctx,
                                    warn_only=True,
                                    kind_label="auth mechanism",
                                )
                        else:
                            self.error(f"{ep_ctx}.authentication must be an object")
                    if "authorization" in ep:
                        authz = ep["authorization"]
                        if isinstance(authz, dict):
                            authz_type = authz.get("type")
                            if authz_type is not None and authz_type != "":
                                self._check_enum(
                                    authz_type,
                                    VALID_AUTHZ_TYPES,
                                    ep_ctx,
                                    warn_only=True,
                                    kind_label="authz type",
                                )
                        else:
                            self.error(f"{ep_ctx}.authorization must be an object")
                    self.check_findings_text(ep, ep_ctx)

        if isinstance(comp.get("env_vars"), list):
            for i, ev in enumerate(comp["env_vars"]):
                if isinstance(ev, dict):
                    self.check_findings_text(ev, f"{ctx}.env_vars[{i}]")

        if comp_type == "datastore":
            for fld in ("engine", "shared", "consumers"):
                if fld not in comp:
                    self.error(f"{ctx}: datastore missing required field '{fld}'")

        if comp_type == "external":
            for fld in ("vendor", "category", "consumers"):
                if fld not in comp:
                    self.error(
                        f"{ctx}: external component missing required field '{fld}'"
                    )

        self.check_findings_text(comp, ctx)

        if "evidence" in comp:
            self.validate_evidence_list(comp["evidence"], ctx, known_repos=known_repos)

    def validate_connection(
        self,
        conn: object,
        idx: int,
        component_ids: set[str],
        *,
        known_repos: set[str] | None = None,
    ) -> None:
        ctx = f"connections[{idx}]"
        if not isinstance(conn, dict):
            self.error(f"{ctx} must be an object")
            return

        for fld in (
            "id",
            "source",
            "target",
            "type",
            "async",
            "confidence",
            "discovery_method",
        ):
            if fld not in conn:
                self.error(f"{ctx} missing required field: {fld}")

        raw_id = conn.get("id")
        conn_id = (
            raw_id if isinstance(raw_id, str) and raw_id else f"<unknown-conn-{idx}>"
        )
        ctx = f"connection '{conn_id}'"
        if "id" in conn and not _is_non_empty_str(raw_id):
            self.error(f"{ctx}: id must be a non-empty string")

        conn_type = conn.get("type")
        if "type" in conn:
            self._check_enum(conn_type, VALID_CONNECTION_TYPES, f"{ctx} type")

        source = conn.get("source")
        target = conn.get("target")
        if "source" in conn and (
            not isinstance(source, str) or not source or source not in component_ids
        ):
            self.error(f"{ctx}: source '{source}' does not match any component ID")
        if "target" in conn and (
            not isinstance(target, str) or not target or target not in component_ids
        ):
            self.error(f"{ctx}: target '{target}' does not match any component ID")

        if "confidence" in conn:
            self.check_confidence(conn["confidence"], ctx)

        if conn_type == "process":
            self._validate_process_connection(conn, ctx)
        elif conn_type == "ipc":
            self._validate_ipc_connection(conn, ctx)
        elif conn_type == "file":
            self._validate_file_connection(conn, ctx)
        elif conn_type == "http":
            if (
                "via" in conn
                and conn["via"] is not None
                and not _is_non_empty_str(conn["via"])
            ):
                self.error(f"{ctx}.via must be a non-empty string")
        elif conn_type == "infrastructure":
            if "mounts" in conn:
                self.validate_mounts(conn["mounts"], ctx)

        self.check_findings_text(conn, ctx)

        if "evidence" in conn:
            self.validate_evidence_list(conn["evidence"], ctx, known_repos=known_repos)

    def _validate_process_connection(self, conn: dict, ctx: str) -> None:
        for fld in ("program", "as_user", "via", "environment", "passes"):
            if fld not in conn:
                self.error(f"{ctx}: process connection missing required field '{fld}'")
        if "program" in conn and not _is_non_empty_str(conn["program"]):
            self.error(f"{ctx}.program must be a non-empty string")
        if "as_user" in conn and not _is_non_empty_str(conn["as_user"]):
            self.error(f"{ctx}.as_user must be a non-empty string")
        if "via" in conn:
            self._check_enum(conn.get("via"), VALID_PROCESS_VIA, f"{ctx}.via")
        if "environment" in conn:
            self._check_enum(
                conn.get("environment"),
                VALID_PROCESS_ENVIRONMENTS,
                f"{ctx}.environment",
            )
        if "passes" in conn:
            passes = conn["passes"]
            if not isinstance(passes, dict):
                self.error(f"{ctx}.passes must be an object")
            else:
                unknown = set(passes) - {"argv", "stdin"}
                if unknown:
                    unknown_str = ", ".join(sorted(unknown))
                    self.error(f"{ctx}.passes has unknown field(s): {unknown_str}")
                if "argv" in passes and passes["argv"] is not None:
                    argv = passes["argv"]
                    if not isinstance(argv, list) or not all(
                        isinstance(a, str) for a in argv
                    ):
                        self.error(f"{ctx}.passes.argv must be a list of strings")
                if "stdin" in passes and passes["stdin"] is not None:
                    stdin = passes["stdin"]
                    ok_stdin = isinstance(stdin, str) or (
                        isinstance(stdin, list)
                        and all(isinstance(s, str) for s in stdin)
                    )
                    if not ok_stdin:
                        self.error(
                            f"{ctx}.passes.stdin must be a string or list of strings"
                        )
        if "mounts" in conn:
            self.validate_mounts(conn["mounts"], ctx)

    def _validate_ipc_connection(self, conn: dict, ctx: str) -> None:
        for fld in ("channel", "channel_auth"):
            if fld not in conn:
                self.error(f"{ctx}: ipc connection missing required field '{fld}'")
        if "channel" in conn:
            self._check_enum(conn.get("channel"), VALID_IPC_CHANNELS, f"{ctx}.channel")
        if "channel_auth" in conn and not _is_non_empty_str(conn["channel_auth"]):
            self.error(f"{ctx}.channel_auth must be a non-empty string")

    def _validate_file_connection(self, conn: dict, ctx: str) -> None:
        for fld in ("path_expr", "mode"):
            if fld not in conn:
                self.error(f"{ctx}: file connection missing required field '{fld}'")
        if "path_expr" in conn and not _is_non_empty_str(conn["path_expr"]):
            self.error(f"{ctx}.path_expr must be a non-empty string")
        if "mode" in conn:
            self._check_enum(conn.get("mode"), VALID_FILE_MODES, f"{ctx}.mode")

    def validate_metadata(
        self,
        meta: object,
        components: list,
        connections: list,
        is_v1_1_plus: bool = False,
    ) -> None:
        ctx = "metadata"
        if not isinstance(meta, dict):
            self.error("metadata must be an object")
            return

        required = [
            "total_components",
            "total_connections",
            "total_stubs",
            "component_counts",
            "low_confidence_components",
            "shared_datastores",
            "unauthenticated_public_endpoints",
            "unmonitored_services",
        ]
        if is_v1_1_plus:
            required.append("repo_staleness")
        for fld in required:
            if fld not in meta:
                self.error(f"{ctx} missing required field: {fld}")

        if is_v1_1_plus and isinstance(meta.get("repo_staleness"), list):
            for i, entry in enumerate(meta["repo_staleness"]):
                ectx = f"{ctx}.repo_staleness[{i}]"
                if not isinstance(entry, dict):
                    self.error(f"{ectx} must be an object")
                    continue
                for fld in ("repo", "last_crawled", "components", "age_days"):
                    if fld not in entry:
                        self.error(f"{ectx} missing required field: {fld}")
                if "last_crawled" in entry:
                    self.check_iso_timestamp(
                        entry["last_crawled"], f"{ectx}.last_crawled"
                    )

        if meta.get("total_components") != len(components):
            self.warn(
                f"{ctx}: total_components ({meta.get('total_components')}) != "
                f"actual component count ({len(components)})"
            )
        if meta.get("total_connections") != len(connections):
            self.warn(
                f"{ctx}: total_connections ({meta.get('total_connections')}) != "
                f"actual connection count ({len(connections)})"
            )

        actual_stubs = sum(
            1 for c in components if isinstance(c, dict) and c.get("stub")
        )
        if meta.get("total_stubs") != actual_stubs:
            stubs_val = meta.get("total_stubs")
            self.warn(f"{ctx}: total_stubs ({stubs_val}) != actual ({actual_stubs})")

        if "component_counts" in meta:
            comp_counts = meta["component_counts"]
            if not isinstance(comp_counts, dict):
                self.error(f"{ctx}.component_counts must be an object")
            else:
                actual_counts = Counter(
                    c.get("type")
                    for c in components
                    if isinstance(c, dict) and isinstance(c.get("type"), str)
                )
                for comp_type, count in comp_counts.items():
                    if actual_counts.get(comp_type, 0) != count:
                        self.warn(
                            f"{ctx}: component_counts.{comp_type} ({count}) != "
                            f"actual ({actual_counts.get(comp_type, 0)})"
                        )

    def validate(self, data: object) -> bool:
        """Validate map structure; returns True when schema_version is 1.1+."""
        if not isinstance(data, dict):
            self.error(f"root must be a JSON object, got {type(data).__name__}")
            return False

        sv = data.get("schema_version", "")
        parsed = _parse_schema_version(sv)
        if "schema_version" in data and parsed is None:
            self.error(f"schema_version must be semver (e.g., '1.0.0'), got '{sv}'")

        is_v1_1_plus = parsed is not None and (parsed[0], parsed[1]) >= (1, 1)
        repo_field = "repositories" if is_v1_1_plus else "repository"

        for fld in (
            "schema_version",
            "generated_at",
            repo_field,
            "components",
            "connections",
            "metadata",
        ):
            if fld not in data:
                self.error(f"Missing required root field: {fld}")

        self.check_findings_text(data, "root")

        known_repos: set[str] | None = None
        if is_v1_1_plus and isinstance(data.get("repositories"), list):
            known_repos = {
                r["name"]
                for r in data["repositories"]
                if isinstance(r, dict) and _is_non_empty_str(r.get("name"))
            }
        elif (
            not is_v1_1_plus
            and isinstance(data.get("repository"), dict)
            and _is_non_empty_str(data["repository"].get("name"))
        ):
            known_repos = {data["repository"]["name"]}

        if "generated_at" in data:
            self.check_iso_timestamp(data["generated_at"], "generated_at")

        if is_v1_1_plus:
            repos = data.get("repositories", [])
            if not isinstance(repos, list):
                self.error("repositories must be an array")
            elif not repos:
                self.error("repositories must contain at least one entry")
            else:
                seen_names: set[str] = set()
                for i, repo in enumerate(repos):
                    rctx = f"repositories[{i}]"
                    if not isinstance(repo, dict):
                        self.error(f"{rctx} must be an object")
                        continue
                    if "name" not in repo or not _is_non_empty_str(repo.get("name")):
                        self.error(f"{rctx}.name is required")
                    else:
                        if repo["name"] in seen_names:
                            self.error(f"{rctx}.name '{repo['name']}' is duplicated")
                        seen_names.add(repo["name"])
                    if "monorepo" not in repo:
                        self.error(f"{rctx}.monorepo is required")
                    if "last_crawled" not in repo:
                        self.error(f"{rctx}.last_crawled is required")
                    else:
                        self.check_iso_timestamp(
                            repo["last_crawled"], f"{rctx}.last_crawled"
                        )
                    self.check_findings_text(repo, rctx)
        else:
            repo = data.get("repository", {})
            if not isinstance(repo, dict):
                self.error("repository must be an object")
            else:
                if "name" not in repo or not _is_non_empty_str(repo.get("name")):
                    self.error("repository.name is required")
                if "monorepo" not in repo:
                    self.error("repository.monorepo is required")
                self.check_findings_text(repo, "repository")

        raw_components = data.get("components", [])
        if not isinstance(raw_components, list):
            self.error("components must be an array")
            components: list = []
        else:
            components = raw_components

        component_ids: set[str] = set()
        for i, comp in enumerate(components):
            self.validate_component(
                comp,
                i,
                component_ids,
                is_v1_1_plus=is_v1_1_plus,
                known_repos=known_repos,
            )

        raw_connections = data.get("connections", [])
        if not isinstance(raw_connections, list):
            self.error("connections must be an array")
            connections: list = []
        else:
            connections = raw_connections

        for i, conn in enumerate(connections):
            self.validate_connection(conn, i, component_ids, known_repos=known_repos)

        if "metadata" in data:
            self.validate_metadata(
                data["metadata"], components, connections, is_v1_1_plus=is_v1_1_plus
            )

        return is_v1_1_plus


def _safe_read_evidence_lines(
    repo_root: Path,
    rel_posix: str,
    cache: dict[str, tuple[str, list[str] | None]],
) -> tuple[str, list[str] | None]:
    if rel_posix in cache:
        return cache[rel_posix]

    cur = repo_root
    for part in rel_posix.split("/"):
        cur = cur / part
        try:
            st = cur.lstat()
        except FileNotFoundError:
            res = ("missing", None)
            cache[rel_posix] = res
            return res
        except OSError:
            res = ("unreadable", None)
            cache[rel_posix] = res
            return res
        if stat.S_ISLNK(st.st_mode):
            try:
                resolved_link = cur.resolve()
            except (OSError, RuntimeError):
                res = ("escape", None)
                cache[rel_posix] = res
                return res
            if not resolved_link.is_relative_to(repo_root):
                res = ("escape", None)
                cache[rel_posix] = res
                return res

    try:
        resolved = cur.resolve()
        st = resolved.stat()
    except FileNotFoundError:
        res = ("missing", None)
        cache[rel_posix] = res
        return res
    except (OSError, RuntimeError):
        res = ("unreadable", None)
        cache[rel_posix] = res
        return res

    if not resolved.is_relative_to(repo_root):
        res = ("escape", None)
        cache[rel_posix] = res
        return res
    if not stat.S_ISREG(st.st_mode):
        res = ("nonregular", None)
        cache[rel_posix] = res
        return res

    try:
        with resolved.open("rb") as fh:
            raw = fh.read(MAX_EVIDENCE_FILE_BYTES + 1)
    except OSError:
        res = ("unreadable", None)
        cache[rel_posix] = res
        return res

    if len(raw) > MAX_EVIDENCE_FILE_BYTES:
        res = ("oversized", None)
        cache[rel_posix] = res
        return res

    res = ("ok", raw.decode("utf-8", errors="replace").splitlines())
    cache[rel_posix] = res
    return res


def _find_moved_range(
    lines: list[str],
    start: int,
    end: int,
    target_sha: str,
    *,
    rel_file: str = "",
    move_cache: dict[tuple[str, int, str], list[int]] | None = None,
) -> tuple[tuple[int, int] | None, str | None]:
    span = end - start + 1
    if span <= 0 or span > len(lines):
        return None, None
    if len(lines) > MAX_MOVE_SCAN_LINES:
        return None, f"move scan skipped (file exceeds {MAX_MOVE_SCAN_LINES} lines)"
    if span > MAX_MOVE_SCAN_SPAN:
        return (
            None,
            f"move scan skipped (span {span} exceeds {MAX_MOVE_SCAN_SPAN} lines)",
        )
    windows = len(lines) - span + 1
    if windows * span > MAX_MOVE_SCAN_WORK:
        return (
            None,
            f"move scan skipped (exceeds {MAX_MOVE_SCAN_WORK} line-window budget)",
        )
    key = (rel_file, span, target_sha)
    if move_cache is not None and key in move_cache:
        matches = move_cache[key]
    else:
        matches = [
            idx
            for idx in range(0, windows)
            if hash_lines(lines[idx : idx + span]) == target_sha
        ]
        if move_cache is not None:
            move_cache[key] = matches
    if not matches:
        return None, None
    best_idx = min(matches, key=lambda idx: (abs(idx - (start - 1)), idx))
    return (best_idx + 1, best_idx + span), None


def _run_evidence_checks(
    validator: _Validator,
    data: dict,
    is_v1_1_plus: bool,
    repo_path: Path,
    repo_name: str | None,
    strict: bool,
) -> tuple[dict[str, int], list[str]]:
    counts = {
        "verified": 0,
        "moved": 0,
        "changed": 0,
        "missing": 0,
        "unverifiable": 0,
        "error": 0,
    }
    details: list[str] = []

    try:
        repo_root = repo_path.resolve()
    except OSError:
        validator.error(f"evidence check repo path could not be resolved: {repo_path}")
        return counts, details

    if not repo_root.is_dir():
        validator.error(f"evidence check repo path is not a directory: {repo_root}")
        return counts, details

    declared = _declared_repos(data, is_v1_1_plus)
    current_repo = resolve_repo_name(
        data, is_v1_1_plus, repo_root, explicit_name=repo_name
    )
    if validator.evidence_refs:
        if current_repo is None:
            msg = (
                "could not determine a single repo name for this checkout; "
                "pass --repo-name NAME to verify citations"
            )
            if strict:
                validator.error(msg)
            else:
                validator.warn(msg)
        elif repo_name is not None and declared and current_repo not in declared:
            msg = f"--repo-name '{current_repo}' does not match any declared repository"
            if strict:
                validator.error(msg)
            else:
                validator.warn(msg)

    cache: dict[str, tuple[str, list[str] | None]] = {}
    move_cache: dict[tuple[str, int, str], list[int]] = {}
    for ctx, entry in validator.evidence_refs:
        cite_repo = entry["repo"]
        rel_file = entry["file"]
        start, end = entry["lines"]
        expected_sha = entry["sha256"]

        if current_repo is None or cite_repo != current_repo:
            counts["unverifiable"] += 1
            details.append(
                sanitize_terminal(
                    f"UNVERIFIABLE: {ctx} ({cite_repo}:{rel_file}:{start}-{end}; "
                    f"checked repo is {current_repo or 'unknown'})"
                )
            )
            continue

        status, file_lines = _safe_read_evidence_lines(repo_root, rel_file, cache)
        if status == "escape":
            counts["error"] += 1
            validator.error(
                f"{ctx}: path '{rel_file}' escapes repository root via symlink"
            )
            continue
        if status == "missing":
            counts["missing"] += 1
            msg = f"{ctx}: cited file '{rel_file}' not found (lines {start}-{end})"
            if strict:
                validator.error(msg)
            else:
                validator.warn(msg)
            continue
        if status != "ok" or file_lines is None:
            counts["error"] += 1
            msg = f"{ctx}: cited file '{rel_file}' is {status}"
            if strict:
                validator.error(msg)
            else:
                validator.warn(msg)
            continue

        if (
            end <= len(file_lines)
            and hash_lines(file_lines[start - 1 : end]) == expected_sha
        ):
            counts["verified"] += 1
            continue

        moved, skip_reason = _find_moved_range(
            file_lines,
            start,
            end,
            expected_sha,
            rel_file=rel_file,
            move_cache=move_cache,
        )
        if moved is not None:
            counts["moved"] += 1
            details.append(
                sanitize_terminal(
                    f"MOVED: {ctx} ({rel_file} lines [{start}, {end}] "
                    f"-> [{moved[0]}, {moved[1]}])"
                )
            )
            continue

        counts["changed"] += 1
        if end > len(file_lines):
            msg = (
                f"{ctx}: cited range {rel_file}:{start}-{end} exceeds file length "
                f"({len(file_lines)} lines)"
            )
        else:
            msg = f"{ctx}: cited lines {rel_file}:{start}-{end} changed (hash mismatch)"
        if skip_reason:
            msg = f"{msg} ({skip_reason})"
        if strict:
            validator.error(msg)
        else:
            validator.warn(msg)

    return counts, details


def validate_map(
    data: object,
    *,
    check_evidence: bool = False,
    repo_path: Path | None = None,
    repo_name: str | None = None,
    strict: bool = False,
) -> ValidationResult:
    """Validate a parsed service map and optionally verify evidence hashes offline."""
    validator = _Validator()
    is_v1_1_plus = validator.validate(data)
    res = ValidationResult(errors=validator.errors, warnings=validator.warnings)

    if check_evidence and isinstance(data, dict):
        if repo_path is None:
            validator.error(
                "--repo is required when calling validate_map with check_evidence=True"
            )
        else:
            counts, details = _run_evidence_checks(
                validator, data, is_v1_1_plus, repo_path, repo_name, strict
            )
            res.evidence_checked = True
            res.evidence_counts = counts
            res.evidence_details = details

    return res


def validate(data: object) -> None:
    """Validate ``data`` and populate module-level ``errors`` and ``warnings``."""
    res = validate_map(data)
    errors[:] = res.errors
    warnings[:] = res.warnings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate a servicemap.json file against the vld8 schema.",
    )
    parser.add_argument(
        "map_path",
        metavar="path-to-servicemap.json",
        help="Path to the servicemap.json file to validate.",
    )
    parser.add_argument(
        "--check-evidence",
        action="store_true",
        help="Verify evidence[] SHA-256 line hashes offline against a local checkout.",
    )
    parser.add_argument(
        "--repo",
        metavar="PATH",
        default=None,
        help=(
            "Repository root to verify evidence against "
            "(default: directory containing the map; requires --check-evidence)."
        ),
    )
    parser.add_argument(
        "--repo-name",
        metavar="NAME",
        default=None,
        help=(
            "Override the repository name matched against evidence[].repo "
            "(requires --check-evidence)."
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Treat changed or missing evidence citations as errors "
            "(requires --check-evidence)."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.check_evidence:
        if args.strict:
            parser.error("--strict requires --check-evidence")
        if args.repo is not None:
            parser.error("--repo requires --check-evidence")
        if args.repo_name is not None:
            parser.error("--repo-name requires --check-evidence")
    if args.repo is not None and not args.repo.strip():
        parser.error("--repo must not be empty")
    if args.repo_name is not None and not args.repo_name.strip():
        parser.error("--repo-name must not be empty")

    path = Path(args.map_path)
    try:
        st = path.stat()
    except FileNotFoundError:
        print(f"FATAL: File not found: {sanitize_terminal(str(path))}")
        return 2
    except OSError as exc:
        safe_p = sanitize_terminal(str(path))
        print(f"FATAL: Cannot stat {safe_p}: {sanitize_terminal(str(exc))}")
        return 2

    if not stat.S_ISREG(st.st_mode):
        print(f"FATAL: Not a regular file: {sanitize_terminal(str(path))}")
        return 2

    try:
        with path.open("rb") as fh:
            raw = fh.read(MAX_MAP_BYTES + 1)
    except OSError as exc:
        safe_p = sanitize_terminal(str(path))
        print(f"FATAL: Cannot read {safe_p}: {sanitize_terminal(str(exc))}")
        return 2

    if len(raw) > MAX_MAP_BYTES:
        print(f"FATAL: Map file exceeds {MAX_MAP_BYTES} byte limit")
        return 2

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"FATAL: Invalid JSON: {sanitize_terminal(str(exc))}")
        return 2

    repo_root = Path(args.repo) if args.repo else path.resolve().parent
    res = validate_map(
        data,
        check_evidence=args.check_evidence,
        repo_path=repo_root,
        repo_name=args.repo_name,
        strict=args.strict,
    )
    errors[:] = res.errors
    warnings[:] = res.warnings

    if not isinstance(data, dict):
        for err in res.errors:
            print(f"  {err}")
        return 1

    raw_components = data.get("components", [])
    components = raw_components if isinstance(raw_components, list) else []
    raw_connections = data.get("connections", [])
    connections = raw_connections if isinstance(raw_connections, list) else []
    dict_components = [c for c in components if isinstance(c, dict)]

    stubs = [c for c in dict_components if c.get("stub")]
    low_conf = [
        c
        for c in dict_components
        if not isinstance(c.get("confidence"), bool)
        and isinstance(c.get("confidence", 1), (int, float))
        and c.get("confidence", 1) < 0.5
    ]
    type_counts = Counter(
        c.get("type") for c in dict_components if isinstance(c.get("type"), str)
    )

    sv_parsed = _parse_schema_version(data.get("schema_version", ""))
    is_v1_1 = sv_parsed is not None and (sv_parsed[0], sv_parsed[1]) >= (1, 1)
    if is_v1_1:
        repos = data.get("repositories", [])
        if isinstance(repos, list) and repos:
            repo_label = (
                ", ".join(
                    sanitize_terminal(str(r.get("name", "?")))
                    for r in repos
                    if isinstance(r, dict)
                )
                or "MISSING"
            )
        else:
            repo_label = "MISSING"
    else:
        repo = data.get("repository", {})
        repo_label = (
            sanitize_terminal(str(repo.get("name", "MISSING")))
            if isinstance(repo, dict)
            else "MISSING"
        )

    print(f"\n{'=' * 60}")
    print("  servicemap.json Validation Report")
    print(f"{'=' * 60}")
    sv_safe = sanitize_terminal(str(data.get("schema_version", "MISSING")))
    ga_safe = sanitize_terminal(str(data.get("generated_at", "MISSING")))
    print(f"  Schema version: {sv_safe}")
    print(f"  Generated at:   {ga_safe}")
    print(f"  Repository:     {repo_label}")
    print(f"{'=' * 60}")
    print(f"\n  Components: {len(components)}")
    for t, count in sorted(type_counts.items()):
        print(f"    {sanitize_terminal(t)}: {count}")
    print(f"  Connections: {len(connections)}")
    print(f"  Stubs (TODOs): {len(stubs)}")
    print(f"  Low confidence (<0.5): {len(low_conf)}")

    if res.evidence_checked:
        ec = res.evidence_counts
        print("\n  Evidence Verification:")
        print(
            f"    verified={ec.get('verified', 0)} moved={ec.get('moved', 0)} "
            f"changed={ec.get('changed', 0)} missing={ec.get('missing', 0)} "
            f"unverifiable={ec.get('unverifiable', 0)} error={ec.get('error', 0)}"
        )
        for line in res.evidence_details:
            print(f"    {line}")

    if res.errors:
        print(f"\n  ERRORS: {len(res.errors)}")
        for err in res.errors:
            print(f"    {err}")

    if res.warnings:
        print(f"\n  WARNINGS: {len(res.warnings)}")
        for warn in res.warnings:
            print(f"    {warn}")

    if not res.errors and not res.warnings:
        print("\n  ✓ All checks passed!")

    print()
    return 1 if res.errors else 0


if __name__ == "__main__":
    sys.exit(main())
