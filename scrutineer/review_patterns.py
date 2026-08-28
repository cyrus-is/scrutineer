"""Shared loading, validation, and projection for review pattern corpora."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

import yaml


class PatternValidationError(ValueError):
    """Raised when a review pattern corpus does not satisfy its schema."""


_SECURITY_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
_PEER_SEVERITIES = {"issue", "concern"}
_PEER_LENSES = {
    "production-reliability",
    "correctness",
    "data-integrity",
    "error-handling",
    "architecture",
    "operability",
    "performance",
    "maintainability",
}
_PLATFORM_CLASSES = {
    "ios-app",
    "ios-first-library",
    "apple-cross-platform",
    "portable-swift",
}
_FIX_RESOLUTIONS = {
    "advisory-reference",
    "official-release-diff",
    "official-release-fix-series",
}


def path_matches(path: str, pattern: str) -> bool:
    """Match a repo-relative path, including root files for ``**/`` globs."""
    return fnmatch.fnmatch(path, pattern) or (
        pattern.startswith("**/") and fnmatch.fnmatch(path, pattern[3:])
    )


def _require_mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PatternValidationError(f"{where} must be a mapping")
    return value


def _require_list(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        raise PatternValidationError(f"{where} must be a list")
    return value


def _require_string(mapping: dict[str, Any], key: str, where: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise PatternValidationError(f"{where}.{key} must be a non-empty string")
    return value.strip()


def load_swift_patterns(path: Path) -> dict[str, Any]:
    """Load and strictly validate the Swift advisory-derived patterns file."""
    try:
        with path.open(encoding="utf-8") as pattern_file:
            raw = yaml.safe_load(pattern_file)
    except OSError as exc:
        raise PatternValidationError(
            f"cannot read Swift patterns at {path}: {exc}"
        ) from exc
    except yaml.YAMLError as exc:
        raise PatternValidationError(
            f"invalid YAML in Swift patterns at {path}: {exc}"
        ) from exc

    document = _require_mapping(raw, "Swift patterns document")
    if document.get("schema_version") != "1.0.0":
        raise PatternValidationError("Swift patterns schema_version must be '1.0.0'")
    if document.get("language") != "swift":
        raise PatternValidationError("Swift patterns language must be 'swift'")

    source = _require_mapping(document.get("source_snapshot"), "source_snapshot")
    if (
        source.get("advisory_database_repository")
        != "https://github.com/github/advisory-database"
    ):
        raise PatternValidationError(
            "source_snapshot.advisory_database_repository must identify the official database"
        )
    if source.get("advisory_database_license") != "CC-BY-4.0":
        raise PatternValidationError(
            "source_snapshot.advisory_database_license must preserve CC-BY-4.0 attribution"
        )
    source_commit = _require_string(
        source, "advisory_database_commit", "source_snapshot"
    )
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise PatternValidationError(
            "source_snapshot.advisory_database_commit must be a full Git commit"
        )
    fixes = _require_list(document.get("fixes"), "fixes")
    patterns = _require_list(document.get("patterns"), "patterns")

    fix_ids: set[str] = set()
    for index, value in enumerate(fixes):
        where = f"fixes[{index}]"
        fix = _require_mapping(value, where)
        advisory_id = _require_string(fix, "advisory_id", where)
        if not re.fullmatch(
            r"GHSA-[23456789cfghjmpqrvwx]{4}(?:-[23456789cfghjmpqrvwx]{4}){2}",
            advisory_id,
        ):
            raise PatternValidationError(f"{where}.advisory_id is not a canonical GHSA")
        if advisory_id in fix_ids:
            raise PatternValidationError(f"duplicate advisory_id: {advisory_id}")
        fix_ids.add(advisory_id)
        for key in ("package", "source_repository", "ios_evidence"):
            _require_string(fix, key, where)
        fixed_versions = _require_list(
            fix.get("fixed_versions"), f"{where}.fixed_versions"
        )
        if not fixed_versions or not all(
            isinstance(item, str) and item for item in fixed_versions
        ):
            raise PatternValidationError(
                f"{where}.fixed_versions must contain patched versions"
            )
        classification = _require_string(fix, "platform_class", where)
        if classification not in _PLATFORM_CLASSES:
            raise PatternValidationError(
                f"{where}.platform_class must be one of {sorted(_PLATFORM_CLASSES)}"
            )
        resolution = _require_string(fix, "resolution", where)
        if resolution not in _FIX_RESOLUTIONS:
            raise PatternValidationError(
                f"{where}.resolution must be one of {sorted(_FIX_RESOLUTIONS)}"
            )
        commits = _require_list(fix.get("fix_commits"), f"{where}.fix_commits")
        if not commits:
            raise PatternValidationError(f"{where}.fix_commits must not be empty")
        for commit_index, commit_value in enumerate(commits):
            commit_where = f"{where}.fix_commits[{commit_index}]"
            commit = _require_mapping(commit_value, commit_where)
            url = _require_string(commit, "url", commit_where)
            if not re.fullmatch(
                r"https://github\.com/[^/]+/[^/]+/commit/[0-9a-f]{7,40}", url
            ):
                raise PatternValidationError(
                    f"{commit_where}.url is not a GitHub commit URL"
                )
            digest = _require_string(commit, "patch_sha256", commit_where)
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise PatternValidationError(
                    f"{commit_where}.patch_sha256 must be 64 hex characters"
                )
            files = _require_list(
                commit.get("production_files"), f"{commit_where}.production_files"
            )
            if not files or not all(
                isinstance(item, str) and item.endswith(".swift") for item in files
            ):
                raise PatternValidationError(
                    f"{commit_where}.production_files must contain Swift source paths"
                )
            if len(files) != len(set(files)):
                raise PatternValidationError(
                    f"{commit_where}.production_files must not contain duplicates"
                )

    if source.get("included_fix_records") != len(fixes):
        raise PatternValidationError(
            "source_snapshot.included_fix_records must match the fixes list"
        )

    pattern_ids: set[str] = set()
    for index, value in enumerate(patterns):
        where = f"patterns[{index}]"
        pattern = _require_mapping(value, where)
        pattern_id = _require_string(pattern, "id", where)
        if not re.fullmatch(r"(?:swift|ios)-[a-z0-9]+(?:-[a-z0-9]+)*", pattern_id):
            raise PatternValidationError(f"{where}.id must be a stable Swift/iOS slug")
        if pattern_id in pattern_ids:
            raise PatternValidationError(f"duplicate pattern id: {pattern_id}")
        pattern_ids.add(pattern_id)
        for key in (
            "title",
            "vulnerable_pattern",
            "verify",
            "safe_when",
            "secure_alternative",
        ):
            _require_string(pattern, key, where)

        evidence = _require_list(pattern.get("evidence"), f"{where}.evidence")
        if not evidence:
            raise PatternValidationError(f"{where}.evidence must not be empty")
        if not all(isinstance(item, str) for item in evidence):
            raise PatternValidationError(f"{where}.evidence must contain advisory IDs")
        if len(evidence) != len(set(evidence)):
            raise PatternValidationError(
                f"{where}.evidence must not contain duplicates"
            )
        unknown = sorted(set(evidence) - fix_ids)
        if unknown:
            raise PatternValidationError(
                f"{where}.evidence references unknown advisories: {', '.join(unknown)}"
            )

        security = _require_mapping(
            pattern.get("security_review"), f"{where}.security_review"
        )
        if not isinstance(security.get("enabled"), bool):
            raise PatternValidationError(
                f"{where}.security_review.enabled must be boolean"
            )
        if security["enabled"]:
            _require_string(security, "owasp", f"{where}.security_review")
            severity = _require_string(
                security, "severity_if_found", f"{where}.security_review"
            )
            if severity not in _SECURITY_SEVERITIES:
                raise PatternValidationError(
                    f"{where}.security_review.severity_if_found must be one of "
                    f"{sorted(_SECURITY_SEVERITIES)}"
                )

        peer = _require_mapping(pattern.get("peer_review"), f"{where}.peer_review")
        if not isinstance(peer.get("enabled"), bool):
            raise PatternValidationError(f"{where}.peer_review.enabled must be boolean")
        if not security["enabled"] and not peer["enabled"]:
            raise PatternValidationError(
                f"{where} must be enabled for at least one review generator"
            )
        if peer["enabled"]:
            lens = _require_string(peer, "lens", f"{where}.peer_review")
            severity = _require_string(peer, "severity", f"{where}.peer_review")
            _require_string(peer, "failure_mode", f"{where}.peer_review")
            if lens not in _PEER_LENSES:
                raise PatternValidationError(
                    f"{where}.peer_review.lens must be one of {sorted(_PEER_LENSES)}"
                )
            if severity not in _PEER_SEVERITIES:
                raise PatternValidationError(
                    f"{where}.peer_review.severity must be one of {sorted(_PEER_SEVERITIES)}"
                )

    referenced_fixes = {
        advisory_id for pattern in patterns for advisory_id in pattern["evidence"]
    }
    orphaned_fixes = sorted(fix_ids - referenced_fixes)
    if orphaned_fixes:
        raise PatternValidationError(
            f"fixes without a derived pattern: {', '.join(orphaned_fixes)}"
        )

    return document


def _investigation_text(pattern: dict[str, Any]) -> str:
    return (
        f"{pattern['vulnerable_pattern']} "
        f"Verify: {pattern['verify']} "
        f"Not a finding when: {pattern['safe_when']}"
    )


def _existing_ids(items: list[dict[str, Any]], where: str) -> set[str]:
    ids: set[str] = set()
    for index, value in enumerate(items):
        item = _require_mapping(value, f"{where}[{index}]")
        item_id = item.get("id")
        if not isinstance(item_id, str) or not item_id:
            raise PatternValidationError(f"{where} contains an item without an id")
        if item_id in ids:
            raise PatternValidationError(f"duplicate guidance id in {where}: {item_id}")
        ids.add(item_id)
    return ids


def merge_security_patterns(guidance: dict[str, Any], corpus: dict[str, Any]) -> int:
    """Project enabled corpus patterns into ``mobile.ios.checklist``."""
    mobile = guidance.get("mobile")
    if mobile is None:
        return 0
    mobile = _require_mapping(mobile, "security guidance mobile")
    ios = mobile.get("ios")
    if ios is None:
        return 0
    ios = _require_mapping(ios, "security guidance mobile.ios")
    checklist = ios.get("checklist")
    if checklist is None:
        raise PatternValidationError(
            "security guidance mobile.ios must define checklist"
        )
    if not isinstance(checklist, list):
        raise PatternValidationError(
            "security guidance mobile.ios.checklist must be a list"
        )

    ids = _existing_ids(checklist, "mobile.ios.checklist")
    added = 0
    for pattern in corpus["patterns"]:
        consumer = pattern["security_review"]
        if not consumer["enabled"]:
            continue
        if pattern["id"] in ids:
            raise PatternValidationError(
                f"duplicate security guidance id: {pattern['id']}"
            )
        checklist.append(
            {
                "id": pattern["id"],
                "title": pattern["title"],
                "pattern": _investigation_text(pattern),
                "secure_alternative": pattern["secure_alternative"],
                "owasp": consumer["owasp"],
                "severity_if_found": consumer["severity_if_found"],
                "source_advisories": sorted(pattern["evidence"]),
            }
        )
        ids.add(pattern["id"])
        added += 1
    return added


def merge_peer_patterns(guidance: dict[str, Any], corpus: dict[str, Any]) -> int:
    """Project enabled corpus patterns into ``mobile.ios.preflight_checks``."""
    mobile = guidance.get("mobile")
    if mobile is None:
        return 0
    mobile = _require_mapping(mobile, "peer guidance mobile")
    ios = mobile.get("ios")
    if ios is None:
        return 0
    ios = _require_mapping(ios, "peer guidance mobile.ios")
    checks = ios.get("preflight_checks")
    if checks is None:
        raise PatternValidationError(
            "peer guidance mobile.ios must define preflight_checks"
        )
    if not isinstance(checks, list):
        raise PatternValidationError(
            "peer guidance mobile.ios.preflight_checks must be a list"
        )

    ids = _existing_ids(checks, "mobile.ios.preflight_checks")
    added = 0
    for pattern in corpus["patterns"]:
        consumer = pattern["peer_review"]
        if not consumer["enabled"]:
            continue
        if pattern["id"] in ids:
            raise PatternValidationError(f"duplicate peer guidance id: {pattern['id']}")
        checks.append(
            {
                "id": pattern["id"],
                "title": pattern["title"],
                "pattern": _investigation_text(pattern),
                "failure_mode": consumer["failure_mode"],
                "fix": pattern["secure_alternative"],
                "lens": consumer["lens"],
                "severity": consumer["severity"],
                "source_advisories": sorted(pattern["evidence"]),
            }
        )
        ids.add(pattern["id"])
        added += 1
    return added


_SWIFT_IOS_SOURCE_MARKERS = (
    re.compile(r"^\s*import\s+UIKit\b", re.MULTILINE),
    re.compile(r"(?:#if\s+)?(?:os\(iOS\)|canImport\(UIKit\))"),
)
_IOS_PROJECT_MARKERS = (
    re.compile(r"\bIPHONEOS_DEPLOYMENT_TARGET\b"),
    re.compile(r"\bSDKROOT\s*=\s*iphoneos\b", re.IGNORECASE),
    re.compile(r"\.iOS\s*\("),
    re.compile(r"\bplatform\s*:\s*[\"']?iOS\b", re.IGNORECASE),
    re.compile(r"\.ios\.deployment_target\s*="),
    re.compile(r"\.platform\s*=\s*:ios\b"),
)
_SWIFT_PROJECT_NAMES = {
    "Package.swift",
    "Project.swift",
    "Workspace.swift",
    "project.yml",
    "project.yaml",
}
_NONPRODUCTION_PATH_PARTS = {
    "benchmark",
    "benchmarks",
    "demo",
    "demos",
    "example",
    "examples",
    "fixture",
    "fixtures",
    "sample",
    "samples",
    "test",
    "tests",
}


def _swift_component_path(relative: Path) -> str:
    parent_parts = relative.parts[:-1]
    lower_parts = [part.lower() for part in parent_parts]
    for marker in ("ios", "iphone", "ipad"):
        if marker in lower_parts:
            index = lower_parts.index(marker)
            return Path(*parent_parts[: index + 1]).as_posix()
    if "sources" in lower_parts:
        index = lower_parts.index("sources")
        prefix = parent_parts[:index]
        return Path(*prefix).as_posix() if prefix else "."
    return Path(*parent_parts).as_posix() if parent_parts else "."


def _project_component_path(relative: Path) -> Path:
    if relative.as_posix().endswith(".xcodeproj/project.pbxproj"):
        return relative.parent.parent
    return relative.parent


def _is_production_path(relative: Path) -> bool:
    return not any(
        part.lower() in _NONPRODUCTION_PATH_PARTS for part in relative.parts[:-1]
    )


def ios_swift_component_paths(repo_path: Path, file_index: list[Path]) -> list[str]:
    """Find local Swift component roots backed by an iOS-specific signal."""
    swift_files: list[Path] = []
    for path in file_index:
        try:
            relative = path.relative_to(repo_path)
        except ValueError:
            continue
        if (
            path.suffix.lower() == ".swift"
            and path.name not in _SWIFT_PROJECT_NAMES
            and _is_production_path(relative)
        ):
            swift_files.append(path)
    if not swift_files:
        return []

    components: set[str] = set()

    for path in swift_files:
        try:
            relative = path.relative_to(repo_path)
        except ValueError:
            continue
        relative_parts = [part.lower() for part in relative.parts[:-1]]
        if any(marker in relative_parts for marker in ("ios", "iphone", "ipad")):
            components.add(_swift_component_path(relative))
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            content = path.read_text(errors="ignore")
        except OSError:
            continue
        if any(marker.search(content) for marker in _SWIFT_IOS_SOURCE_MARKERS):
            components.add(_swift_component_path(relative))

    for path in file_index:
        try:
            relative_path = path.relative_to(repo_path)
        except ValueError:
            continue
        relative = relative_path.as_posix()
        is_project_file = _is_production_path(relative_path) and (
            path.name in _SWIFT_PROJECT_NAMES
            or path.suffix == ".podspec"
            or relative.endswith(".xcodeproj/project.pbxproj")
        )
        if not is_project_file:
            continue
        try:
            if path.stat().st_size > 2_000_000:
                continue
            content = path.read_text(errors="ignore")
        except OSError:
            continue
        if any(marker.search(content) for marker in _IOS_PROJECT_MARKERS):
            component = _project_component_path(relative_path)
            if any(
                swift.relative_to(repo_path).is_relative_to(component)
                for swift in swift_files
            ):
                components.add(component.as_posix() if component.parts else ".")

    return sorted(components)


def has_ios_swift_evidence(repo_path: Path, file_index: list[Path]) -> bool:
    """Return true only when Swift source is corroborated by an iOS-specific signal."""
    return bool(ios_swift_component_paths(repo_path, file_index))


def service_map_ios_swift_component_paths(
    data: dict[str, Any],
    repo_path: Path | None = None,
    file_index: list[Path] | None = None,
) -> list[str]:
    """Find local iOS Swift component roots declared by a service map."""
    components: set[str] = set()
    root = repo_path.resolve() if repo_path is not None else None

    for component in data.get("components", []):
        if (
            not isinstance(component, dict)
            or component.get("type") != "app"
            or component.get("stub")
            or component.get("stale")
        ):
            continue
        language = str(component.get("language", "")).lower()
        platform = str(component.get("platform", "")).lower()
        framework = str(component.get("framework", "")).lower()
        if platform != "ios" or not (
            language == "swift" or framework in {"swiftui", "uikit"}
        ):
            continue

        component_path = component.get("path")
        if root is not None and file_index is not None:
            if not isinstance(component_path, str) or not component_path:
                continue
            local_component = (root / component_path).resolve()
            if not local_component.is_relative_to(root) or not local_component.is_dir():
                continue
            if not any(
                path.suffix.lower() == ".swift"
                and path.resolve().is_relative_to(local_component)
                for path in file_index
            ):
                continue
        if isinstance(component_path, str) and component_path:
            normalized = Path(component_path).as_posix().rstrip("/") or "."
        else:
            normalized = "."
        components.add(normalized)
    return sorted(components)


def service_map_has_ios_swift(
    data: dict[str, Any],
    repo_path: Path | None = None,
    file_index: list[Path] | None = None,
) -> bool:
    """Detect a local iOS Swift app from normalized service-map fields."""
    return bool(service_map_ios_swift_component_paths(data, repo_path, file_index))
