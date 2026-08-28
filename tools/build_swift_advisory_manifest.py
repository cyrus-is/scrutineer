#!/usr/bin/env python3
"""Build an auditable Swift/iOS candidate manifest from GitHub's OSV database.

The manifest is an evidence inventory, not a claim that every Swift package is
an iOS application. Runtime patterns are promoted separately, after inspecting
the fixing diff and establishing iOS applicability.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SOURCE_ROOT = Path(__file__).resolve().parent.parent
if (SOURCE_ROOT / "scrutineer").is_dir():
    sys.path.insert(0, str(SOURCE_ROOT))

from scrutineer.review_patterns import load_swift_patterns

SWIFT_ECOSYSTEM = "SwiftURL"
IOS_MARKER = re.compile(r"\b(?:iOS|UIKit|SwiftUI|iPhone|iPad)\b")
GITHUB_FIX = re.compile(
    r"^https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/"
    r"(?P<kind>commit|pull)/(?P<identifier>[^/#?]+)"
)
GITHUB_REPOSITORY = re.compile(
    r"^https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/#?]+)"
)


def _git_value(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def _fixed_versions(affected: dict[str, Any]) -> list[str]:
    versions = {
        event["fixed"]
        for item_range in affected.get("ranges", [])
        for event in item_range.get("events", [])
        if isinstance(event, dict) and isinstance(event.get("fixed"), str)
    }
    return sorted(versions)


def _package_repository(package_name: str) -> str | None:
    match = re.fullmatch(r"github\.com/([^/]+)/([^/]+)", package_name)
    if not match:
        return None
    return f"{match.group(1)}/{match.group(2).removesuffix('.git')}".lower()


def _github_repository(url: str) -> str | None:
    match = GITHUB_REPOSITORY.match(url)
    if not match:
        return None
    return (
        f"{match.group('owner')}/{match.group('repo').removesuffix('.git')}"
    ).lower()


def _fix_reference(url: str, affected_repositories: set[str]) -> dict[str, Any] | None:
    clean_url = url.split("#", 1)[0].rstrip("/")
    match = GITHUB_FIX.match(clean_url)
    if not match:
        return None
    repository = f"{match.group('owner')}/{match.group('repo').removesuffix('.git')}"
    return {
        "url": clean_url,
        "kind": match.group("kind"),
        "repository": repository,
        "inAffectedRepository": repository.lower() in affected_repositories,
    }


def _included_patterns(
    patterns_path: Path,
) -> tuple[
    dict[str, list[str]],
    list[dict[str, str]],
    set[str],
    dict[str, dict[str, Any]],
]:
    corpus = load_swift_patterns(patterns_path)
    by_advisory: dict[str, list[str]] = {}
    for pattern in corpus.get("patterns", []):
        for advisory_id in pattern.get("evidence", []):
            by_advisory.setdefault(advisory_id, []).append(pattern["id"])

    inferred_commits: list[dict[str, str]] = []
    native_ios_fix_ids: set[str] = set()
    corpus_fixes: dict[str, dict[str, Any]] = {}
    for fix in corpus.get("fixes", []):
        advisory_id = fix["advisory_id"]
        if fix.get("platform_class") == "ios-app":
            native_ios_fix_ids.add(advisory_id)
        corpus_fixes[advisory_id] = {
            "sourceRepository": fix.get("source_repository"),
            "platformClass": fix.get("platform_class"),
            "resolution": fix.get("resolution"),
            "commits": [
                {
                    "url": commit["url"],
                    "patchSha256": commit["patch_sha256"],
                    "productionFiles": commit["production_files"],
                }
                for commit in fix.get("fix_commits", [])
            ],
        }
        for commit in fix.get("fix_commits", []):
            inferred_commits.append(
                {
                    "advisoryId": advisory_id,
                    "url": commit["url"],
                    "expectedPatchSha256": commit["patch_sha256"],
                }
            )
    return (
        {key: sorted(value) for key, value in by_advisory.items()},
        sorted(inferred_commits, key=lambda item: (item["advisoryId"], item["url"])),
        native_ios_fix_ids,
        corpus_fixes,
    )


def _candidate_record(
    advisory: dict[str, Any],
    included_patterns: dict[str, list[str]],
    native_ios_fix_ids: set[str],
    corpus_fixes: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    if advisory.get("withdrawn") is not None:
        return None
    if advisory.get("database_specific", {}).get("github_reviewed") is not True:
        return None

    affected_items = []
    has_swift_fixed = False
    has_unresolved_swift_package = False
    affected_repositories: set[str] = set()
    for affected in advisory.get("affected", []):
        package = affected.get("package", {})
        ecosystem = package.get("ecosystem")
        name = package.get("name")
        if not isinstance(ecosystem, str) or not isinstance(name, str):
            continue
        fixed_versions = _fixed_versions(affected)
        if ecosystem == SWIFT_ECOSYSTEM and fixed_versions:
            has_swift_fixed = True
        if ecosystem == SWIFT_ECOSYSTEM:
            repository = _package_repository(name)
            if repository:
                affected_repositories.add(repository)
            else:
                has_unresolved_swift_package = True
        affected_items.append(
            {
                "ecosystem": ecosystem,
                "name": name,
                "fixedVersions": fixed_versions,
            }
        )

    searchable = "\n".join(
        [
            str(advisory.get("summary", "")),
            str(advisory.get("details", "")),
            *(item["name"] for item in affected_items),
        ]
    )
    explicit_ios = IOS_MARKER.search(searchable) is not None
    native_ios_fix = advisory["id"] in native_ios_fix_ids
    if not has_swift_fixed and not (explicit_ios and native_ios_fix):
        return None

    corpus_fix = corpus_fixes.get(advisory["id"])
    if corpus_fix and isinstance(corpus_fix.get("sourceRepository"), str):
        affected_repositories.add(corpus_fix["sourceRepository"].lower())
    if has_unresolved_swift_package:
        for reference in advisory.get("references", []):
            if not isinstance(reference, dict) or reference.get("type") != "PACKAGE":
                continue
            url = reference.get("url")
            repository = _github_repository(url) if isinstance(url, str) else None
            if repository:
                affected_repositories.add(repository)

    fix_references = []
    for reference in advisory.get("references", []):
        url = reference.get("url") if isinstance(reference, dict) else None
        if not isinstance(url, str):
            continue
        parsed = _fix_reference(url, affected_repositories)
        if parsed and parsed not in fix_references:
            fix_references.append(parsed)
    fix_references.sort(key=lambda item: item["url"])

    pattern_ids = included_patterns.get(advisory["id"], [])
    if pattern_ids:
        disposition = "promoted-pattern-evidence"
    elif any(item["inAffectedRepository"] for item in fix_references):
        disposition = "fix-linked-not-promoted"
    elif fix_references:
        disposition = "other-repository-fix-only"
    else:
        disposition = "unresolved-fix-link"

    selection_basis = []
    if has_swift_fixed:
        selection_basis.append("swift-ecosystem")
    if native_ios_fix:
        selection_basis.append("verified-native-ios-swift-fix")

    database_specific = advisory.get("database_specific", {})
    return {
        "id": advisory["id"],
        "aliases": sorted(advisory.get("aliases", [])),
        "published": advisory.get("published"),
        "modified": advisory.get("modified"),
        "severity": database_specific.get("severity"),
        "cwes": sorted(database_specific.get("cwe_ids", [])),
        "selectionBasis": selection_basis,
        "affected": sorted(
            affected_items,
            key=lambda item: (item["ecosystem"], item["name"]),
        ),
        "fixReferences": fix_references,
        "corpusFix": corpus_fix,
        "patternIds": pattern_ids,
        "disposition": disposition,
    }


def build_manifest(
    advisory_database: Path,
    patterns_path: Path,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    reviewed_root = advisory_database / "advisories" / "github-reviewed"
    if not reviewed_root.is_dir():
        raise ValueError(
            f"{advisory_database} does not contain advisories/github-reviewed"
        )

    (
        included_patterns,
        inferred_commits,
        native_ios_fix_ids,
        corpus_fixes,
    ) = _included_patterns(patterns_path)
    records = []
    for advisory_path in sorted(reviewed_root.glob("**/*.json")):
        try:
            advisory = json.loads(advisory_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot parse {advisory_path}: {exc}") from exc
        record = _candidate_record(
            advisory,
            included_patterns,
            native_ios_fix_ids,
            corpus_fixes,
        )
        if record:
            records.append(record)

    records.sort(key=lambda item: item["id"])
    dispositions: dict[str, int] = {}
    for record in records:
        disposition = record["disposition"]
        dispositions[disposition] = dispositions.get(disposition, 0) + 1

    swift_records = sum(
        "swift-ecosystem" in record["selectionBasis"] for record in records
    )
    explicit_ios_records = sum(
        "verified-native-ios-swift-fix" in record["selectionBasis"]
        for record in records
    )
    manifest = {
        "schemaVersion": "1.0.0",
        "source": {
            "repository": "https://github.com/github/advisory-database",
            "commit": _git_value(advisory_database, "rev-parse", "HEAD"),
            "commitDate": _git_value(
                advisory_database, "show", "-s", "--format=%cI", "HEAD"
            ),
            "license": "CC-BY-4.0",
        },
        "scope": {
            "githubReviewedOnly": True,
            "withdrawnExcluded": True,
            "fixedVersionRequired": True,
            "candidateRule": (
                "fixed SwiftURL affected range OR a reviewed advisory that explicitly "
                "identifies iOS and has a verified production Swift fix in a native iOS target"
            ),
            "coverageCaveat": (
                "GitHub OSV records do not encode runtime platform. This is an auditable "
                "candidate inventory, not a complete census of every iOS vulnerability."
            ),
        },
        "statistics": {
            "candidateRecords": len(records),
            "swiftEcosystemRecords": swift_records,
            "verifiedNativeIosSwiftFixRecords": explicit_ios_records,
            "dispositions": dict(sorted(dispositions.items())),
        },
        "records": records,
    }
    return manifest, inferred_commits


def _patch_url(reference_url: str) -> str:
    return reference_url.rstrip("/") + ".patch"


def _download_patch(task: dict[str, str], patch_dir: Path) -> dict[str, Any]:
    advisory_id = task["advisoryId"]
    url = task["url"]
    digest_name = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    destination = patch_dir / f"{advisory_id}-{digest_name}.patch"
    request = urllib.request.Request(
        _patch_url(url),
        headers={"User-Agent": "scrutineer-swift-advisory-corpus/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            content = response.read()
    except (OSError, urllib.error.URLError) as exc:
        return {**task, "status": "error", "error": str(exc)}

    digest = hashlib.sha256(content).hexdigest()
    destination.write_bytes(content)
    result: dict[str, Any] = {
        **task,
        "status": "downloaded",
        "patchSha256": digest,
        "cacheFile": destination.name,
    }
    expected = task.get("expectedPatchSha256")
    if expected:
        result["hashMatchesCorpus"] = digest == expected
    return result


def fetch_patches(
    manifest: dict[str, Any],
    inferred_commits: list[dict[str, str]],
    patch_dir: Path,
) -> list[dict[str, Any]]:
    patch_dir.mkdir(parents=True, exist_ok=True)
    tasks: dict[str, dict[str, str]] = {item["url"]: item for item in inferred_commits}
    for record in manifest["records"]:
        for reference in record["fixReferences"]:
            if not reference["inAffectedRepository"]:
                continue
            tasks.setdefault(
                reference["url"],
                {"advisoryId": record["id"], "url": reference["url"]},
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                lambda task: _download_patch(task, patch_dir),
                sorted(
                    tasks.values(), key=lambda item: (item["advisoryId"], item["url"])
                ),
            )
        )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "advisory_database",
        type=Path,
        help="Path to a checkout of github/advisory-database",
    )
    parser.add_argument(
        "--patterns",
        type=Path,
        default=(
            Path(__file__).resolve().parent.parent
            / "generate-security-review"
            / "swift_security_patterns.yaml"
        ),
        help="Swift patterns YAML used to mark promoted evidence",
    )
    parser.add_argument("--output", type=Path, help="Write manifest JSON to this path")
    parser.add_argument(
        "--fetch-patches",
        type=Path,
        metavar="DIR",
        help="Download every affected-repository fix plus promoted inferred fixes into DIR",
    )
    args = parser.parse_args()

    try:
        manifest, inferred_commits = build_manifest(
            args.advisory_database.resolve(),
            args.patterns.resolve(),
        )
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.fetch_patches:
        results = fetch_patches(
            manifest, inferred_commits, args.fetch_patches.resolve()
        )
        downloaded = sum(result["status"] == "downloaded" for result in results)
        failed = len(results) - downloaded
        mismatches = sum(result.get("hashMatchesCorpus") is False for result in results)
        manifest["patchFetch"] = {
            "requested": len(results),
            "downloaded": downloaded,
            "failed": failed,
            "promotedHashMismatches": mismatches,
            "results": results,
        }

    rendered = json.dumps(manifest, indent=2, sort_keys=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
