#!/usr/bin/env python3
"""
Validate a servicemap.json file against the schema requirements.
Reports errors, warnings, and summary statistics.

Usage:
    python validate_servicemap.py <path-to-servicemap.json>
"""

import json
import sys
from datetime import datetime
from collections import Counter

VALID_COMPONENT_TYPES = {"service", "app", "library", "infrastructure", "pipeline", "datastore", "external"}
VALID_CONNECTION_TYPES = {"http", "grpc", "graphql", "websocket", "queue", "pubsub", "database", "cache", "storage", "library", "infrastructure", "event"}
VALID_AUTH_MECHANISMS = {"jwt", "api_key", "oauth2", "session", "mtls", "basic", "none", "unknown"}
VALID_AUTHZ_TYPES = {"rbac", "abac", "acl", "scope", "none", "unknown"}
ID_PREFIXES = {"service": "svc-", "app": "app-", "library": "lib-", "infrastructure": "infra-", "pipeline": "pipeline-", "datastore": "datastore-", "external": "ext-"}

errors = []
warnings = []


def error(msg):
    errors.append(f"ERROR: {msg}")


def warn(msg):
    warnings.append(f"WARN: {msg}")


def check_iso_timestamp(value, field_name):
    if not isinstance(value, str):
        error(f"{field_name} must be a string, got {type(value).__name__}")
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        error(f"{field_name} is not a valid ISO 8601 timestamp: {value}")
        return False


def check_confidence(value, context):
    if not isinstance(value, (int, float)):
        error(f"confidence in {context} must be a number, got {type(value).__name__}")
        return
    if value < 0.0 or value > 1.0:
        error(f"confidence in {context} must be 0.0–1.0, got {value}")


def validate_component(comp, idx, all_ids, is_v1_1_plus=False, known_repos=None):
    ctx = f"components[{idx}]"

    # Required fields
    required = ["id", "name", "type", "confidence", "discovery_method", "last_crawled", "stub"]
    if is_v1_1_plus:
        # source_repo is required in 1.1+ (may be None for unresolved stubs)
        required.append("source_repo")
    for field in required:
        if field not in comp:
            error(f"{ctx} missing required field: {field}")

    comp_id = comp.get("id", f"<unknown-{idx}>")
    ctx = f"component '{comp_id}'"

    # ID uniqueness
    if comp_id in all_ids:
        error(f"{ctx}: duplicate component ID")
    all_ids.add(comp_id)

    # Type validation
    comp_type = comp.get("type")
    if comp_type and comp_type not in VALID_COMPONENT_TYPES:
        error(f"{ctx}: invalid type '{comp_type}'. Valid: {VALID_COMPONENT_TYPES}")

    # ID prefix convention
    if comp_type and comp_type in ID_PREFIXES:
        expected_prefix = ID_PREFIXES[comp_type]
        if not comp_id.startswith(expected_prefix):
            warn(f"{ctx}: ID should start with '{expected_prefix}' for type '{comp_type}'")

    # Confidence
    if "confidence" in comp:
        check_confidence(comp["confidence"], ctx)

    # Timestamp
    if "last_crawled" in comp:
        check_iso_timestamp(comp["last_crawled"], f"{ctx}.last_crawled")

    # Stub validation
    if comp.get("stub"):
        if "stub_reason" not in comp:
            error(f"{ctx}: stub=true requires stub_reason")
        if comp.get("confidence", 1) > 0.3:
            warn(f"{ctx}: stub with confidence > 0.3 is unusual")

    # Stale validation
    if comp.get("stale") and "stale_since" not in comp:
        error(f"{ctx}: stale=true requires stale_since")

    # Path required for non-stubs (except external)
    if not comp.get("stub") and comp_type != "external" and not comp.get("path"):
        warn(f"{ctx}: non-stub, non-external component should have a path")

    # source_repo must reference a declared repository (v1.1+); null is acceptable for unresolved stubs.
    if is_v1_1_plus and known_repos is not None and "source_repo" in comp:
        sr = comp["source_repo"]
        if sr is not None and sr not in known_repos:
            error(f"{ctx}: source_repo '{sr}' does not match any entry in repositories[]")
        if sr is None and not comp.get("stub"):
            warn(f"{ctx}: source_repo is null but component is not a stub")

    # Endpoint validation for services/apps
    if comp_type in ("service", "app"):
        for i, ep in enumerate(comp.get("endpoints", [])):
            ep_ctx = f"{ctx}.endpoints[{i}]"
            for field in ["method", "path", "public", "confidence"]:
                if field not in ep:
                    error(f"{ep_ctx} missing required field: {field}")
            if "confidence" in ep:
                check_confidence(ep["confidence"], ep_ctx)
            if "authentication" in ep:
                mech = ep["authentication"].get("mechanism")
                if mech and mech not in VALID_AUTH_MECHANISMS:
                    warn(f"{ep_ctx}: unknown auth mechanism '{mech}'")
            if "authorization" in ep:
                authz_type = ep["authorization"].get("type")
                if authz_type and authz_type not in VALID_AUTHZ_TYPES:
                    warn(f"{ep_ctx}: unknown authz type '{authz_type}'")

    # Datastore-specific
    if comp_type == "datastore":
        if "engine" not in comp:
            error(f"{ctx}: datastore missing required field 'engine'")
        if "shared" not in comp:
            error(f"{ctx}: datastore missing required field 'shared'")
        if "consumers" not in comp:
            error(f"{ctx}: datastore missing required field 'consumers'")

    # External-specific
    if comp_type == "external":
        for field in ["vendor", "category", "consumers"]:
            if field not in comp:
                error(f"{ctx}: external component missing required field '{field}'")


def validate_connection(conn, idx, component_ids):
    ctx = f"connections[{idx}]"

    for field in ["id", "source", "target", "type", "async", "confidence", "discovery_method"]:
        if field not in conn:
            error(f"{ctx} missing required field: {field}")

    conn_id = conn.get("id", f"<unknown-conn-{idx}>")
    ctx = f"connection '{conn_id}'"

    # Type validation
    conn_type = conn.get("type")
    if conn_type and conn_type not in VALID_CONNECTION_TYPES:
        error(f"{ctx}: invalid type '{conn_type}'. Valid: {VALID_CONNECTION_TYPES}")

    # Reference validation
    source = conn.get("source")
    target = conn.get("target")
    if source and source not in component_ids:
        error(f"{ctx}: source '{source}' does not match any component ID")
    if target and target not in component_ids:
        error(f"{ctx}: target '{target}' does not match any component ID")

    if "confidence" in conn:
        check_confidence(conn["confidence"], ctx)


def validate_metadata(meta, components, connections, is_v1_1_plus=False):
    ctx = "metadata"

    required = ["total_components", "total_connections", "total_stubs", "component_counts",
                "low_confidence_components", "shared_datastores",
                "unauthenticated_public_endpoints", "unmonitored_services"]
    if is_v1_1_plus:
        required.append("repo_staleness")
    for field in required:
        if field not in meta:
            error(f"{ctx} missing required field: {field}")

    # repo_staleness shape check (v1.1+)
    if is_v1_1_plus and isinstance(meta.get("repo_staleness"), list):
        for i, entry in enumerate(meta["repo_staleness"]):
            ectx = f"{ctx}.repo_staleness[{i}]"
            for f in ["repo", "last_crawled", "components", "age_days"]:
                if f not in entry:
                    error(f"{ectx} missing required field: {f}")
            if "last_crawled" in entry:
                check_iso_timestamp(entry["last_crawled"], f"{ectx}.last_crawled")

    # Cross-check counts
    if meta.get("total_components") != len(components):
        warn(f"{ctx}: total_components ({meta.get('total_components')}) != actual component count ({len(components)})")
    if meta.get("total_connections") != len(connections):
        warn(f"{ctx}: total_connections ({meta.get('total_connections')}) != actual connection count ({len(connections)})")

    actual_stubs = sum(1 for c in components if c.get("stub"))
    if meta.get("total_stubs") != actual_stubs:
        warn(f"{ctx}: total_stubs ({meta.get('total_stubs')}) != actual stub count ({actual_stubs})")

    # Check component_counts
    if "component_counts" in meta:
        actual_counts = Counter(c.get("type") for c in components)
        for comp_type, count in meta["component_counts"].items():
            if actual_counts.get(comp_type, 0) != count:
                warn(f"{ctx}: component_counts.{comp_type} ({count}) != actual ({actual_counts.get(comp_type, 0)})")


def _parse_schema_version(sv):
    """Return (major, minor, patch) tuple, or None if unparseable."""
    if not sv:
        return None
    parts = sv.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def validate(data):
    # Schema version drives which root shape we expect.
    # 1.0.x: singular `repository` object.
    # 1.1.0+: plural `repositories[]` array (with per-component `source_repo`).
    sv = data.get("schema_version", "")
    parsed = _parse_schema_version(sv)
    if sv and not parsed:
        error(f"schema_version must be semver (e.g., '1.0.0'), got '{sv}'")

    is_v1_1_plus = parsed is not None and (parsed[0], parsed[1]) >= (1, 1)
    repo_field = "repositories" if is_v1_1_plus else "repository"

    # Root fields — repo field name depends on schema version.
    for field in ["schema_version", "generated_at", repo_field, "components", "connections", "metadata"]:
        if field not in data:
            error(f"Missing required root field: {field}")

    # Track known repo names for source_repo cross-referencing on components.
    known_repos = None
    if is_v1_1_plus and isinstance(data.get("repositories"), list):
        known_repos = {r["name"] for r in data["repositories"] if isinstance(r, dict) and "name" in r}

    if "generated_at" in data:
        check_iso_timestamp(data["generated_at"], "generated_at")

    # Repository / Repositories
    if is_v1_1_plus:
        repos = data.get("repositories", [])
        if not isinstance(repos, list):
            error("repositories must be an array")
        elif not repos:
            error("repositories must contain at least one entry")
        else:
            seen_names = set()
            for i, repo in enumerate(repos):
                rctx = f"repositories[{i}]"
                if "name" not in repo:
                    error(f"{rctx}.name is required")
                else:
                    if repo["name"] in seen_names:
                        error(f"{rctx}.name '{repo['name']}' is duplicated")
                    seen_names.add(repo["name"])
                if "monorepo" not in repo:
                    error(f"{rctx}.monorepo is required")
                if "last_crawled" in repo:
                    check_iso_timestamp(repo["last_crawled"], f"{rctx}.last_crawled")
    else:
        # 1.0.x singular form (or version missing — fall back to 1.0 shape).
        repo = data.get("repository", {})
        if "name" not in repo:
            error("repository.name is required")
        if "monorepo" not in repo:
            error("repository.monorepo is required")

    # Components
    component_ids = set()
    for i, comp in enumerate(data.get("components", [])):
        validate_component(comp, i, component_ids, is_v1_1_plus=is_v1_1_plus, known_repos=known_repos)

    # Connections
    for i, conn in enumerate(data.get("connections", [])):
        validate_connection(conn, i, component_ids)

    # Metadata
    if "metadata" in data:
        validate_metadata(data["metadata"], data.get("components", []), data.get("connections", []),
                          is_v1_1_plus=is_v1_1_plus)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path-to-servicemap.json>")
        sys.exit(1)

    path = sys.argv[1]
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"FATAL: Invalid JSON: {e}")
        sys.exit(2)
    except FileNotFoundError:
        print(f"FATAL: File not found: {path}")
        sys.exit(2)

    validate(data)

    # Summary
    components = data.get("components", [])
    connections = data.get("connections", [])
    stubs = [c for c in components if c.get("stub")]
    low_conf = [c for c in components if c.get("confidence", 1) < 0.5]
    type_counts = Counter(c.get("type") for c in components)

    sv_parsed = _parse_schema_version(data.get("schema_version", ""))
    is_v1_1 = sv_parsed is not None and (sv_parsed[0], sv_parsed[1]) >= (1, 1)
    if is_v1_1:
        repos = data.get("repositories", [])
        repo_label = ", ".join(r.get("name", "?") for r in repos) if repos else "MISSING"
    else:
        repo_label = data.get("repository", {}).get("name", "MISSING")

    print(f"\n{'='*60}")
    print(f"  servicemap.json Validation Report")
    print(f"{'='*60}")
    print(f"  Schema version: {data.get('schema_version', 'MISSING')}")
    print(f"  Generated at:   {data.get('generated_at', 'MISSING')}")
    print(f"  Repository:     {repo_label}")
    print(f"{'='*60}")
    print(f"\n  Components: {len(components)}")
    for t, count in sorted(type_counts.items()):
        print(f"    {t}: {count}")
    print(f"  Connections: {len(connections)}")
    print(f"  Stubs (TODOs): {len(stubs)}")
    print(f"  Low confidence (<0.5): {len(low_conf)}")

    if errors:
        print(f"\n  ERRORS: {len(errors)}")
        for e in errors:
            print(f"    {e}")

    if warnings:
        print(f"\n  WARNINGS: {len(warnings)}")
        for w in warnings:
            print(f"    {w}")

    if not errors and not warnings:
        print(f"\n  ✓ All checks passed!")

    print()
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
