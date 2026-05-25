#!/usr/bin/env python3
"""
MCP source-fetch helper — the safe-acquisition half of /mcp-review Pass 3.

Pass 3 reviews an MCP server's source whenever it can be obtained. But ACQUIRING
that source is itself an active, weaponizable operation: a malicious package can
path-traverse out of the extract dir (zip-slip), escape via symlinks, or — if you
let a package manager touch it — run lifecycle/`postinstall` scripts and git
hooks. SKILL.md used to carry those safety rules as prose ("use npm pack", "clone
with hooks disabled"). Prose is advice to the model, not an enforced boundary, and
the most dangerous step in the whole tool should not depend on prompt adherence.

This module makes the dangerous step deterministic and structurally safe:

  * It NEVER invokes npm / pip / git. It resolves the artifact through the
    registry HTTP APIs and downloads a content-addressed tarball directly, so
    "no fetched code is ever executed" is true by construction — not contingent
    on flags like --ignore-scripts that have escape hatches.
  * It extracts with its own path-sanitizing extractor that rejects absolute
    paths, parent-dir escapes, symlinks, hardlinks, and special files, and caps
    entry count / size (tar & zip bombs). Rejections are reported as evidence,
    not silently dropped — an attempted zip-slip is itself a finding.
  * It emits a manifest tying the fetched bytes to provenance (resolved version,
    content sha256, registry integrity, commit SHA) and a `source_artifact_match`
    confidence the verdict rubric consumes. That closes the Phantom-Artifact gap
    deterministically: "the source I reviewed IS the artifact that runs" stops
    being a manual judgment and becomes a checked fact (or an explicit "cannot
    verify").

Network egress is gated: the default is an OFFLINE dry-run that prints the plan
(what it would fetch, the endpoints it would contact, the predicted match). Pass
--fetch to actually download + extract. Nothing fetched is ever run.

Usage:
    # Offline plan (no network):
    python fetch_source.py --npm "@scope/server@1.2.3"
    python fetch_source.py --analysis analysis.json --server github

    # Actually fetch + extract into a throwaway dir:
    python fetch_source.py --npm "@scope/server@1.2.3" --fetch
    python fetch_source.py --github owner/repo --ref <40-hex-sha> --fetch --dest /tmp/rev
"""

import argparse
import base64
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# Caps — a fetched artifact is untrusted input; bound it before it bounds you.
# ---------------------------------------------------------------------------
MAX_TOTAL_BYTES = 256 * 1024 * 1024      # 256 MiB extracted total (tar/zip bomb)
MAX_ENTRY_BYTES = 64 * 1024 * 1024       # 64 MiB per file
MAX_ENTRIES = 20000                      # member count
MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024   # 128 MiB on the wire
HTTP_TIMEOUT = 30
USER_AGENT = "vibecheck-mcp-review-fetch/1 (+https://github.com/cyrus-is/vibecheck)"

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_JSON = "https://pypi.org/pypi"
GH_CODELOAD = "https://codeload.github.com"

# source_artifact_match values — the headline the verdict rubric reads.
MATCH_VERIFIED = "verified"           # reviewed bytes ARE the runtime artifact (exact pin / commit SHA)
MATCH_UNVERIFIABLE = "unverifiable"   # fetched *a* version; runtime may differ (tag/range/latest/branch)
MATCH_UNFETCHABLE = "unfetchable"     # remote endpoint / local binary / closed source — nothing to bind


# ---------------------------------------------------------------------------
# Digests
# ---------------------------------------------------------------------------

def canonical(obj) -> str:
    """Stable JSON serialization for digesting — key-order independent.
    Matches analyze_mcp.canonical so manifests digest consistently."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(obj) -> str:
    return "sha256:" + hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Spec parsing — turn a provenance spec into (ecosystem, name, version, pin)
# ---------------------------------------------------------------------------

# A full git object id is the only ref that immutably binds source to runtime.
_GIT_SHA = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$", re.IGNORECASE)
_NPM_EXACT = re.compile(r"^\d+\.\d+\.\d+(?:[-+][\w.]+)?$")
# PEP 508 / pip version operators that make a spec a range rather than a pin.
_PIP_RANGE_OP = re.compile(r"(===|==|~=|!=|<=|>=|<|>)")


def is_exact_npm_version(ver: str) -> bool:
    return bool(_NPM_EXACT.match(ver or ""))


def split_npm_spec(spec: str) -> tuple[str, str]:
    """('@scope/pkg@1.2.3') -> ('@scope/pkg', '1.2.3'); ('pkg') -> ('pkg', '')."""
    s = (spec or "").strip()
    scope = ""
    if s.startswith("@"):                # keep a leading @scope/ intact
        scope, s = "@", s[1:]
    name, _, ver = s.partition("@")
    return scope + name, ver


def split_pypi_spec(spec: str) -> tuple[str, str]:
    """('pkg==1.2.3') -> ('pkg', '1.2.3'); ('pkg>=1') -> ('pkg', '') (range, no pin)."""
    s = (spec or "").strip()
    m = _PIP_RANGE_OP.search(s)
    if not m:
        return s, ""
    name = s[: m.start()].strip()
    op = m.group(1)
    rest = s[m.end():].strip()
    # Only '==' / '===' bind a single version; every other operator is a range.
    if op in ("==", "===") and "," not in s[m.start():]:
        return name, rest
    return name, ""


def parse_github_spec(spec: str) -> tuple[str, str, str]:
    """Parse a github/git spec into (owner, repo, ref). ref may be '' if none.
    Accepts 'github:owner/repo#ref', 'git+https://github.com/owner/repo.git#ref',
    'https://github.com/owner/repo#ref', and bare 'owner/repo'."""
    s = (spec or "").strip()
    ref = ""
    if "#" in s:
        s, ref = s.split("#", 1)
    s = re.sub(r"^git\+", "", s)
    s = re.sub(r"^github:", "", s)
    # Drop any userinfo (user:token@) BEFORE the host so a credential in a
    # tokenized clone URL is never carried into the constructed codeload URL.
    s = re.sub(r"^https?://[^/@]*@", "https://", s)
    s = re.sub(r"^https?://github\.com/", "", s)
    s = re.sub(r"\.git$", "", s).strip("/")
    parts = s.split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise ValueError(f"cannot parse owner/repo from github spec: {spec!r}")
    return parts[0], parts[1], ref


def predict_match(ecosystem: str, exact: bool) -> str:
    """What `source_artifact_match` will be, from the pin alone (no network)."""
    if ecosystem in ("npm", "pypi", "github"):
        return MATCH_VERIFIED if exact else MATCH_UNVERIFIABLE
    return MATCH_UNFETCHABLE


# ---------------------------------------------------------------------------
# Offline plan (default; no network)
# ---------------------------------------------------------------------------

def plan_npm(spec: str) -> dict:
    name, ver = split_npm_spec(spec)
    exact = is_exact_npm_version(ver)
    plan = {
        "ecosystem": "npm",
        "requested": spec,
        "name": name,
        "version_spec": ver or "(unspecified)",
        "pin_is_exact": exact,
        "predicted_match": predict_match("npm", exact),
    }
    if exact:
        unscoped = name.split("/")[-1]
        plan["would_fetch"] = [
            f"{NPM_REGISTRY}/{quote(name, safe='@/')}/-/{unscoped}-{ver}.tgz (artifact)"
        ]
    else:
        plan["would_fetch"] = [
            f"{NPM_REGISTRY}/{quote(name, safe='@/')} (metadata: resolve dist-tag/range, then artifact)"
        ]
    return plan


def plan_pypi(spec: str) -> dict:
    name, ver = split_pypi_spec(spec)
    exact = bool(ver)
    return {
        "ecosystem": "pypi",
        "requested": spec,
        "name": name,
        "version_spec": ver or "(unspecified/range)",
        "pin_is_exact": exact,
        "predicted_match": predict_match("pypi", exact),
        # PyPI artifact URLs are content-hashed, so even an exact pin needs metadata.
        "would_fetch": [f"{PYPI_JSON}/{quote(name)}/json (metadata: locate sdist), then the sdist artifact"],
    }


def plan_github(owner: str, repo: str, ref: str) -> dict:
    exact = bool(_GIT_SHA.match(ref))
    return {
        "ecosystem": "github",
        "requested": f"{owner}/{repo}" + (f"#{ref}" if ref else ""),
        "name": f"{owner}/{repo}",
        "version_spec": ref or "(default branch)",
        "pin_is_exact": exact,
        "predicted_match": predict_match("github", exact),
        "would_fetch": [f"{GH_CODELOAD}/{owner}/{repo}/tar.gz/{ref or 'HEAD'} (artifact, no git hooks)"],
        "_owner": owner,
        "_repo": repo,
        "_ref": ref,
    }


# ---------------------------------------------------------------------------
# Network — only reached under --fetch
# ---------------------------------------------------------------------------

def http_get(url: str, max_bytes: int = MAX_DOWNLOAD_BYTES) -> bytes:
    """GET with a size cap and timeout. Reads in chunks and aborts if the body
    exceeds max_bytes, so a hostile Content-Length can't blow up memory."""
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    buf = io.BytesIO()
    with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            buf.write(chunk)
            if buf.tell() > max_bytes:
                raise ValueError(f"download exceeded {max_bytes} bytes: {url}")
    return buf.getvalue()


def http_get_json(url: str) -> dict:
    return json.loads(http_get(url, max_bytes=32 * 1024 * 1024).decode("utf-8"))


def verify_npm_integrity(data: bytes, integrity: str):
    """Verify an npm SRI string ('sha512-<base64>', possibly several
    space-separated). Returns True on a match, False if a supported hash was
    present and mismatched, or None if nothing checkable was found (so the
    caller can report 'unverifiable' rather than hard-failing on an algo we
    don't evaluate)."""
    if not integrity:
        return None
    checked = False
    for token in integrity.split():
        algo, _, b64 = token.partition("-")
        algo = algo.lower()
        if not b64 or algo not in ("sha512", "sha384", "sha256"):
            continue
        try:
            want = base64.b64decode(b64)
        except (ValueError, TypeError):
            continue
        checked = True
        if hashlib.new(algo, data).digest() == want:
            return True
    return False if checked else None


def resolve_npm(spec: str) -> dict:
    """Resolve an npm spec to a concrete artifact via the registry API."""
    name, ver = split_npm_spec(spec)
    meta = http_get_json(f"{NPM_REGISTRY}/{quote(name, safe='@/')}")
    versions = meta.get("versions", {})
    dist_tags = meta.get("dist-tags", {})
    exact = is_exact_npm_version(ver)
    if exact and ver in versions:
        resolved = ver
    elif ver in dist_tags:                       # a dist-tag like 'latest', 'next'
        resolved = dist_tags[ver]
    else:                                        # range / branch / unknown -> registry's latest
        resolved = dist_tags.get("latest")
    if not resolved or resolved not in versions:
        raise ValueError(f"could not resolve npm version for {spec!r} (resolved={resolved})")
    dist = versions[resolved].get("dist", {})
    return {
        "ecosystem": "npm",
        "name": name,
        "resolved_version": resolved,
        "artifact_url": dist.get("tarball"),
        "integrity": dist.get("integrity") or "",      # SRI (base64); modern packages
        "shasum": dist.get("shasum") or "",            # legacy sha1 hex fallback
        "pin_is_exact": exact and ver == resolved,
        "archive_kind": "tar",
    }


def resolve_pypi(spec: str) -> dict:
    name, ver = split_pypi_spec(spec)
    meta = http_get_json(f"{PYPI_JSON}/{quote(name)}/json")
    exact = bool(ver)
    resolved = ver if exact else meta.get("info", {}).get("version")
    releases = meta.get("releases", {})
    files = releases.get(resolved) or meta.get("urls", [])
    sdist = next((f for f in files if f.get("packagetype") == "sdist"), None)
    if sdist is None:
        raise ValueError(f"no source distribution (sdist) published for {name} {resolved}")
    url = sdist.get("url", "")
    return {
        "ecosystem": "pypi",
        "name": name,
        "resolved_version": resolved,
        "artifact_url": url,
        "integrity": "sha256-" + sdist["digests"]["sha256"] if sdist.get("digests", {}).get("sha256") else "",
        "pin_is_exact": exact,
        "archive_kind": "zip" if url.endswith(".zip") else "tar",
    }


def resolve_github(owner: str, repo: str, ref: str) -> dict:
    exact = bool(_GIT_SHA.match(ref))
    # Percent-encode each path segment so an exotic owner/repo/ref cannot inject
    # extra path structure (the host stays pinned to codeload.github.com).
    seg = lambda x: quote(x, safe="")
    return {
        "ecosystem": "github",
        "name": f"{owner}/{repo}",
        "resolved_version": ref or "HEAD",
        "artifact_url": f"{GH_CODELOAD}/{seg(owner)}/{seg(repo)}/tar.gz/{seg(ref) or 'HEAD'}",
        "integrity": "",            # codeload is bound to the ref, not a published digest
        "pin_is_exact": exact,
        "archive_kind": "tar",
    }


# ---------------------------------------------------------------------------
# Safe extraction — the security-critical core
# ---------------------------------------------------------------------------

def _name_target(name: str, dest_real: str):
    """Resolve an archive member name under dest. Returns the absolute target
    path, or None if the entry is absolute or escapes the destination."""
    if not name or name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:[\\/]", name):
        return None                                   # absolute path
    if ".." in Path(name.replace("\\", "/")).parts:    # explicit parent ref
        return None
    target = os.path.realpath(os.path.join(dest_real, name))
    # Because we never create symlinks, realpath can't be redirected out of dest.
    if target != dest_real and not target.startswith(dest_real + os.sep):
        return None
    return target


def _reject(report: dict, name: str, reason: str) -> None:
    report["rejected"].append({"name": name, "reason": reason})


def _new_report(dest: Path) -> dict:
    return {"dest": str(dest), "extracted": 0, "total_bytes": 0,
            "root_dirs": [], "rejected": [], "tampering_detected": False}


# Reasons that signal active malice (vs. a benign oversized file).
_MALICIOUS_REASONS = {"path_escape", "absolute_path", "symlink", "hardlink", "special_file"}


def _safe_write(target: str, dest_real: str, payload: bytes, report: dict, name: str) -> bool:
    """Write one validated member's bytes. Rejects (rather than crashes on) a
    name that resolves onto an existing directory — e.g. a member literally
    named '.' or 'pkg/.' — which would otherwise raise IsADirectoryError and
    abort the whole extraction, letting one hostile entry deny the review."""
    if target == dest_real or os.path.isdir(target):
        _reject(report, name, "invalid_name")
        return False
    try:
        os.makedirs(os.path.dirname(target) or dest_real, exist_ok=True)
        with open(target, "wb") as fh:                # write bytes; never execute
            fh.write(payload)
        os.chmod(target, 0o600)                        # strip any setuid/exec bits from the archive
    except OSError:
        _reject(report, name, "write_error")
        return False
    return True


def _finalize(report: dict) -> dict:
    report["root_dirs"] = sorted(set(report["root_dirs"]))
    report["tampering_detected"] = any(
        r["reason"] in _MALICIOUS_REASONS for r in report["rejected"]
    )
    return report


def safe_extract_tar(data: bytes, dest: Path) -> dict:
    """Extract a .tar/.tar.gz from bytes into dest, member by member, rejecting
    anything unsafe. Never follows or creates symlinks; never runs anything."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    dest_real = os.path.realpath(dest)
    report = _new_report(dest)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
        for member in tar:
            if report["extracted"] + len(report["rejected"]) >= MAX_ENTRIES:
                _reject(report, member.name, "entry_cap")
                break
            if member.issym():
                _reject(report, member.name, "symlink"); continue
            if member.islnk():
                _reject(report, member.name, "hardlink"); continue
            if member.ischr() or member.isblk() or member.isfifo() or member.isdev():
                _reject(report, member.name, "special_file"); continue
            target = _name_target(member.name, dest_real)
            if target is None:
                reason = "absolute_path" if (member.name or "").startswith(("/", "\\")) else "path_escape"
                _reject(report, member.name, reason); continue
            if member.isdir():
                os.makedirs(target, exist_ok=True)
                report["root_dirs"].append(Path(member.name.replace("\\", "/")).parts[0]
                                           if member.name.strip("/") else "")
                continue
            if not member.isfile():
                _reject(report, member.name, "special_file"); continue
            if member.size > MAX_ENTRY_BYTES:
                _reject(report, member.name, "entry_too_large"); continue
            if report["total_bytes"] + member.size > MAX_TOTAL_BYTES:
                _reject(report, member.name, "total_too_large"); break
            try:
                src = tar.extractfile(member)
                payload = src.read(MAX_ENTRY_BYTES + 1) if src is not None else None
            except (OSError, tarfile.TarError):
                _reject(report, member.name, "unreadable"); continue
            if payload is None:
                _reject(report, member.name, "unreadable"); continue
            if len(payload) > MAX_ENTRY_BYTES:        # actual bytes, not the (forgeable) header size
                _reject(report, member.name, "entry_too_large"); continue
            if not _safe_write(target, dest_real, payload, report, member.name):
                continue
            report["extracted"] += 1
            report["total_bytes"] += len(payload)
            parts = Path(member.name.replace("\\", "/")).parts
            if parts:
                report["root_dirs"].append(parts[0])
    return _finalize(report)


def safe_extract_zip(data: bytes, dest: Path) -> dict:
    """Extract a .zip from bytes into dest, rejecting unsafe entries."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    dest_real = os.path.realpath(dest)
    report = _new_report(dest)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if report["extracted"] + len(report["rejected"]) >= MAX_ENTRIES:
                _reject(report, info.filename, "entry_cap"); break
            name = info.filename
            mode = (info.external_attr >> 16) & 0xFFFF
            if mode and stat.S_ISLNK(mode):
                _reject(report, name, "symlink"); continue
            target = _name_target(name, dest_real)
            if target is None:
                reason = "absolute_path" if name.startswith(("/", "\\")) else "path_escape"
                _reject(report, name, reason); continue
            if name.endswith("/"):
                os.makedirs(target, exist_ok=True)
                report["root_dirs"].append(Path(name.replace("\\", "/")).parts[0])
                continue
            if info.file_size > MAX_ENTRY_BYTES:
                _reject(report, name, "entry_too_large"); continue
            if report["total_bytes"] + info.file_size > MAX_TOTAL_BYTES:
                _reject(report, name, "total_too_large"); break
            try:
                with zf.open(info) as src:
                    payload = src.read(MAX_ENTRY_BYTES + 1)
            except (OSError, zipfile.BadZipFile, RuntimeError):
                _reject(report, name, "unreadable"); continue
            if len(payload) > MAX_ENTRY_BYTES:        # actual decompressed bytes, not the declared size
                _reject(report, name, "entry_too_large"); continue
            if not _safe_write(target, dest_real, payload, report, name):
                continue
            report["extracted"] += 1
            report["total_bytes"] += len(payload)
            parts = Path(name.replace("\\", "/")).parts
            if parts:
                report["root_dirs"].append(parts[0])
    return _finalize(report)


def safe_extract(data: bytes, dest: Path, archive_kind: str) -> dict:
    return safe_extract_zip(data, dest) if archive_kind == "zip" else safe_extract_tar(data, dest)


# ---------------------------------------------------------------------------
# Fetch + manifest
# ---------------------------------------------------------------------------

def compute_match(resolved: dict, extraction: dict, integrity_verified) -> str:
    """The verdict-facing confidence — deliberately strict, since a false
    `verified` is the worst failure mode (it tells the reviewer the bytes they
    read ARE what runs when they may not be).

    `verified` requires BOTH an immutable reference AND a cryptographic binding
    of the fetched bytes:
      * github: a 40/64-hex commit SHA is itself the binding — codeload serves
        exactly that object — so an exact ref suffices.
      * npm / pypi: an exact version is necessary but NOT sufficient; the
        published digest must have actually checked out (integrity_verified is
        True). An exact version with a missing/unverifiable hash is downgraded,
        because a private or compromised registry could swap the bytes.
    A tampering attempt during extraction disqualifies regardless of pin."""
    if extraction.get("tampering_detected"):
        return MATCH_UNVERIFIABLE
    if not resolved.get("pin_is_exact"):
        return MATCH_UNVERIFIABLE
    if resolved.get("ecosystem") == "github":
        return MATCH_VERIFIED
    return MATCH_VERIFIED if integrity_verified is True else MATCH_UNVERIFIABLE


def fetch_and_extract(resolved: dict, dest: Path) -> dict:
    """Download the resolved artifact, verify integrity, extract safely, and
    build the manifest. Performs network I/O; never executes fetched code."""
    url = resolved["artifact_url"]
    if not url:
        raise ValueError("no artifact URL resolved")
    data = http_get(url)
    content_sha256 = sha256_hex(data)

    integrity = resolved.get("integrity", "")
    shasum = resolved.get("shasum", "")
    integrity_verified = None
    if resolved["ecosystem"] == "pypi" and integrity.startswith("sha256-"):
        integrity_verified = (integrity.split("-", 1)[1] == content_sha256)
    elif integrity:                                  # npm SRI (sha512/384/256)
        integrity_verified = verify_npm_integrity(data, integrity)
    elif shasum:                                     # legacy npm: sha1 hex
        integrity_verified = (hashlib.sha1(data).hexdigest() == shasum)
    if integrity_verified is False:
        # A digest mismatch means the bytes are not what the registry published.
        raise ValueError(f"integrity check FAILED for {url} (registry digest mismatch)")

    extraction = safe_extract(data, dest, resolved.get("archive_kind", "tar"))
    match = compute_match(resolved, extraction, integrity_verified)
    binding = {
        "ecosystem": resolved["ecosystem"],
        "name": resolved["name"],
        "resolved_version": resolved["resolved_version"],
        "content_sha256": content_sha256,
    }
    manifest = {
        "schema": "mcp-review/fetch@1",
        "ecosystem": resolved["ecosystem"],
        "name": resolved["name"],
        "resolved_version": resolved["resolved_version"],
        "artifact_url": url,
        "content_sha256": content_sha256,
        "registry_integrity": integrity or (("sha1:" + shasum) if shasum else None),
        "integrity_verified": integrity_verified,
        "pin_is_exact": resolved.get("pin_is_exact", False),
        "source_artifact_match": match,
        "extraction": extraction,
        "manifest_digest": digest(binding),
        "executed_anything": False,          # invariant: this tool never runs fetched code
    }
    return manifest


# ---------------------------------------------------------------------------
# Input resolution (provenance / analysis / explicit flags)
# ---------------------------------------------------------------------------

def from_analysis(analysis_path: Path, server_name: str) -> tuple[str, dict]:
    """Pull (ecosystem, plan) from an analyze_mcp.py output for one server.
    Uses the server's provenance.source_type + spec and its launch command to
    distinguish npm (npx/bunx/pnpm/yarn) from pypi (uvx/pipx/pip)."""
    data = json.loads(Path(analysis_path).read_text())
    server = next((s for s in data.get("servers", []) if s.get("name") == server_name), None)
    if server is None:
        raise ValueError(f"server {server_name!r} not found in {analysis_path}")
    prov = server.get("provenance", {})
    stype, spec = prov.get("source_type"), prov.get("spec")
    if stype == "github":
        owner, repo, ref = parse_github_spec(spec)
        return "github", plan_github(owner, repo, ref)
    if stype == "registry":
        cmd = os.path.basename((server.get("command") or "").lower())
        if cmd in ("uvx", "uv", "pipx", "pip", "pip3", "python", "python3"):
            return "pypi", plan_pypi(spec)
        return "npm", plan_npm(spec)        # npx/bunx/pnpm/yarn (default registry runner)
    # remote endpoint / local binary / unknown — nothing to fetch.
    return stype or "unknown", {
        "ecosystem": stype or "unknown",
        "requested": spec,
        "pin_is_exact": False,
        "predicted_match": MATCH_UNFETCHABLE,
        "would_fetch": [],
        "note": f"source_type={stype!r}: no fetchable artifact (review the on-disk binary "
                f"or treat as closed-source)" if stype else "unknown source type",
    }


def plan_to_resolved(plan: dict) -> dict:
    """Run the network resolve step for a plan (only called under --fetch)."""
    eco = plan["ecosystem"]
    if eco == "npm":
        return resolve_npm(plan["requested"])
    if eco == "pypi":
        return resolve_pypi(plan["requested"])
    if eco == "github":
        return resolve_github(plan["_owner"], plan["_repo"], plan["_ref"])
    raise ValueError(f"nothing fetchable for ecosystem {eco!r}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Safely fetch + extract MCP server source for /mcp-review Pass 3.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--npm", help="npm spec, e.g. '@scope/pkg@1.2.3'")
    src.add_argument("--pypi", help="PyPI spec, e.g. 'pkg==1.2.3'")
    src.add_argument("--github", help="GitHub 'owner/repo' (use --ref for the commit/tag)")
    src.add_argument("--analysis", help="analyze_mcp.py output JSON (use with --server)")
    parser.add_argument("--server", help="server name to select from --analysis")
    parser.add_argument("--ref", default="", help="commit SHA / tag / branch for --github")
    parser.add_argument("--fetch", action="store_true",
                        help="actually download + extract (default: offline plan only)")
    parser.add_argument("--dest", help="extract dir (default: a throwaway temp dir)")
    parser.add_argument("--indent", type=int, default=2, help="JSON output indent")
    args = parser.parse_args()

    try:
        if args.analysis:
            if not args.server:
                parser.error("--analysis requires --server")
            ecosystem, plan = from_analysis(Path(args.analysis), args.server)
        elif args.npm:
            plan = plan_npm(args.npm)
        elif args.pypi:
            plan = plan_pypi(args.pypi)
        else:
            owner, repo, ref = parse_github_spec(args.github)
            plan = plan_github(owner, repo, args.ref or ref)
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Default: offline plan. Network egress is gated behind --fetch.
    if not args.fetch:
        public = {k: v for k, v in plan.items() if not k.startswith("_")}
        public.setdefault("mode", "dry-run")
        public["mode"] = "dry-run"
        public["hint"] = "re-run with --fetch to download + extract (no code is executed)"
        print(json.dumps(public, indent=args.indent))
        return

    if not plan.get("would_fetch") and plan.get("predicted_match") == MATCH_UNFETCHABLE:
        print(json.dumps({**{k: v for k, v in plan.items() if not k.startswith("_")},
                          "mode": "fetch", "source_artifact_match": MATCH_UNFETCHABLE}, indent=args.indent))
        return

    dest = Path(args.dest) if args.dest else Path(tempfile.mkdtemp(prefix="mcp-review-src-"))
    try:
        resolved = plan_to_resolved(plan)
        manifest = fetch_and_extract(resolved, dest)
    except (ValueError, OSError, tarfile.TarError, zipfile.BadZipFile) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    manifest["mode"] = "fetch"
    print(json.dumps(manifest, indent=args.indent))


if __name__ == "__main__":
    main()
