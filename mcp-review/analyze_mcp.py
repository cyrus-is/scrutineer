#!/usr/bin/env python3
"""
MCP review analyzer — the deterministic half of /scrutineer-mcp.

This is NOT a skill generator. Unlike generate-peer-review / generate-security-
review (which scan the HOST repo at generate time and emit a tailored skill),
this runs at REVIEW time, like generate-servicemap's validate_servicemap.py. It
consumes the thing under review — an MCP client config and/or a tools/list
response — and emits a normalized JSON record the /scrutineer-mcp skill reasons over.

It does only what must be deterministic and reproducible:
  1. Parse a config (the mcpServers map) and normalize each server entry.
  2. Flag known config smells from mcp_risk_guidance.yaml (shell wrappers,
     package-runner installs, unpinned sources, non-HTTPS remotes, creds-in-URL,
     sensitive env requirements, broad filesystem scope).
  3. Detect — but never echo — unredacted secret values, so the report stays
     shareable.
  4. Record provenance (pin strength, runtime-binding confidence, mutable
     install path) and containment (transport, exposure, fs scope, privilege)
     per server.
  5. Flag CANDIDATE tool capabilities (basis="declared") from tools/list
     metadata — a recall prefilter the skill refines against schema and source.
  6. Emit toxic combinations: individually-tolerable capabilities that together
     form an attack primitive (read-then-send exfil, exec+secrets, etc.).
  7. Compute STABLE per-server and per-tool digests over the fields that change
     the trust decision (command/args/env-key-names/url; tool name/desc/schema)
     — NOT over secret values. These anchor digest-bound suppression.
  8. Detect approval drift: correlate the client's permission allow-list against
     each tool's recommended classification and flag where granted access
     exceeds what review recommends (auto-approved deny-tier tools, server
     wildcards, egress-plus-sensitive-filesystem).
  9. Reconcile findings against a suppressions file: a suppression matches only
     while its bound digest is unchanged, so an edited server/tool re-enters
     review automatically.

All judgment — source review, final severity, verdict, whether to suppress —
belongs to the skill. This tool produces evidence, not verdicts.

Usage:
    python analyze_mcp.py --config claude_desktop_config.redacted.json
    python analyze_mcp.py --tools-list tools.json --server "github mcp"
    python analyze_mcp.py --config cfg.json --tools-list tools.json \\
        --server "github mcp" --suppressions .claude/scrutineer-mcp-suppressions.json
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit, parse_qs

import yaml


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def canonical(obj) -> str:
    """Stable JSON serialization for digesting — key order independent."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(obj) -> str:
    return "sha256:" + hashlib.sha256(canonical(obj).encode("utf-8")).hexdigest()


def basename(cmd: str) -> str:
    """Last path segment, lowercased, without a Windows-style extension stripped
    only for matching (cmd.exe stays cmd.exe because the list carries both)."""
    if not cmd:
        return ""
    seg = re.split(r"[\\/]", cmd.strip())[-1]
    return seg.lower()


# ---------------------------------------------------------------------------
# Secret redaction. These run before a URL or args list is EMITTED or DIGESTED,
# so (a) no live secret ever reaches stdout/the JSON report, and (b) a redacted
# config and its unredacted twin produce the SAME identity digest (suppressions
# survive redaction). Deliberately HARDCODED, not YAML-tunable: redaction is a
# safety guarantee that must not be weakenable by editing a data file.
# ---------------------------------------------------------------------------
_MASK = "***"
# Flag names whose following value is a secret (whole trailing component, so
# --api-key matches but --keyboard does not).
_SENSITIVE_FLAG_RE = re.compile(
    r"^--?([\w-]*[-_])?"
    r"(token|secret|passwd|password|pwd|auth|bearer|credential"
    r"|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)$",
    re.IGNORECASE,
)
# Bare values whose shape is a known live-secret format.
_SECRET_VALUE_RE = re.compile(
    r"(gh[opusr]_|github_pat_|xox[baprs]-|sk-[A-Za-z0-9]{8,}"
    r"|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{10,}"
    r"|eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.)"
)
_SENSITIVE_QUERY_RE = re.compile(
    r"token|secret|password|api[_-]?key|access[_-]?key|auth|bearer|sig|signature|key",
    re.IGNORECASE,
)


def redact_url(url: str) -> str:
    """Strip userinfo and mask sensitive query-param VALUES. Keys are kept."""
    if not url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return _MASK  # unparseable — never risk emitting the raw string
    netloc = parts.netloc
    if parts.username or parts.password:
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        netloc = f"{_MASK}@{host}"
    query = parts.query
    if query:
        pairs = []
        for kv in query.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                if _SENSITIVE_QUERY_RE.search(k):
                    v = _MASK
                pairs.append(f"{k}={v}")
            else:
                pairs.append(kv)
        query = "&".join(pairs)
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


def mask_args(args: list) -> list:
    """Mask secret-bearing CLI args: the value after a sensitive flag, the
    value in --flag=value form, and any bare token matching a known secret
    shape. Non-secret args (paths, package specs, plain flags) pass through."""
    out = []
    expect_value = False
    for a in args:
        if expect_value:
            out.append(_MASK)
            expect_value = False
            continue
        if isinstance(a, str):
            if "=" in a and _SENSITIVE_FLAG_RE.match(a.split("=", 1)[0]):
                out.append(a.split("=", 1)[0] + "=" + _MASK)
                continue
            if _SENSITIVE_FLAG_RE.match(a):
                out.append(a)
                expect_value = True
                continue
            if _SECRET_VALUE_RE.search(a):
                out.append(_MASK)
                continue
        out.append(a)
    return out


def finding(code, severity, category, title, detail, recommendation="", evidence=None):
    f = {
        "code": code,
        "severity": severity,
        "category": category,
        "title": title,
        "detail": detail,
    }
    if recommendation:
        f["recommendation"] = recommendation
    if evidence is not None:
        f["evidence"] = evidence
    return f


# ---------------------------------------------------------------------------
# Guidance
# ---------------------------------------------------------------------------

class Guidance:
    def __init__(self, path: Path):
        with open(path) as fh:
            self.data = yaml.safe_load(fh)
        self.smells = self.data.get("config_smells", {})
        lists = self.data.get("lists", {})
        self.shell_binaries = set(s.lower() for s in lists.get("shell_binaries", []))
        self.package_runners = set(s.lower() for s in lists.get("package_runners", []))
        self.auto_accept_flags = set(lists.get("runner_auto_accept_flags", []))
        self.placeholder_markers = [m.lower() for m in lists.get("placeholder_markers", [])]
        self.broad_fs_paths = lists.get("broad_fs_paths", [])
        self.sensitive_key_res = [
            re.compile(p, re.IGNORECASE) for p in self.data.get("sensitive_env_key_patterns", [])
        ]
        self.capabilities = self.data.get("dangerous_capabilities", {})
        self._cap_res = {
            cap: [re.compile(p, re.IGNORECASE) for p in spec.get("patterns", [])]
            for cap, spec in self.capabilities.items()
        }
        self.data_sensitivity = self.data.get("data_sensitivity", {})
        self._data_res = {
            cat: [re.compile(p, re.IGNORECASE) for p in spec.get("patterns", [])]
            for cat, spec in self.data_sensitivity.items()
        }
        sig = self.data.get("tool_schema_signals", {})
        self._power_param_res = [re.compile(p, re.IGNORECASE) for p in sig.get("power_params", [])]
        self._destructive_flag_res = [re.compile(p, re.IGNORECASE) for p in sig.get("destructive_flags", [])]
        self._arbitrary_arg_names = set(n.lower() for n in sig.get("arbitrary_arg_names", []))

    def smell(self, code, detail, evidence=None):
        spec = self.smells.get(code, {})
        return finding(
            code=code,
            severity=spec.get("severity", "MEDIUM"),
            category=spec.get("category", "config"),
            title=spec.get("title", code),
            detail=detail,
            recommendation=" ".join((spec.get("recommendation", "") or "").split()),
            evidence=evidence,
        )

    def is_sensitive_key(self, key: str) -> bool:
        return any(r.search(key) for r in self.sensitive_key_res)

    def looks_like_placeholder(self, value: str) -> bool:
        v = (value or "").strip().lower()
        if not v:
            return True
        return any(m in v for m in self.placeholder_markers)

    def capability_hits(self, name: str, description: str,
                        param_names: list[str], param_descs: list[str]) -> list[dict]:
        # RECALL-ORIENTED CANDIDATES from metadata, not a classification.
        # basis="declared" marks the signal is the tool's own metadata; the skill
        # refines via schema semantics and, where available, handler source.
        # Each hit now carries evidence (the matched token + zone + snippet) and
        # a confidence derived from WHERE it matched: a hit in the tool/param NAME
        # is high-confidence; one only in prose is medium. This is what the
        # SKILL's "basis=declared" transparency promised, and it lets the verdict
        # layer (and the toxic-combo gate) discount weak signals.
        zones = [
            ("name", name or "", "high"),
            ("param_name", " ".join(param_names), "high"),
            ("description", " ".join([description or ""] + param_descs), "medium"),
        ]
        hits = []
        for cap, regexes in self._cap_res.items():
            ev = _first_zone_match(regexes, zones)
            if ev:
                spec = self.capabilities[cap]
                hits.append({
                    "capability": cap,
                    "title": spec.get("title", cap),
                    "severity": spec.get("severity", "MEDIUM"),
                    "default_classification": spec.get("default_classification", "ask"),
                    "basis": "declared",
                    "confidence": ev["confidence"],
                    "evidence": {k: ev[k] for k in ("zone", "matched", "pattern", "snippet")},
                    "rationale": " ".join((spec.get("rationale", "") or "").split()),
                })
        return hits

    def schema_intent_signals(self, schema: dict) -> dict:
        """Deterministic 'Swiss-army-knife schema' signals. Evasion looks like a
        benignly-named tool (format_json) whose schema accepts powerful or
        abstract inputs (an exec param, an args[] array, additionalProperties).
        These are SIGNALS for the skill to weigh against the tool's name/purpose
        — a name-vs-schema mismatch — not findings on their own.

        Walks the WHOLE schema, not just top-level properties: a power param
        buried in a nested object, an array's items, or a oneOf/anyOf/allOf
        branch is exactly where an evader would hide it."""
        out = {"power_params": [], "destructive_flags": [], "arbitrary_input": False}
        seen_power, seen_destr = set(), set()

        def walk(node, depth=0):
            if depth > 6 or not isinstance(node, dict):
                return
            if node.get("additionalProperties") is True:
                out["arbitrary_input"] = True
            props = node.get("properties")
            if isinstance(props, dict):
                for pname, pspec in props.items():
                    pn = str(pname).lower()
                    if any(r.search(pn) for r in self._power_param_res) and pname not in seen_power:
                        seen_power.add(pname)
                        out["power_params"].append(pname)
                    if any(r.search(pn) for r in self._destructive_flag_res) and pname not in seen_destr:
                        seen_destr.add(pname)
                        out["destructive_flags"].append(pname)
                    if pn in self._arbitrary_arg_names and isinstance(pspec, dict) and pspec.get("type") == "array":
                        out["arbitrary_input"] = True
                    walk(pspec, depth + 1)
            items = node.get("items")
            if isinstance(items, dict):
                walk(items, depth + 1)
            elif isinstance(items, list):
                for it in items:
                    walk(it, depth + 1)
            for comb in ("oneOf", "anyOf", "allOf"):
                for sub in node.get(comb, []) or []:
                    walk(sub, depth + 1)
            ap = node.get("additionalProperties")
            if isinstance(ap, dict):
                walk(ap, depth + 1)

        walk(schema)
        return out

    def data_category_hits(self, name: str, description: str,
                          param_names: list[str], param_descs: list[str]) -> list[dict]:
        zones = [
            ("name", name or "", "high"),
            ("param_name", " ".join(param_names), "high"),
            ("description", " ".join([description or ""] + param_descs), "medium"),
        ]
        hits = []
        for cat, regexes in self._data_res.items():
            ev = _first_zone_match(regexes, zones)
            if ev:
                spec = self.data_sensitivity[cat]
                hits.append({
                    "category": cat,
                    "label": spec.get("label", cat),
                    "tier": spec.get("tier", "medium"),
                    "confidence": ev["confidence"],
                    "evidence": {k: ev[k] for k in ("zone", "matched", "pattern", "snippet")},
                    "rationale": " ".join((spec.get("rationale", "") or "").split()),
                })
        return hits


# ---------------------------------------------------------------------------
# Config parsing + smell detection
# ---------------------------------------------------------------------------

def find_server_map(cfg: dict) -> dict:
    """Locate the mcpServers map across the common config shapes:
    claude_desktop_config.json, .mcp.json, and .claude/settings.json all nest
    it under "mcpServers"; some tools put it at the top level."""
    if not isinstance(cfg, dict):
        return {}
    if isinstance(cfg.get("mcpServers"), dict):
        return cfg["mcpServers"]
    # Fall back to treating the top level as the map if its values look like
    # server entries (have a command or a url).
    if cfg and all(
        isinstance(v, dict) and ("command" in v or "url" in v)
        for v in cfg.values()
    ):
        return cfg
    return {}


def classify_transport(entry: dict) -> str:
    if entry.get("command"):
        return "stdio"
    if entry.get("url"):
        t = (entry.get("type") or "").lower()
        if t in ("sse", "http", "streamable-http", "ws"):
            return t
        url = entry["url"].lower()
        if url.startswith(("ws://", "wss://")):
            return "ws"
        return "http"
    return "unknown"


def runner_spec(command: str, args: list[str], g: Guidance) -> tuple[str | None, list[str]]:
    """If the command (or a 'dlx' arg) is a package runner, return (spec, flags)
    where spec is the first positional package argument. Returns (None, []) when
    not a runner."""
    cmd = basename(command)
    rest = list(args or [])
    is_runner = cmd in g.package_runners
    # Handle "pnpm dlx <pkg>" / "yarn dlx <pkg>" — dlx is an arg, not the command.
    if not is_runner and rest and rest[0].lower() == "dlx":
        is_runner = True
        rest = rest[1:]
    if not is_runner:
        return None, []
    flags = [a for a in rest if a.startswith("-")]
    positionals = [a for a in rest if not a.startswith("-")]
    # The --package <spec> form names the spec explicitly.
    if "--package" in rest:
        i = rest.index("--package")
        if i + 1 < len(rest):
            return rest[i + 1], flags
    spec = positionals[0] if positionals else None
    return spec, flags


_SEMVER_PIN = re.compile(r"@\d+\.\d+\.\d+(?:[-+][\w.]+)?$")
# Only a FULL git object id is immutable enough to bypass the unpinned flag:
# 40 hex (SHA-1) or 64 hex (SHA-256). Short SHAs are ambiguous and rejected.
_GIT_SHA = re.compile(r"#(?:[0-9a-f]{40}|[0-9a-f]{64})$", re.IGNORECASE)
_GIT_SEMVER_TAG = re.compile(r"#v?\d+\.\d+\.\d+", re.IGNORECASE)

# Pin strength ordering, most → least immutable. The risk a reviewer cares about
# is FALSE ASSURANCE: a "version-shaped" spec (a dist-tag, a range, a branch ref)
# looks pinned but can still resolve to a freshly-compromised release. Only an
# exact version or a commit SHA actually binds the reviewed code to what runs.
_PIN_RANK = {"commit_sha": 5, "exact": 4, "version_tag": 2, "range": 1, "latest": 0, "none": 0, "n/a": 3}
# Specs at or below this rank are treated as a mutable install path.
_PIN_RISKY = {"version_tag", "range", "latest", "none"}


def pin_strength(spec: str) -> tuple[str, str]:
    """Classify how immutable a package spec's reference is.
    Returns (strength, detail) where strength is one of:
    commit_sha, exact, version_tag, range, latest, none, n/a."""
    if not spec:
        return "n/a", ""
    s = spec.strip()
    # git / github specs
    if s.startswith(("github:", "git+", "https://github.com")) or "#" in s:
        if _GIT_SHA.search(s):
            return "commit_sha", "pinned to an exact commit SHA (immutable)"
        if _GIT_SEMVER_TAG.search(s):
            return "version_tag", "pinned to a git version tag (mutable — tags can be moved)"
        return "none", "git/github ref with no commit SHA or version tag (floating branch/HEAD)"
    if "==" in s:  # uv / pip exact pin
        return "exact", "exact version pin (==)"
    if "@latest" in s or s.endswith("@latest"):
        return "latest", "pinned to @latest (resolves to newest release every launch)"
    # npm scoped (@scope/name) vs versioned (name@1.2.3): strip a leading scope @
    body = s[1:] if s.startswith("@") else s
    if "@" in body:
        ver = body.split("@", 1)[1]
        if _SEMVER_PIN.search("@" + ver):
            return "exact", "exact semver pin"
        if re.match(r"^[\^~><=]", ver) or "||" in ver or "*" in ver or " - " in ver \
                or re.search(r"\d+\.x", ver, re.IGNORECASE):
            return "range", f"semver range '{ver}' (admits future releases)"
        return "version_tag", f"dist-tag '{ver}' (mutable — the tag can be repointed)"
    # Bare uv/pip comparison specs (foo>=1.2, foo~=1.2, foo!=1.0) have no '@'
    # but are still ranges that admit other releases.
    if re.search(r"(~=|!=|[<>]=?)", body):
        return "range", "version range (admits future releases)"
    return "none", "no version specified (resolves to whatever the registry serves now)"


def url_credentials(url: str) -> str | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.username or parts.password:
        return "userinfo (user:pass@) in URL"
    q = parse_qs(parts.query)
    for key in q:
        if re.search(r"token|secret|password|api[_-]?key|access[_-]?key|auth|bearer", key, re.IGNORECASE):
            return f"credential-bearing query parameter: {key}"
    return None


def is_localhost(url: str) -> bool:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    return host in ("localhost", "127.0.0.1", "::1", "0.0.0.0")


def analyze_server(name: str, entry: dict, g: Guidance) -> dict:
    command = entry.get("command", "") or ""
    env = entry.get("env", {}) or {}
    transport = classify_transport(entry)

    # Sanitize up front. Redaction preserves keys/structure, so detection below
    # still flags creds-in-URL ("***@host", "token=***"); but no raw secret in a
    # URL or CLI arg can reach a finding, the output, or the identity digest.
    args = mask_args(entry.get("args", []) or [])
    url = redact_url(entry.get("url", "") or "")

    env_keys = sorted(env.keys())
    sensitive_keys = [k for k in env_keys if g.is_sensitive_key(k)]

    findings = []
    is_runner = False
    runner_name = None
    spec = None
    auto = []
    pin = "n/a"
    pin_detail = ""
    broad = []
    is_shell = False

    # --- stdio: shell wrapper -------------------------------------------------
    if transport == "stdio":
        cmd = basename(command)
        shell_via_c = cmd in g.shell_binaries or (
            args and any(a == "-c" or a.lower().startswith("-command") for a in args)
        )
        if cmd in g.shell_binaries or shell_via_c:
            is_shell = True
            findings.append(g.smell(
                "shell_wrapper",
                f"Server '{name}' launches via '{command or cmd}'.",
                evidence={"command": command, "args_count": len(args)},
            ))

        # --- package runner + pin -------------------------------------------
        spec, flags = runner_spec(command, args, g)
        if spec is not None:
            is_runner = True
            runner_name = basename(command)
            auto = sorted(set(flags) & g.auto_accept_flags)
            findings.append(g.smell(
                "package_runner_install",
                f"Server '{name}' is fetched and executed at launch via "
                f"'{runner_name}'"
                + (f" with auto-accept flag(s) {', '.join(auto)}" if auto else "")
                + f"; package spec: {spec}.",
                evidence={"runner": runner_name, "spec": spec, "auto_accept": auto},
            ))
            pin, pin_detail = pin_strength(spec)
            if pin in _PIN_RISKY:
                findings.append(g.smell(
                    "unpinned_source",
                    f"Server '{name}' package spec '{spec}' is unpinned "
                    f"(pin strength: {pin}): {pin_detail}.",
                    evidence={"spec": spec, "pin_strength": pin, "reason": pin_detail},
                ))

        # --- broad filesystem scope -----------------------------------------
        for a in args:
            av = a.strip()
            for p in g.broad_fs_paths:
                if av == p or (av.startswith(p) and (av == p or av[len(p):len(p) + 1] in ("", "/", "\\"))):
                    broad.append(av)
                    break
        if broad:
            findings.append(g.smell(
                "broad_filesystem_scope",
                f"Server '{name}' is pointed at broad path(s): {', '.join(sorted(set(broad)))}.",
                evidence={"paths": sorted(set(broad))},
            ))

    # --- remote: transport + url creds ---------------------------------------
    if url:
        creds = url_credentials(url)
        if creds:
            findings.append(g.smell(
                "credentials_in_url",
                f"Server '{name}' embeds credentials in its URL: {creds}.",
                evidence={"reason": creds},  # the credential itself is never recorded
            ))
        scheme = (urlsplit(url).scheme or "").lower()
        if scheme in ("http", "ws") and not is_localhost(url):
            findings.append(g.smell(
                "non_https_remote",
                f"Server '{name}' uses cleartext transport '{scheme}://' to a "
                f"non-localhost host.",
                evidence={"scheme": scheme},
            ))

    # --- sensitive env requirements ------------------------------------------
    if sensitive_keys:
        findings.append(g.smell(
            "sensitive_env_required",
            f"Server '{name}' requires credential-like env keys: "
            f"{', '.join(sensitive_keys)}.",
            evidence={"sensitive_keys": sensitive_keys},
        ))

    # --- unredacted secret values (never echo the value) ---------------------
    # Only inspect values of credential-like keys; a non-secret value being
    # present is normal. We record only the KEY whose value looked live.
    leaked_keys = []
    for k in sensitive_keys:
        v = env.get(k)
        if isinstance(v, str) and not g.looks_like_placeholder(v):
            leaked_keys.append(k)
    redaction_ok = not leaked_keys
    if leaked_keys:
        findings.append(g.smell(
            "unredacted_secret_value",
            f"Server '{name}' config contains what appears to be a live secret "
            f"value for: {', '.join(leaked_keys)}. The value is not recorded here. "
            f"Rotate it and redact the config before sharing this review.",
            evidence={"keys_with_live_values": leaked_keys},
        ))

    # --- provenance: can we tie reviewed code to what actually runs? ---------
    # The honest answer for a package-runner install with a non-exact pin is
    # "no" — there is no fixed artifact, so source review can only cover *a*
    # version. We surface that as runtime_binding_confidence so the verdict
    # layer can cap such servers at CAUTION. signature_status is reported but
    # left "unknown": we never fetch, and almost no MCP server ships
    # attestations today, so absence carries little signal.
    if is_runner:
        if spec and spec.startswith(("github:", "git+", "https://github.com")) or (spec and "#" in spec):
            source_type = "github"
        else:
            source_type = "registry"
    elif url:
        source_type = "remote"
    elif command:
        source_type = "local_binary"
    else:
        source_type = "unknown"

    mutable_install_path = bool(is_runner and pin in _PIN_RISKY)
    if source_type == "local_binary":
        binding = "local_binary"          # whatever is installed on disk; reviewer must inspect it
    elif source_type == "remote":
        binding = "remote_endpoint"       # the endpoint controls behavior; cannot be bound
    elif pin in ("commit_sha", "exact"):
        binding = "strong"
    elif pin == "version_tag":
        binding = "weak"
    else:                                  # range / latest / none
        binding = "none"

    provenance = {
        "source_type": source_type,
        "spec": spec,
        "pin_strength": pin,
        "pin_detail": pin_detail or None,
        "mutable_install_path": mutable_install_path,
        "lockfile_present": None,          # unknown without the installing project's lockfile
        "signature_status": "unknown",     # not fetched/verified by this static pass
        "runtime_binding_confidence": binding,
    }

    # --- containment: transport, exposure, scope, privilege assumptions ------
    # A path-like arg starts with a filesystem anchor — not just any arg
    # containing "/" (that would catch URLs and git specs like
    # "github:owner/repo").
    def _looks_like_path(a: str) -> bool:
        if "://" in a:
            return False
        return bool(re.match(r"^(/|~|\./|\.\./|[A-Za-z]:[\\/])", a.strip()))

    if broad:
        fs_scope = "broad"
    elif any(_looks_like_path(a) for a in args):
        fs_scope = "scoped"
    else:
        fs_scope = "none_declared"
    privilege_notes = []
    if is_shell:
        privilege_notes.append("launched via a shell — can chain/expand arbitrarily")
    if is_runner:
        privilege_notes.append("runs fetched package code at launch")
    if auto:
        privilege_notes.append(f"non-interactive install ({', '.join(auto)})")

    containment = {
        "transport": transport,
        "localhost": is_localhost(url) if url else None,
        "network_exposure": "remote" if url and not is_localhost(url)
                            else "localhost" if url else "local_stdio",
        "filesystem_scope": fs_scope,
        "sandbox_evidence": "none_detected",   # static config can't prove a sandbox
        "privilege_notes": privilege_notes,
    }

    # --- stable identity digest (args/url already sanitized at top) ----------
    identity = {
        "transport": transport,
        "command": command,
        "args": args,
        "env_keys": env_keys,   # names only — values deliberately excluded
        "url": url,
    }
    server_digest = digest(identity)

    return {
        "name": name,
        "transport": transport,
        "command": command or None,
        "args": args,
        "env_keys": env_keys,
        "sensitive_env_keys": sensitive_keys,
        "url": url or None,
        "redaction_ok": redaction_ok,
        "provenance": provenance,
        "containment": containment,
        "digest": server_digest,
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# tools/list parsing + capability detection
# ---------------------------------------------------------------------------

def extract_tools(payload) -> list[dict]:
    """Accept either an MCP tools/list response {"tools":[...]}, a JSON-RPC
    envelope {"result":{"tools":[...]}}, or a bare list of tool objects."""
    if isinstance(payload, dict):
        if isinstance(payload.get("tools"), list):
            return payload["tools"]
        if isinstance(payload.get("result"), dict) and isinstance(payload["result"].get("tools"), list):
            return payload["result"]["tools"]
        return []
    if isinstance(payload, list):
        return payload
    return []


def _schema_param_text(schema) -> tuple[list[str], list[str]]:
    """Recursively collect (property_names, descriptions) from a JSON Schema.

    Deliberately EXCLUDES meta-keys ($schema/$id/$ref), type strings, enum and
    default VALUES — i.e. everything that is not a human-meaningful name or
    description. Matching capability/data regexes against the full
    canonical(schema) blob is what made 'http' in the "$schema":"http://..."
    dialect URL light up network_egress on every tool; names + descriptions are
    the only zones an evader actually uses."""
    names, descs = [], []

    def walk(node, depth=0):
        if depth > 6 or not isinstance(node, dict):
            return
        d = node.get("description")
        if isinstance(d, str) and d:
            descs.append(d)
        props = node.get("properties")
        if isinstance(props, dict):
            for pname, pspec in props.items():
                names.append(str(pname))
                walk(pspec, depth + 1)
        items = node.get("items")
        if isinstance(items, dict):
            walk(items, depth + 1)
        elif isinstance(items, list):
            for it in items:
                walk(it, depth + 1)
        for comb in ("oneOf", "anyOf", "allOf"):
            for sub in node.get(comb, []) or []:
                walk(sub, depth + 1)
        ap = node.get("additionalProperties")
        if isinstance(ap, dict):
            walk(ap, depth + 1)

    walk(schema if isinstance(schema, dict) else {})
    return names, descs


def _first_zone_match(regexes: list, zones: list) -> dict | None:
    """Search ordered (zone_name, text, confidence) tuples and return the FIRST
    match — zones are passed highest-confidence-first, so the returned evidence
    carries the strongest basis for the hit (a match in the tool/param NAME is
    worth more than one buried in prose). snippet gives a reviewer the span to
    confirm or dismiss the candidate without re-deriving it."""
    for zone_name, text, conf in zones:
        if not text:
            continue
        for r in regexes:
            m = r.search(text)
            if m:
                s, e = m.start(), m.end()
                return {
                    "zone": zone_name,
                    "matched": m.group(0),
                    "pattern": r.pattern,
                    "confidence": conf,
                    "snippet": text[max(0, s - 30):e + 30].strip(),
                }
    return None


def analyze_tool(tool: dict, server_name: str | None, g: Guidance) -> dict:
    name = tool.get("name", "")
    description = tool.get("description", "") or ""
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}

    # Capability/data scans run over zoned metadata — the tool name, the schema
    # PROPERTY NAMES, and the descriptions (tool + nested params) — NOT the raw
    # canonical(schema) blob. That keeps a parameter named "command" or "url" in
    # scope while excluding meta-keys, type strings, and values (the "$schema"
    # dialect URL, enum/default strings) that produced systematic false hits.
    param_names, param_descs = _schema_param_text(schema)
    caps = g.capability_hits(name, description, param_names, param_descs)
    data_categories = g.data_category_hits(name, description, param_names, param_descs)
    schema_signals = g.schema_intent_signals(schema)

    identity = {"name": name, "description": description, "inputSchema": schema}
    tool_digest = digest(identity)

    return {
        "server": server_name,
        "name": name,
        "description": description,
        "param_names": sorted(schema.get("properties", {}).keys()) if isinstance(schema, dict) else [],
        "candidate_capabilities": caps,
        "data_categories": data_categories,
        "schema_signals": schema_signals,
        "max_severity": _max_severity([c["severity"] for c in caps]),
        "data_tier": _max_tier([d["tier"] for d in data_categories]),
        "digest": tool_digest,
    }


_SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def _max_severity(sevs: list[str]) -> str | None:
    if not sevs:
        return None
    return max(sevs, key=lambda s: _SEV_ORDER.get(s, 0))


# Data sensitivity is a SEPARATE axis from security severity, with its own
# vocabulary so the two never get confused in the report.
_TIER_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_TIER_TO_RATING = {0: "MINIMAL", 1: "LIMITED", 2: "SENSITIVE", 3: "HIGHLY_SENSITIVE"}


def _max_tier(tiers: list[str]) -> str | None:
    if not tiers:
        return None
    return max(tiers, key=lambda t: _TIER_ORDER.get(t, 0))


def data_profile(tools: list[dict], g: Guidance) -> dict:
    """Aggregate the union of data categories across a set of tools into a
    single sensitivity rating. This is what answers "how much / how sensitive
    is the data this server wants?" — independent of any security finding."""
    categories: dict[str, dict] = {}
    for t in tools:
        for d in t["data_categories"]:
            cat = d["category"]
            if cat not in categories:
                categories[cat] = {"label": d["label"], "tier": d["tier"], "tool_count": 0}
            categories[cat]["tool_count"] += 1
    tiers_present = sorted({c["tier"] for c in categories.values()},
                           key=lambda t: _TIER_ORDER.get(t, 0), reverse=True)
    top = _max_tier([c["tier"] for c in categories.values()])
    rating = _TIER_TO_RATING[_TIER_ORDER[top]] if top else "MINIMAL"
    return {
        "rating": rating,
        "tiers_present": tiers_present,
        "categories": categories,
    }


# ---------------------------------------------------------------------------
# Toxic combinations — individually-tolerable capabilities that together form
# a complete attack primitive. These are the findings that pure per-tool review
# misses: a "read secrets" tool is fine, an "HTTP POST" tool is fine, but a
# server exposing both is a read-then-send exfil chain. Computed deterministically
# over the union of (active config findings + tool capabilities + data categories)
# for the analyzed set. Most meaningful scoped to one server (--server + --tools).
# ---------------------------------------------------------------------------

def toxic_combinations(servers: list[dict], tools: list[dict]) -> list[dict]:
    # Computed over RAW signal presence — deliberately NOT gated on atomic-finding
    # suppression. A toxic combination is a HIGH attack primitive in its own right;
    # suppressing a lesser atomic note (e.g. the INFO "requires a credential")
    # must never silently clear it. If the user accepts a credential requirement,
    # the server can still exfiltrate that credential — the combo stands until
    # addressed on its own terms.
    cap_set = {c["capability"] for t in tools for c in t["candidate_capabilities"]}
    data_set = {d["category"] for t in tools for d in t["data_categories"]}
    config_codes = {f["code"] for s in servers for f in s["findings"]}

    reads_secrets = "secrets_access" in cap_set or "credentials_secrets" in data_set \
        or "sensitive_env_required" in config_codes
    egress = "network_egress" in cap_set
    broad_fs = "broad_filesystem_scope" in config_codes
    reads_files = "file_read" in cap_set or "files_documents" in data_set
    reads_comms = "communications_content" in data_set

    # Is the read ARBITRARY? A file_read tool exposing a free path-like param can
    # be pointed at any file (a secret, a config) — that's what makes read+egress
    # a HIGH exfil primitive rather than a benign scoped read.
    _PATH_PARAMS = {"path", "file_path", "filepath", "filename", "file", "paths",
                    "dir", "directory", "uri", "location"}
    arbitrary_read = broad_fs or any(
        any(c["capability"] == "file_read" for c in t["candidate_capabilities"])
        and (_PATH_PARAMS & {p.lower() for p in t.get("param_names", [])})
        for t in tools
    )

    combos = []

    def add(cid, severity, title, detail, contributing):
        combos.append({
            "id": cid, "severity": severity, "title": title,
            "detail": detail, "contributing": contributing,
        })

    if reads_secrets and egress:
        add("exfil_chain", "HIGH",
            "Read-then-send exfiltration chain",
            "The server can both read secrets/credentials and make outbound "
            "network calls — a complete path to exfiltrate them to an "
            "attacker-chosen host.",
            ["secrets_access/sensitive_env", "network_egress"])

    if "code_execution" in cap_set and reads_secrets:
        add("exec_with_secret_access", "HIGH",
            "Code execution alongside secret access",
            "Arbitrary execution combined with credential access means a single "
            "tool call can read and abuse every secret the server holds.",
            ["code_execution", "secrets_access/sensitive_env"])

    if ("file_write" in cap_set or "file_delete" in cap_set) and egress:
        add("remote_controlled_fs_mutation", "HIGH",
            "Filesystem mutation driven by network input",
            "The server can write/delete files and make network calls — remote "
            "input can drive destructive or persistence-establishing writes.",
            ["file_write/file_delete", "network_egress"])

    if (reads_files or reads_comms) and egress:
        sev = "HIGH" if arbitrary_read else "MEDIUM"
        title = ("Arbitrary file read paired with egress" if arbitrary_read
                 else "File/message read paired with egress")
        detail = (
            "The server can read file" + ("/message " if reads_comms else " ")
            + "contents and make outbound network calls — a read-then-send "
            "exfiltration path. "
            + ("The read accepts an arbitrary path (or the server is scoped to a "
               "broad directory), so it can reach secrets/configs far beyond the "
               "task." if arbitrary_read
               else "Severity is MEDIUM because the read appears scoped; confirm "
                    "what the read tool can reach and where egress can target.")
        )
        contributing = ["file_read" + (" (arbitrary path)" if arbitrary_read else "")]
        if reads_comms:
            contributing.append("communications_content")
        if broad_fs:
            contributing.append("broad_filesystem_scope")
        contributing.append("network_egress")
        add("read_and_exfil", sev, title, detail, contributing)

    return combos


# ---------------------------------------------------------------------------
# Approval drift — the trust picture isn't just what a server COULD do, it's
# what the client has ALREADY authorized it to do. A tool whose capabilities
# warrant ask/deny but which sits in the client's allow-list is auto-approved
# every invocation with no prompt. We parse the client's permission rules and
# flag where granted access exceeds what review recommends.
# ---------------------------------------------------------------------------

_FS_TOOLS = {"read", "edit", "write", "notebookedit", "multiedit"}
_SENSITIVE_PATH = re.compile(
    r"(\.env|\.ssh|id_rsa|id_ed25519|credentials|\.aws|\.npmrc|\.git-credentials|secrets?|\.pem|keychain)",
    re.IGNORECASE,
)


def parse_allowlist(path: Path) -> dict:
    """Parse Claude-Code-style permission rules from a settings.json / .mcp.json.
    MCP rules look like `mcp__server` (whole server) or `mcp__server__tool`.
    Filesystem rules look like `Read(/path)` / `Write(/path/**)`."""
    with open(path) as fh:
        data = json.load(fh)
    perms = data.get("permissions", {}) if isinstance(data, dict) else {}

    def split_rules(rules):
        servers, tools, fs_paths = set(), set(), []
        for r in rules or []:
            if not isinstance(r, str):
                continue
            if r.startswith("mcp__"):
                rest = r[len("mcp__"):]
                if "__" in rest:
                    s, t = rest.split("__", 1)
                    tools.add((s, t))
                elif rest:
                    servers.add(rest)
            else:
                m = re.match(r"^(\w+)\((.*)\)$", r)
                if m and m.group(1).lower() in _FS_TOOLS:
                    fs_paths.append(m.group(2))
        return servers, tools, fs_paths

    allow_servers, allow_tools, allow_fs = split_rules(perms.get("allow"))
    deny_servers, deny_tools, _ = split_rules(perms.get("deny"))

    return {
        "allow_servers": allow_servers,
        "allow_tools": allow_tools,
        "deny_servers": deny_servers,
        "deny_tools": deny_tools,
        "granted_filesystem": allow_fs,
        "sensitive_filesystem_granted": any(_SENSITIVE_PATH.search(p) for p in allow_fs),
        "enable_all_project": bool(data.get("enableAllProjectMcpServers")) if isinstance(data, dict) else False,
        "enabled_mcpjson": set(data.get("enabledMcpjsonServers", []) or []) if isinstance(data, dict) else set(),
    }


_CLASS_RANK = {"allow": 0, "ask": 1, "deny": 2}


def approval_drift(servers: list[dict], tools: list[dict], allow: dict) -> list[dict]:
    """Flag where the client's existing grants exceed what review recommends."""
    findings = []
    relevant = {s["name"] for s in servers} | {t["server"] for t in tools if t.get("server")}

    def add(code, severity, detail, **extra):
        findings.append({"code": code, "severity": severity, "detail": detail, **extra})

    # Blanket approvals.
    if allow.get("enable_all_project"):
        add("blanket_mcp_approval", "MEDIUM",
            "`enableAllProjectMcpServers` is true — every project MCP server is "
            "auto-enabled and its tools auto-approved without per-server review.")

    # Server-level wildcard grants (auto-approve all current AND future tools).
    for s in sorted(allow.get("allow_servers", set())):
        if relevant and s not in relevant:
            continue
        if s in allow.get("deny_servers", set()):
            continue
        add("server_wildcard_grant", "MEDIUM",
            f"Server '{s}' is granted at the server level (`mcp__{s}`): every tool "
            f"it exposes now AND any it adds later is auto-approved with no "
            f"re-review. This is the grant most exposed to tool-redefinition "
            f"(rug-pull) risk.", server=s)

    # Per-tool: granted while recommended classification is ask/deny.
    blanket = allow.get("enable_all_project")
    for t in tools:
        s, name = t.get("server"), t["name"]
        rec = "allow"
        for c in t["candidate_capabilities"]:
            if _CLASS_RANK.get(c["default_classification"], 0) > _CLASS_RANK[rec]:
                rec = c["default_classification"]
        if rec == "allow":
            continue
        granted = (
            blanket
            or s in allow.get("allow_servers", set())
            or (s, name) in allow.get("allow_tools", set())
        )
        denied = s in allow.get("deny_servers", set()) or (s, name) in allow.get("deny_tools", set())
        if granted and not denied:
            caps = [c["capability"] for c in t["candidate_capabilities"]]
            add("approval_drift", "HIGH" if rec == "deny" else "MEDIUM",
                f"Tool '{name}' is auto-approved in the client allow-list, but its "
                f"capabilities ({', '.join(caps)}) warrant '{rec}' — granted access "
                f"exceeds what review recommends.",
                server=s, tool=name, recommended=rec, capabilities=caps)

    # Escalation: a network-egress tool granted alongside sensitive filesystem access.
    if allow.get("sensitive_filesystem_granted"):
        if any(c["capability"] == "network_egress" for t in tools for c in t["candidate_capabilities"]):
            add("egress_with_sensitive_fs", "HIGH",
                "A network-egress tool is exposed while the client grants filesystem "
                "access to sensitive paths (.env / .ssh / credentials). Read-then-send "
                "of those secrets is a complete exfiltration path.",
                granted_paths=[p for p in allow.get("granted_filesystem", []) if _SENSITIVE_PATH.search(p)])

    return findings


# ---------------------------------------------------------------------------
# Suppression reconciliation
# ---------------------------------------------------------------------------

def load_suppressions(path: Path | None) -> list[dict]:
    if not path or not path.exists():
        return []
    with open(path) as fh:
        data = json.load(fh)
    return data.get("suppressions", data) if isinstance(data, dict) else data


def reconcile(servers: list[dict], tools: list[dict], suppressions: list[dict]) -> dict:
    """Mark findings suppressed iff a suppression matches (scope, code, digest).
    Because suppressions bind to a digest, any edit to the server/tool changes
    the digest and the finding re-enters review. Stale suppressions (bound to a
    digest no longer present) are surfaced so the user can prune them."""
    index = {(s.get("scope"), s.get("code"), s.get("digest")): s for s in suppressions}
    matched = set()

    for srv in servers:
        for f in srv["findings"]:
            key = ("server", f["code"], srv["digest"])
            if key in index:
                f["suppressed"] = True
                f["suppression_reason"] = index[key].get("reason", "")
                matched.add(key)
            else:
                f["suppressed"] = False

    for t in tools:
        for c in t["candidate_capabilities"]:
            key = ("tool", c["capability"], t["digest"])
            if key in index:
                c["suppressed"] = True
                c["suppression_reason"] = index[key].get("reason", "")
                matched.add(key)
            else:
                c["suppressed"] = False

    stale = [
        {"scope": k[0], "code": k[1], "digest": k[2], "reason": v.get("reason", "")}
        for k, v in index.items() if k not in matched
    ]
    return {"stale_suppressions": stale}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Analyze an MCP config and/or tools/list for /scrutineer-mcp.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", help="Path to a (redacted) MCP client config JSON")
    parser.add_argument("--tools-list", dest="tools_list",
                        help="Path to a tools/list response JSON")
    parser.add_argument("--server", help="Server name to scope/label the tools-list "
                                          "to, and to filter the config to one server")
    parser.add_argument("--suppressions", help="Path to a suppressions JSON file")
    parser.add_argument("--allowlist", help="Path to a settings.json / .mcp.json whose "
                                            "permission rules are checked for approval drift")
    parser.add_argument("--guidance", help="Override path to mcp_risk_guidance.yaml")
    parser.add_argument("--indent", type=int, default=2, help="JSON output indent")
    args = parser.parse_args()

    if not args.config and not args.tools_list:
        parser.error("provide at least one of --config or --tools-list")

    guidance_path = Path(args.guidance) if args.guidance else Path(__file__).parent / "mcp_risk_guidance.yaml"
    if not guidance_path.exists():
        print(f"Error: guidance file not found: {guidance_path}", file=sys.stderr)
        sys.exit(1)
    g = Guidance(guidance_path)

    servers = []
    if args.config:
        cfg_path = Path(args.config)
        if not cfg_path.exists():
            print(f"Error: config not found: {cfg_path}", file=sys.stderr)
            sys.exit(1)
        try:
            cfg = json.loads(cfg_path.read_text())
        except json.JSONDecodeError as e:
            print(f"Error: config is not valid JSON: {e}", file=sys.stderr)
            sys.exit(1)
        server_map = find_server_map(cfg)
        if not server_map:
            print("Warning: no mcpServers map found in config", file=sys.stderr)
        for sname, entry in server_map.items():
            if args.server and sname != args.server:
                continue
            if isinstance(entry, dict):
                servers.append(analyze_server(sname, entry, g))

    tools = []
    if args.tools_list:
        tl_path = Path(args.tools_list)
        if not tl_path.exists():
            print(f"Error: tools-list not found: {tl_path}", file=sys.stderr)
            sys.exit(1)
        try:
            payload = json.loads(tl_path.read_text())
        except json.JSONDecodeError as e:
            print(f"Error: tools-list is not valid JSON: {e}", file=sys.stderr)
            sys.exit(1)
        for tool in extract_tools(payload):
            if isinstance(tool, dict):
                tools.append(analyze_tool(tool, args.server, g))

    suppressions = load_suppressions(Path(args.suppressions) if args.suppressions else None)
    recon = reconcile(servers, tools, suppressions)

    # Summary counts only ACTIVE (non-suppressed) findings.
    active_server_findings = [
        f for s in servers for f in s["findings"] if not f.get("suppressed")
    ]
    active_tool_caps = [
        c for t in tools for c in t["candidate_capabilities"] if not c.get("suppressed")
    ]
    sev_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in active_server_findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    for c in active_tool_caps:
        sev_counts[c["severity"]] = sev_counts.get(c["severity"], 0) + 1

    profile = data_profile(tools, g)
    combos = toxic_combinations(servers, tools)
    for c in combos:
        sev_counts[c["severity"]] = sev_counts.get(c["severity"], 0) + 1

    # Approval drift — what the client has already authorized vs. what review
    # recommends. Requires both an allowlist and a tool surface to correlate.
    allow_info = None
    drift = []
    if args.allowlist:
        al_path = Path(args.allowlist)
        if not al_path.exists():
            print(f"Error: allowlist not found: {al_path}", file=sys.stderr)
            sys.exit(1)
        try:
            allow_info = parse_allowlist(al_path)
        except json.JSONDecodeError as e:
            print(f"Error: allowlist is not valid JSON: {e}", file=sys.stderr)
            sys.exit(1)
        drift = approval_drift(servers, tools, allow_info)
        for d in drift:
            sev_counts[d["severity"]] = sev_counts.get(d["severity"], 0) + 1

    # Lowest runtime-binding confidence across servers — the verdict layer uses
    # this to cap unbindable (e.g. npx/latest) servers at CAUTION.
    binding_rank = {"none": 0, "weak": 1, "remote_endpoint": 1, "local_binary": 2, "strong": 3}
    weakest_binding = None
    if servers:
        weakest_binding = min(
            (s["provenance"]["runtime_binding_confidence"] for s in servers),
            key=lambda b: binding_rank.get(b, 0),
        )

    # Surface the granted picture (sets → sorted lists for JSON).
    granted = None
    if allow_info is not None:
        granted = {
            "allow_servers": sorted(allow_info["allow_servers"]),
            "allow_tools": sorted(f"{s}__{t}" for s, t in allow_info["allow_tools"]),
            "deny_servers": sorted(allow_info["deny_servers"]),
            "granted_filesystem": allow_info["granted_filesystem"],
            "sensitive_filesystem_granted": allow_info["sensitive_filesystem_granted"],
            "enable_all_project": allow_info["enable_all_project"],
        }

    out = {
        "schema": "mcp-review/analysis@2",
        "servers": servers,
        "tools": tools,
        "data_profile": profile,
        "toxic_combinations": combos,
        "approval_drift": drift,
        "granted": granted,
        "stale_suppressions": recon["stale_suppressions"],
        "summary": {
            "server_count": len(servers),
            "tool_count": len(tools),
            "active_config_findings": len(active_server_findings),
            "active_tool_capabilities": len(active_tool_caps),
            "toxic_combination_count": len(combos),
            "approval_drift_count": len(drift),
            "severity_counts": sev_counts,
            "data_sensitivity_rating": profile["rating"],
            "data_categories_touched": sorted(profile["categories"].keys()),
            "weakest_runtime_binding": weakest_binding,
            "all_servers_redacted": all(s["redaction_ok"] for s in servers) if servers else True,
        },
    }
    print(json.dumps(out, indent=args.indent))


if __name__ == "__main__":
    main()
