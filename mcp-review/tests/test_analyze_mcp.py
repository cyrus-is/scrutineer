#!/usr/bin/env python3
"""Smoke + regression suite for analyze_mcp.py.

Dependency-free (no pytest): run with the project venv from the mcp-review dir:

    .venv/bin/python tests/test_analyze_mcp.py

Exits non-zero if any check fails. Covers the guarantees that matter most:
secret no-echo, redaction-stable digests, pin heuristics, schema-intent signals,
toxic combinations, and approval drift — the things a regression would silently
break.
"""

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIX = HERE / "fixtures"
sys.path.insert(0, str(ROOT))

import analyze_mcp as A  # noqa: E402

G = A.Guidance(ROOT / "mcp_risk_guidance.yaml")

_results: list[tuple[str, bool]] = []


def check(name: str, cond) -> None:
    _results.append((name, bool(cond)))


def srv(entry: dict) -> dict:
    return A.analyze_server("s", entry, G)


def srv_digest(entry: dict) -> str:
    return srv(entry)["digest"]


# --- pin strength: only exact versions / full SHAs bypass the unpinned flag ---
check("pin exact ==", A.pin_strength("foo==1.2.3")[0] == "exact")
check("pin npm exact", A.pin_strength("foo@1.2.3")[0] == "exact")
check("pin @latest", A.pin_strength("foo@latest")[0] == "latest")
check("pin caret range", A.pin_strength("foo@^1.2.0")[0] == "range")
check("pin npm >= range", A.pin_strength("foo@>=1.2")[0] == "range")
check("pin bare >= range", A.pin_strength("foo>=1.2")[0] == "range")
check("pin pip ~= range", A.pin_strength("foo~=1.2")[0] == "range")
check("pin no-version none", A.pin_strength("@scope/pkg")[0] == "none")
check("pin full sha immutable", A.pin_strength("github:o/r#" + "a" * 40)[0] == "commit_sha")
check("pin short sha rejected", A.pin_strength("github:o/r#abc1234")[0] == "none")
check("pin git tag mutable", A.pin_strength("github:o/r#v1.2.3")[0] == "version_tag")
check("pin git branch floating", A.pin_strength("github:o/r#main")[0] == "none")

# --- redaction primitives ---
check("redact url query", A.redact_url("http://h/p?token=SEKRET") == "http://h/p?token=***")
check("redact url userinfo", A.redact_url("http://u:p@h/p").startswith("http://***@h"))
check("redact url keeps host", "h.example.com" in A.redact_url("https://h.example.com/x?key=z"))
check("mask flag+value", A.mask_args(["--api-key", "sk-LIVE-abcdefgh"]) == ["--api-key", "***"])
check("mask inline flag", A.mask_args(["--token=ghp_aaaaaaaa"]) == ["--token=***"])
check("mask bare secret shape", A.mask_args(["ghp_aaaaaaaaaaaa"]) == ["***"])
check("mask keeps path", A.mask_args(["/Users/me/data"]) == ["/Users/me/data"])
check("mask keeps benign flag value", A.mask_args(["--port", "8080"]) == ["--port", "8080"])

# --- digests are stable across redaction and key order ---
check("digest url redaction-stable",
      srv_digest({"url": "http://h/p?token=REALSECRETXYZ"}) == srv_digest({"url": "http://h/p?token=***"}))
check("digest args redaction-stable",
      srv_digest({"command": "x", "args": ["--token", "sk-LIVE-zzzzzzzz"]})
      == srv_digest({"command": "x", "args": ["--token", "***"]}))
check("digest env value-independent",
      srv_digest({"command": "x", "env": {"GITHUB_TOKEN": "ghp_realval"}})
      == srv_digest({"command": "x", "env": {"GITHUB_TOKEN": "***"}}))
check("digest env-key-order stable",
      srv_digest({"command": "x", "env": {"A": "1", "B": "2"}})
      == srv_digest({"command": "x", "env": {"B": "2", "A": "1"}}))
check("digest identical across runs",
      srv_digest({"command": "x", "args": ["a", "b"]}) == srv_digest({"command": "x", "args": ["a", "b"]}))

# --- no-echo: no live secret ever reaches the emitted record ---
rec = srv({"command": "x",
           "args": ["--api-key", "sk-LIVE-abcdefgh"],
           "url": "http://h/p?token=SEKRETVAL"})
blob = json.dumps(rec)
check("no-echo args secret", "sk-LIVE-abcdefgh" not in blob)
check("no-echo url secret", "SEKRETVAL" not in blob)
check("creds-in-url still detected", any(f["code"] == "credentials_in_url" for f in rec["findings"]))
check("non-https still detected", any(f["code"] == "non_https_remote" for f in rec["findings"]))

# --- env secret values: flagged, never echoed; placeholders ignored ---
rec_env = srv({"command": "x", "env": {"GITHUB_TOKEN": "ghp_livevalue1234"}})
check("unredacted secret flagged", any(f["code"] == "unredacted_secret_value" for f in rec_env["findings"]))
check("unredacted value not echoed", "ghp_livevalue1234" not in json.dumps(rec_env))
check("placeholder not flagged",
      not any(f["code"] == "unredacted_secret_value"
              for f in srv({"command": "x", "env": {"GITHUB_TOKEN": "${X}"}})["findings"]))

# --- schema-intent: benign name, powerful schema ---
sig = G.schema_intent_signals({"type": "object",
                               "properties": {"options": {"type": "string"}, "args": {"type": "array"}},
                               "additionalProperties": True})
check("schema power param", "options" in sig["power_params"])
check("schema arbitrary input", sig["arbitrary_input"] is True)
benign = G.schema_intent_signals({"type": "object", "properties": {"city": {"type": "string"}}})
check("schema benign clean", not benign["power_params"] and not benign["arbitrary_input"])

# nested power param (buried one object deep) must still be caught
nested = G.schema_intent_signals({"type": "object", "properties": {
    "payload": {"type": "object", "properties": {"command": {"type": "string"}}}}})
check("schema nested power param", "command" in nested["power_params"])
# oneOf branch hiding a power param
combinator = G.schema_intent_signals({"oneOf": [
    {"type": "object", "properties": {"city": {"type": "string"}}},
    {"type": "object", "properties": {"exec": {"type": "string"}}}]})
check("schema oneOf power param", "exec" in combinator["power_params"])
# array items carrying an abstract arg
arr = G.schema_intent_signals({"type": "object", "properties": {
    "steps": {"type": "array", "items": {"type": "object", "properties": {"script": {"type": "string"}}}}}})
check("schema array-items power param", "script" in arr["power_params"])

# --- Phase 1: zoned matching + evidence + confidence ---
def _cap(t):
    return A.analyze_tool(t, "s", G)["candidate_capabilities"]

# A $schema dialect URL ("http://json-schema.org/...") must NOT manufacture
# network_egress — the regression that lit it up on every filesystem tool.
fs_like = _cap({"name": "list_allowed_directories",
                "description": "Returns the directories the server may access.",
                "inputSchema": {"$schema": "http://json-schema.org/draft-07/schema#",
                                "type": "object", "properties": {}}})
check("zone: $schema url is not egress",
      "network_egress" not in {c["capability"] for c in fs_like})

# A hit records evidence (matched token + zone + snippet) and a confidence
# derived from the zone: a param-NAME match is high-confidence.
nav = _cap({"name": "browser_navigate", "description": "Navigate to a page.",
            "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}})
eg = next((c for c in nav if c["capability"] == "network_egress"), None)
check("evidence: matched+zone recorded", eg and {"matched", "zone", "snippet"} <= set(eg["evidence"]))
check("confidence: param-name zone is high",
      eg and eg["confidence"] == "high" and eg["evidence"]["zone"] == "param_name")

# A match only in prose is medium-confidence.
prose = _cap({"name": "do_thing", "description": "This will fetch a remote resource.",
              "inputSchema": {"type": "object", "properties": {}}})
eg2 = next((c for c in prose if c["capability"] == "network_egress"), None)
check("confidence: description-only zone is medium", eg2 and eg2["confidence"] == "medium")

# --- Phase 2: tightened regexes kill bare-token false positives, keep TPs ---
def _caps(name, desc, props=None):
    return {c["capability"] for c in _cap(
        {"name": name, "description": desc,
         "inputSchema": {"type": "object", "properties": props or {}}})}

# False positives that must NO LONGER fire:
check("fp: 'file system' is not code_execution",
      "code_execution" not in _caps("read_text_file", "Read a file from the file system as text."))
check("fp: 'root URL' is not privilege_escalation",
      "privilege_escalation" not in _caps("crawl", "Crawl from the root URL.", {"root_url": {"type": "string"}}))
check("fp: search 'query' param is not database_access",
      "database_access" not in _caps("web_search", "Search the web.", {"query": {"type": "string"}}))
check("fp: 'pull request' is not network_egress",
      "network_egress" not in _caps("create_pull_request", "Create a pull request in the repository."))
check("fp: 'remove domains' is not file_delete",
      "file_delete" not in _caps("search", "Use excludeDomains to remove domains from results."))

# True positives that must STILL fire:
check("tp: SQL query is database_access",
      "database_access" in _caps("query", "Run a read-only SQL query against the database."))
check("tp: delete_file is file_delete", "file_delete" in _caps("delete_file", "Delete a file at the given path."))
check("tp: 'remove a file' is file_delete", "file_delete" in _caps("cleanup", "Remove a file from disk."))
check("tp: chmod is privilege_escalation", "privilege_escalation" in _caps("set_perms", "chmod the target path."))
check("tp: url param is network_egress",
      "network_egress" in _caps("navigate", "Go to a page.", {"url": {"type": "string"}}))

# --- 5-server fixture: config smells land on the right servers ---
cfg = json.loads((FIX / "sample_config.json").read_text())
servers = [A.analyze_server(n, e, G) for n, e in A.find_server_map(cfg).items()]
by_name = {s["name"]: {f["code"] for f in s["findings"]} for s in servers}
check("fs: unpinned + broad", {"unpinned_source", "broad_filesystem_scope"} <= by_name["filesystem"])
check("github: pinned (no unpinned)", "unpinned_source" not in by_name["github"])
check("weird: shell wrapper", "shell_wrapper" in by_name["weird"])
check("remote-insecure: creds + non-https",
      {"credentials_in_url", "non_https_remote"} <= by_name["remote-insecure"])

# --- toxic combinations ---
tools = [A.analyze_tool(t, "github", G) for t in A.extract_tools(json.loads((FIX / "sample_tools.json").read_text()))]
combos = {c["id"] for c in A.toxic_combinations(servers, tools)}
check("toxic exfil_chain", "exfil_chain" in combos)
check("toxic exec_with_secret_access", "exec_with_secret_access" in combos)

# combos survive suppression of a contributing atomic finding
gh_digest = next(s["digest"] for s in servers if s["name"] == "github")
A.reconcile(servers, tools,
            [{"scope": "server", "code": "sensitive_env_required", "digest": gh_digest, "reason": "x"}])
check("toxic survives atomic suppression",
      "exfil_chain" in {c["id"] for c in A.toxic_combinations(servers, tools)})

# --- approval drift ---
allow = A.parse_allowlist(FIX / "settings.json")
drift = {f["code"] for f in A.approval_drift(servers, tools, allow)}
check("drift approval_drift", "approval_drift" in drift)
check("drift server_wildcard_grant", "server_wildcard_grant" in drift)
check("drift egress_with_sensitive_fs", "egress_with_sensitive_fs" in drift)

# tight allowlist → no drift
tight = {"allow_servers": set(), "allow_tools": {("github", "read_file")},
         "deny_servers": set(), "deny_tools": set(), "granted_filesystem": [],
         "sensitive_filesystem_granted": False, "enable_all_project": False, "enabled_mcpjson": set()}
check("drift none when tight", A.approval_drift(servers, tools, tight) == [])

# --- suppression reconcile / stale exposure ---
fs_only = [A.analyze_server("filesystem", A.find_server_map(cfg)["filesystem"], G)]
recon = A.reconcile(fs_only, [],
                    [{"scope": "server", "code": "broad_filesystem_scope", "digest": "sha256:STALE", "reason": "old"}])
check("stale suppression surfaced", len(recon["stale_suppressions"]) == 1)

# ----------------------------------------------------------------------------
fails = [n for n, ok in _results if not ok]
for n, ok in _results:
    print(("PASS " if ok else "FAIL ") + n)
print(f"\n{len(_results) - len(fails)}/{len(_results)} checks passed")
if fails:
    print("FAILURES: " + ", ".join(fails))
    sys.exit(1)
