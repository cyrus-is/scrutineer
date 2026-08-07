#!/usr/bin/env python3
"""Suite for capture_runtime.py — the basis="observed" layer.

Dependency-free (no pytest), same shape as test_analyze_mcp.py:

    .venv/bin/python tests/test_capture_runtime.py

These are integration tests: they LAUNCH the stdio fixture servers in
tests/fixtures/servers/ and drive them through a real handshake. That is the only
honest way to test a behavioral capture. They stay deterministic — no live
network (the sink binds 127.0.0.1; the one hardcoded fixture host is `.invalid`),
no sleeps that gate correctness, no retries.

Covers the guarantees a regression would silently break: the --run gate, the
scrubbed child environment (a probe must never hand real credentials to code
under review), manifest-drift detection including the redefinition case, and the
canary chain that closes the weather-exfil miss.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURE_SERVERS = HERE / "fixtures" / "servers"
sys.path.insert(0, str(ROOT))

import analyze_mcp as A  # noqa: E402
import capture_runtime as C  # noqa: E402

G = A.Guidance(ROOT / "mcp_risk_guidance.yaml")

_results: list[tuple[str, bool]] = []


def check(name: str, cond) -> None:
    _results.append((name, bool(cond)))


def entry_for(script: str, env: dict | None = None) -> dict:
    return {"command": sys.executable, "args": [str(FIXTURE_SERVERS / script)],
            "env": env or {}}


def codes(findings) -> set:
    return {f["code"] for f in findings}


def by_code(findings, code) -> list:
    return [f for f in findings if f["code"] == code]


# ---------------------------------------------------------------------------
# Gating — nothing runs without --run
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as td:
    cfg = Path(td) / "config.json"
    cfg.write_text(json.dumps({"mcpServers": {"drift": entry_for("drift_server.py")}}))
    marker = Path(td) / "launched"
    # The plan path must not execute the server. Point HOME at a temp dir and
    # assert the fixture never got far enough to write its launch marker.
    plan = subprocess.run(
        [sys.executable, str(ROOT / "capture_runtime.py"),
         "--config", str(cfg), "--server", "drift"],
        capture_output=True, text=True, env={**os.environ, "HOME": td}, timeout=60)
    check("gate: plan exits 0 without --run", plan.returncode == 0)
    check("gate: plan says nothing has run", "NOTHING HAS RUN" in plan.stdout)
    check("gate: plan does not launch the server",
          not (Path(td) / ".scrutineer-drift-launch").exists() and not marker.exists())
    check("gate: plan names the scrubbed environment", "SCRUBBED" in plan.stdout)

# A remote/url server has no local process — capture must refuse, not improvise.
try:
    C.run_capture({"url": "https://remote.example/sse"}, "remote", G, probe=False,
                  relaunch=False, baseline_path=None, timeout=5, call_timeout=5,
                  keep_home=False)
    check("gate: remote server refused", False)
except C.SessionError as e:
    check("gate: remote server refused", "stdio-only" in str(e))


# ---------------------------------------------------------------------------
# Child environment is SCRUBBED — the probe must never hand over real secrets
# ---------------------------------------------------------------------------

os.environ["SCRUTINEER_TEST_REAL_SECRET"] = "ghp_averyrealtokenvalue"
with tempfile.TemporaryDirectory() as td:
    home = Path(td) / "home"
    home.mkdir()
    env, canaries = C.build_child_env(
        {"WEATHER_API_KEY": "ghp_realvalue", "REGION": "eu-west-1"}, home, G,
        "http://127.0.0.1:9")
    blob = json.dumps(env)
    check("env: real os.environ secret not passed through",
          "SCRUTINEER_TEST_REAL_SECRET" not in env and "ghp_averyrealtokenvalue" not in blob)
    check("env: declared secret replaced by a canary",
          env["WEATHER_API_KEY"].startswith(C.CANARY_PREFIX) and "ghp_realvalue" not in blob)
    check("env: canary is attributable to its key",
          canaries.get(env["WEATHER_API_KEY"]) == "env:WEATHER_API_KEY")
    check("env: benign declared value passes through", env["REGION"] == "eu-west-1")
    check("env: HOME redirected to the throwaway dir", env["HOME"] == str(home))
    check("env: proxy vars point at the sink", env["HTTP_PROXY"] == "http://127.0.0.1:9")
del os.environ["SCRUTINEER_TEST_REAL_SECRET"]

# A secret-shaped value under a NON-credential key name is still withheld — the
# key-name patterns are not the only line of defence.
with tempfile.TemporaryDirectory() as td:
    env2, _ = C.build_child_env({"ENDPOINT": "ghp_realtokenvalue1234"}, Path(td), G, None)
    check("env: secret-shaped value withheld even under a benign key",
          "ghp_realtokenvalue1234" not in json.dumps(env2))
check("env: withholding covers key name, value shape, and ${VAR} refs",
      C.withhold_value("API_TOKEN", "anything", G)
      and C.withhold_value("ENDPOINT", "ghp_aaaaaaaaaaaa", G)
      and C.withhold_value("REGION", "${REGION}", G)
      and not C.withhold_value("REGION", "eu-west-1", G))

# Decoy HOME seeding is attributable and actually on disk.
home, file_canaries = C.seed_home(G)
try:
    check("decoys: seeded on disk", (home / ".aws" / "credentials").exists())
    check("decoys: content carries a canary",
          C.CANARY_PREFIX in (home / ".aws" / "credentials").read_text())
    check("decoys: every canary maps back to its path",
          all(v.startswith("file:~/") for v in file_canaries.values()))
finally:
    import shutil
    shutil.rmtree(home, ignore_errors=True)


# ---------------------------------------------------------------------------
# Probe-input synthesis
# ---------------------------------------------------------------------------

_schema = {"type": "object", "properties": {
    "city": {"type": "string"}, "report_url": {"type": "string"},
    "cache_path": {"type": "string"}, "count": {"type": "integer"},
    "mode": {"enum": ["fast", "slow"]}}}
hostile = C.probe_arguments(_schema, G, "/tmp/decoy/.aws/credentials", "http://sink", hostile=True)
benign = C.probe_arguments(_schema, G, "/tmp/decoy/.aws/credentials", "http://sink", hostile=False)
check("probe: url-shaped param gets the sink", hostile["report_url"] == "http://sink")
check("probe: path-shaped param gets a decoy", hostile["cache_path"].endswith("credentials"))
check("probe: plain param gets filler", hostile["city"] == G.probe["benign_string"])
check("probe: typed params respected", hostile["count"] == 1 and hostile["mode"] == "fast")
check("probe: benign call points at nothing sensitive",
      "sink" not in json.dumps(benign) and "credentials" not in json.dumps(benign))


# ---------------------------------------------------------------------------
# diff_manifest — the three drift shapes, with redefinition escalated
# ---------------------------------------------------------------------------

base = {"a": "sha256:1", "b": "sha256:2"}
check("drift: identical surfaces produce nothing", C.diff_manifest(base, dict(base), G) == [])
redef = C.diff_manifest(base, {"a": "sha256:1", "b": "sha256:CHANGED"}, G)
check("drift: redefinition detected", "manifest_drift" in codes(redef))
check("drift: redefinition escalated to HIGH", redef[0]["severity"] == "HIGH")
check("drift: redefinition carries both digests",
      redef[0]["evidence"]["redefined"][0]["baseline_digest"] == "sha256:2")
added = C.diff_manifest(base, {**base, "c": "sha256:3"}, G)
check("drift: added tool detected at MEDIUM",
      added and added[0]["severity"] == "MEDIUM" and added[0]["evidence"]["added"])
removed = C.diff_manifest(base, {"a": "sha256:1"}, G)
check("drift: removed tool detected", removed and removed[0]["evidence"]["removed"])
check("drift: findings carry basis=observed",
      all(f["basis"] == "observed" for f in redef + added + removed))


# ---------------------------------------------------------------------------
# Phase 1 END-TO-END — launch the rug-pull fixture twice and diff
# ---------------------------------------------------------------------------

rec = C.run_capture(entry_for("drift_server.py"), "drift", G, probe=False, relaunch=True,
                    baseline_path=None, timeout=30, call_timeout=10, keep_home=False)
check("phase1: capture succeeded", rec["captured"] is True)
check("phase1: schema is behavioral@1", rec["schema"] == C.BEHAVIORAL_SCHEMA)
check("phase1: served surface captured", set(rec["tools_observed"]) >= {"get_weather", "list_cities"})
check("phase1: rug-pull on relaunch detected", "manifest_drift" in codes(rec["findings"]))
_hi = [f for f in by_code(rec["findings"], "manifest_drift") if f["severity"] == "HIGH"]
check("phase1: redefinition of get_weather is HIGH",
      _hi and any(r["tool"] == "get_weather" for r in _hi[0]["evidence"]["redefined"]))
check("phase1: newly added run_helper flagged",
      any("run_helper" in json.dumps(f.get("evidence", {}))
          for f in by_code(rec["findings"], "manifest_drift")))
check("phase1: no probing without --probe",
      rec["coverage"]["calls_made"] == 0 and rec["coverage"]["probe_mode"] is False)
check("phase1: drift block agrees with itself",
      rec["drift"]["checked"] is True and rec["drift"]["relaunch_checked"] is True
      and "relaunch" in rec["drift"]["against"])
check("phase1: coverage refuses to imply clean",
      rec["coverage"]["absence_of_findings_is_not_proof"] is True and rec["coverage"]["limitations"])
check("phase1: session digest is stable and bound",
      isinstance(rec["session_digest"], str) and rec["session_digest"].startswith("sha256:"))

# Per-tool digests must be comparable to the STATIC analyzer's, or drift against a
# reviewed baseline is meaningless.
_static = A.analyze_tool(
    {"name": "list_cities", "description": "List supported cities.",
     "inputSchema": {"type": "object", "properties": {}}}, "drift", G)
check("phase1: capture digests match analyze_tool digests",
      rec["per_tool_digests"]["list_cities"] == _static["digest"])

# Drift against a reviewed baseline (the analyzer's own record), not a relaunch.
_baseline = {"schema": "mcp-review/analysis@4", "tools": [
    {"server": "drift", "name": "get_weather", "digest": "sha256:REVIEWED-DIFFERENT"}]}
with tempfile.TemporaryDirectory() as td:
    bpath = Path(td) / "analysis.json"
    bpath.write_text(json.dumps(_baseline))
    rec_b = C.run_capture(entry_for("drift_server.py"), "drift", G, probe=False,
                          relaunch=False, baseline_path=bpath, timeout=30,
                          call_timeout=10, keep_home=False)
check("phase1: drift checked against a reviewed baseline",
      rec_b["drift"]["checked"] is True and "manifest_drift" in codes(rec_b["findings"]))


# ---------------------------------------------------------------------------
# Phase 2 END-TO-END — canary probe against the defanged exfil fixture
# ---------------------------------------------------------------------------

exfil_entry = entry_for("exfil_server.py", {"WEATHER_API_KEY": "${WEATHER_API_KEY}"})
prec = C.run_capture(exfil_entry, "weather", G, probe=True, relaunch=False,
                     baseline_path=None, timeout=30, call_timeout=15, keep_home=False)
pcodes = codes(prec["findings"])

check("phase2: capture succeeded", prec["captured"] is True)
check("phase2: mechanism records the probe", prec["mechanism"] == "stdio_proxy+probe")
check("phase2: every served tool was called",
      set(prec["coverage"]["tools_called"]) == {"get_weather", "get_forecast", "describe"})

# The anchor finding: a planted credential canary left the process.
check("phase2: secret_in_egress fired", "secret_in_egress" in pcodes)
_sie = by_code(prec["findings"], "secret_in_egress")
check("phase2: secret_in_egress is HIGH/high",
      all(f["severity"] == "HIGH" and f["confidence"] == "high" for f in _sie))
check("phase2: the leaked env key is named",
      any(f["evidence"].get("secret_key") == "WEATHER_API_KEY" for f in _sie))

# The decoy read — the source half, observed rather than inferred.
check("phase2: undeclared_file_access fired", "undeclared_file_access" in pcodes)
check("phase2: the decoy that was read is named",
      any(".aws/credentials" in f["evidence"].get("decoy", "")
          for f in by_code(prec["findings"], "undeclared_file_access")))

# Runtime prompt injection — invisible to every description-level scan.
check("phase2: injected_tool_result fired", "injected_tool_result" in pcodes)
check("phase2: injection attributed to the describe tool",
      any(f["evidence"]["tool"] == "describe"
          for f in by_code(prec["findings"], "injected_tool_result")))

# Egress via the caller's proxy env (the hardcoded .invalid host) is recorded too.
check("phase2: proxied egress to the hardcoded host captured",
      any("collector.example.invalid" in r["target"] for r in prec["side_effects"]["outbound_requests"]))

# Relative-to-baseline discipline: this server DECLARES egress (a `report_url`
# param), so raw outbound calls are not a finding on their own. Only the canary
# content is.
check("phase2: declared egress is not flagged as undeclared",
      "network_egress" in prec["declared_capabilities"]
      and "undeclared_network_egress" not in pcodes)

check("phase2: observed capabilities recorded",
      {"file_read", "network_egress", "secrets_access"} <= set(prec["observed_capabilities"]))
check("phase2: findings all carry basis=observed",
      all(f["basis"] == "observed" for f in prec["findings"]))
check("phase2: coverage still refuses to imply clean",
      prec["coverage"]["absence_of_findings_is_not_proof"] is True)
check("phase2: no declared env value reached the child unreplaced",
      prec["coverage"]["env_passed_through"] == [])


# ---------------------------------------------------------------------------
# THE WEATHER-EXFIL GAP — static is structurally blind; observed closes it
# ---------------------------------------------------------------------------

_srv = [A.analyze_server("weather", exfil_entry, G)]
_tools = [A.analyze_tool(t, "weather", G) for t in [
    {"name": "get_weather", "description": "Return the current weather for a city.",
     "inputSchema": {"type": "object", "properties": {
         "city": {"type": "string"}, "report_url": {"type": "string"}}}},
    {"name": "get_forecast", "description": "Return a three-day forecast for a city.",
     "inputSchema": {"type": "object", "properties": {"city": {"type": "string"}}}},
    {"name": "describe", "description": "Describe this weather service.",
     "inputSchema": {"type": "object", "properties": {}}},
]]

_static_combos = {c["id"]: c for c in A.toxic_combinations(_srv, _tools)}
check("gap: static analysis MISSES read_and_exfil (nothing declares a read)",
      "read_and_exfil" not in _static_combos)

_observed_combos = {c["id"]: c for c in
                    A.toxic_combinations(_srv, _tools, prec["observed_capabilities"])}
check("gap: observed capabilities make read_and_exfil fire",
      "read_and_exfil" in _observed_combos)
check("gap: the observed combo is HIGH/high",
      _observed_combos["read_and_exfil"]["severity"] == "HIGH"
      and _observed_combos["read_and_exfil"]["confidence"] == "high")
check("gap: the combo records its observed basis",
      _observed_combos["read_and_exfil"]["basis"] == "observed")
check("gap: exfil_chain also upgrades to HIGH on observation",
      _observed_combos.get("exfil_chain", {}).get("severity") == "HIGH")


# ---------------------------------------------------------------------------
# Failure to capture must never read as an absence of findings
# ---------------------------------------------------------------------------

with tempfile.TemporaryDirectory() as td:
    cfg = Path(td) / "config.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "nope": {"command": str(Path(td) / "does-not-exist"), "args": []}}}))
    out = Path(td) / "behavioral.json"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "capture_runtime.py"), "--config", str(cfg),
         "--server", "nope", "--run", "--out", str(out)],
        capture_output=True, text=True, timeout=60)
    failed = json.loads(out.read_text())
    check("failure: exits non-zero", proc.returncode == 2)
    check("failure: record is explicitly uncaptured", failed["captured"] is False)
    check("failure: the reason is stated, not swallowed",
          "error" in failed and failed["coverage"]["limitations"])


# ----------------------------------------------------------------------------
fails = [n for n, ok in _results if not ok]
for n, ok in _results:
    print(("PASS " if ok else "FAIL ") + n)
print(f"\n{len(_results) - len(fails)}/{len(_results)} checks passed")
if fails:
    print("FAILURES: " + ", ".join(fails))
    sys.exit(1)
