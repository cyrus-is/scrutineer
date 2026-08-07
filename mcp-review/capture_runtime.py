#!/usr/bin/env python3
"""
Behavioral capture for /scrutineer-mcp — the `basis: "observed"` layer.

THIS MODULE RUNS UNTRUSTED CODE. That is the whole point of it, and it is why it
is a separate, explicitly-gated entrypoint that `analyze_mcp.py` never imports.
The static analyzer keeps its charter — "never starts an MCP server, calls a
tool, executes fetched code, or runs a package manager" — because the boundary
between the two halves is a JSON file, not a function call. Nothing here happens
without `--run`.

What it answers that the static passes cannot: the auditor reasons about what a
server DECLARES and (when source is fetchable) what its source statically
CONTAINS. It never observes what the server DOES. This produces the missing
third evidence basis.

Two mechanisms, in increasing cost:

  Phase 1 — MANIFEST DRIFT (default; stdlib only, no probing).
    Launch the server behind the stdio JSON-RPC handshake, capture the tools/list
    it actually serves, and diff the per-tool digests against the reviewed
    baseline (an analyze_mcp.py record via --baseline, or a second launch via
    --relaunch). Catches the rug-pull the static pass concedes it only makes
    "detectable on re-review". Also scans captured tool RESULTS for the
    tool-poisoning patterns — the runtime form of the attack the description
    scan cannot reach, because the payload does not exist until the call.

  Phase 2 — CANARY PROBE (--probe).
    Seed every credential-shaped env var with a unique canary, seed a throwaway
    HOME with decoy credential files (each carrying its own canary), point
    egress at a local recording sink, then call each tool twice: once with
    benign inputs, once with probe inputs (a decoy path for path-shaped params,
    the sink URL for URL-shaped params). A canary that surfaces in a tool result
    or an outbound request is ground truth: the server read a file it had no
    business reading, or transmitted its own credential off-process.

COVERAGE IS THE HONEST LIMIT. A probe only observes code paths it triggers, so a
logic bomb gated on an input we did not send stays dormant. Absence of a
behavioral finding is NOT "clean" — every record carries a `coverage` block
stating exactly what was and was not exercised, and the skill is required to
report it. Without an OS sandbox (Phase 3), egress is captured only from clients
that honor proxy env vars or that we handed a sink URL, and file reads are
detected only via canary content that comes back to us.

Safety rails:
  - Gated: prints an inspectable plan and exits unless --run is passed.
  - No real credentials. The child gets a SCRUBBED environment (a small
    allowlist plus canaries) — never os.environ. A server that exfiltrates
    during the probe exfiltrates a canary, not your GitHub token.
  - Throwaway HOME, deleted afterwards (--keep-home to retain for inspection).
  - stdio servers only; remote/url servers are refused (nothing to launch).
  - Hard timeouts; the child is terminated then killed.
  - The sink binds 127.0.0.1 and never forwards a request onward — it records
    and answers. It is a black hole, not a proxy that completes the egress.

Usage:
    # Inspect the plan (no execution)
    python capture_runtime.py --config .mcp.json --server weather

    # Phase 1 — capture the running surface, diff against the reviewed baseline
    python capture_runtime.py --config .mcp.json --server weather --run \\
        --baseline analysis.json --out behavioral.json

    # Phase 1 — no baseline: launch twice and diff launch 1 against launch 2
    python capture_runtime.py --config .mcp.json --server weather --run --relaunch

    # Phase 2 — add the canary probe (calls every tool)
    python capture_runtime.py --config .mcp.json --server weather --run --probe \\
        --out behavioral.json

Then fold the record into the review — the analyzer reads it, never runs it:
    python analyze_mcp.py --config .mcp.json --server weather --behavioral behavioral.json
"""

import argparse
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import analyze_mcp as A  # noqa: E402

PROTOCOL_VERSION = "2025-06-18"
BEHAVIORAL_SCHEMA = "mcp-review/behavioral@1"
CANARY_PREFIX = "SCRUTINEER-CANARY"

# Bound what we read back from a hostile child so a server cannot exhaust memory
# by returning (or POSTing) an unbounded stream.
_MAX_BODY = 256 * 1024
_MAX_RESULT = 256 * 1024
_MAX_STDERR = 256 * 1024


# ---------------------------------------------------------------------------
# Canaries — deterministic by design. Uniqueness only has to hold WITHIN a
# capture (so a hit identifies which secret leaked); determinism keeps
# session_digest stable across runs, which is what lets a behavioral
# suppression bind to it the way static suppressions bind to a config digest.
# ---------------------------------------------------------------------------

def canary(kind: str, ident: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9]+", "-", ident).strip("-").upper() or "X"
    return f"{CANARY_PREFIX}-{kind.upper()}-{safe}"


# ---------------------------------------------------------------------------
# Recording sink. Doubles as (a) an HTTP forward proxy for children that honor
# HTTP_PROXY/HTTPS_PROXY, and (b) a plain endpoint we hand out as a probe URL.
# It NEVER forwards a request to its real destination — capturing exfiltration
# must not also perform it.
# ---------------------------------------------------------------------------

class _SinkHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "scrutineer-sink"

    def _capture(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        body = b""
        if length > 0:
            try:
                body = self.rfile.read(min(length, _MAX_BODY))
            except OSError:
                body = b""
        self.server.record({
            "method": self.command,
            "target": self.path,
            "headers": dict(self.headers.items()),
            "body": body.decode("utf-8", "replace"),
        })

    def _answer(self):
        payload = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._capture()
        self._answer()

    do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = do_GET

    def do_CONNECT(self):
        # An HTTPS tunnel attempt. We deliberately do NOT terminate TLS — MITMing
        # a server under review is out of scope and would need a trusted CA. The
        # attempt itself is the signal: it names the host the server wanted, and
        # refusing it means the egress does not complete.
        self.server.record({
            "method": "CONNECT", "target": self.path, "headers": {}, "body": "",
            "note": "TLS tunnel refused — host recorded, body not observable "
                    "without an OS sandbox (Phase 3) or a trusted MITM CA.",
        })
        self.send_response(502)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass  # keep the child's traffic out of our stderr


class Sink(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _SinkHandler)
        self._requests: list[dict] = []
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def record(self, entry: dict) -> None:
        with self._lock:
            self._requests.append(entry)

    @property
    def requests(self) -> list[dict]:
        with self._lock:
            return list(self._requests)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"

    def __enter__(self):
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.shutdown()
        self.server_close()


# ---------------------------------------------------------------------------
# stdio MCP session. The handshake is the one tests/corpus/capture_tools.py
# already performs, promoted to a first-class, instrumented citizen with a
# scrubbed environment and tools/call support.
# ---------------------------------------------------------------------------

class SessionError(RuntimeError):
    pass


class MCPSession:
    def __init__(self, command: str, args: list[str], env: dict,
                 cwd: str | None = None, timeout: float = 30.0):
        self.command = command
        self.args = list(args or [])
        self.env = env
        self.cwd = cwd
        self.timeout = timeout
        self.proc: subprocess.Popen | None = None
        self._q: queue.Queue = queue.Queue()
        self._stderr: list[str] = []
        self._next_id = 0

    # -- lifecycle ----------------------------------------------------------
    def __enter__(self):
        try:
            self.proc = subprocess.Popen(
                [self.command] + self.args,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=self.env, cwd=self.cwd, text=True, bufsize=1,
            )
        except (FileNotFoundError, PermissionError, OSError) as e:
            raise SessionError(f"launch failed: {e}") from e
        threading.Thread(target=self._drain_stdout, daemon=True).start()
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        if not self.proc:
            return
        for finish in (self.proc.terminate, self.proc.kill):
            try:
                finish()
                self.proc.wait(timeout=5)
                break
            except subprocess.TimeoutExpired:
                continue
            except OSError:
                break
        for pipe in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            try:
                if pipe:
                    pipe.close()
            except OSError:
                pass

    def _drain_stdout(self):
        try:
            for line in iter(self.proc.stdout.readline, ""):
                self._q.put(line)
        except (OSError, ValueError):
            pass
        finally:
            self._q.put(None)

    def _drain_stderr(self):
        try:
            for line in iter(self.proc.stderr.readline, ""):
                if sum(len(s) for s in self._stderr) < _MAX_STDERR:
                    self._stderr.append(line)
        except (OSError, ValueError):
            pass

    @property
    def stderr_text(self) -> str:
        return "".join(self._stderr)

    # -- JSON-RPC -----------------------------------------------------------
    def _send(self, msg: dict):
        try:
            self.proc.stdin.write(json.dumps(msg) + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise SessionError(f"server closed stdin: {e}") from e

    def _await(self, want_id: int, deadline: float) -> dict:
        while time.time() < deadline:
            try:
                line = self._q.get(timeout=0.25)
            except queue.Empty:
                continue
            if line is None:
                raise SessionError("server closed stdout")
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue  # servers routinely log noise to stdout
            if isinstance(msg, dict) and msg.get("id") == want_id:
                return msg
        raise SessionError(f"timeout waiting for response id={want_id}")

    def _request(self, method: str, params: dict, timeout: float | None = None) -> dict:
        self._next_id += 1
        rid = self._next_id
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        return self._await(rid, time.time() + (timeout or self.timeout))

    # -- MCP ----------------------------------------------------------------
    def initialize(self) -> dict:
        resp = self._request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "scrutineer-capture-runtime", "version": "1"},
        })
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return resp.get("result") or {}

    def list_tools(self) -> list[dict]:
        resp = self._request("tools/list", {})
        return [t for t in (resp.get("result") or {}).get("tools", []) if isinstance(t, dict)]

    def call_tool(self, name: str, arguments: dict, timeout: float | None = None) -> dict:
        return self._request("tools/call", {"name": name, "arguments": arguments},
                             timeout=timeout)


# ---------------------------------------------------------------------------
# Child environment. NEVER os.environ: a probe that hands a possibly-malicious
# server the reviewer's real credentials would exfiltrate live secrets to prove
# it can exfiltrate. The child gets a minimal allowlist plus canaries.
# ---------------------------------------------------------------------------

_ENV_PASSTHROUGH = ("PATH", "LANG", "LC_ALL", "TZ", "SystemRoot", "COMSPEC",
                    "PATHEXT", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE")


def withhold_value(key: str, value, g: A.Guidance) -> bool:
    """True when a declared env value must NOT be handed to the child: its key
    looks credential-ish, its value looks like a live secret, or it is an
    unresolved ${VAR} reference. Everything withheld is replaced by a canary or
    an inert placeholder."""
    return (g.is_sensitive_key(key)
            or not isinstance(value, str) or not value
            or value.startswith("$")
            or bool(A._SECRET_VALUE_RE.search(value)))


def build_child_env(declared_env: dict, home: Path, g: A.Guidance,
                    sink_url: str | None) -> tuple[dict, dict]:
    """Return (env, canaries). Credential-shaped keys get a unique canary so a
    leak is attributable; other declared keys get an inert placeholder so
    boot-time presence checks pass."""
    env = {k: os.environ[k] for k in _ENV_PASSTHROUGH if k in os.environ}
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)          # Windows homedir resolution
    env["TMPDIR"] = str(home / "tmp")
    env["XDG_CONFIG_HOME"] = str(home / ".config")
    env["XDG_DATA_HOME"] = str(home / ".local" / "share")
    env["NODE_OPTIONS"] = ""                # no injected --require preload
    env["SCRUTINEER_PROBE"] = "1"           # honest: we do not hide from the server

    canaries: dict[str, str] = {}
    for key, value in (declared_env or {}).items():
        if g.is_sensitive_key(key):
            c = canary("env", key)
            env[key] = c
            canaries[c] = f"env:{key}"
        elif withhold_value(key, value, g):
            env[key] = "scrutineer-probe-placeholder"
        else:
            # A benign declared value (a region, a base path) passes through so the
            # server boots configured. Anything shaped like a live secret is
            # replaced even though its key name did not look credential-ish — the
            # probe must never hand real material to code under review. Which keys
            # took this path is reported in coverage.env_passed_through, so the
            # residual is auditable rather than silent.
            env[key] = value

    if sink_url:
        # Well-behaved HTTP clients route through these. A client that ignores
        # them egresses unobserved — stated in coverage, not papered over.
        for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
                    "ALL_PROXY", "all_proxy"):
            env[var] = sink_url
        env["NO_PROXY"] = ""
        env["no_proxy"] = ""
    return env, canaries


def seed_home(g: A.Guidance) -> tuple[Path, dict]:
    """Create a throwaway HOME seeded with decoy credential files. Each decoy
    carries a unique canary, so its content coming back to us in a result or an
    outbound body proves the read."""
    home = Path(tempfile.mkdtemp(prefix="scrutineer-probe-home-"))
    (home / "tmp").mkdir(exist_ok=True)
    canaries: dict[str, str] = {}
    for rel in g.probe.get("decoy_files", []):
        target = home / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        c = canary("file", rel)
        target.write_text(
            f"# scrutineer decoy — not a real credential\n"
            f"{c}\n"
            f"# If this string appears in a tool result or an outbound request,\n"
            f"# the server read a file it has no business reading.\n"
        )
        try:
            target.chmod(0o600)
        except OSError:
            pass
        canaries[c] = f"file:~/{rel}"
    return home, canaries


# ---------------------------------------------------------------------------
# Probe input synthesis
# ---------------------------------------------------------------------------

def _compile(patterns) -> list:
    return [re.compile(p, re.IGNORECASE) for p in patterns or []]


def probe_arguments(schema: dict, g: A.Guidance, decoy_path: str, sink_url: str,
                    hostile: bool) -> dict:
    """Build one argument set for a tool.

    hostile=False  — benign control call: the REQUIRED params only, filled with
                     inert values. A minimal valid call, pointed at nothing.
    hostile=True   — probe call: EVERY param, because an exfiltration sink is
                     exactly the kind of parameter a server leaves optional.
                     Path-shaped params get a decoy credential path, URL-shaped
                     params get the sink URL. A handler that reads wherever it is
                     pointed, or forwards to a caller-chosen host, reveals itself.
    """
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties")
    if not isinstance(props, dict):
        return {}
    required = schema.get("required")
    if hostile or not (isinstance(required, list) and required):
        names = list(props.keys())
    else:
        names = [n for n in required if n in props]

    path_res = _compile(g.probe.get("path_param_patterns"))
    url_res = _compile(g.probe.get("url_param_patterns"))
    filler = g.probe.get("benign_string", "scrutineer-probe")

    args = {}
    for name in names[:12]:
        spec = props.get(name) if isinstance(props.get(name), dict) else {}
        args[name] = _value_for(str(name), spec, path_res, url_res,
                                decoy_path, sink_url, filler, hostile)
    return args


def _value_for(name, spec, path_res, url_res, decoy_path, sink_url, filler, hostile):
    enum = spec.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    ptype = spec.get("type")
    if isinstance(ptype, list):
        ptype = next((t for t in ptype if t != "null"), "string")
    if ptype in ("integer", "number"):
        return 1
    if ptype == "boolean":
        return False
    if ptype == "array":
        item = spec.get("items") if isinstance(spec.get("items"), dict) else {}
        return [_value_for(name, item, path_res, url_res, decoy_path, sink_url, filler, hostile)]
    if ptype == "object":
        sub = spec.get("properties")
        if not isinstance(sub, dict):
            return {}
        out = {}
        for k in list(sub)[:6]:
            child = sub[k] if isinstance(sub[k], dict) else {}
            out[k] = _value_for(str(k), child, path_res, url_res,
                                decoy_path, sink_url, filler, hostile)
        return out
    if hostile:
        if any(r.search(name) for r in url_res):
            return sink_url
        if any(r.search(name) for r in path_res):
            return decoy_path
    return filler


# ---------------------------------------------------------------------------
# Phase 1 — capture + manifest drift
# ---------------------------------------------------------------------------

def tool_identity(tool: dict) -> dict:
    """The identity analyze_tool() digests, reproduced exactly so per-tool
    digests from a capture and from the static analyzer are comparable."""
    return {
        "name": tool.get("name", ""),
        "description": tool.get("description", "") or "",
        "inputSchema": tool.get("inputSchema") or tool.get("input_schema") or {},
    }


def digest_tools(tools: list[dict]) -> tuple[str, dict]:
    per_tool = {t.get("name", ""): A.digest(tool_identity(t)) for t in tools}
    return A.digest(sorted(per_tool.items())), per_tool


def diff_manifest(baseline: dict, observed: dict, g: A.Guidance,
                  baseline_label: str = "the reviewed baseline") -> list[dict]:
    """Emit manifest_drift findings for tools added, removed, or REDEFINED.

    Redefinition is the severe case and is escalated to HIGH: the tool name a
    grant or a classification points at now means something else, so every
    approval carried over from review silently applies to new behavior.
    """
    findings = []
    added = sorted(set(observed) - set(baseline))
    removed = sorted(set(baseline) - set(observed))
    redefined = sorted(n for n in set(baseline) & set(observed)
                       if baseline[n] != observed[n])

    if redefined:
        findings.append(g.observed(
            "manifest_drift",
            f"{len(redefined)} tool(s) served by the running server were REDEFINED "
            f"relative to {baseline_label} — same name, different definition: "
            f"{', '.join(redefined)}. Any allow-list grant or reviewed "
            f"classification for these names now applies to a definition nobody "
            f"reviewed.",
            severity="HIGH",
            evidence={"redefined": [
                {"tool": n, "baseline_digest": baseline[n], "observed_digest": observed[n]}
                for n in redefined]},
        ))
    if added:
        findings.append(g.observed(
            "manifest_drift",
            f"The running server serves {len(added)} tool(s) absent from "
            f"{baseline_label}: {', '.join(added)}. The reviewed surface is not "
            f"the surface in use.",
            evidence={"added": [{"tool": n, "observed_digest": observed[n]} for n in added]},
        ))
    if removed:
        findings.append(g.observed(
            "manifest_drift",
            f"{len(removed)} tool(s) present in {baseline_label} are not served by "
            f"the running server: {', '.join(removed)}. Benign drift (a version "
            f"change) looks identical to a surface that hides tools from review.",
            evidence={"removed": [{"tool": n, "baseline_digest": baseline[n]} for n in removed]},
        ))
    return findings


def baseline_from_analysis(path: Path, server: str | None) -> dict:
    """Per-tool digests out of an analyze_mcp.py record."""
    with open(path) as fh:
        data = json.load(fh)
    tools = data.get("tools", []) if isinstance(data, dict) else []
    out = {}
    for t in tools:
        if not isinstance(t, dict):
            continue
        if server and t.get("server") and t["server"] != server:
            continue
        if t.get("name") and t.get("digest"):
            out[t["name"]] = t["digest"]
    return out


# ---------------------------------------------------------------------------
# Result / egress analysis
# ---------------------------------------------------------------------------

def result_text(resp: dict) -> str:
    """Flatten a tools/call response to searchable text. Errors count: a server
    can leak just as well through an error message as a result."""
    return A.canonical(resp)[:_MAX_RESULT]


def scan_results_for_injection(calls: list[dict], g: A.Guidance) -> list[dict]:
    """Run the tool-poisoning patterns over RETURN VALUES. The description-level
    scan cannot see this: the payload does not exist until the tool is called."""
    findings = []
    seen = set()
    for call in calls:
        hits = g.injection_hits(call["result_text"])
        # One finding per TOOL, not per call: the benign and probe calls of a
        # poisoned tool return the same payload, and reporting it twice inflates
        # the count without adding evidence.
        if not hits or call["tool"] in seen:
            continue
        seen.add(call["tool"])
        findings.append(g.observed(
            "injected_tool_result",
            f"The result of `{call['tool']}` carries hidden-instruction patterns — "
            f"directives aimed at the model rather than content for the user. "
            f"This is prompt injection delivered at call time; the tool's own "
            f"description stayed clean through review.",
            evidence={"tool": call["tool"], "probe": call["probe"], "signals": hits[:5]},
        ))
    return findings


def match_canaries(canaries: dict, calls: list[dict], sink_requests: list[dict],
                   stderr: str, declared_caps: set, g: A.Guidance) -> tuple[list[dict], set]:
    """Correlate planted canaries against everything that came back out.

    Returns (findings, observed_capabilities). A canary is ground truth, so these
    findings carry confidence=high with no baseline needed to interpret them.
    """
    findings: list[dict] = []
    observed_caps: set = set()

    egress_blobs = [
        {"where": f"{r['method']} {r['target']}",
         "text": " ".join([r["target"], A.canonical(r.get("headers", {})), r.get("body", "")])}
        for r in sink_requests
    ]

    for value, origin in sorted(canaries.items()):
        kind = origin.split(":", 1)[0]          # "env" | "file"
        label = origin.split(":", 1)[1]

        in_egress = [b for b in egress_blobs if value in b["text"]]
        in_results = [c for c in calls if value in c["result_text"]]
        in_stderr = value in stderr

        if kind == "env" and in_egress:
            observed_caps |= {"secrets_access", "network_egress"}
            findings.append(g.observed(
                "secret_in_egress",
                f"The canary planted in `{label}` was transmitted off-process in an "
                f"outbound request to {in_egress[0]['where']}. The server sent its "
                f"own credential to a host during a probed tool call — in a real "
                f"install that value is a live token.",
                severity="HIGH",
                evidence={"secret_key": label, "requests": [b["where"] for b in in_egress[:5]],
                          "canary": value},
            ))
        elif kind == "env" and (in_results or in_stderr):
            # It did not leave the process, but a tool that hands the server's
            # credential back to the model is exercising secrets_access it never
            # declared. Phase 3 generalizes divergence; this is the canary-backed
            # subset where the evidence is ground truth.
            observed_caps.add("secrets_access")
            if "secrets_access" not in declared_caps:
                findings.append(g.observed(
                    "capability_divergence",
                    f"The canary planted in `{label}` came back in "
                    f"{'a tool result' if in_results else 'the server log'} even though "
                    f"no tool declares a secrets capability. The server surfaces its own "
                    f"credential on a call that never advertised doing so.",
                    evidence={"secret_key": label,
                              "tools": sorted({c["tool"] for c in in_results})[:5],
                              "declared_capabilities": sorted(declared_caps)},
                ))

        if kind == "file" and (in_egress or in_results):
            observed_caps.add("file_read")
            where = "an outbound request" if in_egress else "a tool result"
            findings.append(g.observed(
                "undeclared_file_access",
                f"A probed call read the decoy credential file `{label}` — its canary "
                f"surfaced in {where}. Nothing in the tool surface asks for credential "
                f"files; this is the source half of an exfiltration chain, observed.",
                severity="HIGH" if in_egress else "MEDIUM",
                evidence={"decoy": label,
                          "tools": sorted({c["tool"] for c in in_results})[:5],
                          "requests": [b["where"] for b in in_egress[:5]],
                          "canary": value},
            ))
            if in_egress:
                observed_caps.add("network_egress")
                findings.append(g.observed(
                    "secret_in_egress",
                    f"The contents of the decoy credential file `{label}` were "
                    f"transmitted to {in_egress[0]['where']}. Read-then-send, recorded "
                    f"end to end in a single probed call.",
                    severity="HIGH",
                    evidence={"decoy": label, "requests": [b["where"] for b in in_egress[:5]]},
                ))

    return findings, observed_caps


def egress_findings(sink_requests: list[dict], declared_caps: set, g: A.Guidance) -> tuple[list[dict], set]:
    """Outbound calls, judged RELATIVE TO THE DECLARED BASELINE — a search server
    should make network calls. Only egress from a server that declared none is a
    finding on its own."""
    if not sink_requests:
        return [], set()
    observed = {"network_egress"}
    if "network_egress" in declared_caps:
        return [], observed
    targets = sorted({f"{r['method']} {r['target']}" for r in sink_requests})
    return [g.observed(
        "undeclared_network_egress",
        f"The server made {len(sink_requests)} outbound request(s) during probed "
        f"calls while no tool declares a network capability: {', '.join(targets[:5])}"
        + (" …" if len(targets) > 5 else "") + ".",
        evidence={"request_count": len(sink_requests), "targets": targets[:10],
                  "declared_capabilities": sorted(declared_caps)},
    )], observed


# ---------------------------------------------------------------------------
# Capture orchestration
# ---------------------------------------------------------------------------

def declared_capabilities(tools: list[dict], server: str | None, g: A.Guidance) -> set:
    """What the OBSERVED surface declares — the baseline divergence is measured
    against. Computed with the analyzer's own capability scan so declared and
    observed are the same vocabulary."""
    caps = set()
    for t in tools:
        for c in A.analyze_tool(t, server, g)["candidate_capabilities"]:
            caps.add(c["capability"])
    return caps


def run_capture(entry: dict, server: str, g: A.Guidance, *, probe: bool,
                relaunch: bool, baseline_path: Path | None, timeout: float,
                call_timeout: float, keep_home: bool) -> dict:
    command = entry.get("command")
    if not command:
        raise SessionError(
            f"server '{server}' has no command — it is a remote/url server. "
            f"Behavioral capture is stdio-only in this phase; there is no local "
            f"process to launch or observe.")

    home, file_canaries = seed_home(g)
    sink_cm = Sink() if probe else None
    findings: list[dict] = []
    calls: list[dict] = []
    observed_caps: set = set()
    warnings: list[str] = []

    try:
        with (sink_cm or _NullContext()) as sink:
            sink_url = sink.base_url if probe else None
            env, env_canaries = build_child_env(entry.get("env") or {}, home, g, sink_url)
            canaries = {**file_canaries, **env_canaries}
            args = list(entry.get("args") or [])

            # --- launch 1: the surface the server actually serves -----------
            with MCPSession(command, args, env, timeout=timeout) as session:
                server_info = session.initialize()
                tools = session.list_tools()
                tools_digest, per_tool = digest_tools(tools)
                declared = declared_capabilities(tools, server, g)

                probe_plan = {}
                if probe:
                    decoy = str(home / (g.probe.get("decoy_files") or [".env"])[0])
                    for tool in tools:
                        name = tool.get("name") or ""
                        if not name:
                            continue
                        schema = tool.get("inputSchema") or tool.get("input_schema") or {}
                        probe_plan[name] = {
                            "benign": probe_arguments(schema, g, decoy, sink_url, hostile=False),
                            "probe": probe_arguments(schema, g, decoy, sink_url, hostile=True),
                        }
                    for name, plan in probe_plan.items():
                        for kind in ("benign", "probe"):
                            try:
                                resp = session.call_tool(name, plan[kind], timeout=call_timeout)
                                calls.append({"tool": name, "probe": kind,
                                              "arguments": plan[kind],
                                              "result_text": result_text(resp)})
                            except SessionError as e:
                                warnings.append(f"call {name}[{kind}] failed: {e}")
                                calls.append({"tool": name, "probe": kind,
                                              "arguments": plan[kind],
                                              "result_text": "", "error": str(e)})
                    # Give a fire-and-forget egress path a moment to land.
                    time.sleep(0.5)
                stderr_text = session.stderr_text

            # --- launch 2 (optional): drift without a prior baseline --------
            second = None
            if relaunch:
                with MCPSession(command, args, env, timeout=timeout) as s2:
                    s2.initialize()
                    tools2 = s2.list_tools()
                    second_digest, second_per_tool = digest_tools(tools2)
                    second = {"tools_digest": second_digest, "per_tool_digests": second_per_tool}

            sink_requests = sink.requests if probe else []

        # --- drift ----------------------------------------------------------
        drift = {"checked": False, "against": None}
        if baseline_path:
            base = baseline_from_analysis(baseline_path, server)
            if base:
                drift = {"checked": True, "against": "reviewed baseline",
                         "baseline_tool_count": len(base), "observed_tool_count": len(per_tool)}
                findings += diff_manifest(base, per_tool, g)
            else:
                warnings.append(
                    f"--baseline {baseline_path} contains no tool digests for "
                    f"server '{server}' — drift not checked against it.")
        if second is not None:
            against = drift["against"]
            drift = {**drift, "checked": True, "relaunch_checked": True,
                     "against": f"{against} + relaunch" if against else "relaunch"}
            findings += diff_manifest(per_tool, second["per_tool_digests"], g,
                                      baseline_label="the first launch in this session")

        # --- behavior -------------------------------------------------------
        findings += scan_results_for_injection(calls, g)
        if probe:
            eg_findings, eg_caps = egress_findings(sink_requests, declared, g)
            findings += eg_findings
            observed_caps |= eg_caps
            can_findings, can_caps = match_canaries(
                canaries, calls, sink_requests, stderr_text, declared, g)
            findings += can_findings
            observed_caps |= can_caps

        session_digest = A.digest({
            "server_digest": A.analyze_server(server, entry, g)["digest"],
            "probe_set_digest": A.digest(probe_plan if probe else {}),
            "observed_tools_digest": tools_digest,
        })

        return {
            "schema": BEHAVIORAL_SCHEMA,
            "captured": True,
            "mechanism": "stdio_proxy+probe" if probe else "stdio_proxy",
            "server": server,
            "server_info": server_info.get("serverInfo"),
            "session_digest": session_digest,
            "tools_observed": sorted(per_tool),
            "observed_tools_digest": tools_digest,
            "per_tool_digests": per_tool,
            "declared_capabilities": sorted(declared),
            "observed_capabilities": sorted(observed_caps),
            "drift": drift,
            "side_effects": {
                "outbound_requests": [
                    {"method": r["method"], "target": r["target"],
                     "body_bytes": len(r.get("body", ""))} for r in sink_requests
                ],
                "tool_calls": [{"tool": c["tool"], "probe": c["probe"],
                                "error": c.get("error")} for c in calls],
            },
            "coverage": coverage_block(tools, calls, probe, relaunch, bool(baseline_path),
                                       sink_requests, warnings,
                                       env_passed_through=sorted(
                                           k for k, v in (entry.get("env") or {}).items()
                                           if not withhold_value(k, v, g))),
            "findings": findings,
        }
    finally:
        if keep_home:
            print(f"Probe HOME retained: {home}", file=sys.stderr)
        else:
            shutil.rmtree(home, ignore_errors=True)


class _NullContext:
    def __enter__(self):
        return None

    def __exit__(self, *exc):
        return False


def coverage_block(tools, calls, probe, relaunch, had_baseline, sink_requests, warnings,
                   env_passed_through=()) -> dict:
    """What was and was NOT exercised. A probe only observes the code paths it
    triggers, so this block is what stops "no behavioral finding" being read as
    "clean" — the same scoping SAFE already carries in the verdict rubric."""
    called = {c["tool"] for c in calls}
    limits = [
        "A probe observes only the code paths its inputs trigger. Behavior gated "
        "on a specific input, date, or call count stays dormant and undetected.",
    ]
    if not probe:
        limits.append(
            "Probe mode was OFF: no tool was called. Only the served tool surface "
            "and its digests were observed — no file, network, or execution side "
            "effect was exercised.")
    else:
        limits.append(
            "Egress is observed only from clients that honor HTTP_PROXY/HTTPS_PROXY "
            "or that were handed the sink URL as a parameter. A server using a raw "
            "socket, DNS, or an ignored proxy setting egresses unobserved until the "
            "OS-sandbox phase.")
        limits.append(
            "HTTPS tunnels (CONNECT) are refused, not decrypted: the destination "
            "host is recorded but the request body is not observable.")
        limits.append(
            "File reads are detected only when decoy canary CONTENT comes back in a "
            "result or an outbound request. A read whose contents are kept internal "
            "is invisible without syscall/sandbox tracing.")
    if not had_baseline and not relaunch:
        limits.append(
            "No baseline and no --relaunch: manifest drift was NOT checked. The "
            "captured surface is a snapshot with nothing to compare it against.")
    if env_passed_through:
        limits.append(
            "These declared env values were passed to the child verbatim because "
            "neither their key name nor their value looked credential-shaped: "
            + ", ".join(env_passed_through)
            + ". Confirm none of them is sensitive.")
    return {
        "tools_served": len(tools),
        "env_passed_through": list(env_passed_through),
        "tools_called": sorted(called),
        "tools_not_called": sorted({t.get("name", "") for t in tools} - called - {""}),
        "calls_made": len(calls),
        "probe_mode": probe,
        "drift_checked": had_baseline or relaunch,
        "outbound_requests_seen": len(sink_requests),
        "absence_of_findings_is_not_proof": True,
        "limitations": limits,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Plan (the ungated default) + main
# ---------------------------------------------------------------------------

def print_plan(server: str, entry: dict, g: A.Guidance, probe: bool, relaunch: bool):
    command = entry.get("command")
    args = A.mask_args(entry.get("args") or [])
    sensitive = [k for k in (entry.get("env") or {}) if g.is_sensitive_key(k)]
    print(f"Behavioral capture plan — server '{server}' (NOTHING HAS RUN)\n")
    if not command:
        print("  REFUSED: remote/url server — no local process to launch.\n"
              "  Behavioral capture is stdio-only in this phase.")
        return
    print(f"  Would launch : {command} {' '.join(map(str, args))}")
    print(f"  Launches     : {2 if relaunch else 1}"
          f"{'  (second launch diffed against the first)' if relaunch else ''}")
    print(f"  Mode         : {'stdio capture + canary probe' if probe else 'stdio capture only'}")
    print("  Environment  : SCRUBBED — os.environ is NOT passed through.")
    if sensitive:
        print(f"                 credential-shaped keys seeded with canaries, "
              f"never real values: {', '.join(sensitive)}")
    print(f"  HOME         : throwaway temp dir seeded with decoy credential files "
          f"({len(g.probe.get('decoy_files', []))} decoys)")
    if probe:
        print("  Probing      : every served tool called twice (benign, then probe "
              "inputs). Egress routed to a local recording sink that never "
              "forwards a request onward.")
        print("  WARNING      : this EXECUTES the server's tool handlers. Only run it "
              "on a host you can afford to have run untrusted code.")
    print("\n  Re-run with --run to execute this plan.")


def main():
    ap = argparse.ArgumentParser(
        description="Behavioral (basis=observed) capture for /scrutineer-mcp. "
                    "Launches an MCP server behind a recording harness. "
                    "Requires --run; prints an inspectable plan otherwise.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--config", required=True, help="MCP client config JSON")
    ap.add_argument("--server", required=True, help="Server name within the config")
    ap.add_argument("--run", action="store_true",
                    help="Actually launch the server. Without this, print the plan and exit.")
    ap.add_argument("--probe", action="store_true",
                    help="Phase 2: call every tool with benign then probe inputs, with "
                         "canary env/decoy files and a recording egress sink.")
    ap.add_argument("--relaunch", action="store_true",
                    help="Launch twice and diff the two surfaces — catches drift with "
                         "no prior baseline.")
    ap.add_argument("--baseline", help="analyze_mcp.py record whose per-tool digests the "
                                       "observed surface is diffed against")
    ap.add_argument("--out", help="Write the behavioral record here (default: stdout)")
    ap.add_argument("--timeout", type=float, default=30.0, help="Handshake/list timeout (s)")
    ap.add_argument("--call-timeout", type=float, default=15.0, help="Per tools/call timeout (s)")
    ap.add_argument("--keep-home", action="store_true",
                    help="Keep the throwaway HOME for inspection instead of deleting it")
    ap.add_argument("--guidance", help="Override path to mcp_risk_guidance.yaml")
    ap.add_argument("--indent", type=int, default=2)
    args = ap.parse_args()

    gpath = Path(args.guidance) if args.guidance else Path(__file__).parent / "mcp_risk_guidance.yaml"
    if not gpath.exists():
        print(f"Error: guidance file not found: {gpath}", file=sys.stderr)
        sys.exit(1)
    g = A.Guidance(gpath)

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"Error: config not found: {cfg_path}", file=sys.stderr)
        sys.exit(1)
    try:
        cfg = json.loads(cfg_path.read_text())
    except json.JSONDecodeError as e:
        print(f"Error: config is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    servers = A.find_server_map(cfg)
    if args.server not in servers:
        print(f"Error: server '{args.server}' not found in {cfg_path}. "
              f"Available: {', '.join(sorted(servers)) or '(none)'}", file=sys.stderr)
        sys.exit(1)
    entry = servers[args.server]

    if not args.run:
        print_plan(args.server, entry, g, args.probe, args.relaunch)
        sys.exit(0)

    baseline_path = Path(args.baseline) if args.baseline else None
    if baseline_path and not baseline_path.exists():
        print(f"Error: baseline not found: {baseline_path}", file=sys.stderr)
        sys.exit(1)

    try:
        record = run_capture(
            entry, args.server, g,
            probe=args.probe, relaunch=args.relaunch, baseline_path=baseline_path,
            timeout=args.timeout, call_timeout=args.call_timeout, keep_home=args.keep_home,
        )
    except SessionError as e:
        # A capture that could not run is not a clean server. Emit an explicit
        # uncaptured record so a downstream report can never mistake the failure
        # for an absence of findings.
        record = {
            "schema": BEHAVIORAL_SCHEMA, "captured": False, "server": args.server,
            "error": str(e),
            "coverage": {"absence_of_findings_is_not_proof": True,
                         "limitations": [f"Behavioral capture did not run: {e}"]},
            "findings": [],
        }
        print(f"Behavioral capture failed: {e}", file=sys.stderr)

    text = json.dumps(record, indent=args.indent)
    if args.out:
        Path(args.out).write_text(text)
        print(f"Behavioral record -> {args.out} "
              f"({len(record.get('findings', []))} finding(s))", file=sys.stderr)
    else:
        print(text)
    sys.exit(0 if record.get("captured") else 2)


if __name__ == "__main__":
    main()
