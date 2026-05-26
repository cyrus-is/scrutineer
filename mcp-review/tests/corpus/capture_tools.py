#!/usr/bin/env python3
"""Minimal MCP stdio client used to build the eval corpus.

Launches one MCP server from a client-config entry, performs the stdio
JSON-RPC handshake (initialize -> notifications/initialized -> tools/list),
writes the captured tools array to a file, then terminates the server.

This is a *capture* tool for assembling fixtures — it is NOT part of the
/scrutineer-mcp audit (which never launches a server). Only run it against
servers you trust. Placeholder values are injected for any declared env var
that is unset, so servers that demand a credential to boot will still start
far enough to answer tools/list (which does not require real auth).

Usage:
  python3 capture_tools.py --config top/config.json --server github --out top/tools/github.json
"""
import argparse
import json
import os
import queue
import subprocess
import sys
import threading
import time

PROTOCOL_VERSION = "2025-06-18"


def _drain(pipe, q):
    try:
        for line in iter(pipe.readline, ""):
            q.put(line)
    finally:
        q.put(None)


def _send(proc, msg):
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()


def _await(q, want_id, deadline):
    """Read newline-delimited JSON until a response with id==want_id arrives."""
    while time.time() < deadline:
        try:
            line = q.get(timeout=0.25)
        except queue.Empty:
            continue
        if line is None:
            return None, "server closed stdout"
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue  # server log noise on stdout
        if isinstance(msg, dict) and msg.get("id") == want_id:
            return msg, None
    return None, f"timeout waiting for id={want_id}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--server", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=float, default=90.0)
    args = ap.parse_args()

    cfg = json.load(open(args.config))
    servers = cfg.get("mcpServers") or cfg.get("servers") or {}
    if args.server not in servers:
        sys.exit(f"server '{args.server}' not in config")
    entry = servers[args.server]

    command = entry.get("command")
    cmd_args = entry.get("args", [])
    if not command:
        sys.exit(f"server '{args.server}' has no command (remote/url server — skip)")

    env = dict(os.environ)
    # Inject placeholders for declared-but-unset env so boot-time checks pass.
    for k, v in (entry.get("env") or {}).items():
        if not os.environ.get(k):
            env[k] = "placeholder-not-a-real-credential" if not v or v.startswith("$") else v

    full = [command] + cmd_args
    sys.stderr.write(f"[{args.server}] launching: {' '.join(full)}\n")
    try:
        proc = subprocess.Popen(
            full, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=env, text=True, bufsize=1,
        )
    except FileNotFoundError as e:
        _fail(args, f"launch failed: {e}")
        return

    q = queue.Queue()
    threading.Thread(target=_drain, args=(proc.stdout, q), daemon=True).start()
    deadline = time.time() + args.timeout

    try:
        _send(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "scrutineer-corpus-capture", "version": "0"},
            },
        })
        init, err = _await(q, 1, deadline)
        if err:
            _fail(args, f"initialize: {err}")
            return
        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        resp, err = _await(q, 2, deadline)
        if err:
            _fail(args, f"tools/list: {err}")
            return
        tools = (resp.get("result") or {}).get("tools", [])
        out = {
            "server": args.server,
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "protocolVersion": (init.get("result") or {}).get("protocolVersion"),
            "serverInfo": (init.get("result") or {}).get("serverInfo"),
            "tools": tools,
        }
        with open(args.out, "w") as f:
            json.dump(out, f, indent=2)
        sys.stderr.write(f"[{args.server}] captured {len(tools)} tools -> {args.out}\n")
        print(f"OK {args.server} {len(tools)} tools")
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


def _fail(args, msg):
    with open(args.out, "w") as f:
        json.dump({"server": args.server, "error": msg, "tools": []}, f, indent=2)
    sys.stderr.write(f"[{args.server}] FAILED: {msg}\n")
    print(f"FAIL {args.server} {msg}")


if __name__ == "__main__":
    main()
