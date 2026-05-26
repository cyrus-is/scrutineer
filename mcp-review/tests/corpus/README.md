# MCP audit eval corpus

A dogfooding / regression corpus for `/scrutineer-mcp`: real top MCP servers and
reconstructed known-bad cases, with captured evidence and synthesized verdicts.
Built 2026-05-25. The narrative writeup is **[REVIEW.md](REVIEW.md)**.

This is distinct from `mcp-review/tests/fixtures/` (the analyzer's hand-built unit
fixtures). This corpus is *empirical* — the tool surfaces in `top/tools/` were
captured live from the actual published packages.

## Layout

```
corpus/
  REVIEW.md                 # the review — read this
  capture_tools.py          # minimal MCP stdio client: initialize -> tools/list -> dump
  capture_all.sh            # run capture across every server in top/config.json
  run_analysis.sh           # run analyze_mcp.py over both corpora -> analysis/
  # (validate_findings.py, in mcp-review/, runs the Pass-4 agentic FP sweep over an analysis)
  top/
    config.json             # 22 servers, documented unpinned install specs
    tools/<server>.json     # live-captured tools/list (serverInfo records the version seen)
    analysis/<server>.json  # analyze_mcp.py output (Pass 1 + Pass 2)
    expected_verdicts.json  # synthesized verdicts + human corrections (regression baseline)
  known-bad/
    config.json             # 6 reconstructed malicious/vulnerable cases (FAKE endpoints)
    tools/<server>.json     # crafted malicious tool surfaces (3 of 6)
    source/                 # illustrative source snippets for the 2 source-level cases
    analysis/<server>.json
    expected_verdicts.json  # the detection scorecard
```

## Known-bad provenance

Each known-bad entry reconstructs a documented, public incident, and every entry
is **defanged** so it can't hurt anyone who pulls the repo and tinkers: package
names are non-existent placeholders (`…-EXAMPLE-do-not-install`) so a runner can't
fetch real or squatted code; all hosts use the non-routable `.invalid` TLD
(RFC 2606); and the `source/` snippets are stubbed (no `exec`, no send). The
defanging is **safety-only** — the malicious *signal* (poisoned descriptions, the
backdoor line, the exfil pairing) is left intact on purpose, and each fixture
carries a "pretend this is valid for test purposes" note so the detector still
fires and a reviewer can still find it. Do **not** launch them.

| Fixture | Maps to | Layer |
|---------|---------|-------|
| `postmark-mcp` | Koi Security, Sept 2025 — trojaned npm, v1.0.16 BCC'd every email to an attacker address | source |
| `mcp-remote-untrusted` | CVE-2025-6514 (CVSS 9.6) — OS command injection via malicious OAuth `authorization_endpoint` in mcp-remote 0.0.5–0.1.15 | source / transport |
| `calc-poisoned` | Invariant Labs tool-poisoning, Apr 2025 — hidden instructions in a tool description | tool metadata |
| `weather-exfil` | read-then-send exfil chain (broad file read + steered egress) | tool metadata / combination |
| `cryptoprice-installer` | shell-wrapper install (`curl \| sh`) | config |
| `datatool-remote` | credentials embedded in a cleartext `http://` SSE URL | config / transport |

## Caveats

- `top/config.json` uses unpinned specs on purpose (it mirrors what READMEs publish).
  Live-captured surfaces in `top/tools/` therefore drift as packages update; the
  version actually captured is recorded in each file's `serverInfo`.
- `stripe` is intentionally present though it failed to boot without a real key —
  see REVIEW.md (the "no surface => MINIMAL" under-rating finding).
- `capture_*` require `node`/`npx` and `uv`/`uvx`; `run_analysis.sh` is offline and
  only needs `python3` + `pyyaml`.

## Regenerate

```bash
bash capture_all.sh && bash run_analysis.sh
```
