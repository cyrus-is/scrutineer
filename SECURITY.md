# Security Policy

Scrutineer is a security tool, so its own disclosure process is held to the same bar.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately via GitHub's **[Report a vulnerability](https://github.com/cyrus-is/scrutineer/security/advisories/new)** (the repo's Security tab → Advisories). That opens a private channel with the maintainer.

You'll get an acknowledgement within a few days — best effort; this is solo-maintained OSS. If a fix is warranted we'll coordinate a private patch and a disclosure timeline, and credit you in the advisory unless you'd prefer to stay anonymous.

## What's in scope

Scrutineer is a **static** analyzer: by design it never starts an MCP server, calls a tool, executes fetched code, or runs a package manager. The highest-value areas to probe:

- **`mcp-review/fetch_source.py`** — the source-acquisition step. Its extractor must reject zip-slip (`../`), symlinks, hardlinks, absolute paths, and special files, and must never execute a fetched lifecycle/`postinstall` script. (Guarded by `mcp-review/tests/test_fetch_source.py`.)
- **Secret handling** — the analyzer must never echo a live secret value into its output or its digests. A credential leaking through a report is in scope.
- **Analyzer evasion (false negatives)** — a crafted config or `tools/list` that gets a real risk (an exfil chain, tool poisoning, code execution) reported as `SAFE`. These are in scope; routine false *positives* are best filed as normal issues.

## Supported versions

The latest release on PyPI is supported. Please `pip install -U scrutineer` before reporting.
