# Security Review Skill Generator

Scans a repository (and optionally a `servicemap.json`) to generate a tailored
`.claude/commands/vld8-security.md` with platform-specific vulnerability checklists.

> **Most users don't run this directly.** The top-level installer does it for you —
> `vld8 install <repo>` (or the `/vld8-setup` skill); see the
> [main README](../README.md). Run the generator directly when you want control over
> the output path, guidance file, or service-map wiring.

## Quick Start

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# Basic (file scanning only):
.venv/bin/python generate.py /path/to/repo

# With a service map (richer context, enables component audit mode). A servicemap.json
# at the repo root is auto-discovered; pass --service-map only for a non-standard path:
.venv/bin/python generate.py /path/to/repo --service-map servicemap.json

# Dry run:
.venv/bin/python generate.py /path/to/repo --dry-run
```

## What It Does

1. **Scans** the repo for languages, frameworks, and infrastructure
2. **Loads** platform-specific security checklists from `security_guidance.yaml` — each item names a specific vulnerable API/pattern and its secure alternative
3. **Optionally reads** `servicemap.json` to discover reviewable components, unauthenticated endpoints, and shared datastores
4. **Generates** a `/vld8-security` skill with four invocation modes:
   - `/vld8-security` — review current branch diff vs main
   - `/vld8-security 123` — review PR #123 (outputs to terminal, not auto-posted — security findings may be sensitive)
   - `/vld8-security <component-name>` — full security audit of a service/app directory (requires service map)
   - `/vld8-security --deep` — deep repo-wide audit tracing cross-service flows and attack chains
5. **Embeds self-healing** — flags unknown platforms and offers to enrich itself

## Service Map Integration

When `--service-map` is provided, the generated skill gets:
- **Component lookup table** for full audit mode (Mode 3)
- **Known unauthenticated endpoints** injected into the universal checklist — makes it easy to spot new unintended public endpoints
- **Shared datastore flags** — extra scrutiny on tenant scoping for multi-service databases

Generate a service map first: see `../generate-servicemap/`.

## Supported Platforms

**Backend:** Go, Python, Java, Node.js, Rust, C#, Ruby, PHP
**Web:** React/Next.js, Vue/Nuxt, Angular
**Mobile:** Android (Kotlin), React Native, Flutter
**Apple:** Swift (storage, crypto, logging), SwiftUI, CloudKit, Foundation Models, SwiftPM,
Apple app target, macOS app

OWASP references use the Mobile Top 10 **2024** list, paired with a MASVS control where one applies.
The nine original iOS checks are unchanged — they were never the problem — and are redistributed to
the block that owns the surface each describes.
**Infra:** Terraform, Kubernetes, Docker
**CI/CD:** GitHub Actions, GitLab CI
**API:** OpenAPI/REST, GraphQL, gRPC
**Database:** SQL (general), MongoDB
**Auth:** JWT, OAuth 2.0

## Customizing

Edit `security_guidance.yaml` to add new platforms or checklist items. Each entry needs:
- `detect_files`: glob patterns to identify the platform
- `detect_content`: regex patterns to confirm (for content-only detection like JWT)
- `checklist`: specific, actionable security items — not generic advice

## Options

```
--output, -o        Output path (default: .claude/commands/vld8-security.md)
--service-map, -s   Path to servicemap.json for richer context
--guidance, -g      Custom guidance YAML path
--dry-run, -n       Preview without writing
--force, -f         Overwrite without prompting
```
