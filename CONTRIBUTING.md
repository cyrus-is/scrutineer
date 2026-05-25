# Contributing to Scrutineer

Contributions are welcome! All PRs require approval before merging.

## What to contribute

The highest-impact contributions are additions to the guidance YAML files:

- **New platforms** — Add detection rules, pre-flight checks, and focus areas for languages/frameworks not yet covered
- **New checks** — Add vulnerability patterns, review focus areas, or change-type signals for existing platforms
- **Improved patterns** — Refine detection regexes, fix false positives, or improve severity calibrations

### Adding a new platform

**Peer review** (`generate-peer-review/peer_review_guidance.yaml`):

```yaml
your_platform:
  name: "Your Platform"
  detect_files: ["*.ext", "config_file"]
  detect_content: ["^import your_platform"]
  preflight_checks:
    - id: your-platform-common-bug
      title: "Description of the check"
      pattern: "What to look for"
      failure_mode: "What goes wrong"
      fix: "How to fix it"
      lens: correctness  # one of the 8 lenses
      severity: issue     # issue, concern, or pass
  focus_areas:
    - area: "Area name"
      description: "What to focus on and why"
      lens: production-reliability
  change_type_signals:
    - type: "database-migration"
      patterns: ["migrations/", "*.sql"]
```

**Security review** (`generate-security-review/security_guidance.yaml`):

```yaml
your_platform:
  name: "Your Platform"
  detect_files: ["*.ext", "config_file"]
  checklist:
    - id: your-platform-vuln
      title: "Vulnerability name"
      pattern: "What the vulnerable code looks like"
      secure_alternative: "What to do instead"
      owasp: "A01:2021 Broken Access Control"
      severity_if_found: HIGH  # CRITICAL, HIGH, MEDIUM, LOW
```

Both generators self-heal — if they detect an unknown platform in a repo, they'll flag it. If you see that happen, consider contributing the platform.

### Service map schema

The service map schema is documented in `references/schema.md`. If you're proposing schema changes, update both the reference doc and `generate-servicemap/validate_servicemap.py`.

## How to submit

1. Fork the repo
2. Create a branch (`git checkout -b add-scala-platform`)
3. Make your changes
4. Test by running the generator against a repo that uses the platform you're adding
5. Open a PR with a description of what you added and why

## Code style

- YAML: 2-space indent, quoted strings for patterns and descriptions
- Python: Follow existing style, no additional dependencies without discussion
- Keep check descriptions actionable — "what to look for" not "this might be bad"

## Questions?

Open an issue.
