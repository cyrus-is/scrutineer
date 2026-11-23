# generate-servicemap

A Claude Code skill that performs a deep, phased crawl of a repository and produces a machine-readable `servicemap.json` — mapping every service, app, library, data store, external dependency, infrastructure resource, CI/CD pipeline, and inter-service connection.

> **Most users don't copy this manually.** The top-level installer places the skill for you —
> `vld8 install <repo>`, or the `/vld8-setup` skill which also runs the crawl; see the
> [main README](../README.md). The setup below is for installing the skill by hand. The default
> output is `./servicemap.json` with `./references/schema.md` alongside; the `tools/` paths below are
> just an example of pointing `--path` elsewhere.

## Setup

1. Copy `SKILL.md` into your repo's `.claude/commands/` directory (rename to `vld8-map.md`)
2. Place `references/schema.md` as a sibling `references/` folder next to where you want the output:

```
your-repo/
├── .claude/commands/
│   └── vld8-map.md              ← copy of SKILL.md
├── tools/
│   ├── references/
│   │   └── schema.md            ← schema reference
│   └── servicemap.json          ← generated output (after running)
```

The schema must be at `references/schema.md` relative to the output directory. The skill looks for it there automatically.

## Usage

From Claude Code in your repo:

```
# Default: writes to ./servicemap.json, looks for ./references/schema.md
/vld8-map

# Specify output path: writes to tools/servicemap.json, looks for tools/references/schema.md
/vld8-map --path tools/servicemap.json
```

## What it produces

A `servicemap.json` (schema v1.0.0) containing:

- **Components**: services, apps, libraries, infrastructure modules, CI/CD pipelines, data stores, external dependencies — each with language, framework, endpoints, auth/authz detail, env vars, container config, observability surface, and confidence scores
- **Connections**: every inter-component relationship (HTTP, gRPC, database, queue, pub/sub, etc.) with protocol details, auth requirements, and confidence
- **Metadata**: summary statistics, shared datastores, unauthenticated endpoints, unmonitored services, low-confidence detections

## Downstream consumers

The service map is consumed by both review generators at generate time, and by the generated skills at review time:
- **generate-peer-review** — lists the reviewable components (name, type, path, language) for Mode 3, uses connection counts to name the most-connected components for Mode 4, and partitions oversized diffs along component boundaries
- **generate-security-review** — lists the reviewable components, and adds the map's unauthenticated public endpoints and shared datastores to the universal checklist
- **The generated skills** — tell the reviewer to read `servicemap.json` for cross-service flows in Modes 3 and 4

Platform detection does not use the map; both generators detect platforms from the repo's files.

## Validation

After generating, validate the output:

```bash
python3 validate_servicemap.py path/to/servicemap.json
```

## Incremental updates

Re-running the skill with an existing `servicemap.json` at the target path triggers an incremental update:
- New components are added
- Existing components are re-crawled and updated
- Components not found in the latest crawl are marked `stale` (not deleted)
- Fields with `manual_override: true` are preserved
