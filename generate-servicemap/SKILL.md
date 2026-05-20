---
name: generateservicemap
description: >
  Deep agentic crawl of a code repository to produce a machine-readable servicemap.json that maps every service,
  app, library, data store, external dependency, infrastructure resource, CI/CD pipeline, and inter-service
  communication path — including authentication, authorization, public/private endpoints, and confidence scores.
  Use this skill whenever the user says /generateservicemap, asks to "map a repo", "build a service map",
  "generate a service topology", "trace service dependencies", "map infrastructure", or any variation of
  "understand how this codebase fits together." Also trigger when the user asks to update or enrich an
  existing servicemap.json. This skill is designed for DEEP crawls — it does not support shallow or partial
  mapping. The output is JSON optimized for machine consumption by other Claude skills and agents, not for
  direct human reading.
---

# /generateservicemap

Generate a comprehensive, machine-readable `servicemap.json` from a repository by performing a deep, phased
agentic crawl. The map captures services, apps, libraries, infrastructure, data stores, external dependencies,
inter-service communication, security posture, observability surface, and ownership — with confidence scores
on every discovery.

## Invocation

```
/generateservicemap --path <output-path>
```

- `--path` (optional): Where to write the output file. Defaults to `./servicemap.json` in the current
  working directory. Use a specific path to control where the map lands (e.g.,
  `/generateservicemap --path tools/servicemap.json`).

## Before You Start

1. **Locate the schema**: Look for `references/schema.md` relative to the directory where `servicemap.json`
   will be written (i.e., sibling `references/` folder next to the output path). For example:
   - Output path `tools/servicemap.json` → read `references/schema.md`
   - Output path `./servicemap.json` → read `./references/schema.md`

   Read the schema to internalize the full JSON structure. Every field matters — the schema is
   the contract that downstream skills and apps depend on.
2. Check if a `servicemap.json` already exists at the target path. If it does, this is an **incremental
   update** — read the Incremental Update Strategy section below.

## Crawl Philosophy

This is a DEEP crawl. The goal is to trace every meaningful connection, not to produce a quick summary.
The reason depth matters is that this map will be consumed by other Claude instances and automated tooling
that need to reason about blast radius, security boundaries, deployment dependencies, and operational
risk. A shallow map that misses a database connection or an unauthenticated endpoint is worse than no map,
because it creates false confidence.

That said, depth must be managed against context constraints. The phased approach below is how you do that.

## Phase 1: Discovery — Identify All Components

**Goal**: Build a manifest of every discrete component in the repo without deep-diving any of them yet.

Scan the repository structure to identify:

- **Services**: Anything that runs independently. Heuristics: has its own Dockerfile, has a `package.json`
  / `go.mod` / `Cargo.toml` / `pyproject.toml` / `build.gradle` / `pom.xml` / `*.csproj` / `*.sln`
  with an entrypoint, has its own Terraform module that provisions compute (ECS, Lambda, EC2, Cloud Run,
  App Service, etc.), or has its own Kubernetes Deployment manifest.
- **Apps**: Frontend applications, mobile apps, CLI tools. Distinguished from services by being
  user-facing rather than API-facing.
- **Libraries**: Shared internal packages without their own entrypoint. Look for workspace members,
  internal package references, monorepo package directories.
- **Infrastructure**: Terraform/OpenTofu/Pulumi/CloudFormation directories. Each module or stack is a
  component.
- **CI/CD Pipelines**: GitHub Actions workflows, GitLab CI, CircleCI, Jenkins, etc. Scan ALL
  workflow files, not just the obvious ones — repos often have 10-20+ workflows for linting,
  security scanning, ephemeral environments, dependency updates, etc.
- **Data stores**: Database migration directories, schema files, seed data.
- **Utility containers**: Dockerfiles that don't fit the service/app pattern — migration runners,
  reverse proxies, setup/initialization containers, database seed tools, static file servers.
  Check `util/`, `tools/`, `scripts/`, `deploy/` directories and CI build matrices for Docker
  images that are built and shipped but aren't traditional services. These are components too.

For each component discovered, record:
- `name`, `type`, `path` (relative to repo root), `language`, `framework`, `platform`
- `confidence`: How certain you are this is correctly classified (0.0–1.0)
- `discovery_method`: What heuristic identified it (e.g., "Dockerfile present", "Kubernetes Deployment manifest")

Write the Phase 1 manifest to memory before proceeding. This is your roadmap for subsequent phases.

### Phase 1b: Fallback Discovery — Unknown or Sparse Stacks

If Phase 1 discovers fewer components than the repository structure suggests (e.g., a large repo with
many directories but only 1-2 matched heuristics), or the repo uses a stack not covered by the
heuristics above, run a fallback discovery pass:

1. **Scan for generic service signals**:
   - Entrypoint files: `main.*`, `app.*`, `server.*`, `Program.cs`, `Startup.cs`, `index.*`
   - Build system files not already matched: `Makefile`, `CMakeLists.txt`, `*.csproj`, `*.sln`,
     `*.fsproj`, `mix.exs`, `build.zig`, `dune-project`, `*.cabal`, `stack.yaml`
   - Port exposure: `EXPOSE` in any Dockerfile, `ports:` in docker-compose, `listen` calls in source
   - HTTP handler patterns: any file registering routes, handlers, or controllers
   - Database connection patterns: connection strings, ORM config, migration directories

2. **Reason from directory structure**: If a subdirectory has its own build file, its own entrypoint,
   and its own source tree — it's likely a component even if you don't recognize the stack. Classify
   it with lower confidence (0.4–0.6) and note the discovery method as "inferred from project
   structure."

3. **Flag unknown stacks**: For any component discovered via fallback, add a note in the component's
   `discovery_method` field:
   ```
   "discovery_method": "Fallback: .csproj with Program.cs entrypoint — stack not in primary heuristics"
   ```
   This helps downstream consumers know where the map is less certain.

4. **Self-heal suggestion**: At the end of the crawl, if fallback discovery found components, include
   a message to the user:
   ```
   ⚠️ ENRICHMENT AVAILABLE: N components were discovered via fallback heuristics rather than
   primary detection. Consider adding explicit heuristics for [stack] to improve future crawl
   accuracy. Affected components: [list]
   ```

## Phase 2: Deep Dive — Analyze Each Component

**Goal**: For each component from Phase 1, extract detailed metadata.

Work through components one at a time (or in small batches if they're lightweight). For each:

### Services and Apps

- **Endpoints**: Trace route definitions by **reading the actual route attributes and registrations
  in the source code**. Do NOT guess or infer route prefixes — read them. Common patterns:
  - Express/Koa/Hono: `app.get('/path', ...)`, `router.post('/path', ...)`
  - FastAPI/Flask/Django: `@app.get("/path")`, `urlpatterns`, `@api_view`
  - Spring: `@RequestMapping("/path")`, `@GetMapping`, `@PostMapping`
  - Go chi/mux/gin: `r.Get("/path", ...)`, `r.Route("/path", ...)`
  - Rails: `routes.rb` — `resources`, `get`, `post`
  - ASP.NET: `[Route("path")]`, `[ApiController]`, `[HttpGet]`, `[HttpPost]` — note that
    the `[Route]` attribute on the controller IS the prefix, do not add `/api/v1/` or other
    prefixes unless they are explicitly in the attribute. Also check `MapGet`/`MapPost` minimal
    APIs and `UseEndpoints` / `MapControllers` in `Program.cs`/`Startup.cs`.
  - Phoenix: `scope "/api"`, `get "/path"`, `resources "/path"`
  - For each endpoint: method, path (exactly as defined in code — include route constraints like
    `{id:int}` and path parameters like `{organizationId}`), whether it's public or private
    (behind auth middleware), authentication mechanism (JWT, API key, OAuth, session, mTLS, none),
    authorization requirements (roles, scopes, policies).
- **Dependencies — other services**: Trace HTTP client calls, gRPC stubs, SDK imports that point to
  other internal services. Look for base URLs, service names in env vars, Kubernetes service DNS names,
  `HttpClient` / `IHttpClientFactory` registrations (.NET), `Refit` interface definitions (.NET).
- **Dependencies — data stores**: Database connection strings/configs, ORM model definitions (Entity
  Framework `DbContext`, Dapper, ActiveRecord, SQLAlchemy, GORM, Prisma, etc.), cache client
  instantiation, object storage client usage, message queue producer/consumer setup. For .NET,
  check `appsettings.json` / `appsettings.*.json` for `ConnectionStrings` sections.
  - **Use the actual cloud service name for `engine` types.** Azure Blob Storage is
    `azure-blob-storage`, not `s3`. Azure Service Bus is `azure-service-bus`, not `sqs`.
    Cosmos DB is `cosmosdb`, not `mongodb`. Never map one cloud provider's service to another's
    equivalent. Secret stores (`vault-kv`, `aws-secrets-manager`, `azure-key-vault`,
    `google-secret-manager`) and container registries (`aws-ecr`, `azure-container-registry`,
    `google-artifact-registry`, `docker-hub`, `ghcr`) are first-class datastore engines — do not
    collapse them under `s3` or `redis`. See the schema for the full list of valid engine values.
- **Dependencies — external APIs**: Third-party SDK imports and API calls (Stripe, Twilio, SendGrid,
  Auth0, Datadog, PagerDuty, etc.). For .NET, check NuGet package references in `*.csproj` files.
- **Environment and config**: How config is loaded — env vars, config files (`appsettings.json`,
  `application.yml`, `.env`, `config.toml`, etc.), Vault references, AWS Secrets Manager,
  Kubernetes ConfigMaps/Secrets. Catalog every env var referenced.
- **Observability**: Health check endpoints, logging framework, tracing instrumentation (OpenTelemetry,
  Datadog APM, Jaeger, Zipkin), metrics endpoints, alerting rules.
- **Container config**: Dockerfile analysis — base image, exposed ports, build stages, runtime user.
  Docker Compose service definitions if present.

### Infrastructure

- **Terraform / IaC**: For each module, catalog:
  - Resources provisioned (with types: `aws_ecs_service`, `aws_rds_instance`, etc.)
  - Variables and their defaults
  - Outputs (these are the interface other modules/services consume)
  - Remote state references (how modules connect to each other)
  - Provider and backend configuration
  - Workspaces or environment parameterization
- **Kubernetes manifests**: Deployments, Services, Ingresses, NetworkPolicies, HPA, PDB, ServiceAccounts,
  RBAC roles. Map port relationships between Deployment containers and Service/Ingress definitions.

### CI/CD Pipelines

- Trigger conditions (push, PR, schedule, manual)
- Steps and their purposes
- Which services/apps they build, test, and deploy
- Environment targets (dev, staging, prod)
- Secret references
- Deployment strategy (rolling, blue-green, canary)

### Libraries

- What exports they provide
- Which services/apps import them
- Version pinning strategy

## Phase 3: Trace Connections

**Goal**: Build the relationship graph between all components.

This phase is where the map becomes genuinely valuable. Using the data from Phase 2:

1. **Service-to-service**: Match outbound HTTP/gRPC/queue calls in one service to inbound endpoint
   definitions in another. Record the protocol, whether it's sync or async, and the specific
   endpoints involved.
2. **Service-to-data-store**: Match database connection configs to Terraform/IaC resources that
   provision those stores. Flag shared databases (multiple services connecting to the same store).
3. **Service-to-external**: Catalog all third-party API dependencies.
4. **Infrastructure-to-service**: Map Terraform resources to the services they support (e.g.,
   `aws_ecs_service` → the service that runs on it).
5. **Pipeline-to-service**: Map CI/CD workflows to the services they deploy.
6. **Library-to-consumer**: Map internal library usage across all services. **Every library
   relationship must be represented in two places**: (a) the library component's `consumers`
   array AND (b) a corresponding entry in `connections[]` with `"type": "library"`. Do not
   list a consumer without creating the connection, or vice versa. Verify consistency.

For each connection:
- `source`, `target`, `type` (http, grpc, graphql, queue, database, library, infrastructure)
- `async`: boolean
- `protocol_details`: method, path, queue name, topic, etc.
- `auth_required`: what auth the connection uses
- `confidence`: how certain you are this connection exists

**Verify that every service listed in a datastore's `consumers` array actually connects to that
datastore.** Read the service's startup/config code to confirm — do not assume a service uses a
database just because a shared library provides database access. Only list services that directly
establish a connection.

## Phase 4: Assemble and Validate

**Goal**: Produce the final `servicemap.json`.

1. Assemble all phase outputs into the schema defined in `references/schema.md`.
2. **Validate completeness**: Every service discovered in Phase 1 should have a deep-dive entry from
   Phase 2 and connections from Phase 3. If any are missing, go back and fill them.
3. **Identify stubs**: Any service, data store, or dependency referenced but NOT found in this repo
   (and not already present from another repo in an existing map) gets a stub entry with
   `"stub": true` and a `"stub_reason"` explaining what's missing.
4. **Set `source_repo`** on every component discovered in this crawl to the current repo name.
5. **Set timestamps**: `last_crawled` on every component and `generated_at` on the root.
6. **Merge with existing map** if one exists at the target path (see Multi-Repo and Incremental
   Update Strategy below).
7. Write to the `--path` location.

## Multi-Repo and Incremental Update Strategy

The servicemap supports multiple repositories in a single map. Each component tracks which repo
it came from via `source_repo`. When an existing `servicemap.json` is found at the target path,
the crawler **adds to it** — it never deletes components from other repos.

### Core Principle: Never Delete Unless Explicitly Asked

Running the crawler against repo B does not touch repo A's components. Components are never
removed from the map automatically. They can only be:
- **Updated** (re-crawled from their source repo)
- **Marked stale** (not found in their own source repo during a re-crawl)
- **Explicitly deleted** by the user (e.g., `/generateservicemap --remove-repo my-old-repo`)

### When an existing servicemap.json is found:

1. Read and parse the existing map.
2. Check `schema_version` compatibility. If the major version differs, warn the user and offer to
   regenerate from scratch. If `repository` (singular, 1.0 format) exists, migrate to
   `repositories[]` array format.
3. Identify the current repo (from git remote or working directory name).
4. Crawl the current repo as normal (all four phases).
5. Merge strategy:
   - **Components from the current repo**: crawl wins for discovered data. New components are
     added. Components previously from this repo but not found in this crawl get marked
     `"stale": true` with `"stale_since": "<timestamp>"`. They are NOT removed.
   - **Components from other repos**: left completely untouched. Not updated, not marked stale,
     not removed. They belong to their source repo's crawl cycle.
   - **Manual overrides**: any field with `"manual_override": true` is preserved, not overwritten.
   - **Stub resolution**: if a component discovered in this crawl matches a stub (by ID or name),
     the stub is replaced with the full entry and `source_repo` is set to this repo.
   - **Connections**: connections where the `source` belongs to the current repo are rebuilt from
     the crawl. Connections where the `source` belongs to another repo are preserved. Cross-repo
     connections (source in one repo, target in another) are rebuilt if the source repo is being
     crawled.
6. Update `last_crawled` on all components from this repo.
7. Update the repo's entry in `repositories[]` (add it if this is the first crawl for this repo).
8. Recompute `metadata.repo_staleness` for all repos.

### Staleness reporting

The `metadata.repo_staleness` array shows how fresh each repo's data is, sorted stalest-first:

```json
"repo_staleness": [
  {"repo": "notification-service", "last_crawled": "2026-03-01T10:00:00Z", "components": 5, "age_days": 13},
  {"repo": "my-platform", "last_crawled": "2026-03-14T12:00:00Z", "components": 18, "age_days": 0}
]
```

After every crawl, report the staleness table to the user so they can see which repos need
a refresh. If any repo is more than 30 days stale, flag it:

```
⚠️ STALE REPOS: notification-service was last crawled 45 days ago (5 components).
   Consider re-running /generateservicemap from that repo to refresh.
```

### First-time crawl (no existing map)

If no `servicemap.json` exists at the target path, this is a fresh map. Create the
`repositories[]` array with a single entry for the current repo and proceed normally.

## Confidence Scoring Guide

Every discovery should include a confidence score. Use this calibration:

- **1.0**: Definitive evidence. A Dockerfile with an ENTRYPOINT, a Kubernetes Deployment manifest, an
  explicit route definition.
- **0.8–0.9**: Strong evidence. A database connection string in config pointing to a named resource,
  an import of another internal package.
- **0.5–0.7**: Inferential. An env var that looks like a service URL but isn't confirmed, a comment
  referencing another service, a TODO mentioning a dependency.
- **0.3–0.4**: Speculative. Naming conventions suggest a relationship, a file structure implies a
  service but no entrypoint found.
- **< 0.3**: Weak signal. Include only if it fills a gap that would otherwise be a stub.

## Output

The output is a single JSON file conforming to the schema in `references/schema.md`. The JSON should
be pretty-printed with 2-space indentation for version control friendliness, even though it's
machine-targeted.

After writing the file, report to the user:
- Total components discovered in this crawl (by type)
- Total connections traced
- Number of stubs remaining (unresolved cross-repo references)
- Stubs resolved in this crawl (if merging into existing map)
- Any components with confidence below 0.5 (these need human review)
- If incremental: what changed since last crawl of this repo
- **Repo staleness table**: for every repo in the map, show name, last crawled date, component
  count, and age in days. Flag any repo > 30 days stale.

## Context Management

Large repos will challenge context limits. Strategies:

- In Phase 1, use directory listings and file existence checks rather than reading file contents.
  You're just building the manifest.
- In Phase 2, process one component at a time. Read only the files relevant to that component,
  extract what you need, then move on. Don't try to hold the entire repo in context.
- In Phase 3, work from the structured data you already extracted in Phase 2, not from raw files.
  You should rarely need to re-read source files in this phase.
- If the repo is exceptionally large (50+ services), consider batching Phase 2 into groups of
  5–10 services, writing intermediate results to a temp file between batches.
