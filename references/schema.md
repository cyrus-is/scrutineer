# servicemap.json Schema Reference

**Schema Version**: 1.1.0

This document defines the complete schema for `servicemap.json`. Downstream skills and applications
can depend on this structure. Fields marked **(required)** must always be present. Fields marked
**(optional)** may be omitted. Fields marked **(stub-safe)** are the minimum required for stub entries.

## Root Object

```json
{
  "schema_version": "1.1.0",
  "generated_at": "2026-03-14T12:00:00Z",
  "repositories": [ ],
  "components": [ ],
  "connections": [ ],
  "metadata": { }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | yes | Semver version of this schema. Consumers should check major version for compatibility. |
| `generated_at` | string (ISO 8601) | yes | Timestamp of when this map was last generated or updated. |
| `repositories` | array | yes | All source repositories that have contributed to this map. (Replaces singular `repository` from 1.0.) |
| `components` | array | yes | All discovered components (services, apps, libraries, infra, pipelines, data stores, external). |
| `connections` | array | yes | All traced relationships between components. |
| `metadata` | object | yes | Crawl metadata and summary statistics. |

**Migration from 1.0**: If `repository` (singular object) is present instead of `repositories` (array),
wrap it in an array: `"repositories": [<old repository object>]`.

---

## repositories[]

Each entry represents a source repository that has been crawled into this map.

```json
{
  "name": "my-platform",
  "url": "https://github.com/org/my-platform",
  "default_branch": "main",
  "monorepo": true,
  "description": "Primary platform monorepo",
  "last_crawled": "2026-03-14T12:00:00Z"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Repository name. Used as the value for `source_repo` on components. |
| `url` | string | optional | Remote URL if discoverable from git config. |
| `default_branch` | string | optional | Default branch name. |
| `monorepo` | boolean | yes | Whether this repo contains multiple independently deployable components. |
| `description` | string | optional | Human-readable description. Supports `manual_override`. |
| `last_crawled` | string (ISO 8601) | yes | When this repository was last crawled. Used to assess staleness. |

---

## components[] — Common Fields

Every component shares these base fields regardless of type.

```json
{
  "id": "svc-user-api",
  "name": "user-api",
  "type": "service",
  "source_repo": "my-platform",
  "path": "services/user-api",
  "description": "Handles user registration, authentication, and profile management",
  "language": "typescript",
  "framework": "express",
  "platform": "aws-ecs",
  "runtime": "node:20-alpine",
  "confidence": 0.95,
  "discovery_method": "Dockerfile with ENTRYPOINT + Kubernetes Deployment manifest",
  "last_crawled": "2026-03-14T12:00:00Z",
  "stub": false,
  "stale": false,
  "manual_override": false,
  "tags": ["core", "auth"],
  "ownership": { },
  "observability": { }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique identifier. Convention: `{type_prefix}-{name}`. Prefixes: `svc-`, `app-`, `lib-`, `infra-`, `pipeline-`, `datastore-`, `ext-`. |
| `name` | string | yes | Human-readable name. |
| `type` | enum | yes | One of: `service`, `app`, `library`, `infrastructure`, `pipeline`, `datastore`, `external`. |
| `source_repo` | string | yes | Name of the repository this component was discovered in. Must match a `name` in `repositories[]`. Null for stubs not yet resolved to a repo. |
| `path` | string | yes (except stubs) | Path relative to repo root. Null for external/stub components. |
| `description` | string | optional | What this component does. Supports `manual_override`. |
| `language` | string | optional | Primary language (lowercase): `typescript`, `python`, `go`, `rust`, `java`, `kotlin`, `ruby`, `csharp`, etc. |
| `framework` | string | optional | Primary framework: `express`, `fastapi`, `spring-boot`, `rails`, `nextjs`, `react`, `django`, etc. |
| `platform` | string | optional | Deployment platform: `aws-ecs`, `aws-lambda`, `kubernetes`, `cloud-run`, `vercel`, `netlify`, `heroku`, etc. |
| `runtime` | string | optional | Runtime image or version: `node:20-alpine`, `python:3.12`, `go:1.22`, etc. |
| `confidence` | number | yes | 0.0–1.0 confidence in the accuracy of this entry. |
| `discovery_method` | string | yes | What heuristic or evidence led to this discovery. |
| `last_crawled` | string (ISO 8601) | yes | When this component was last analyzed. |
| `stub` | boolean | yes | True if this component was referenced but not found in the crawled repo. |
| `stub_reason` | string | conditional | Required when `stub: true`. Why this is a stub (e.g., "Referenced in env var SERVICE_URL but no matching service found in repo"). |
| `stale` | boolean | optional | True if this component was not found in its `source_repo` during the most recent crawl of that repo. Components are never marked stale by crawls of *other* repos. |
| `stale_since` | string (ISO 8601) | conditional | Required when `stale: true`. When this component was first marked stale. |
| `manual_override` | boolean | optional | If true, this component's fields are preserved during incremental updates. Defaults to false. |
| `tags` | array of strings | optional | Freeform tags for categorization. |
| `ownership` | object | optional | See Ownership section. |
| `observability` | object | optional | See Observability section. |

---

## Component Type-Specific Fields

### type: "service" or "app"

```json
{
  "endpoints": [ ],
  "env_vars": [ ],
  "secrets_management": { },
  "container": { },
  "kubernetes": { }
}
```

#### endpoints[]

```json
{
  "method": "POST",
  "path": "/api/v1/users",
  "handler": "controllers/user.ts:createUser",
  "public": false,
  "authentication": {
    "mechanism": "jwt",
    "details": "Bearer token validated via middleware/auth.ts"
  },
  "authorization": {
    "type": "rbac",
    "requirements": ["role:admin", "scope:users:write"]
  },
  "rate_limited": true,
  "description": "Create a new user account",
  "confidence": 0.95
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `method` | string | yes | HTTP method: GET, POST, PUT, PATCH, DELETE, or `*` for catch-all. For gRPC: the RPC method name. |
| `path` | string | yes | Route path with parameter placeholders (`:id`, `{id}`). |
| `handler` | string | optional | File and function that handles this endpoint. |
| `public` | boolean | yes | Whether this endpoint is exposed without authentication. |
| `authentication` | object | optional | Auth mechanism. `mechanism` is one of: `jwt`, `api_key`, `oauth2`, `session`, `mtls`, `basic`, `none`, `unknown`. |
| `authorization` | object | optional | Authz requirements. `type` is one of: `rbac`, `abac`, `acl`, `scope`, `none`, `unknown`. `requirements` lists specific roles/scopes/policies. |
| `rate_limited` | boolean | optional | Whether rate limiting is applied. |
| `description` | string | optional | What this endpoint does. |
| `confidence` | number | yes | Confidence in this endpoint's classification. |

#### env_vars[]

```json
{
  "name": "DATABASE_URL",
  "source": "kubernetes-secret",
  "secret": true,
  "referenced_in": ["src/config/database.ts"],
  "description": "PostgreSQL connection string"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Environment variable name. |
| `source` | string | optional | Where this var is set: `kubernetes-secret`, `kubernetes-configmap`, `docker-compose`, `env-file`, `terraform-output`, `vault`, `aws-secrets-manager`, `aws-ssm`, `github-actions-secret`, `unknown`. |
| `secret` | boolean | yes | Whether this appears to contain sensitive data. |
| `referenced_in` | array of strings | optional | Files that reference this var. |
| `description` | string | optional | What this var configures. |

#### secrets_management

```json
{
  "provider": "aws-secrets-manager",
  "references": ["arn:aws:secretsmanager:us-east-1:123456:secret:prod/user-api/*"],
  "rotation_configured": true,
  "confidence": 0.8
}
```

#### container

```json
{
  "dockerfile": "services/user-api/Dockerfile",
  "base_image": "node:20-alpine",
  "exposed_ports": [3000],
  "build_stages": ["builder", "runtime"],
  "runtime_user": "node",
  "healthcheck": "GET /health"
}
```

#### kubernetes

```json
{
  "namespace": "production",
  "deployment": "user-api",
  "replicas": {"min": 2, "max": 10},
  "service_type": "ClusterIP",
  "ingress": {"host": "api.example.com", "path": "/api/v1/users*"},
  "network_policies": ["allow-from-gateway", "allow-to-postgres"],
  "service_account": "user-api-sa",
  "rbac_roles": ["user-api-role"],
  "resource_limits": {"cpu": "500m", "memory": "512Mi"},
  "hpa": {"metric": "cpu", "target": 70}
}
```

### type: "infrastructure"

```json
{
  "iac_tool": "terraform",
  "provider": "aws",
  "resources": [
    {
      "type": "aws_ecs_service",
      "name": "user-api",
      "key_attributes": {"cluster": "main", "desired_count": 2}
    }
  ],
  "variables": [
    {"name": "environment", "type": "string", "default": "production"}
  ],
  "outputs": [
    {"name": "service_url", "description": "URL of the deployed service"}
  ],
  "remote_state_refs": [
    {"source": "networking", "key": "vpc_id"}
  ],
  "backend": {"type": "s3", "bucket": "terraform-state-prod"},
  "workspaces": ["dev", "staging", "prod"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `iac_tool` | string | yes | One of: `terraform`, `opentofu`, `pulumi`, `cloudformation`, `cdk`, `bicep`, `helm`, `argocd`, `kustomize`, `kyverno`, `crossplane`. The last five cover Kubernetes-declarative IaC — use them when describing in-cluster resource management rather than stretching `cdk` or `terraform`. |
| `provider` | string | yes | Cloud provider: `aws`, `gcp`, `azure`, `cloudflare`, `kubernetes` (for in-cluster IaC like Helm/ArgoCD/Kustomize/Kyverno), etc. |
| `resources` | array | yes | Resources managed by this module. |
| `variables` | array | optional | Input variables. |
| `outputs` | array | optional | Outputs exposed to other modules. |
| `remote_state_refs` | array | optional | References to other IaC modules' state. |
| `backend` | object | optional | State backend configuration. |
| `workspaces` | array | optional | Environment workspaces. |

### type: "pipeline"

```json
{
  "ci_platform": "github-actions",
  "file": ".github/workflows/deploy-user-api.yml",
  "triggers": ["push:main", "pull_request:main", "workflow_dispatch"],
  "targets": ["svc-user-api"],
  "environments": ["staging", "production"],
  "steps_summary": [
    "checkout", "install dependencies", "run tests", "build docker image",
    "push to ECR", "deploy to ECS staging", "integration tests", "deploy to ECS prod"
  ],
  "deployment_strategy": "rolling",
  "secret_refs": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "DOCKER_TOKEN"],
  "approval_gates": ["production"]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `ci_platform` | string | yes | One of: `github-actions`, `gitlab-ci`, `circleci`, `jenkins`, `buildkite`, `argo`, `tekton`, etc. |
| `file` | string | yes | Path to the pipeline definition file. |
| `triggers` | array | yes | What triggers this pipeline. |
| `targets` | array | yes | Component IDs this pipeline builds/deploys. |
| `environments` | array | optional | Target environments. |
| `steps_summary` | array | optional | High-level step descriptions. |
| `deployment_strategy` | string | optional | `rolling`, `blue-green`, `canary`, `recreate`. |
| `secret_refs` | array | optional | Secrets referenced by the pipeline. |
| `approval_gates` | array | optional | Environments requiring manual approval. |

### type: "datastore"

```json
{
  "engine": "postgresql",
  "version": "15.4",
  "managed_by": "infra-rds-user-db",
  "connection_pattern": "direct",
  "shared": false,
  "consumers": ["svc-user-api"],
  "migrations_path": "services/user-api/migrations",
  "schemas": ["public", "auth"],
  "read_replicas": true,
  "backup_configured": true,
  "encryption_at_rest": true,
  "encryption_in_transit": true
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `engine` | string | yes | Use the actual service name, not cross-cloud equivalents. **Databases:** `postgresql`, `mysql`, `mssql`, `mongodb`, `cosmosdb`, `dynamodb`, `redis`, `memcached`, `elasticsearch`, `sqlite`. **Object storage:** `s3`, `azure-blob-storage`, `gcs`. **Queues/messaging:** `sqs`, `sns`, `azure-queue-storage`, `azure-service-bus`, `google-pubsub`, `kafka`, `rabbitmq`, `nats`. **Table/KV stores:** `dynamodb`, `azure-table-storage`, `google-bigtable`. **Secret stores:** `vault-kv`, `aws-secrets-manager`, `azure-key-vault`, `google-secret-manager`. **Container registries:** `aws-ecr`, `azure-container-registry`, `google-artifact-registry`, `docker-hub`, `ghcr`. **HashiCorp suite:** `vault-pki`, `consul-kv`. **Never map Azure→AWS or vice versa** (e.g., Azure Blob is NOT `s3`, Azure Service Bus is NOT `sqs`). Never collapse a secret store or container registry under `s3` or `redis` — they have distinct semantics and downstream filters depend on the actual service name. |
| `version` | string | optional | Engine version. |
| `managed_by` | string | optional | Component ID of the IaC that provisions this store. |
| `connection_pattern` | string | optional | `direct`, `pooled`, `orm`, `sdk`. |
| `shared` | boolean | yes | Whether multiple services connect to this store. This is an architectural risk signal. |
| `consumers` | array | yes | Component IDs of services that use this store. |
| `migrations_path` | string | optional | Path to migration files if found. |
| `schemas` | array | optional | Database schemas discovered. |
| `read_replicas` | boolean | optional | Whether read replicas are configured. |
| `backup_configured` | boolean | optional | Whether backups are set up. |
| `encryption_at_rest` | boolean | optional | Encryption status. |
| `encryption_in_transit` | boolean | optional | TLS/SSL status. |

### type: "external"

External third-party services referenced in the codebase.

```json
{
  "vendor": "stripe",
  "category": "payments",
  "sdk": "stripe-node@14.x",
  "api_version": "2024-12-18",
  "consumers": ["svc-payment-api", "svc-billing-api"],
  "webhook_endpoints": ["/webhooks/stripe"],
  "documentation_url": "https://stripe.com/docs/api"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `vendor` | string | yes | Vendor name: `stripe`, `twilio`, `sendgrid`, `auth0`, `datadog`, `pagerduty`, `launchdarkly`, etc. |
| `category` | string | yes | `payments`, `communications`, `auth`, `monitoring`, `feature-flags`, `analytics`, `cdn`, `dns`, `email`, `search`, `ai`, etc. |
| `sdk` | string | optional | SDK package and version used. |
| `api_version` | string | optional | API version pinned in config. |
| `consumers` | array | yes | Component IDs of services that use this external service. |
| `webhook_endpoints` | array | optional | Inbound webhook endpoints registered for this vendor. |
| `documentation_url` | string | optional | Link to vendor docs. |

### type: "library"

```json
{
  "package_name": "@myorg/auth-utils",
  "exports": ["validateToken", "requireRole", "AuthMiddleware"],
  "consumers": ["svc-user-api", "svc-order-api", "svc-payment-api"],
  "version_strategy": "workspace",
  "pinned_version": "2.3.1"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `package_name` | string | yes | Package name as referenced by consumers. |
| `exports` | array | optional | Key exports. Not exhaustive — focus on the important interfaces. |
| `consumers` | array | yes | Component IDs that import this library. |
| `version_strategy` | string | optional | `workspace`, `pinned`, `range`, `latest`. |
| `pinned_version` | string | optional | Current version if pinned. |

---

## Ownership

```json
{
  "team": "platform-auth",
  "codeowners": ["@org/auth-team"],
  "contacts": ["auth-team@example.com"],
  "documentation_url": "https://wiki.internal/auth-api",
  "runbook_url": "https://wiki.internal/runbooks/auth-api"
}
```

All fields optional. Sourced from CODEOWNERS files, Kubernetes labels/annotations, README files,
package.json `author`/`maintainers` fields, or Terraform tags.

---

## Observability

```json
{
  "health_check": {"path": "/health", "method": "GET"},
  "readiness_check": {"path": "/ready", "method": "GET"},
  "logging": {"framework": "pino", "structured": true, "level": "info"},
  "tracing": {"provider": "opentelemetry", "exporter": "datadog"},
  "metrics": {"provider": "prometheus", "endpoint": "/metrics"},
  "alerting": {"provider": "pagerduty", "escalation_policy": "platform-p1"},
  "dashboards": ["https://grafana.internal/d/user-api"]
}
```

All fields optional. This section tells you what's monitored and — critically — what isn't. A service
with no observability fields is a blind spot.

---

## connections[]

```json
{
  "id": "conn-user-api-to-postgres",
  "source": "svc-user-api",
  "target": "datastore-user-db",
  "type": "database",
  "async": false,
  "protocol": "tcp",
  "protocol_details": {
    "driver": "pg",
    "connection_pool": true,
    "max_connections": 20,
    "ssl": true
  },
  "auth_required": {
    "mechanism": "password",
    "credential_source": "aws-secrets-manager"
  },
  "endpoints_involved": [],
  "description": "Primary user data store",
  "confidence": 0.95,
  "discovery_method": "DATABASE_URL env var traced to Terraform aws_rds_instance"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique identifier. Convention: `conn-{source}-to-{target}`. |
| `source` | string | yes | Component ID of the caller/producer. |
| `target` | string | yes | Component ID of the callee/consumer/store. |
| `type` | enum | yes | `http`, `grpc`, `graphql`, `websocket`, `queue`, `pubsub`, `database`, `cache`, `storage`, `library`, `infrastructure`, `event`. |
| `async` | boolean | yes | Whether this is an asynchronous interaction (queues, events, pub/sub). |
| `protocol` | string | optional | Wire protocol: `http/1.1`, `http/2`, `tcp`, `amqp`, `kafka`, etc. |
| `protocol_details` | object | optional | Freeform details specific to the connection type. For HTTP: methods, paths. For queues: queue names, topics. For databases: driver, pool size, SSL. |
| `auth_required` | object | optional | How this connection authenticates. Same structure as endpoint authentication. |
| `endpoints_involved` | array | optional | For HTTP connections: which specific endpoints on the target are called. |
| `description` | string | optional | What this connection is for. |
| `confidence` | number | yes | 0.0–1.0. |
| `discovery_method` | string | yes | How this connection was identified. |

---

## metadata

```json
{
  "total_components": 23,
  "total_connections": 47,
  "total_stubs": 5,
  "component_counts": {
    "service": 8,
    "app": 3,
    "library": 4,
    "infrastructure": 3,
    "pipeline": 5,
    "datastore": 4,
    "external": 6
  },
  "low_confidence_components": ["svc-legacy-worker"],
  "shared_datastores": ["datastore-analytics-db"],
  "unauthenticated_public_endpoints": [
    {"component": "svc-user-api", "endpoint": "GET /health"},
    {"component": "svc-user-api", "endpoint": "POST /api/v1/auth/login"}
  ],
  "unmonitored_services": ["svc-legacy-worker"],
  "repo_staleness": [
    {
      "repo": "my-platform",
      "last_crawled": "2026-03-14T12:00:00Z",
      "components": 18,
      "age_days": 0
    },
    {
      "repo": "notification-service",
      "last_crawled": "2026-03-01T10:00:00Z",
      "components": 5,
      "age_days": 13
    }
  ],
  "crawl_duration_phases": {
    "phase_1_discovery": "12s",
    "phase_2_deep_dive": "3m 42s",
    "phase_3_connections": "1m 15s",
    "phase_4_assembly": "8s"
  },
  "incremental": {
    "is_incremental": true,
    "repo_crawled": "my-platform",
    "previous_generated_at": "2026-03-10T08:00:00Z",
    "components_added": 2,
    "components_removed": 0,
    "components_updated": 15,
    "components_marked_stale": 1,
    "stubs_resolved": 0,
    "manual_overrides_preserved": 3
  }
}
```

The metadata section is a summary designed to surface the most operationally important signals at
a glance. Downstream skills can use this to quickly assess the health and completeness of the map
without traversing the full component/connection arrays.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `total_components` | number | yes | Total count of all components. |
| `total_connections` | number | yes | Total count of all connections. |
| `total_stubs` | number | yes | Count of stub entries (TODOs). |
| `component_counts` | object | yes | Breakdown by component type. |
| `low_confidence_components` | array | yes | IDs of components with confidence < 0.5. |
| `shared_datastores` | array | yes | IDs of datastores with `shared: true`. Architectural risk signal. |
| `unauthenticated_public_endpoints` | array | yes | Endpoints with `public: true` and `authentication.mechanism: "none"`. Security signal. |
| `unmonitored_services` | array | yes | Service/app IDs with empty or missing observability. Operational risk signal. |
| `repo_staleness` | array | yes | Per-repo crawl age summary. Each entry: `repo` (name), `last_crawled` (ISO 8601), `components` (count from that repo), `age_days` (days since last crawl, computed at generation time). Sorted by `age_days` descending so the stalest repo is first. |
| `crawl_duration_phases` | object | optional | Time spent in each crawl phase. |
| `incremental` | object | optional | Present only for incremental updates. Summarizes what changed. `repo_crawled` identifies which repo was crawled in this run. `stubs_resolved` counts stubs that were replaced with full entries. |

---

## Stub Entries

Stubs represent components that are referenced but not found in any crawled repo. They exist so
the map shows the full dependency picture, with clear markers for what needs to be filled in.

Minimum required fields for a stub:

```json
{
  "id": "svc-notification-service",
  "name": "notification-service",
  "type": "service",
  "source_repo": null,
  "path": null,
  "confidence": 0.0,
  "discovery_method": "Referenced in env var NOTIFICATION_SERVICE_URL in svc-user-api",
  "last_crawled": "2026-03-14T12:00:00Z",
  "stub": true,
  "stub_reason": "Service URL referenced in user-api config but no matching service found in this repository. Likely lives in a separate repo."
}
```

### Stub Resolution (Multi-Repo)

When running `/generateservicemap` against a new repo that points to an existing servicemap:
1. If a discovered component matches a stub by ID or name, the stub is **replaced** with the full
   entry. The `source_repo` is set to the newly crawled repo. The `stub` field becomes `false`.
2. The `stubs_resolved` count in `metadata.incremental` tracks how many stubs were resolved.
3. Stubs that are not resolved remain unchanged — they are never deleted or marked stale.

---

## Schema Version Compatibility

| Version | Status | Notes |
|---------|--------|-------|
| 1.1.0 | Current | Multi-repo support: `repository` → `repositories[]`, `source_repo` on components, `repo_staleness` in metadata, scoped stale-marking. |
| 1.0.0 | Deprecated | Initial schema. Single-repo only. |

**Versioning rules:**
- **Patch** (1.0.x): Clarifications, documentation fixes. No structural changes.
- **Minor** (1.x.0): New optional fields added. Fully backward compatible.
- **Major** (x.0.0): Breaking changes. Consumers must be updated.

Consuming skills should check `schema_version` and handle:
```
major_version = parseInt(schema_version.split('.')[0])
if (major_version !== EXPECTED_MAJOR) {
  warn("Incompatible servicemap schema version")
}
```
