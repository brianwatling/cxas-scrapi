# cxas push

`cxas push` uploads a local agent directory to CX Agent Studio, either updating an existing app or creating a fresh one — it's how your local edits make it into the platform.

## Usage

```
cxas push [--app-dir DIR] [--to TARGET] [--env-file FILE] [--service-directory-map FILE]
          [--app-name APP] [--display-name NAME]
          [--create-version] [--version-name NAME] [--version-description DESC]
          [--overwrite]
          [--project-id PROJECT] [--location LOCATION]
```

## Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--app-dir DIR` | No | `.` (current directory) | Path to the local agent directory to upload. |
| `--to TARGET` | No | — | Target app to overwrite. Accepts a full resource name or display name. When provided, the existing app is updated in place. |
| `--env-file FILE` | No | — | Path to a JSON environment file to inject as `environment.json` before uploading. Useful for supplying environment-specific resource bindings and resolving `"$env_var"` defaults in `app.json` / `app.yaml` `variableDeclarations` without committing secrets or per-stage overrides. |
| `--service-directory-map FILE` | No | — | Path to a JSON, YAML, or plain-text Service Directory mapping file. Injects or overrides concrete `serviceDirectoryConfig.service` values across matching OpenAPI and MCP toolsets/tools in the staging bundle (leaving local files untouched). |
| `--app-name APP` | No | — | Explicit app resource name to push to (v1beta API). Use this when you want to overwrite a specific app and already know its full ID. |
| `--display-name NAME` | No | `"Pushed Agent"` | Display name for the new app when no target is specified and a new app will be created. |
| `--create-version` | No | `false` | Automatically create a version snapshot after a successful push. |
| `--version-name NAME` | No | `import-TIMESTAMP` | Custom display name for the created version snapshot (used with `--create-version`). |
| `--version-description DESC` | No | — | Description text for the created version snapshot (used with `--create-version`). |
| `--overwrite` | No | `false` | Overwrite existing resources with imported data. Unmatched existing resources will be deleted. |
| `--project-id PROJECT` | No | — | GCP project ID. Required for a display-name target or when creating a new app. Inferred from a full target resource name. |
| `--location LOCATION` | No | — | GCP location (e.g., `global`, `us-central1`). Required for a display-name target or when creating a new app. Inferred from a full target resource name. |

## What Gets Uploaded

The CLI bundles the following top-level items from `--app-dir` into a ZIP archive before uploading:

- `app.yaml` / `app.json`
- `global_instruction.txt`
- `environment.json` (or the file you pass via `--env-file`)
- `agents/`, `tools/`, `guardrails/`, `toolsets/`
- `evaluations/`, `evaluationDatasets/`, `evaluationExpectations/`
- `.github/workflows/`

Everything else in the directory (e.g. `.git`, local test output) is ignored.

## Environment-Specific Variable Defaults (`$env_var`)

When a variable in `app.json` (or `app.yaml`) sets `"default": "$env_var"`, `cxas push` resolves its typed default from `environment.json` (or `--env-file`) inside a temporary staging directory before uploading — leaving your local working tree untouched.

Declare the placeholder in `app.json`:

```json
{
  "variableDeclarations": [
    {
      "name": "enable_authentication",
      "description": "Whether caller authentication is enforced.",
      "schema": {
        "type": "BOOLEAN",
        "default": "$env_var"
      }
    }
  ]
}
```

Supply the per-environment value under `app.variableDeclarations` in `environment.json` (or `--env-file`):

```json
{
  "app": {
    "variableDeclarations": [
      {
        "name": "enable_authentication",
        "schema": {
          "type": "BOOLEAN",
          "default": true
        }
      }
    ]
  }
}
```

`cxas push` fails fast before uploading if `--env-file` is missing, a `"$env_var"` variable is absent from `app.variableDeclarations`, `variableDeclarations` is mistakenly placed at the top level of `environment.json`, or the supplied value does not match the declared schema type.

## Service Directory Mapping (`--service-directory-map`)

When routing outbound OpenAPI (`openApiToolset`, `openApiTool`) or MCP (`mcpToolset`, `mcpTool`) connections through per-project Service Directory Private Network Access, pass `--service-directory-map FILE` (or declare `"service": "$env_var"` and supply bindings in `environment.json`).

In staging, `cxas push`:

1. Resolves each toolset/tool's effective target hostname from `--env-file` / `environment.json` URL overrides, `url` / `serverAddress`, or `openApiSchema` (`servers[0].url` / `host`).
2. Injects or overrides `serviceDirectoryConfig.service` for every matching OpenAPI/MCP toolset or tool (even if `serviceDirectoryConfig` is omitted locally), while leaving non-matching resources (such as `*.googleapis.com` and `*.run.app`) untouched on direct egress.
3. Enforces concrete GCP regions (e.g., `us-central1`, never `us`/`eu`/`global`) and the Layer 4 proxy invariant (**1 Service Directory service = 1 FQDN**).

Supported mapping formats (`.yaml`, `.json`, or plain-text summary lines):

```yaml
# Optional defaults for expanding shorthand service IDs
project: my-agent-prod
location: us-central1
namespace: ces-egress

hosts:
  api.partner.example.com: ces-svc-api-partner-exampl-3f9a1c
  idp.partner.example.com: projects/my-agent-prod/locations/us-central1/namespaces/ces-egress/services/ces-svc-idp-c207aa

# Optional explicit per-resource overrides
toolsets:
  custom_gateway_toolset: ces-svc-custom-999999
```

Plain-text summary lines printed by egress provisioning scripts (`<fqdn> (VIP ...) -> projects/.../services/...` or `<fqdn>=projects/.../services/...`) are also accepted directly.

## Examples

**Push the current directory to an existing app by display name:**

```bash
cxas push \
  --to "My Support Agent" \
  --project-id my-gcp-project \
  --location us-central1
```

**Push a specific directory and create a new app with a custom display name:**

```bash
cxas push \
  --app-dir ./my-agent \
  --display-name "My Support Agent (Staging)" \
  --project-id my-gcp-project \
  --location us-central1
```

**Push current directory and create a version snapshot with a custom name:**

```bash
cxas push \
  --to "My Support Agent" \
  --create-version \
  --version-name "v1.2.0" \
  --version-description "Release candidate v1.2.0" \
  --project-id my-gcp-project \
  --location us-central1
```

**Push using a separate environment file (keeps secrets out of source control):**

```bash
cxas push \
  --app-dir ./my-agent \
  --to projects/my-gcp-project/locations/us-central1/apps/abc123 \
  --env-file ./secrets/env-prod.json \
  --project-id my-gcp-project \
  --location us-central1
```

## Related Commands

- [`cxas pull`](pull.md) — Download an app to a local directory first.
- [`cxas create`](create.md) — Create an empty app shell before pushing.
- [`cxas ci-test`](ci-test.md) — Run the full push + test lifecycle in CI.
