# Contributing to Jager-C2

Thank you for contributing. This document covers setup, conventions, and the development workflow.

## Legal and ethical baseline

Jager-C2 is a dual-use security tool. Contributions are accepted for defensive research, authorized red teaming, and education. Do not submit code whose only purpose is to facilitate clearly illegal activity, and never test the framework against systems you do not own or have written authorization to test.

## Development setup

Requirements:

- Go 1.22+ (teamserver, CLI)
- Python 3.11+ (builder, MCP server)
- MinGW x86_64 (Windows implant builds, optional)
- `yara` binary (signature self-tests, optional)
- Docker (deployment stack, optional)

```bash
# Teamserver
cd teamserver && go build ./... && go test ./...

# Operator CLI
cd client/cli && go mod tidy && go build

# Builder / MCP
pip install -r mcp/requirements.txt
python -m compileall -q mcp builder

# Full pipeline (builds implants, runs YARA self-tests, e2e)
bash scripts/ci-pipeline.sh
```

## Repository conventions

### Layout

```
teamserver/       Go gRPC teamserver (one go.mod per module tree)
client/cli/       Go operator CLI (separate go.mod)
implant/          C Windows implant (MinGW cross-compiled)
implant-linux/    C Linux implant
implant-go/       Go implant prototype
builder/          Python polymorphic build pipeline
mcp/              Python MCP server
profiles/         Malleable C2 profile arsenal and schema
deploy/           Docker Compose, Dockerfiles, Terraform
scripts/          CI, e2e, and validation scripts
tests/            Contract (fast) and integration (requires running teamserver) tests
docs/             Architecture and operator documentation
```

### Task contract sync (enforced in CI)

Task type numbers are defined in three places that must stay synchronized:

1. `teamserver/proto/tasks.proto` (canonical enum)
2. `implant/include/config.h` and `implant-linux/include/config.h` (`#define TASK_*`)
3. `capability-registry.yaml` (registry with handler/tool mappings)

When you add or change a task, update all three, then verify:

```bash
python tests/contract/test_task_dispatch.py
python scripts/validate-c2-capabilities.py
```

### Naming and branding

- The product is **Jager-C2**. Do not introduce upstream/legacy names into new code.
- Go module paths use `github.com/0xhackerfren/Jager-C2/...`.
- Environment variables use the `JAGER_` prefix.
- REST management endpoints live under `/mgmt/*`; the API key header is `X-Jager-C2-Api-Key`.

### Secrets hygiene (non-negotiable)

Never commit: API keys, build secrets, AES keys/IVs, compiled implant binaries, engagement data, or runtime logs. Generated material belongs under `data/` (gitignored) or `builds/`. If a secret is accidentally committed, rotate it immediately and notify the maintainers.

### Determinism

Builds must be reproducible given the same `(engagement_id, template, build_nonce)`. Avoid adding time, randomness, or network lookups to profile derivation paths. Tests must not depend on execution order.

## Docs → tests → code

Follow [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md): commit the specification,
then failing regression tests with evidence, then implementation. The issue
[Kanban dashboard](https://github.com/0xhackerfren/Jager-C2/issues/12) uses
exclusive status labels. Review [docs/TESTING.md](docs/TESTING.md) for known
CI failures; do not infer release readiness from a partial check.

## Pull requests

1. Fork or branch from `main` (`feat/...`, `fix/...`, `docs/...`).
2. Run the relevant tests locally; CI must pass.
3. Keep PRs focused; one logical change per PR.
4. Describe what changed and why; reference the related GitHub issue (see the project kanban board).
5. New user-facing behavior requires a README or `docs/` update in the same PR.

## Issue tracking

Work is tracked on the GitHub Projects kanban board linked from the README ([Jager-C2 Roadmap](https://github.com/users/0xhackerfren/projects/2)). Agents and contributors should read `AGENTS.md` for the board workflow (columns, labels, and how to move items).

## License

By contributing you agree that your contributions are licensed under the MIT License covering this repository.