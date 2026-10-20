# AGENTS.md - Jager-C2 Agent Development Rules

Canonical rules for AI agents and human contributors working on Jager-C2.
Cursor-specific agents read `.cursor/rules/` which mirrors this file.

## Project identity

- Product name: **Jager-C2** (never reintroduce legacy/upstream names)
- Go modules: `github.com/0xhackerfren/Jager-C2/teamserver`, `/client/cli`, `/implant-go`
- Env var prefix: `JAGER_`; API header: `X-Jager-C2-Api-Key`
- Proto package: `jager`; generated stubs: `teamserver/proto/jagerpb`

## First commandment: determinism

Non-determinism is the primary failure mode of agent-driven development. Therefore:

- Never introduce time, randomness, or network lookups into derivation paths (profiles, IOC generation, build nonces are keyed on `(engagement_id, template, build_nonce)` and must be reproducible)
- Prefer explicit state over inference: read files, run commands, verify output. Do not assume a build succeeded because a command "probably worked"
- Tests must be order-independent and pass twice in a row from a clean tree
- When editing generated code (`proto/jagerpb/`), regenerate or keep hand-edits consistent with the `.proto` source; never leave both diverging silently

## Secrets and artifacts (non-negotiable)

- Never commit: API keys, build secrets, AES keys/IVs, implant binaries, engagement data, runtime logs, `.db` files
- Generated material lives under `data/` (gitignored) or `builds/`; runtime logs under `logs/`
- If a secret is found in the tree or history: stop, rotate it, report to the user before any push
- Before every push, run the secret scan (see Verification below)

## Repository layout

```
teamserver/       Go gRPC teamserver (module: teamserver go.mod)
client/cli/       Go operator CLI (module: client/cli go.mod)
implant/          C Windows implant (MinGW, cross-compiled)
implant-linux/    C Linux implant (static libcurl)
builder/          Python polymorphic build pipeline
mcp/              Python MCP server (FastMCP + tools registry)
profiles/         Malleable C2 arsenal + schema
deploy/           Docker Compose, Dockerfiles, Terraform
scripts/          CI, e2e, validation scripts
tests/            tests/contract (fast), tests/integration (needs running teamserver)
docs/             ARCHITECTURE.md, OPERATOR_GUIDE.md
```

## Task contract sync (enforced by CI)

Task type numbers are defined in three synchronized places:

1. `teamserver/proto/tasks.proto` - canonical `TaskType` enum
2. `implant/include/config.h`, `implant-linux/include/config.h` - `#define TASK_*`
3. `capability-registry.yaml` - registry with handler/tool/status mappings

Adding or changing a task requires updating all three, then:

```bash
python tests/contract/test_task_dispatch.py
python scripts/validate-c2-capabilities.py
```

Task names may contain digits (`TASK_P2P_LISTEN`); regexes over these files must use `TASK_[A-Z0-9_]+`.

## Kanban board workflow

Work is tracked on the GitHub Projects kanban board ("Jager-C2 Roadmap") linked in the README, with repo issues as cards.

### Columns

| Column | Meaning |
|--------|---------|
| Backlog | Accepted work, not yet scheduled |
| Ready | Spec'd, prioritized, next up |
| In Progress | Actively being worked (limit: 1 per agent) |
| In Review | PR open, CI running |
| Done | Merged to main |

### Label taxonomy

- `priority/p1` `priority/p2` `priority/p3` - urgency
- `area/teamserver` `area/implant` `area/mcp` `area/builder` `area/cli` `area/ci` `area/docs` - component
- `bug` `enhancement` `documentation` `good first issue` - type

### Agent workflow rules

1. Before starting work: `gh project list --owner 0xhackerfren`, then query the board and issue list for the highest-priority unassigned item in Ready
2. Claim an item by assigning yourself to the issue and moving it to In Progress; one item at a time
3. If a task is too large, split it into a new issue with the same labels and reference the parent
4. When opening a PR: reference the issue with `Fixes #N`; CI must pass; move the card to In Review
5. On merge: move the card to Done and close the issue
6. If blocked >30 minutes of effort or by a decision only the user can make: stop, comment on the issue with the blocker, move the card back to Ready
7. New discovered work goes in a new issue with labels, never in a commit message alone
8. `gh issue create`, `gh issue edit`, `gh issue view` operate on `0xhackerfren/Jager-C2`; project commands need the `project` scope on the gh token

### Definition of done

- Code compiles (`go build ./...` in teamserver and client/cli; `python -m compileall mcp builder tests`)
- Contract and capability validators pass
- New behavior has a test where practical and a docs update where user-facing
- CHANGELOG.md updated for user-visible changes
- No secrets, no TODO-only commits

## Verification before any push

```bash
# 1. Compile
python -m compileall -q mcp builder tests
cd teamserver && go build ./... && go test ./...
cd ../client/cli && go mod tidy && go build

# 2. Contracts
python tests/contract/test_task_dispatch.py
python scripts/validate-c2-capabilities.py

# 3. Secret scan (must print nothing)
rg -i "api-key|build-secret" --glob "!*.md" --glob "!LICENSE" .
rg "[0-9a-f]{64}" data/ teamserver/ 2>/dev/null

# 4. Branding scan (must print nothing)
rg -i "suzu" . --glob "!AGENTS.md"
```

## API surface rules

- REST management endpoints: `/mgmt/*` on port 31338. Check `teamserver/internal/server/management.go` routes before adding client calls; do not invent endpoints
- CLI (`client/cli`) and MCP (`mcp/grpc_client.py`) must use identical endpoint names and JSON field names (`id` not `session_id` for session kill, etc.)
- Task payloads over `/mgmt/task` use numeric TaskType values; helper `taskTypeFromString` accepts names too

## Docs truth rule

Docs must describe the system as it is. If you implement or remove a capability, update README.md, docs/ARCHITECTURE.md, docs/OPERATOR_GUIDE.md, and CHANGELOG.md in the same change. Never document aspirational features as existing.

## License

MIT. Contributions are licensed under the repo LICENSE (see CONTRIBUTING.md).