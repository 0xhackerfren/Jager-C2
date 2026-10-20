# Changelog

All notable changes to Jager-C2 are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

## [1.0.1] - 2026-10-20

### Fixed
- Workspace layout: teamserver no longer assumes the repository sits under a `jager/` subdirectory; all paths (builder, profiles, data, hooks, secrets) are repo-root relative
- `deploy/Dockerfile.mcp`: removed stale `COPY __init__.py`, MCP container now runs in SSE mode on port 8000 as docker-compose expects
- Operator CLI: kill/build endpoints matched to the actual management API, added `go.mod`
- MCP client: removed calls to nonexistent `/mgmt/session/interact` and `/mgmt/pivots/add` endpoints
- Task contract: added `TASK_TOKEN_RUNAS` to the proto, fixed contract-test regex for task names containing digits, registry synced to proto (69/69)
- CI pipeline no longer imports the unwired `profile_engine` module

### Added
- GitHub Actions CI workflow (teamserver build/tests, implants, YARA self-test, contract and capability validation)
- `scripts/validate-c2-capabilities.py` capability registry validator
- CONTRIBUTING.md, SECURITY.md, CODE_OF_CONDUCT.md, this changelog
- AGENTS.md agent development rules and `.cursor/rules` referencing them
- `.gitattributes` for consistent cross-platform line endings
- Third-party notices for vendored libcurl

## [1.0.0] - 2026-10-20

- Initial open-source release: Go gRPC teamserver, C Windows/Linux implants, polymorphic Python build pipeline, MCP agentic interface, MIT license.