# Jager-C2

> **Development preview — release qualification pending.** Current CI has known
> failures. Review [release readiness](docs/RELEASE_READINESS.md) and
> [documentation](docs/README.md) before relying on feature claims below.
> Some CLI/MCP commands are placeholders; implementation does not imply validation.

An open-source, agentic command-and-control framework built for authorized red team operations. Jager-C2 pairs a Go teamserver with a hardened C implant, a polymorphic Python build pipeline, and a first-class MCP server so AI agents can orchestrate engagements end to end.

> **Disclaimer**: Jager-C2 is intended for authorized security testing, red team engagements, and research only. Unauthorized use against systems you do not own or have explicit written permission to test is illegal. The authors accept no liability for misuse.

## Highlights

- **Agentic-first** - Every capability is exposed as an MCP tool, so Claude, GPT, or any MCP-capable agent can run sessions, tasking, and builds
- **Polymorphic builds** - Per-engagement IOC profiles: unique strings, paths, user agents, mutexes, and pipe names, validated against YARA self-test rules
- **Layered evasion** - Indirect syscalls, patchless AMSI/ETW bypass, sleep obfuscation with heap encryption, stack spoofing, NTDLL unhooking
- **Multi-transport** - HTTPS, DNS (DoH/TXT/AAAA), SMB named pipes, TCP, and external C2 listeners with failover
- **Pivot and tunnel** - SOCKS, port forwarding, TCP/pipe pivots, P2P mesh relay
- **BOF ecosystem** - Full Cobalt Strike BOF/COFF loader compatibility

## Architecture

```
Jager-C2/
├── teamserver/        Go gRPC teamserver (sessions, task queue, listeners, loot, RBAC)
├── implant/           C Stage-1 Windows implant (beacon loop, evasion, BOF loader)
├── implant-linux/     C Stage-1 Linux ELF implant (libcurl transport, pivot, post-ex)
├── implant-go/        Go implant prototype
├── builder/           Python polymorphic build pipeline (IOC profiles, YARA)
├── mcp/               Python MCP server (agentic interface, ~60 tools)
├── client/            Go operator CLI
├── profiles/          Malleable C2 profile schemas and arsenal
├── deploy/            Docker Compose, Dockerfiles, Terraform
├── scripts/           CI and end-to-end pipeline scripts
├── tests/             Contract and integration test suites
├── docs/              Architecture and operator documentation
└── yara/              YARA self-test rules
```

## Components

### Teamserver (Go)
- gRPC API with mTLS operator authentication
- Session and beacon management with long-poll task delivery
- Multi-transport listeners: HTTPS, DNS, SMB, TCP, external C2
- SQLite-backed loot store (credentials, targets, findings)
- REST management API with API-key auth and RBAC

### Stage-1 Implant - Windows (C)
- WinHTTP beacon loop with jitter and URL failover
- DNS transport (DoH/TXT/AAAA tunneling)
- SMB named-pipe P2P mesh relay
- Indirect syscalls (Hell's Gate / Halo's Gate)
- Patchless AMSI/ETW bypass (hardware breakpoint, page guard, or legacy patch)
- Threadless injection with module stomping
- Foliage / Ekko / Zilean sleep obfuscation with heap encryption
- CFG-aware stack spoofing and NTDLL unhooking
- Dynamic API resolution via PEB walk
- Post-ex: hashdump, credential harvest, lateral movement, privesc, token ops

### Stage-1 Implant - Linux (C)
- libcurl HTTPS beacon with malleable profiles
- Anti-analysis and process management
- Credential harvest, discovery, persistence
- SOCKS proxy and tunnel relay

### Build Pipeline (Python)
- Per-engagement IOC profiles (unique strings, paths, user agents)
- Compile-time config injection via `-D` flags
- YARA self-test validation against known C2 signatures
- AES encryption of Stage-1 for delivery
- Build metadata tracking with per-build nonces

### MCP Server (Python)
- FastMCP-based with ~60 tools
- Session, task, listener, build, and loot management
- OPSEC guard with noise budget enforcement

## Quick Start

### Local management lab

Follow [LOCAL_LAB.md](docs/LOCAL_LAB.md) for a loopback-only startup and health
check using the actual server flags. The Docker Compose deployment is
experimental and still requires authentication and clean-install validation.

On Windows, use the build script:

```powershell
.\build-implant.ps1 -C2URL "https://your-server:443" -Sleep 5 -Jitter 20 -OS windows
```

## MCP Integration

Add the MCP server to your agent harness:

```json
{
  "mcpServers": {
    "jager-c2": {
      "command": "python",
      "args": ["-m", "server"],
      "cwd": "/path/to/Jager-C2/mcp",
      "env": { "JAGER_MGMT_URL": "http://localhost:31338" }
    }
  }
}
```

## Configuration

| Variable | Purpose |
|----------|---------|
| `JAGER_MGMT_API_KEY` | REST management API authentication (auto-generated on first start if unset) |
| `JAGER_WORKSPACE` | Repo root for the profile engine and build artifacts |
| `JAGER_BUILDS` | Override build output directory |
| `JAGER_LOG_LEVEL` | Teamserver log level |

## Security Notes

- Never commit API keys or build secrets; generated material lives under `data/` and is gitignored
- Run the teamserver with TLS in production (`--mgmt-tls --cert <cert> --key <key>` for management TLS; configure `--ca` for gRPC mTLS)
- All `/mgmt/*` routes except `/mgmt/ping` require the `X-Jager-C2-Api-Key` or `Authorization: Bearer` header
- Rotate keys after operator turnover; each build gets a unique nonce and profile fingerprint, never reuse implants across engagements

## Development

```bash
# Run the CI pipeline (builds, tests, YARA validation)
./scripts/ci-pipeline.sh

# Go tests
cd teamserver && go test ./...

# Python tests
pytest tests/
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/OPERATOR_GUIDE.md](docs/OPERATOR_GUIDE.md) for details.

Development starts with docs, then failing tests, then implementation. See the
[workflow](docs/DEVELOPMENT.md), [test strategy](docs/TESTING.md), and
[issue Kanban](https://github.com/0xhackerfren/Jager-C2/issues/12). The existing
Projects board below has not been verified through the current connection.

Development workflow, board, and agent rules: [CONTRIBUTING.md](CONTRIBUTING.md), [AGENTS.md](AGENTS.md), and the [project kanban board](https://github.com/users/0xhackerfren/projects/2) track all open work.

## Roadmap

- AI BOF generation pipeline
- AI loader generation pipeline
- Linux parity: port forwarding, transport failover, DNS/SMB transports

## Known Limitations

- The MCP server's operator/engagement tooling (`mcp/tools/operator.py`) and the engagement profile engine (`builder/profile_engine.py`) import a shared profile library (`jager_shared`) that is not yet included in this repository. These modules require components outside this repository. Other components have failing build/test stages; see the release readiness checklist. CLI task shell/upload/download currently print messages, several list commands return empty tables, and campaign/AI tools include placeholders. Do not treat registration as support.

## License

[MIT](LICENSE)