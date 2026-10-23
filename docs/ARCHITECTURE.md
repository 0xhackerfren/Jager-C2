# Jager-C2 Architecture

> This is a source map, not a validated support matrix. See
> [release readiness](RELEASE_READINESS.md) for current failures and limitations.

## Overview

Jager-C2 is an agentic-first command-and-control framework for authorized red team operations. It pairs a Go gRPC teamserver with hardened C implants, a polymorphic Python build pipeline, and an MCP server that exposes the framework to AI agents.

## Component Architecture

```
+-------------------+  REST /mgmt/*  +-------------------+
|   Operator CLI    | <------------> |    Teamserver     |
|   (Go cobra)      |      HTTP      |    (Go + gRPC)    |
+-------------------+                +---------+---------+
        |                                      |
+-------------------+  REST /mgmt/*  +--------v--------+
|   MCP Server      | <------------> |    Listeners    |
|   (Python)        |      HTTP      | HTTPS/DNS/SMB/  |
+-------------------+                | TCP/External    |
        |                            +---------+-------+
+-------------------+                          |
|   AI Agent        |                +---------v-------+
|   (any MCP host)  |                |     Implant     |
+-------------------+                |   (C + ASM)     |
                                     +-----------------+
```

Both the operator CLI and the MCP server talk to the teamserver over the REST
management API (default port 31338). Operators authenticate with the
`X-Jager-C2-Api-Key` header; implants connect to listeners on separate ports.

## Teamserver (Go)

The teamserver is the core orchestration engine (`teamserver/`):

- **gRPC API** (`proto/`): Service contracts for operator clients; generated stubs in `proto/jagerpb/`
- **Listeners** (`internal/listeners/`): HTTPS with malleable profiles, DNS (TXT/AAAA tunneling), SMB named pipes, raw TCP, and external C2; failover orchestration across transports
- **Session Manager** (`internal/sessions/`): Implant lifecycle and persistence
- **Task Queue** (`internal/tasks/`): Long-poll task dispatch
- **Auth/RBAC** (`internal/auth/`, `internal/server/`): API-key and mTLS auth with role-based permissions
- **Build Engine** (`internal/builds/`): Drives the Python polymorphic builder
- **Malleable Profiles** (`internal/malleable/`): CS-style profile parsing and transforms
- **Pivot/Tunnel** (`internal/pivot/`): SOCKS relay, port forwarding, reverse port forwarding, tunnel frames
- **Redirectors** (`internal/redirectors/`): Generates nginx redirector configurations
- **Loot Store** (`internal/loot/`): SQLite-backed credentials, targets, findings
- **Campaign Tracker** (`internal/campaign/`): Operation logging
- **Scripting** (`internal/scripting/`): Hook engine (Lua-style hooks from `hooks/`)

## Implant - Windows (C)

`implant/` is the Stage-1 Windows implant:

### Evasion Engine (`src/evasion/`)
- Indirect syscalls (Hell's Gate / Halo's Gate)
- Sleep obfuscation (Ekko / Foliage / Zilean) with heap encryption
- Patchless AMSI/ETW bypass (hardware breakpoint, page guard, or legacy patch)
- Process injection: module stomping, threadless injection, early bird, process hollowing
- NTDLL unhooking, IAT obfuscation, stack spoofing, PPID spoofing

### Post-Exploitation (`src/postex/`)
- Credentials: SAM, LSASS, Credential Manager, tokens, browser creds, DPAPI
- Discovery: process list, netstat, AV detection, environment
- Lateral movement: WMI, SCM, DCOM, schtasks, SMB exec
- Persistence: registry, services, schtasks, WMI events, COM hijack
- Privilege escalation: token abuse, UAC bypass, unquoted paths
- BOF loader: executes Cobalt Strike BOFs in-process

### Pivot (`src/pivot/`)
- SOCKS5 proxy, local/reverse port forwarding, named-pipe relay, TCP pivot

### Transports (`src/core/`)
- HTTPS (WinHTTP), DNS tunneling, SMB pipes, TCP, transport failover

## Implant - Linux (C)

`implant-linux/` is the Stage-1 Linux ELF implant: libcurl HTTPS beacon with
malleable profiles, anti-analysis, persistence (cron/systemd), SOCKS proxy,
tunnel relay, and memfd-based module loading.

## MCP Server (Python)

The MCP server (`mcp/`) exposes the framework as tools for AI agents. Tool
modules self-register through `tools/registry.py` and are bridged onto FastMCP
by `registry_bridge.py`. Session, tasking, listener, build, credential, pivot,
and loot tools talk to the teamserver management API over HTTP.

Module wiring status is documented in `mcp/tools/UNWIRED_README.md`.

## Build Pipeline (Python)

`builder/` implements the polymorphic build pipeline:

- **Profile engine** (`profile_engine.py`): deterministic per-engagement IOC derivation (unwired until `jager_shared` ships - see README Known Limitations)
- **Polymorphic engine** (`polymorphic.py`): source mutation, identifier renaming, string encryption, dead code, opaque predicates
- **Format generator** (`formats.py`): EXE, DLL, shellcode, HTA, VBA, MSI, CPL, XLL, ISO/IMG, LNK, PowerShell, C# outputs
- **Builder CLI** (`build_implant.py`): compile-time config injection via `-D` flags, AES delivery encryption, build manifests

## Deployment

### Docker (`deploy/`)
- `docker-compose.yml`: teamserver + MCP server on an isolated bridge network
- `Dockerfile.teamserver`: multi-stage Go build into a minimal Alpine image

### Terraform (`deploy/terraform/`)
- AWS VPC with public/private subnets, teamserver in private subnet,
  redirector instances in public subnets, security groups scoped to operator IPs

## Security Model

Management authentication fails closed when its key store or RBAC manager is missing; protected routes require a valid key and permission checks require an authenticated operator. See [management authentication](management-authentication.md).

1. Operator auth: API keys (REST) and mTLS certificates (gRPC) with role-based permissions
2. Implant auth: per-build crypto material bound at build time
3. Kill date: implants self-destruct after engagement end
4. Session crypto: encrypted tasking channel between teamserver and implants
5. IOC profiles: unique per-engagement wire signature
6. Audit trail: management actions logged via `/mgmt/audit`