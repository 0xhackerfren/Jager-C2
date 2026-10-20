# Jager-C2 Architecture

## Overview

Jager-C2 is an agentic-first Command and Control framework designed for professional red team operations. It provides feature parity with Cobalt Strike and Sliver while adding AI-native capabilities and per-engagement polymorphic evasion.

## Component Architecture

```
+-------------------+     gRPC      +-------------------+
|   Operator CLI    | <-----------> |    Teamserver     |
|   (Go cobra)     |               |    (Go + gRPC)    |
+-------------------+               +-------------------+
                                           |
+-------------------+     gRPC      +------+------+
|   MCP Server      | <-----------> |  Listeners  |
|   (Python)        |               +-------------+
+-------------------+               | HTTPS | DNS |
        |                           | SMB   | TCP |
        v                           +------+------+
+-------------------+                      |
|   AI Agent        |               +------v------+
|   (Cursor/LLM)   |               |   Implant   |
+-------------------+               |   (C/ASM)   |
                                    +-------------+
```

## Teamserver (Go)

The teamserver is the core orchestration engine:

- **gRPC API** (`proto/`): Defines all service contracts
- **Listeners** (`teamserver/internal/listeners/`): Protocol handlers
  - HTTPS with malleable profiles
  - DNS (TXT, AAAA, A record encoding)
  - SMB named pipes
  - Raw TCP/TLS
- **Session Manager** (`teamserver/internal/sessions/`): Implant lifecycle
- **Task Queue** (`teamserver/internal/tasks/`): Asynchronous task dispatch
- **Auth/RBAC** (`teamserver/internal/auth/`): mTLS + role-based access
- **Campaign Tracker** (`teamserver/internal/campaign/`): Operation logging

## Implant (C)

The implant is written in C for maximum control over evasion:

### Evasion Engine (`implant/src/evasion/`)
- **Indirect Syscalls** (Hell's Gate / Halo's Gate)
- **Sleep Encryption** (Ekko/FOLIAGE technique)
- **ETW/AMSI Bypass**
- **Process Injection** (module stomp, threadless, early bird, map view)

### Post-Exploitation (`implant/src/postex/`)
- **Credentials**: SAM, Credential Manager, tokens, browser creds
- **Discovery**: Process list, netstat, AV detection, environment
- **Lateral Movement**: WMI, SCM, DCOM, schtasks, SMB exec
- **Persistence**: Registry, services, schtasks, WMI events, COM hijack
- **Privilege Escalation**: Token abuse, UAC bypass, unquoted paths
- **BOF Loader**: Execute Cobalt Strike BOFs in-process

### Pivot (`implant/src/pivot/`)
- **SOCKS5 Proxy**: Full SOCKS5 with auth
- **Port Forwarding**: Local and reverse
- **Named Pipe Relay**: SMB-based pivoting

### Platform Support (`implant/src/platform/`)
- **Windows** (primary): Full feature set
- **Linux**: ELF with memfd_create, /proc evasion, cron/systemd persistence
- **macOS** (planned): Mach-O with launchd persistence

## MCP Server (Python)

The MCP server exposes all C2 functionality as tools for AI agents:

### Tool Modules (`mcp/tools/`)
- `sessions.py`: Session management (6 tools)
- `execution.py`: Command execution (6 tools)
- `credentials.py`: Credential operations (15 tools)
- `lateral.py`: Lateral movement (11 tools)
- `evasion.py`: Defense evasion (10 tools)
- `pivot.py`: Proxy/tunnel management (9 tools)
- `builders.py`: Payload generation (9 tools)
- `campaign.py`: Campaign tracking (9 tools)
- `ai_native.py`: AI-generated tooling (8 tools)

Total: 83+ tools (expanding to 200+)

### Registry (`mcp/tools/registry.py`)
Dynamic tool discovery and dispatch. Modules self-register their tools and handlers.

## Build Engine (Python)

### Polymorphic Engine (`builder/polymorphic.py`)
- C source AST mutation
- Variable/function renaming
- String encryption (XOR rolling, RC4, AES-CTR)
- Dead code insertion
- Opaque predicates
- Junk API calls
- Build manifest tracking

### Format Generator (`builder/formats.py`)
Multi-format output:
- EXE, DLL, Shellcode (sRDI)
- HTA, VBA Macro, MSI, CPL, XLL
- PowerShell, C#
- ISO/IMG containers
- LNK shortcuts

## Deployment

### Docker (`deploy/`)
- `docker-compose.yml`: Full stack (teamserver + MCP + builder + redirector)
- Isolated internal network for C2 components
- nginx redirector for domain fronting

### Terraform (`deploy/terraform/`)
- AWS VPC with public/private subnets
- Teamserver in private subnet
- Redirectors in public subnet with elastic IPs
- Security groups restrict operator access

## Security Model

1. **Operator Auth**: mTLS certificates with role-based permissions
2. **Implant Auth**: Pre-shared keys embedded at build time
3. **Kill Date**: Implant self-destructs after engagement end date
4. **Session Journal**: All artifacts tracked for cleanup
5. **IOC Profile**: Unique per-engagement binary fingerprint
