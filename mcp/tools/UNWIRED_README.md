# Jager-C2 Tools Registry

Tool modules are registered through `mcp/tools/registry.py` and exposed on the
MCP server by `mcp/registry_bridge.py` at startup.

## Module status

| Module | Status |
|--------|--------|
| `sessions.py` | Wired - session/interact/kill/sleep tools |
| `execution.py` | Wired - shell/powershell/filesystem/process tools |
| `credentials.py` | Wired - credential vault operations |
| `pivot.py` | Wired - SOCKS/port-forward/P2P tools |
| `evasion.py` | Wired - evasion task wrappers |
| `lateral.py` | Wired - lateral movement task wrappers |
| `builders.py` | Partially wired - build tools call the teamserver build API; some schema-only |
| `campaign.py` | Schema-level - returns placeholder IDs and a local JSONL store |
| `ai_native.py` | Schema-level - AI-assist scaffolding, not connected to live tasking |
| `operator.py` | Unwired - depends on the external `jagerexec` package (not in this repo) |

Modules marked "schema-level" or "unwired" register tools that either return
placeholder data or require components outside this repository. See README
"Known Limitations".

## Adding tools

1. Define a `TOOLS` list (dicts with `name`, `description`, `input_schema`) in the module.
2. Implement `async def handle(tool_name, args, client)`.
3. Add the module to `TOOL_MODULES` in `mcp/tools/registry.py` if new.