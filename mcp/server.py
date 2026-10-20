"""Jager-C2 MCP Server - modular registry-backed agent interface."""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_JAGER_ROOT = _SCRIPT_DIR.parent
_WORKSPACE = _JAGER_ROOT.parent
_DEBUG_LOG = _WORKSPACE / ".cursor" / "debug-11ac4f.log"


def _agent_log(message: str, data: dict, hypothesis_id: str) -> None:
    # #region agent log
    try:
        payload = {
            "sessionId": "11ac4f",
            "timestamp": int(time.time() * 1000),
            "location": "jager/mcp/server.py",
            "message": message,
            "data": data,
            "hypothesisId": hypothesis_id,
            "runId": os.environ.get("JAGER_RESTART", "startup"),
        }
        with _DEBUG_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")
    except OSError:
        pass
    # #endregion


def _sanitize_sys_path() -> None:
    """Remove jager paths that shadow the pip 'mcp' package (jager/mcp -> import mcp)."""
    blocked = {_JAGER_ROOT.resolve(), _SCRIPT_DIR.resolve()}
    cleaned: list[str] = []
    for entry in sys.path:
        if not entry:
            cleaned.append(entry)
            continue
        try:
            if Path(entry).resolve() in blocked:
                continue
        except OSError:
            pass
        cleaned.append(entry)
    sys.path[:] = cleaned
    if str(_SCRIPT_DIR) not in sys.path:
        sys.path.append(str(_SCRIPT_DIR))


_agent_log(
    "pre-sanitize startup",
    {"sys_path_head": sys.path[:6], "cwd": os.getcwd(), "pythonpath": os.environ.get("PYTHONPATH", "")},
    "H2",
)
_sanitize_sys_path()

try:
    import mcp as _pip_mcp  # noqa: F401

    _mcp_origin = getattr(_pip_mcp, "__file__", "unknown")
except Exception as exc:  # pragma: no cover - debug only
    _mcp_origin = f"import failed: {exc}"

_agent_log("post-sanitize mcp resolve", {"mcp_origin": _mcp_origin, "sys_path_head": sys.path[:6]}, "H2")

from fastmcp import FastMCP

_agent_log("fastmcp import ok", {"fastmcp": "loaded"}, "H3")

try:
    from .grpc_client import GRPCClient
    from .registry_bridge import register_legacy_aliases, register_registry_tools
    from .tools.registry import registry
except ImportError:
    from grpc_client import GRPCClient
    from registry_bridge import register_legacy_aliases, register_registry_tools
    from tools.registry import registry

logger = logging.getLogger("jager.mcp")
mcp = FastMCP("jager")


@dataclass
class OpsecGuard:
    mode: str = "balanced"
    blocked_actions: list = field(default_factory=list)
    noise_budget: int = 100

    def check(self, action: str, target: str, risk_level: int) -> tuple[bool, str]:
        if action in self.blocked_actions:
            return False, f"Action '{action}' is blocked by OPSEC policy"
        if risk_level > self.noise_budget:
            return False, f"Risk level {risk_level} exceeds noise budget {self.noise_budget}"
        return True, "allowed"


client = GRPCClient()
opsec = OpsecGuard(mode=os.environ.get("JAGER_OPSEC_MODE", "aggressive"), noise_budget=200)


def _client_factory():
    return client


async def _teamserver_up() -> bool:
    result = await client.call("Ping")
    if isinstance(result, dict):
        if result.get("success") is False or result.get("error"):
            return False
        return True
    return bool(result)


def _register_meta_tools() -> None:
    @mcp.tool()
    async def ping() -> str:
        """Check teamserver connectivity. When offline, operator_exec runs locally."""
        result = await client.call("Ping")
        if isinstance(result, dict) and (result.get("success") is False or result.get("error")):
            registry.load_all()
            return json.dumps(
                {
                    "teamserver": "offline",
                    "operator_mode": "local",
                    "mgmt_url": client.base_url,
                    "routing": {
                        "jump_host_commands": "operator_exec",
                        "protocol_commands": "operator_protocol or jagerexec dispatch_protocol",
                        "implant_commands": "exec_* / lateral_* (requires session_id)",
                    },
                    "registry_tools": registry.tool_count,
                    "note": "Start teamserver with docker-compose in jager/deploy when available.",
                },
                indent=2,
            )
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def get_opsec_status() -> str:
        """Get current OPSEC mode and noise budget."""
        return json.dumps(
            {
                "mode": opsec.mode,
                "noise_budget": opsec.noise_budget,
                "blocked_actions": opsec.blocked_actions,
            },
            indent=2,
        )

    @mcp.tool()
    async def set_opsec_mode(mode: str) -> str:
        """Set OPSEC mode: stealth, balanced, or aggressive."""
        if mode not in ("stealth", "balanced", "aggressive"):
            return json.dumps({"error": "Invalid mode. Use: stealth, balanced, aggressive"})
        opsec.mode = mode
        opsec.noise_budget = {"stealth": 30, "balanced": 100, "aggressive": 200}[mode]
        return json.dumps({"status": "ok", "mode": mode, "noise_budget": opsec.noise_budget})

    @mcp.tool()
    async def list_c2_tools(category: str = "") -> str:
        """List all Jager-C2 MCP tools, optionally filtered by name prefix (session, exec, cred, lateral, pivot, build, campaign, ai)."""
        registry.load_all()
        tools = registry.get_all_tools()
        if category:
            prefix = category.rstrip("_") + "_"
            tools = [t for t in tools if t["name"].startswith(prefix) or category in t["name"]]
        grouped: dict[str, list[str]] = {}
        for tool in tools:
            name = tool["name"]
            key = name.split("_", 1)[0] if "_" in name else "misc"
            grouped.setdefault(key, []).append(name)
        return json.dumps(
            {
                "total": len(tools),
                "categories": grouped,
                "tools": [{"name": t["name"], "description": t.get("description", "")} for t in tools],
            },
            indent=2,
        )

    @mcp.tool()
    async def get_c2_context() -> str:
        """Return teamserver URL, workspace paths, and tool counts for agent orientation."""
        registry.load_all()
        return json.dumps(
            {
                "mgmt_url": client.base_url,
                "teamserver": os.environ.get("JAGER_TEAMSERVER", "127.0.0.1:31337"),
                "wsl_distro": os.environ.get("JAGER_WSL_DISTRO", ""),
                "workspace": os.environ.get("JAGER_WORKSPACE", ""),
                "evidence_dir": os.environ.get("JAGER_EVIDENCE", ""),
                "builds_dir": os.environ.get("JAGER_BUILDS", ""),
                "registry_tool_count": registry.tool_count,
                "operator_mode": "local" if not await _teamserver_up() else "connected",
                "routing": {
                    "all_jump_host_commands": "operator_exec",
                    "protocol_via_c2": "operator_protocol",
                    "protocol_via_jagerexec": "dispatch_protocol",
                },
                "opsec_mode": opsec.mode,
            },
            indent=2,
        )

    @mcp.tool()
    async def get_engagement_summary() -> str:
        """Get teamserver engagement summary (sessions, targets, findings)."""
        result = await client.call("GetEngagementSummary")
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def start_listener(transport: str = "https", host: str = "0.0.0.0", port: int = 443) -> str:
        """Start a new C2 listener on the teamserver."""
        result = await client.call("StartListener", transport=transport, host=host, port=port)
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def stop_listener(listener_id: str) -> str:
        """Stop and remove a C2 listener."""
        result = await client.call("StopListener", listener_id=listener_id)
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def list_listeners() -> str:
        """List all active C2 listeners."""
        result = await client.call("ListListeners")
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def add_target(ip: str, hostname: str = "", os_info: str = "", notes: str = "") -> str:
        """Register a discovered target host in the C2 database."""
        result = await client.call("AddTarget", ip=ip, hostname=hostname, os_info=os_info, notes=notes)
        if isinstance(result, dict) and result.get("error") == "not connected":
            ws = Path(os.environ.get("JAGER_WORKSPACE", os.getcwd()))
            local_log = ws / "logs" / "c2-local-targets.jsonl"
            local_log.parent.mkdir(parents=True, exist_ok=True)
            entry = {"ip": ip, "hostname": hostname, "os_info": os_info, "notes": notes}
            local_log.open("a").write(json.dumps(entry) + "\n")
            return json.dumps({"mode": "local", "stored": entry, "path": str(local_log)}, indent=2)
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def list_targets() -> str:
        """List all known targets in the engagement."""
        result = await client.call("ListTargets")
        if isinstance(result, dict) and result.get("error") == "not connected":
            ws = Path(os.environ.get("JAGER_WORKSPACE", os.getcwd()))
            local_log = ws / "logs" / "c2-local-targets.jsonl"
            targets = []
            if local_log.exists():
                for line in local_log.read_text().splitlines():
                    if line.strip():
                        targets.append(json.loads(line))
            return json.dumps({"mode": "local", "targets": targets}, indent=2)
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def add_finding(title: str, severity: str, description: str, affected_host: str = "", cve: str = "") -> str:
        """Log a security finding discovered during the engagement."""
        result = await client.call(
            "AddFinding",
            title=title,
            severity=severity,
            description=description,
            affected_host=affected_host,
            cve=cve,
        )
        return json.dumps(result, indent=2)


registry_count = register_registry_tools(mcp, registry, _client_factory, opsec)
alias_count = register_legacy_aliases(mcp, registry, _client_factory, opsec)
logger.info("Jager-C2 MCP ready: %d registry tools, %d legacy aliases", registry_count, alias_count)

_register_meta_tools()


def main():
    _agent_log("main() entered", {"transport": os.environ.get("MCP_TRANSPORT", "stdio")}, "H1")
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "stdio":
        mcp.run()
    else:
        import uvicorn

        app = mcp.sse_app()
        host = os.environ.get("MCP_HOST", "0.0.0.0")
        port = int(os.environ.get("MCP_PORT", "8000"))
        uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
