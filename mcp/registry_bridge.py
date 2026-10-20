"""Register modular C2 tools from ToolRegistry onto FastMCP."""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("jager.registry_bridge")

_TYPE_MAP = {
    "string": "str",
    "integer": "int",
    "number": "float",
    "boolean": "bool",
    "array": "list",
    "object": "dict",
}


def _format_default(value: Any) -> str:
    return repr(value)


def _param_annotation(prop: dict[str, Any]) -> str:
    return _TYPE_MAP.get(prop.get("type", "string"), "str")


def _build_handler(
    name: str,
    description: str,
    input_schema: dict[str, Any],
    registry,
    client_factory: Callable[[], Any],
    opsec=None,
):
    """Build an async handler with an explicit signature (fastmcp rejects **kwargs)."""
    properties: dict[str, Any] = input_schema.get("properties") or {}
    required = set(input_schema.get("required") or [])

    ordered = sorted(properties.items(), key=lambda item: (item[0] not in required, item[0]))
    params: list[str] = []
    kwargs_entries: list[str] = []
    for pname, pdef in ordered:
        ann = _param_annotation(pdef)
        if pname in required:
            params.append(f"{pname}: {ann}")
        elif "default" in pdef:
            params.append(f"{pname}: {ann} = {_format_default(pdef['default'])}")
        else:
            params.append(f"{pname}: {ann} | None = None")
        kwargs_entries.append(f'"{pname}": {pname}')

    sig = ", ".join(params)
    kwargs_literal = "{" + ", ".join(kwargs_entries) + "}"

    opsec_guard = ""
    if opsec is not None:
        opsec_guard = """
    if __opsec__ is not None and __tool_name__.startswith(("exec_", "lateral_", "cred_dump_", "evasion_")):
        __risk__ = 60 if __tool_name__.startswith("cred_dump_") else 50
        __allowed__, __reason__ = __opsec__.check(__tool_name__, __kwargs__.get("session_id", ""), __risk__)
        if not __allowed__:
            return json.dumps({"error": __reason__}, indent=2)
"""

    src = f"""
async def {name}({sig}) -> str:
    __kwargs__ = {kwargs_literal}
    __kwargs__ = {{k: v for k, v in __kwargs__.items() if v is not None}}
{opsec_guard}
    __client__ = __client_factory__()
    __result__ = await __registry__.dispatch(__tool_name__, __kwargs__, __client__)
    return json.dumps(__result__, indent=2, default=str)
"""
    namespace: dict[str, Any] = {
        "json": json,
        "__registry__": registry,
        "__client_factory__": client_factory,
        "__opsec__": opsec,
        "__tool_name__": name,
    }
    exec(src, namespace)  # noqa: S102 — generated handler from JSON schema
    fn = namespace[name]
    fn.__doc__ = description
    return fn


def register_registry_tools(
    mcp: FastMCP,
    registry,
    client_factory: Callable[[], Any],
    opsec=None,
) -> int:
    """Dynamically expose every tool in ToolRegistry as an MCP tool."""
    registry.load_all()
    count = 0

    for tool_def in registry.get_all_tools():
        tool_name = tool_def["name"]
        description = tool_def.get("description", "")
        input_schema = tool_def.get("inputSchema") or {"type": "object", "properties": {}}

        handler = _build_handler(tool_name, description, input_schema, registry, client_factory, opsec)
        mcp.tool(name=tool_name, description=description)(handler)
        count += 1

    logger.info("Registered %d registry tools on MCP server", count)
    return count


LEGACY_ALIASES: dict[str, str] = {
    "list_sessions": "session_list",
    "list_beacons": "beacon_list",
    "interact_session": "session_interact",
    "kill_session": "session_kill",
    "set_sleep": "session_sleep",
    "shell": "exec_shell",
    "powershell": "exec_powershell",
    "execute_bof": "exec_bof",
    "execute_assembly": "exec_assembly",
    "inject_shellcode": "exec_shellcode",
    "generate_implant": "build_implant",
    "generate_stager": "build_stager",
    "list_builds": "build_list",
    "add_credential": "cred_vault_add",
    "list_credentials": "cred_vault_list",
}


def _normalize_alias_kwargs(alias: str, kwargs: dict[str, Any]) -> dict[str, Any]:
    if alias == "shell":
        return {"session_id": kwargs.get("session_id", ""), "command": kwargs.get("command", "")}
    if alias == "powershell":
        return {
            "session_id": kwargs.get("session_id", ""),
            "script": kwargs.get("command", kwargs.get("script", "")),
        }
    if alias == "execute_bof":
        return {
            "session_id": kwargs.get("session_id", ""),
            "bof_path": kwargs.get("bof_path", ""),
            "arguments": kwargs.get("args", kwargs.get("arguments", "")),
        }
    if alias == "execute_assembly":
        return {
            "session_id": kwargs.get("session_id", ""),
            "assembly_path": kwargs.get("assembly_path", ""),
            "arguments": kwargs.get("args", kwargs.get("arguments", "")),
        }
    if alias == "inject_shellcode":
        return {
            "session_id": kwargs.get("session_id", ""),
            "shellcode_path": kwargs.get("shellcode_path", ""),
            "target_pid": kwargs.get("pid", kwargs.get("target_pid", 0)),
        }
    if alias == "set_sleep":
        return {
            "session_id": kwargs.get("session_id", ""),
            "interval": kwargs.get("seconds", kwargs.get("interval", 60)),
            "jitter": kwargs.get("jitter", 20),
        }
    if alias == "generate_implant":
        return {
            "listener_id": kwargs.get("c2_url", kwargs.get("listener_id", "")),
            "arch": kwargs.get("arch", "x64"),
            "format": kwargs.get("format", "exe"),
            "sleep": kwargs.get("sleep", 60),
            "jitter": kwargs.get("jitter", 20),
        }
    if alias == "generate_stager":
        return {"listener_id": kwargs.get("c2_url", kwargs.get("listener_id", ""))}
    if alias == "add_credential":
        return {
            "username": kwargs.get("username", ""),
            "domain": kwargs.get("domain", ""),
            "credential_type": kwargs.get("credential_type", "password"),
            "credential_data": kwargs.get("secret", kwargs.get("credential_data", "")),
            "source": kwargs.get("source", "manual"),
        }
    return kwargs


def register_legacy_aliases(mcp: FastMCP, registry, client_factory: Callable[[], Any], opsec=None) -> int:
    """Backward-compatible tool names for older agent prompts and rules."""
    count = 0
    for legacy_name, registry_name in LEGACY_ALIASES.items():
        tool_def = registry.get_tool(registry_name)
        if not tool_def:
            continue
        description = f"[alias of {registry_name}] {tool_def.get('description', '')}"
        input_schema = tool_def.get("inputSchema") or {"type": "object", "properties": {}}

        properties = input_schema.get("properties") or {}
        required = set(input_schema.get("required") or [])
        params = []
        kwargs_entries = []
        for pname, pdef in sorted(properties.items(), key=lambda item: (item[0] not in required, item[0])):
            ann = _param_annotation(pdef)
            if pname in required:
                params.append(f"{pname}: {ann}")
            elif "default" in pdef:
                params.append(f"{pname}: {ann} = {_format_default(pdef['default'])}")
            else:
                params.append(f"{pname}: {ann} | None = None")
            kwargs_entries.append(f'"{pname}": {pname}')
        sig = ", ".join(params)
        kwargs_literal = "{" + ", ".join(kwargs_entries) + "}"
        opsec_guard = ""
        if opsec is not None:
            opsec_guard = """
    if __opsec__ is not None and __legacy_name__ in ("shell", "powershell", "inject_shellcode"):
        __allowed__, __reason__ = __opsec__.check(__legacy_name__, __kwargs__.get("session_id", ""), 50)
        if not __allowed__:
            return json.dumps({"error": __reason__}, indent=2)
"""
        src = f"""
async def {legacy_name}({sig}) -> str:
    __kwargs__ = {kwargs_literal}
    __kwargs__ = {{k: v for k, v in __kwargs__.items() if v is not None}}
    __kwargs__ = __normalize_alias__(__legacy_name__, __kwargs__)
{opsec_guard}
    __client__ = __client_factory__()
    __result__ = await __registry__.dispatch(__registry_name__, __kwargs__, __client__)
    return json.dumps(__result__, indent=2, default=str)
"""
        ns: dict[str, Any] = {
            "json": json,
            "__registry__": registry,
            "__client_factory__": client_factory,
            "__opsec__": opsec,
            "__legacy_name__": legacy_name,
            "__registry_name__": registry_name,
            "__normalize_alias__": _normalize_alias_kwargs,
        }
        exec(src, ns)  # noqa: S102
        handler = ns[legacy_name]
        handler.__doc__ = description

        mcp.tool(name=legacy_name, description=description)(handler)
        count += 1
    return count
