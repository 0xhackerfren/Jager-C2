"""Pivot and proxy tools for Jager-C2 MCP server."""

from typing import Any, Dict

TOOLS = [
    {
        "name": "pivot_socks_start",
        "description": "Start a SOCKS5 proxy on the implant (routes traffic through target)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "port": {"type": "integer", "default": 1080}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "pivot_socks_stop",
        "description": "Stop the SOCKS5 proxy on the implant",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "pivot_portfwd_add",
        "description": "Add a local port forward (listen on implant, forward to remote)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "local_port": {"type": "integer"},
                "remote_host": {"type": "string"},
                "remote_port": {"type": "integer"}
            },
            "required": ["session_id", "local_port", "remote_host", "remote_port"]
        }
    },
    {
        "name": "pivot_portfwd_remove",
        "description": "Remove a port forward",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "local_port": {"type": "integer"}
            },
            "required": ["session_id", "local_port"]
        }
    },
    {
        "name": "pivot_portfwd_list",
        "description": "List all active port forwards",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "pivot_rportfwd_add",
        "description": "Add a reverse port forward (listen on teamserver, forward through implant to remote)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "teamserver_port": {"type": "integer"},
                "target_host": {"type": "string"},
                "target_port": {"type": "integer"}
            },
            "required": ["session_id", "teamserver_port", "target_host", "target_port"]
        }
    },
    {
        "name": "pivot_pipe_link",
        "description": "Link to a child implant via named pipe (P2P mesh)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target_host": {"type": "string"},
                "pipe_name": {"type": "string"}
            },
            "required": ["session_id", "target_host", "pipe_name"]
        }
    },
    {
        "name": "pivot_pipe_unlink",
        "description": "Unlink a P2P pipe connection",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "child_session_id": {"type": "string"}
            },
            "required": ["session_id", "child_session_id"]
        }
    },
    {
        "name": "pivot_tcp_link",
        "description": "Link to a child implant via TCP (P2P mesh)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target_host": {"type": "string"},
                "target_port": {"type": "integer"}
            },
            "required": ["session_id", "target_host", "target_port"]
        }
    },
]


async def handle(tool_name: str, args: Dict[str, Any], client) -> Dict[str, Any]:
    """Handle pivot/proxy tool calls."""
    try:
        from task_client import queue_task
        from task_types import TaskType
    except ImportError:
        from ..task_client import queue_task
        from ..task_types import TaskType

    session_id = args.get("session_id", "")

    pivot_map = {
        "pivot_socks_start": TaskType.TASK_SOCKS_START,
        "pivot_socks_stop": TaskType.TASK_SOCKS_STOP,
        "pivot_portfwd_add": TaskType.TASK_PORTFWD_ADD,
        "pivot_portfwd_remove": TaskType.TASK_PORTFWD_RM,
        "pivot_pipe_link": TaskType.TASK_P2P_CONNECT,
        "pivot_pipe_unlink": TaskType.TASK_P2P_RELAY,
        "pivot_tcp_link": TaskType.TASK_P2P_CONNECT,
    }

    if tool_name in pivot_map:
        return await queue_task(client, session_id, pivot_map[tool_name], args)

    if tool_name in ("pivot_portfwd_list", "pivot_rportfwd_add"):
        return await queue_task(client, session_id, TaskType.TASK_PORTFWD_ADD, {"variant": tool_name, **args})

    return {"error": f"Unknown tool: {tool_name}"}
