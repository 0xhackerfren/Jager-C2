"""Session management tools for Jager-C2 MCP server."""

from typing import Any, Dict, List

TOOLS = [
    {
        "name": "session_list",
        "description": "List all active interactive sessions",
        "inputSchema": {
            "type": "object",
            "properties": {
                "alive_only": {"type": "boolean", "default": True}
            }
        }
    },
    {
        "name": "session_interact",
        "description": "Get detailed information about a specific session",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "session_kill",
        "description": "Kill/terminate a session",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "force": {"type": "boolean", "default": False}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "session_sleep",
        "description": "Change sleep interval and jitter for a beacon",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "interval": {"type": "integer", "description": "Sleep interval in seconds"},
                "jitter": {"type": "integer", "description": "Jitter percentage (0-99)"}
            },
            "required": ["session_id", "interval"]
        }
    },
    {
        "name": "session_note",
        "description": "Add a note to a session for tracking",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "note": {"type": "string"}
            },
            "required": ["session_id", "note"]
        }
    },
    {
        "name": "beacon_list",
        "description": "List all beacon (callback-based) sessions",
        "inputSchema": {
            "type": "object",
            "properties": {
                "alive_only": {"type": "boolean", "default": True}
            }
        }
    },
]


async def handle(tool_name: str, args: Dict[str, Any], client) -> Dict[str, Any]:
    """Handle session management tool calls."""
    if tool_name == "session_list":
        return await client.get_sessions(args.get("alive_only", True))
    elif tool_name == "session_interact":
        return await client.interact_session(args["session_id"])
    elif tool_name == "session_kill":
        return await client.kill_session(args["session_id"], args.get("force", False))
    elif tool_name == "session_sleep":
        return await client.set_sleep(args["session_id"], args["interval"], args.get("jitter", 0))
    elif tool_name == "session_note":
        return {"status": "ok", "note": args["note"]}
    elif tool_name == "beacon_list":
        return await client.get_beacons(args.get("alive_only", True))
    return {"error": f"Unknown tool: {tool_name}"}
