"""Payload generation and build tools for Jager-C2 MCP server."""

from typing import Any, Dict

TOOLS = [
    {
        "name": "build_implant",
        "description": "Generate a new implant binary with specified configuration",
        "inputSchema": {
            "type": "object",
            "properties": {
                "listener_id": {"type": "string"},
                "os": {"type": "string", "enum": ["windows", "linux", "macos"], "default": "windows"},
                "arch": {"type": "string", "enum": ["x64", "x86"], "default": "x64"},
                "format": {"type": "string", "enum": ["exe", "dll", "shellcode", "service"], "default": "exe"},
                "profile": {"type": "string", "description": "IOC profile name"},
                "sleep": {"type": "integer", "default": 60},
                "jitter": {"type": "integer", "default": 20},
                "kill_date": {"type": "string", "description": "ISO date after which implant self-destructs"},
                "evasion": {
                    "type": "object",
                    "properties": {
                        "sleep_encrypt": {"type": "boolean", "default": True},
                        "etw_patch": {"type": "boolean", "default": True},
                        "amsi_patch": {"type": "boolean", "default": True},
                        "syscalls": {"type": "boolean", "default": True},
                        "unhook": {"type": "boolean", "default": False}
                    }
                }
            },
            "required": ["listener_id"]
        }
    },
    {
        "name": "build_stager",
        "description": "Generate a small Stage-0 stager (fetches full implant)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "listener_id": {"type": "string"},
                "format": {"type": "string", "enum": ["exe", "dll", "shellcode", "hta", "vba", "msi"], "default": "shellcode"},
                "arch": {"type": "string", "enum": ["x64", "x86"], "default": "x64"},
                "profile": {"type": "string"}
            },
            "required": ["listener_id"]
        }
    },
    {
        "name": "build_shellcode",
        "description": "Convert an implant/stager to position-independent shellcode (sRDI)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "build_id": {"type": "string", "description": "Existing build to convert"},
                "function_name": {"type": "string", "default": "DllMain"},
                "user_data": {"type": "string", "description": "Data to pass to shellcode entry"}
            },
            "required": ["build_id"]
        }
    },
    {
        "name": "build_bof",
        "description": "Compile a BOF from C source code (AI-generated or provided)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_code": {"type": "string", "description": "C source code for the BOF"},
                "source_path": {"type": "string", "description": "Path to C source file"},
                "output_name": {"type": "string"}
            }
        }
    },
    {
        "name": "build_loader",
        "description": "Generate a custom loader with specified injection technique",
        "inputSchema": {
            "type": "object",
            "properties": {
                "payload_build_id": {"type": "string"},
                "technique": {
                    "type": "string",
                    "enum": ["module_stomp", "threadless", "early_bird", "process_ghost", "phantom_dll"],
                    "default": "module_stomp"
                },
                "target_process": {"type": "string", "default": "dllhost.exe"},
                "format": {"type": "string", "enum": ["exe", "dll", "cpl"], "default": "exe"}
            },
            "required": ["payload_build_id"]
        }
    },
    {
        "name": "build_list",
        "description": "List all generated builds/payloads",
        "inputSchema": {
            "type": "object",
            "properties": {
                "type_filter": {"type": "string", "enum": ["implant", "stager", "shellcode", "bof", "loader", ""]}
            }
        }
    },
    {
        "name": "build_download",
        "description": "Download a generated build artifact",
        "inputSchema": {
            "type": "object",
            "properties": {
                "build_id": {"type": "string"},
                "output_path": {"type": "string"}
            },
            "required": ["build_id"]
        }
    },
    {
        "name": "build_profile_list",
        "description": "List available IOC/malleable profiles",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "build_profile_create",
        "description": "Create a new malleable C2 profile",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "based_on": {"type": "string", "description": "Base profile to derive from"},
                "overrides": {"type": "object", "description": "Profile fields to override"}
            },
            "required": ["name"]
        }
    },
]


async def handle(tool_name: str, args: Dict[str, Any], client) -> Dict[str, Any]:
    """Handle build/generation tool calls."""
    if tool_name == "build_implant":
        return await client.generate_implant(args)
    elif tool_name == "build_stager":
        return await client.generate_stager(args)
    elif tool_name == "build_list":
        return {"builds": []}  # Placeholder
    elif tool_name == "build_download":
        build_id = args.get("build_id", "")
        return {"status": "ok", "build_id": build_id}
    elif tool_name == "build_profile_list":
        return {"profiles": ["default", "amazon", "microsoft"]}

    return {"status": "ok", "args": args}
