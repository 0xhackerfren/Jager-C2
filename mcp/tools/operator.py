"""Operator jump-host execution tools — ALL harness commands route here when no implant session."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import time
import importlib.util
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


def _check_operator_exec(command: str, tool: str) -> tuple[bool, str | None, dict | None]:
    ws = _workspace()
    mod_path = ws / "mcp_servers" / "command_routing.py"
    spec = importlib.util.spec_from_file_location("command_routing", mod_path)
    if spec is None or spec.loader is None:
        return True, None, None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.check_operator_exec(command, tool)

TOOLS = [
    {
        "name": "operator_exec",
        "description": (
            "Execute a command on the operator jump host with full audit logging. "
            "MANDATORY for nmap, curl, dig, wpscan, openvpn, and any shell command "
            "that is not a JagerExec protocol dispatch. Returns stdout/stderr and writes "
            "logs/c2-operator-audit.jsonl plus logs/tool-runs/command-audit.jsonl."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Full shell command to run"},
                "tool": {
                    "type": "string",
                    "description": "Tool name for audit (nmap, curl, dig, wpscan, openvpn, shell, ...)",
                    "default": "shell",
                },
                "target": {
                    "type": "string",
                    "description": "Primary target IP/hostname/CIDR for scope audit",
                    "default": "",
                },
                "evidence_file": {
                    "type": "string",
                    "description": "Optional path under workspace to tee raw stdout/stderr",
                    "default": "",
                },
                "timeout": {"type": "integer", "default": 300},
                "cwd": {"type": "string", "default": ""},
            },
            "required": ["command"],
        },
    },
    {
        "name": "operator_protocol",
        "description": (
            "Route a protocol operation to JagerExec (se) with audit logging. "
            "Prefer this over bare operator_exec when se supports the protocol."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "protocol": {
                    "type": "string",
                    "enum": ["smb", "ldap", "mssql", "ssh", "winrm", "rdp", "ftp", "vnc", "wmi", "nfs"],
                },
                "target": {"type": "string"},
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": [],
                },
                "evidence_file": {"type": "string", "default": ""},
                "timeout": {"type": "integer", "default": 300},
            },
            "required": ["protocol", "target"],
        },
    },
]

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _workspace() -> Path:
    return Path(os.environ.get("JAGER_WORKSPACE", os.getcwd())).resolve()


def _audit_paths(ws: Path) -> tuple[Path, Path]:
    c2 = ws / "logs" / "c2-operator-audit.jsonl"
    cmd = ws / "logs" / "tool-runs" / "command-audit.jsonl"
    c2.parent.mkdir(parents=True, exist_ok=True)
    cmd.parent.mkdir(parents=True, exist_ok=True)
    return c2, cmd


def _scope_check(target: str, ws: Path) -> tuple[bool, str]:
    candidates = [
        ws / "scope" / "scope-master.txt",
        ws / "scope" / "scope" / "scope-master.txt",
        ws / "engagements" / "dante" / "scope" / "scope-master.txt",
    ]
    scope_file = next((p for p in candidates if p.exists()), None)
    if scope_file is None or not target:
        return True, "no scope file or empty target"
    try:
        import ipaddress

        nets = []
        for line in scope_file.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line and not line.startswith("#"):
                try:
                    nets.append(ipaddress.ip_network(line, strict=False))
                except ValueError:
                    continue
        if not nets:
            return True, "empty scope"
        if "/" in target:
            tnet = ipaddress.ip_network(target, strict=False)
            ok = any(tnet.subnet_of(n) or tnet.overlaps(n) for n in nets)
            return ok, "cidr in scope" if ok else "cidr out of scope"
        tip = ipaddress.ip_address(target)
        ok = any(tip in n for n in nets)
        return ok, "in scope" if ok else "out of scope"
    except Exception as exc:
        return True, f"scope check skipped: {exc}"


def _append_audit(
    ws: Path,
    *,
    tool: str,
    command: str,
    target: str,
    exit_code: int,
    duration_ms: int,
    evidence_file: str,
) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    c2_log, cmd_log = _audit_paths(ws)
    entry = {
        "timestamp": ts,
        "source": "jager.operator_exec",
        "tool": tool,
        "command": command,
        "target": target or "local",
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "evidence_file": evidence_file,
    }
    line = json.dumps(entry) + "\n"
    c2_log.open("a").write(line)
    cmd_log.open("a").write(line)


def _run_subprocess(
    command: str,
    *,
    timeout: int,
    cwd: Path,
    evidence_file: str,
) -> dict[str, Any]:
    start = time.time()
    proc = subprocess.run(
        command,
        shell=True,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    duration_ms = int((time.time() - start) * 1000)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    if evidence_file:
        ep = Path(evidence_file)
        if not ep.is_absolute():
            ep = cwd / ep
        ep.parent.mkdir(parents=True, exist_ok=True)
        with ep.open("w") as f:
            f.write(stdout)
            if stderr:
                f.write("\n--- stderr ---\n")
                f.write(stderr)
    return {
        "exit_code": proc.returncode,
        "stdout": stdout[:8192],
        "stderr": stderr[:4096],
        "duration_ms": duration_ms,
    }


async def handle(tool_name: str, args: Dict[str, Any], client) -> Dict[str, Any]:
    ws = _workspace()

    if tool_name == "operator_exec":
        command = args["command"]
        tool = args.get("tool", "shell")
        target = args.get("target", "")
        if not target:
            ips = _IP_RE.findall(command)
            target = ips[0] if ips else ""

        allowed, route_err, redirect = _check_operator_exec(command, tool)
        if not allowed:
            return {
                "error": "routing_denied",
                "message": route_err,
                "redirect": redirect,
                "command": command[:200],
            }

        ok, scope_msg = _scope_check(target, ws)
        if not ok:
            return {"error": "scope_denied", "scope": scope_msg, "target": target, "command": command}
        try:
            result = _run_subprocess(
                command,
                timeout=int(args.get("timeout", 300)),
                cwd=ws,
                evidence_file=args.get("evidence_file", ""),
            )
        except subprocess.TimeoutExpired:
            return {"error": "timeout", "command": command, "timeout": args.get("timeout", 300)}
        _append_audit(
            ws,
            tool=tool,
            command=command,
            target=target,
            exit_code=result["exit_code"],
            duration_ms=result["duration_ms"],
            evidence_file=args.get("evidence_file", ""),
        )
        return {"mode": "operator_exec", "scope": scope_msg, **result}

    if tool_name == "operator_protocol":
        protocol = args["protocol"]
        target = args["target"]
        extra = args.get("args") or []
        ok, scope_msg = _scope_check(target, ws)
        if not ok:
            return {"error": "scope_denied", "scope": scope_msg, "target": target}
        try:
            import sys as _sys

            _sx_src = ws / "jagerexec" / "src"
            if _sx_src.is_dir():
                _sx = str(_sx_src)
                if _sx not in _sys.path:
                    _sys.path.insert(0, _sx)
            from jagerexec.config import EngagementConfig
            from jagerexec.dispatch import ProtocolDispatcher
            from jagerexec.profile import IOCProfile
        except ImportError:
            argv = ["se", protocol, target, *extra]
            cmd = " ".join(shlex.quote(a) for a in argv)
            return await handle(
                "operator_exec",
                {
                    "command": cmd,
                    "tool": "se",
                    "target": target,
                    "evidence_file": args.get("evidence_file", ""),
                    "timeout": args.get("timeout", 300),
                },
                client,
            )
        config_path = ws / "engagement.config.json"
        if not hasattr(EngagementConfig, "load_or_default"):
            raise ImportError("stale jagerexec package on PYTHONPATH")
        config, _ = EngagementConfig.load_or_default(config_path, ws)
        profile = IOCProfile.from_config(config.engagement_id, config.profile)
        dispatcher = ProtocolDispatcher(config, profile)
        start = time.time()
        disp = dispatcher.dispatch(protocol, target, extra, timeout=int(args.get("timeout", 300)))
        duration_ms = int((time.time() - start) * 1000)
        evidence_file = args.get("evidence_file", "")
        if evidence_file:
            ep = ws / evidence_file if not Path(evidence_file).is_absolute() else Path(evidence_file)
            ep.parent.mkdir(parents=True, exist_ok=True)
            ep.write_text((disp.stdout or "") + ("\n--- stderr ---\n" + disp.stderr if disp.stderr else ""))
        _append_audit(
            ws,
            tool="se",
            command=" ".join(shlex.quote(x) for x in disp.command),
            target=target,
            exit_code=disp.exit_code,
            duration_ms=duration_ms,
            evidence_file=evidence_file,
        )
        return {
            "mode": "operator_protocol",
            "protocol": protocol,
            "scope": scope_msg,
            "command": disp.command,
            "exit_code": disp.exit_code,
            "stdout": (disp.stdout or "")[:8192],
            "stderr": (disp.stderr or "")[:4096],
            "duration_ms": duration_ms,
        }

    return {"error": f"Unknown operator tool: {tool_name}"}
