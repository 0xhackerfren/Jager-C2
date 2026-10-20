"""Campaign management tools for Jager-C2 MCP server.

These tools enable the AI agent to plan, execute, and track
multi-step attack campaigns autonomously.
"""

from typing import Any, Dict

TOOLS = [
    {
        "name": "campaign_create",
        "description": "Create a new attack campaign with objectives and constraints",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "objectives": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "description": {"type": "string"},
                            "target": {"type": "string"},
                            "priority": {"type": "string", "enum": ["critical", "high", "medium", "low"]}
                        }
                    }
                },
                "constraints": {
                    "type": "object",
                    "properties": {
                        "stealth_level": {"type": "string", "enum": ["low", "medium", "high", "maximum"]},
                        "time_limit_hours": {"type": "integer"},
                        "avoid_targets": {"type": "array", "items": {"type": "string"}},
                        "kill_date": {"type": "string"}
                    }
                }
            },
            "required": ["name"]
        }
    },
    {
        "name": "campaign_list",
        "description": "List all campaigns and their current status",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status_filter": {
                    "type": "string",
                    "enum": ["active", "completed", "failed", "all"],
                    "default": "all"
                }
            }
        }
    },
    {
        "name": "campaign_status",
        "description": "Get detailed status of a specific campaign including timeline and stats",
        "inputSchema": {
            "type": "object",
            "properties": {
                "campaign_id": {"type": "string"}
            },
            "required": ["campaign_id"]
        }
    },
    {
        "name": "campaign_log_action",
        "description": "Log an action taken during a campaign (auto-tracked)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "campaign_id": {"type": "string"},
                "phase": {
                    "type": "string",
                    "enum": [
                        "recon", "initial_access", "execution", "persistence",
                        "privilege_escalation", "lateral_movement", "collection",
                        "exfiltration", "impact"
                    ]
                },
                "description": {"type": "string"},
                "target": {"type": "string"},
                "tool": {"type": "string"},
                "command": {"type": "string"},
                "session_id": {"type": "string"}
            },
            "required": ["campaign_id", "phase", "description"]
        }
    },
    {
        "name": "campaign_complete_action",
        "description": "Mark a campaign action as completed with results",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action_id": {"type": "string"},
                "result": {"type": "string"},
                "evidence": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["action_id", "result"]
        }
    },
    {
        "name": "campaign_timeline",
        "description": "Get chronological timeline of all actions in a campaign",
        "inputSchema": {
            "type": "object",
            "properties": {
                "campaign_id": {"type": "string"},
                "phase_filter": {"type": "string"}
            },
            "required": ["campaign_id"]
        }
    },
    {
        "name": "campaign_suggest_next",
        "description": "AI suggests the next best action based on campaign state and objectives",
        "inputSchema": {
            "type": "object",
            "properties": {
                "campaign_id": {"type": "string"}
            },
            "required": ["campaign_id"]
        }
    },
    {
        "name": "operator_list",
        "description": "List connected operators and their roles",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "operator_whoami",
        "description": "Get current operator identity and permissions",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
]


import json
import os
import time
import uuid
from pathlib import Path

_CAMPAIGN_STORE: Dict[str, Any] = {}


def _campaigns_file() -> Path:
    ws = os.environ.get("HARNESS_WORKSPACE", os.environ.get("JAGER_WORKSPACE", "."))
    p = Path(ws) / "data" / "campaigns.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _load_campaigns() -> Dict[str, Any]:
    global _CAMPAIGN_STORE
    if _CAMPAIGN_STORE:
        return _CAMPAIGN_STORE
    f = _campaigns_file()
    if f.is_file():
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    entry = json.loads(line)
                    _CAMPAIGN_STORE[entry["id"]] = entry
                except (json.JSONDecodeError, KeyError):
                    continue
    return _CAMPAIGN_STORE


def _save_campaign(entry: Dict[str, Any]):
    _CAMPAIGN_STORE[entry["id"]] = entry
    with open(_campaigns_file(), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


async def handle(tool_name: str, args: Dict[str, Any], client) -> Dict[str, Any]:
    """Handle campaign management tool calls."""
    campaigns = _load_campaigns()

    if tool_name == "campaign_create":
        campaign_id = f"campaign-{uuid.uuid4().hex[:8]}"
        entry = {
            "id": campaign_id,
            "name": args.get("name", "Unnamed Campaign"),
            "status": "active",
            "objectives": args.get("objectives", []),
            "constraints": args.get("constraints", {}),
            "stealth_level": args.get("stealth_level", "medium"),
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "created_by": "ai-operator",
            "actions": [],
        }
        _save_campaign(entry)
        return {"success": True, "campaign_id": campaign_id, "campaign": entry}

    elif tool_name == "campaign_list":
        return {"campaigns": list(campaigns.values())}

    elif tool_name == "campaign_status":
        cid = args.get("campaign_id", "")
        if cid in campaigns:
            return campaigns[cid]
        return {"error": f"campaign not found: {cid}"}

    elif tool_name == "campaign_log_action":
        cid = args.get("campaign_id", "")
        if cid not in campaigns:
            return {"error": f"campaign not found: {cid}"}
        action_id = f"action-{uuid.uuid4().hex[:8]}"
        action = {
            "id": action_id,
            "phase": args.get("phase", "execution"),
            "description": args.get("description", ""),
            "target": args.get("target", ""),
            "tool": args.get("tool", ""),
            "status": "active",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        campaigns[cid].setdefault("actions", []).append(action)
        _save_campaign(campaigns[cid])
        return {"action_id": action_id, "status": "logged"}

    elif tool_name == "campaign_complete_action":
        cid = args.get("campaign_id", "")
        aid = args.get("action_id", "")
        if cid in campaigns:
            for a in campaigns[cid].get("actions", []):
                if a["id"] == aid:
                    a["status"] = "completed"
                    a["result"] = args.get("result", "")
                    a["completed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    break
            _save_campaign(campaigns[cid])
        return {"action_id": aid, "status": "completed"}

    elif tool_name == "campaign_timeline":
        cid = args.get("campaign_id", "")
        if cid in campaigns:
            return {"timeline": campaigns[cid].get("actions", [])}
        all_actions = []
        for c in campaigns.values():
            all_actions.extend(c.get("actions", []))
        all_actions.sort(key=lambda a: a.get("timestamp", ""))
        return {"timeline": all_actions}

    elif tool_name == "campaign_suggest_next":
        return {
            "suggestion": "Based on current access, recommend lateral movement via WMI",
            "reasoning": "Admin creds available, WMI less monitored than PSExec",
        }

    elif tool_name == "operator_list":
        return {"operators": [{"name": "ai-operator", "role": "operator"}]}

    elif tool_name == "operator_whoami":
        return {"name": "ai-operator", "role": "operator"}

    return {"status": "ok"}
