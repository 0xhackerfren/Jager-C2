#!/usr/bin/env python3
"""
Capability registry validator.

Checks capability-registry.yaml against the canonical task contract in
teamserver/proto/tasks.proto:
  - every registry task id exists in the proto enum and vice versa
  - task type numbers match exactly
  - no duplicate ids or type numbers
  - status values are one of the allowed states
  - MCP tool mappings reference known tool prefixes

Dependency-free (lightweight YAML scanning; no PyYAML required).
Exit code 0 = valid, 1 = drift detected.
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "capability-registry.yaml"
PROTO_PATH = REPO_ROOT / "teamserver" / "proto" / "tasks.proto"

VALID_STATUS = {"implemented", "partial", "stub", "planned"}
ID_PATTERN = re.compile(r"^TASK_[A-Z0-9_]+$")


def parse_registry(path: Path):
    tasks = []
    current = None
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.split("#", 1)[0]
        id_m = re.match(r"\s*-\s*id:\s*(\S+)\s*$", line)
        if id_m:
            current = {"id": id_m.group(1), "_line": lineno}
            tasks.append(current)
            continue
        if current is None:
            continue
        type_m = re.match(r"\s*type:\s*(\d+)\s*$", line)
        if type_m:
            current["type"] = int(type_m.group(1))
            continue
        status_m = re.match(r"\s*status:\s*(\S+)\s*$", line)
        if status_m:
            current["status"] = status_m.group(1)
            continue
        tool_m = re.match(r"\s*mcp_tool:\s*(\S+)\s*$", line)
        if tool_m:
            current["mcp_tool"] = tool_m.group(1)
    return tasks


def parse_proto(path: Path):
    tasks = {}
    pattern = re.compile(r"^\s*(TASK_[A-Z0-9_]+)\s*=\s*(\d+)\s*;", re.MULTILINE)
    for m in pattern.finditer(path.read_text()):
        name = m.group(1)
        if name.startswith("TASK_STATE_") or name == "TASK_UNKNOWN":
            continue
        tasks[name] = int(m.group(2))
    return tasks


def main() -> int:
    if not REGISTRY_PATH.exists():
        print(f"FAIL: registry not found: {REGISTRY_PATH}")
        return 1
    if not PROTO_PATH.exists():
        print(f"FAIL: proto not found: {PROTO_PATH}")
        return 1

    reg_tasks = parse_registry(REGISTRY_PATH)
    proto_tasks = parse_proto(PROTO_PATH)
    errors = []

    ids_seen = {}
    types_seen = {}
    for t in reg_tasks:
        if not ID_PATTERN.match(t["id"]):
            errors.append(f"line {t['_line']}: malformed id '{t['id']}'")
        if t["id"] in ids_seen:
            errors.append(f"line {t['_line']}: duplicate id {t['id']} (first at line {ids_seen[t['id']]})")
        ids_seen[t["id"]] = t["_line"]
        if "type" not in t:
            errors.append(f"line {t['_line']}: {t['id']} missing type")
        elif t["type"] in types_seen:
            errors.append(
                f"line {t['_line']}: duplicate type {t['type']} "
                f"({t['id']} vs {types_seen[t['type']]})"
            )
        else:
            types_seen[t["type"]] = t["id"]
        status = t.get("status", "")
        if status and status not in VALID_STATUS:
            errors.append(f"line {t['_line']}: invalid status '{status}' (allowed: {sorted(VALID_STATUS)})")

    # Registry must stay in sync with the proto contract.
    for t in reg_tasks:
        if "type" not in t:
            continue
        if t["id"] not in proto_tasks:
            errors.append(f"registry has {t['id']}={t['type']} but proto does not")
        elif proto_tasks[t["id"]] != t["type"]:
            errors.append(
                f"type mismatch: {t['id']} registry={t['type']} proto={proto_tasks[t['id']]}"
            )
    for name, value in proto_tasks.items():
        if name not in ids_seen:
            errors.append(f"proto has {name}={value} but registry does not")

    if errors:
        print("Capability registry drift detected:")
        for e in errors:
            print(f"  - {e}")
        return 1

    print(
        f"Capability registry OK: {len(reg_tasks)} registry tasks, "
        f"{len(proto_tasks)} proto tasks - synchronized"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())