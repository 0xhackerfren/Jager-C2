"""
Contract drift detection test: proto <-> implant task ID synchronization.

Parses task type enums from:
  - jager/teamserver/proto/tasks.proto (protobuf definition)
  - jager/implant/include/config.h (C implant defines)

Asserts that every task ID in the implant has a matching enum in proto,
and vice versa. Catches contract drift automatically in CI.
"""

import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def parse_proto_tasks(proto_path: Path) -> dict[str, int]:
    """Parse TASK_* enum entries from tasks.proto."""
    tasks = {}
    pattern = re.compile(r'^\s*(TASK_[A-Z0-9_]+)\s*=\s*(\d+)\s*;', re.MULTILINE)

    content = proto_path.read_text()
    for match in pattern.finditer(content):
        name = match.group(1)
        value = int(match.group(2))
        if name.startswith("TASK_STATE_"):
            continue
        if name == "TASK_UNKNOWN":
            continue
        tasks[name] = value

    return tasks


def parse_implant_tasks(config_h: Path) -> dict[str, int]:
    """Parse #define TASK_* from config.h."""
    tasks = {}
    pattern = re.compile(r'^\s*#define\s+(TASK_[A-Z0-9_]+)\s+(\d+)', re.MULTILINE)

    content = config_h.read_text()
    for match in pattern.finditer(content):
        name = match.group(1)
        value = int(match.group(2))
        tasks[name] = value

    return tasks


def test_proto_implant_sync():
    """Every task in proto must exist in implant and vice versa."""
    proto_path = REPO_ROOT / "teamserver" / "proto" / "tasks.proto"
    config_path = REPO_ROOT / "implant" / "include" / "config.h"

    if not proto_path.exists():
        raise FileNotFoundError(f"Proto file not found: {proto_path}")
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    proto_tasks = parse_proto_tasks(proto_path)
    implant_tasks = parse_implant_tasks(config_path)

    errors = []

    # Check proto has everything the implant defines
    for name, value in implant_tasks.items():
        if name not in proto_tasks:
            errors.append(f"IMPLANT has {name}={value} but PROTO does not")
        elif proto_tasks[name] != value:
            errors.append(
                f"VALUE MISMATCH: {name} proto={proto_tasks[name]} implant={value}"
            )

    # Check implant has everything proto defines
    for name, value in proto_tasks.items():
        if name not in implant_tasks:
            errors.append(f"PROTO has {name}={value} but IMPLANT does not")

    if errors:
        msg = "Contract drift detected:\n" + "\n".join(f"  - {e}" for e in errors)
        raise AssertionError(msg)

    print(f"Contract OK: {len(proto_tasks)} proto tasks, {len(implant_tasks)} implant tasks - all synchronized")


def test_task_values_unique():
    """No duplicate task IDs within either definition."""
    proto_path = REPO_ROOT / "teamserver" / "proto" / "tasks.proto"
    config_path = REPO_ROOT / "implant" / "include" / "config.h"

    for label, path in [("proto", proto_path), ("implant", config_path)]:
        if not path.exists():
            continue

        if label == "proto":
            tasks = parse_proto_tasks(path)
        else:
            tasks = parse_implant_tasks(path)

        values_seen: dict[int, str] = {}
        for name, value in tasks.items():
            if value in values_seen:
                raise AssertionError(
                    f"Duplicate task ID in {label}: {name}={value} conflicts with {values_seen[value]}={value}"
                )
            values_seen[value] = name


def test_p2p_tasks_present():
    """P2P tasks (110-112) must be in both proto and implant."""
    proto_path = REPO_ROOT / "teamserver" / "proto" / "tasks.proto"
    config_path = REPO_ROOT / "implant" / "include" / "config.h"

    proto_tasks = parse_proto_tasks(proto_path)
    implant_tasks = parse_implant_tasks(config_path)

    required_p2p = ["TASK_P2P_LISTEN", "TASK_P2P_CONNECT", "TASK_P2P_RELAY"]
    for name in required_p2p:
        assert name in proto_tasks, f"Missing in proto: {name}"
        assert name in implant_tasks, f"Missing in implant: {name}"


def test_lateral_tasks_present():
    """All lateral movement tasks must be synchronized."""
    proto_path = REPO_ROOT / "teamserver" / "proto" / "tasks.proto"
    config_path = REPO_ROOT / "implant" / "include" / "config.h"

    proto_tasks = parse_proto_tasks(proto_path)
    implant_tasks = parse_implant_tasks(config_path)

    required_lateral = [
        "TASK_LATERAL_PSEXEC",
        "TASK_LATERAL_WMI",
        "TASK_LATERAL_DCOM",
        "TASK_LATERAL_WINRM",
        "TASK_LATERAL_SCHTASK",
    ]
    for name in required_lateral:
        assert name in proto_tasks, f"Missing in proto: {name}"
        assert name in implant_tasks, f"Missing in implant: {name}"


if __name__ == "__main__":
    tests = [
        test_proto_implant_sync,
        test_task_values_unique,
        test_p2p_tasks_present,
        test_lateral_tasks_present,
    ]

    failed = 0
    for test in tests:
        try:
            test()
            print(f"  PASS  {test.__name__}")
        except (AssertionError, FileNotFoundError) as e:
            print(f"  FAIL  {test.__name__}: {e}")
            failed += 1

    sys.exit(1 if failed > 0 else 0)
