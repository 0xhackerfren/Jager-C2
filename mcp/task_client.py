"""Helpers for queueing implant tasks with canonical type IDs and payloads."""

from __future__ import annotations

import json
from typing import Any

from task_types import TaskType


def _payload(data: str | bytes | dict | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    if isinstance(data, dict):
        return json.dumps(data, separators=(",", ":"))
    return str(data)


async def queue_task(
    client,
    session_id: str,
    task_type: TaskType | int,
    data: str | bytes | dict | None = None,
    *,
    wait: bool = True,
    timeout: float = 120.0,
) -> dict[str, Any]:
    """Queue a task on the teamserver and optionally wait for completion."""
    task_id_value = int(task_type)
    payload = _payload(data)
    result = await client.queue_task(session_id, task_id_value, payload)
    if not wait or not result.get("success"):
        return result
    task_id = result.get("task_id", "")
    if not task_id:
        return result
    waited = await client.wait_for_task(task_id, timeout=timeout)
    return waited
