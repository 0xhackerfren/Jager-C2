"""
Pytest fixtures for Jager-C2 integration tests.

Provides teamserver lifecycle management (start/teardown)
and common test utilities.
"""

import os
import sys
import time
import signal
import socket
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TEAMSERVER_BIN_CANDIDATES = [
    REPO_ROOT / "bin" / "jager-server",
    REPO_ROOT / "teamserver" / "jager-server",
]
TEAMSERVER_REST_PORT = 31338
TEAMSERVER_GRPC_PORT = 31337

sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "mcp"))


def _teamserver_bin():
    for cand in TEAMSERVER_BIN_CANDIDATES:
        if cand.exists():
            return cand
    return TEAMSERVER_BIN_CANDIDATES[0]


def _port_open(port: int, host: str = "127.0.0.1", timeout: float = 1.0) -> bool:
    """Check if a TCP port is accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ConnectionRefusedError):
        return False


def _wait_for_port(port: int, timeout: float = 10.0) -> bool:
    """Block until port is open or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _port_open(port):
            return True
        time.sleep(0.2)
    return False


@pytest.fixture(scope="session")
def teamserver():
    """Start teamserver for the test session if not already running.

    Yields a dict with connection info.
    Kills the process on teardown if we started it.
    """
    if _port_open(TEAMSERVER_REST_PORT):
        yield {
            "rest": f"http://127.0.0.1:{TEAMSERVER_REST_PORT}",
            "grpc": f"127.0.0.1:{TEAMSERVER_GRPC_PORT}",
            "managed": False,
        }
        return

    teamserver_bin = _teamserver_bin()
    if not teamserver_bin.exists():
        pytest.skip("teamserver binary not built")

    db_path = REPO_ROOT / "data" / "ci-test.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    proc = subprocess.Popen(
        [
            str(teamserver_bin),
            "--no-tls",
            "--db", str(db_path),
            "--workspace", str(REPO_ROOT),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )

    if not _wait_for_port(TEAMSERVER_REST_PORT, timeout=15):
        proc.kill()
        pytest.skip("teamserver failed to start within 15s")

    yield {
        "rest": f"http://127.0.0.1:{TEAMSERVER_REST_PORT}",
        "grpc": f"127.0.0.1:{TEAMSERVER_GRPC_PORT}",
        "managed": True,
        "proc": proc,
    }

    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    proc.wait(timeout=5)
    if db_path.exists():
        db_path.unlink()


@pytest.fixture
def repo_root():
    """Return the resolved REPO_ROOT path."""
    return REPO_ROOT
