"""
Jager-C2 Management API Client.
Communicates with the teamserver via HTTP REST (management API on port 31338).

When the teamserver runs inside WSL2 and this client runs on Windows,
localhost:31338 is NOT reachable without admin port-forwarding.  The client
auto-discovers the WSL2 VM IP by running ``wsl hostname -I`` and retries
on that address when the primary URL fails.
"""

import os
import logging
import subprocess
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse

import httpx

logger = logging.getLogger("jager.client")

MGMT_URL = os.environ.get("JAGER_MGMT_URL", "http://127.0.0.1:31338")
WSL_DISTRO = os.environ.get("JAGER_WSL_DISTRO", os.environ.get("JAGEREXEC_WSL_DISTRO", ""))


def _resolve_wsl_ip(distro: str) -> Optional[str]:
    """Get the first IPv4 address of the WSL2 VM."""
    try:
        out = subprocess.check_output(
            ["wsl", "-d", distro, "--", "hostname", "-I"],
            text=True, timeout=5,
        ).strip()
        for tok in out.split():
            if "." in tok and not tok.startswith("127."):
                return tok
    except Exception as exc:
        logger.debug("WSL IP resolution failed: %s", exc)
    return None


def _swap_host(url: str, new_host: str) -> str:
    """Replace the hostname (but keep port and scheme) in a URL."""
    parsed = urlparse(url)
    port = parsed.port or 31338
    new_netloc = f"{new_host}:{port}"
    return urlunparse(parsed._replace(netloc=new_netloc))


@dataclass
class GRPCClient:
    """HTTP REST client to the Jager-C2 teamserver management API.
    Named GRPCClient for backward compatibility with server.py imports."""

    base_url: str = field(default_factory=lambda: MGMT_URL)
    _client: httpx.AsyncClient = field(default=None, init=False, repr=False)
    _connected: bool = field(default=False, init=False)

    async def _try_connect(self, url: str) -> bool:
        """Attempt a single connection to *url*. Returns True on success."""
        try:
            client = httpx.AsyncClient(base_url=url, timeout=5.0)
            resp = await client.get("/mgmt/ping")
            if resp.status_code == 200:
                self._client = client
                self.base_url = url
                self._connected = True
                logger.info("Connected to teamserver at %s", url)
                return True
            await client.aclose()
        except Exception as exc:
            logger.debug("Connection to %s failed: %s", url, exc)
        return False

    async def connect(self) -> bool:
        if await self._try_connect(self.base_url):
            return True
        if WSL_DISTRO:
            wsl_ip = _resolve_wsl_ip(WSL_DISTRO)
            if wsl_ip:
                fallback = _swap_host(self.base_url, wsl_ip)
                logger.info("Primary URL unreachable, trying WSL IP %s -> %s", wsl_ip, fallback)
                if await self._try_connect(fallback):
                    return True
        logger.error("All connection attempts failed for %s", self.base_url)
        return False

    async def disconnect(self):
        if self._client:
            await self._client.aclose()
            self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    async def ensure_connected(self) -> bool:
        if not self._connected or self._client is None:
            return await self.connect()
        return True

    async def ping(self) -> Dict[str, Any]:
        if not await self.ensure_connected():
            return {"success": False, "error": "not connected"}
        resp = await self._client.get("/mgmt/ping")
        return resp.json()

    async def get_sessions(self, alive_only: bool = True) -> List[Dict[str, Any]]:
        if not await self.ensure_connected():
            return []
        resp = await self._client.get("/mgmt/sessions")
        data = resp.json()
        return data.get("sessions", []) or []

    async def get_beacons(self, alive_only: bool = True) -> List[Dict[str, Any]]:
        if not await self.ensure_connected():
            return []
        resp = await self._client.get("/mgmt/beacons")
        data = resp.json()
        return data.get("beacons", []) or []

    async def interact_session(self, session_id: str) -> Dict[str, Any]:
        """Sessions are stateless over the REST management API.

        The gRPC service exposes InteractSession; over REST there is nothing to
        call. Tasking is done via queue_task()."""
        if not await self.ensure_connected():
            return {"error": "not connected to teamserver", "session_id": session_id}
        return {"success": True, "session_id": session_id,
                "note": "REST sessions are stateless; use queue_task to task this session"}

    async def kill_session(self, session_id: str, force: bool = False) -> Dict[str, Any]:
        if not await self.ensure_connected():
            return {"error": "not connected"}
        resp = await self._client.post("/mgmt/session/kill",
                                       json={"id": session_id, "force": force})
        return resp.json()

    async def set_sleep(self, session_id: str, interval: int, jitter: int) -> Dict[str, Any]:
        if not await self.ensure_connected():
            return {"error": "not connected"}
        resp = await self._client.post("/mgmt/session/sleep",
                                       json={"id": session_id, "interval": interval, "jitter": jitter})
        return resp.json()

    async def queue_task(self, session_id: str, task_type: int, data: str | bytes = "") -> Dict[str, Any]:
        if not await self.ensure_connected():
            return {"error": "not connected"}
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        resp = await self._client.post("/mgmt/task",
                                       json={"session_id": session_id, "type": task_type, "data": data})
        return resp.json()

    async def wait_for_task(self, task_id: str, timeout: float = 120.0) -> Dict[str, Any]:
        if not await self.ensure_connected():
            return {"error": "not connected"}
        resp = await self._client.get(f"/mgmt/task/wait?task_id={task_id}",
                                      timeout=timeout + 5)
        return resp.json()

    async def list_tasks(self, session_id: str = "") -> List[Dict[str, Any]]:
        if not await self.ensure_connected():
            return []
        params = {}
        if session_id:
            params["session_id"] = session_id
        resp = await self._client.get("/mgmt/tasks", params=params)
        data = resp.json()
        return data.get("tasks", []) or []

    async def start_listener(self, config: Dict[str, Any]) -> Dict[str, Any]:
        if not await self.ensure_connected():
            return {"error": "not connected"}
        resp = await self._client.post("/mgmt/listener/start", json=config)
        return resp.json()

    async def stop_listener(self, listener_id: str) -> Dict[str, Any]:
        if not await self.ensure_connected():
            return {"error": "not connected"}
        resp = await self._client.get(f"/mgmt/listener/stop?id={listener_id}")
        return resp.json()

    async def list_listeners(self) -> List[Dict[str, Any]]:
        if not await self.ensure_connected():
            return []
        resp = await self._client.get("/mgmt/listeners")
        data = resp.json()
        return data.get("listeners", []) or []

    async def add_credential(self, credential: Dict[str, Any]) -> Dict[str, Any]:
        if not await self.ensure_connected():
            return {"error": "not connected"}
        resp = await self._client.post("/mgmt/credential", json=credential)
        return resp.json()

    async def list_credentials(self, domain_filter: str = "", type_filter: str = "") -> List[Dict[str, Any]]:
        if not await self.ensure_connected():
            return []
        params = {}
        if domain_filter:
            params["domain"] = domain_filter
        resp = await self._client.get("/mgmt/credentials", params=params)
        data = resp.json()
        return data.get("credentials", []) or []

    async def add_target(self, target: Dict[str, Any]) -> Dict[str, Any]:
        if not await self.ensure_connected():
            return {"error": "not connected"}
        resp = await self._client.post("/mgmt/target", json=target)
        return resp.json()

    async def add_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        if not await self.ensure_connected():
            return {"error": "not connected"}
        resp = await self._client.post("/mgmt/finding", json=finding)
        return resp.json()

    async def list_findings(self, severity_filter: str = "") -> List[Dict[str, Any]]:
        if not await self.ensure_connected():
            return []
        params = {}
        if severity_filter:
            params["severity"] = severity_filter
        resp = await self._client.get("/mgmt/findings", params=params)
        data = resp.json()
        return data.get("findings", []) or []

    async def list_targets(self, compromised_only: bool = False) -> List[Dict[str, Any]]:
        if not await self.ensure_connected():
            return []
        resp = await self._client.get("/mgmt/targets")
        data = resp.json()
        return data.get("targets", []) or []

    async def get_engagement_summary(self) -> Dict[str, Any]:
        if not await self.ensure_connected():
            return {"error": "not connected"}
        resp = await self._client.get("/mgmt/summary")
        return resp.json()

    async def generate_implant(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Build implant via local builder (teamserver build API placeholder)."""
        import os
        try:
            from builder.build_implant import ImplantBuilder, IOCProfile, BuildConfig
        except ImportError as exc:
            return {"error": f"builder unavailable: {exc}"}
        source_dir = os.path.join(os.path.dirname(__file__), "..", "implant")
        output_dir = os.environ.get("JAGER_BUILDS", os.path.join(os.path.dirname(__file__), "..", "builds"))
        profile = IOCProfile()
        builder = ImplantBuilder(source_dir, output_dir, profile)
        build_cfg = BuildConfig(
            c2_url=config.get("listener_id", config.get("c2_url", "")),
            profile=profile,
            format=config.get("format", "exe"),
            arch=config.get("arch", "x64"),
            sleep=config.get("sleep", 60),
            jitter=config.get("jitter", 20),
        )
        return builder.build_implant(build_cfg)

    async def generate_stager(self, config: Dict[str, Any]) -> Dict[str, Any]:
        import os
        try:
            from builder.build_implant import ImplantBuilder, IOCProfile, BuildConfig
        except ImportError as exc:
            return {"error": f"builder unavailable: {exc}"}
        source_dir = os.path.join(os.path.dirname(__file__), "..", "implant")
        output_dir = os.environ.get("JAGER_BUILDS", os.path.join(os.path.dirname(__file__), "..", "builds"))
        profile = IOCProfile()
        builder = ImplantBuilder(source_dir, output_dir, profile)
        build_cfg = BuildConfig(c2_url=config.get("listener_id", config.get("c2_url", "")), profile=profile)
        return builder.build_stager(build_cfg)

    async def call(self, method: str, **kwargs) -> Dict[str, Any]:
        """Generic dispatch for the MCP server.py compatibility layer."""
        if method == "Ping":
            return await self.ping()
        elif method == "QueueTask":
            session_id = kwargs.get("session_id", "")
            task_type_str = kwargs.get("type", "shell")
            data = kwargs.get("data", "")

            from .task_types import LEGACY_TYPE_MAP, resolve_task_type
            try:
                task_type = resolve_task_type(task_type_str)
            except ValueError:
                task_type = int(LEGACY_TYPE_MAP.get(str(task_type_str).lower(), 0))

            result = await self.queue_task(session_id, task_type, data)
            if result.get("success"):
                task_id = result.get("task_id", "")
                waited = await self.wait_for_task(task_id)
                return waited
            return result
        elif method == "StartListener":
            transport = kwargs.get("transport", "https")
            host = kwargs.get("host", "0.0.0.0")
            port = kwargs.get("port", 443)
            return await self.start_listener({"transport": transport, "host": host, "port": port})
        elif method == "StopListener":
            return await self.stop_listener(kwargs.get("listener_id", ""))
        elif method == "ListListeners":
            items = await self.list_listeners()
            return {"listeners": items}
        elif method == "ListBuilds":
            if not await self.ensure_connected():
                return {"error": "not connected to teamserver - cannot list builds", "builds": []}
            try:
                resp = await self._client.get("/mgmt/builds")
                return resp.json()
            except Exception as e:
                return {"error": f"ListBuilds failed: {e}", "builds": []}
        elif method == "AddCredential":
            if "secret" in kwargs:
                kwargs["data"] = kwargs.pop("secret")
            return await self.add_credential(kwargs)
        elif method == "ListCredentials":
            items = await self.list_credentials(kwargs.get("domain", ""))
            return {"credentials": items}
        elif method == "AddTarget":
            return await self.add_target(kwargs)
        elif method == "ListTargets":
            items = await self.list_targets()
            return {"targets": items}
        elif method == "AddFinding":
            if "affected_host" in kwargs:
                kwargs["target_id"] = kwargs.pop("affected_host")
            if "cve" in kwargs:
                cve = kwargs.pop("cve")
                if cve:
                    kwargs["technique_id"] = cve
            return await self.add_finding(kwargs)
        elif method == "GetEngagementSummary":
            return await self.get_engagement_summary()
        elif method == "AddPivot":
            if not await self.ensure_connected():
                return {"error": "not connected to teamserver - cannot add pivot", "success": False}
            # Map to the pivot-specific REST endpoints the teamserver exposes.
            pivot_kind = str(kwargs.get("kind", kwargs.get("type", "socks"))).lower()
            try:
                if pivot_kind == "portfwd":
                    resp = await self._client.post("/mgmt/pivots/portfwd", json=kwargs)
                elif pivot_kind == "socks_stop":
                    resp = await self._client.post("/mgmt/pivots/socks/stop", json=kwargs)
                else:
                    resp = await self._client.post("/mgmt/pivots/socks/start", json=kwargs)
                return resp.json()
            except Exception as e:
                return {"error": f"AddPivot failed: {e}", "success": False}
        elif method == "ListPivots":
            if not await self.ensure_connected():
                return {"error": "not connected to teamserver - cannot list pivots", "pivots": []}
            try:
                resp = await self._client.get("/mgmt/pivots")
                return resp.json()
            except Exception as e:
                return {"error": f"ListPivots failed: {e}", "pivots": []}
        else:
            return {"error": f"unknown method: {method}"}
