"""Async ONOS REST client.

A thin wrapper around aiohttp for the small subset of ONOS REST endpoints
GapFuzz uses:

  - POST   /onos/v1/flows/{deviceId}?appId=gapfuzz   (install a flow)
  - DELETE /onos/v1/flows/{deviceId}/{flowId}        (remove one flow)
  - GET    /onos/v1/flows/{deviceId}                 (list flows on device)

The client is intentionally narrow: each method does one HTTP call.
Higher-level orchestration lives in the injector, oracle, and reset modules.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class OnosNode:
    """One ONOS cluster node, as a REST endpoint."""

    name: str
    host: str
    port: int = 8181
    username: str = "onos"
    password: str = "rocks"

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}/onos/v1"


class OnosClient:
    """Async client for one ONOS node.

    Each call returns the parsed JSON body (for GET) or the Location-style
    flow id (for POST). On non-2xx responses the underlying aiohttp
    ClientResponseError is propagated.
    """

    def __init__(self, node: OnosNode, app_id: str = "gapfuzz", timeout_s: float = 10.0):
        self.node = node
        self.app_id = app_id
        self._timeout = aiohttp.ClientTimeout(total=timeout_s)
        self._auth = aiohttp.BasicAuth(node.username, node.password)
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "OnosClient":
        self._session = aiohttp.ClientSession(auth=self._auth, timeout=self._timeout)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    def _require_session(self) -> aiohttp.ClientSession:
        if self._session is None:
            raise RuntimeError(
                "OnosClient must be used as 'async with OnosClient(node) as c:'"
            )
        return self._session

    # ----- flows -----

    async def install_flow(self, device_id: str, flow_body: dict) -> str:
        """POST a flow to ONOS. Returns the resulting flow id (string).

        The flow_body must follow the ONOS schema (selector + treatment +
        priority + isPermanent/timeout). The deviceId in the URL takes
        precedence over the one in the body.
        """
        session = self._require_session()
        url = f"{self.node.base_url}/flows/{device_id}"
        params = {"appId": self.app_id}
        async with session.post(url, params=params, json=flow_body) as resp:
            if resp.status not in (200, 201):
                text = await resp.text()
                resp.raise_for_status()
                # If raise_for_status didn't fire (shouldn't happen), at
                # least surface the body.
                raise RuntimeError(
                    f"install_flow on {self.node.name} returned {resp.status}: {text}"
                )
            # ONOS returns the new flow id in the Location header:
            # /onos/v1/flows/{deviceId}/{flowId}
            location = resp.headers.get("Location", "")
            flow_id = location.rsplit("/", 1)[-1] if location else ""
            if not flow_id:
                # Fallback: parse body if ONOS later changes the contract.
                try:
                    body = await resp.json()
                    flow_id = str(body.get("flows", [{}])[0].get("id", ""))
                except Exception:
                    flow_id = ""
            logger.debug(
                "install_flow ok node=%s device=%s flow_id=%s",
                self.node.name, device_id, flow_id,
            )
            return flow_id

    async def delete_flow(self, device_id: str, flow_id: str) -> None:
        session = self._require_session()
        url = f"{self.node.base_url}/flows/{device_id}/{flow_id}"
        async with session.delete(url) as resp:
            if resp.status not in (200, 204, 404):
                resp.raise_for_status()

    async def list_flows(self, device_id: str) -> list[dict]:
        """GET /onos/v1/flows/{deviceId}. Returns the 'flows' list."""
        session = self._require_session()
        url = f"{self.node.base_url}/flows/{device_id}"
        async with session.get(url) as resp:
            resp.raise_for_status()
            body = await resp.json()
            return body.get("flows", [])

    async def get_device(self, device_id: str) -> dict:
        """GET /onos/v1/devices/{deviceId}. Returns role/available/etc.

        Each ONOS node knows its own role for the device (MASTER/STANDBY/
        NONE), so we can poll any node to identify the current master.
        """
        session = self._require_session()
        url = f"{self.node.base_url}/devices/{device_id}"
        async with session.get(url) as resp:
            resp.raise_for_status()
            return await resp.json()
