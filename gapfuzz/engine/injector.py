"""Injector: concurrent emission of R and R' on two backup nodes.

Implements the spatial scheduling chosen by the user (R on the first
non-master node, R' on the second non-master node) and the temporal
scheduling driven by the Timing Analyzer (Δt = 0 for Phase 1, Δt > 0 for
Phase 2 doubling/dichotomy).

For Δt = 0 the two POSTs are launched via asyncio.gather(), which yields
near-simultaneous emission with negligible overhead. For Δt > 0 the
second POST is delayed via asyncio.sleep(Δt) AFTER the first one has
returned its HTTP response (so Δt is the inter-injection delay measured
between the two flow-installation requests as observed by the cluster).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

from gapfuzz.engine.seed_generator import Seed
from gapfuzz.onos_client import OnosClient, OnosNode

logger = logging.getLogger(__name__)


@dataclass
class InjectionResult:
    """Outcome of one Inject(R, R', Δt) call.

    Stores the flow ids returned by ONOS so that Reset can later DELETE
    them via REST. Either id may be None if the corresponding POST raised.
    """

    target_node_R: str
    target_node_R_prime: str
    flow_id_R: Optional[str]
    flow_id_R_prime: Optional[str]
    delta_t_s: float


class Injector:
    """Injects R and R' on two distinct backup nodes."""

    def __init__(self, target_R: OnosNode, target_R_prime: OnosNode,
                 app_id: str = "gapfuzz", request_timeout_s: float = 10.0):
        if target_R.host == target_R_prime.host and target_R.port == target_R_prime.port:
            raise ValueError(
                "target_R and target_R_prime must be different nodes; "
                "the spatial scheduling fixed in §5 requires injection "
                "on two distinct backup nodes."
            )
        self.target_R = target_R
        self.target_R_prime = target_R_prime
        self.app_id = app_id
        self.request_timeout_s = request_timeout_s

    async def inject(self, seed: Seed, delta_t_s: float) -> InjectionResult:
        """Inject(R, R', Δt). Returns the flow ids on success."""
        if delta_t_s < 0:
            raise ValueError(f"Δt must be >= 0; got {delta_t_s}")

        if delta_t_s == 0.0:
            return await self._inject_concurrent(seed)
        return await self._inject_with_delay(seed, delta_t_s)

    async def _inject_concurrent(self, seed: Seed) -> InjectionResult:
        async with OnosClient(self.target_R, self.app_id, self.request_timeout_s) as c1, \
                   OnosClient(self.target_R_prime, self.app_id, self.request_timeout_s) as c2:
            results = await asyncio.gather(
                c1.install_flow(seed.device_id, seed.R),
                c2.install_flow(seed.device_id, seed.R_prime),
                return_exceptions=True,
            )
        flow_id_R, flow_id_R_prime = self._unpack_results(results)
        return InjectionResult(
            target_node_R=self.target_R.name,
            target_node_R_prime=self.target_R_prime.name,
            flow_id_R=flow_id_R,
            flow_id_R_prime=flow_id_R_prime,
            delta_t_s=0.0,
        )

    async def _inject_with_delay(self, seed: Seed, delta_t_s: float) -> InjectionResult:
        async with OnosClient(self.target_R, self.app_id, self.request_timeout_s) as c1:
            try:
                flow_id_R = await c1.install_flow(seed.device_id, seed.R)
                first_exc = None
            except Exception as exc:
                flow_id_R = None
                first_exc = exc
                logger.warning("First injection failed on %s: %s",
                               self.target_R.name, exc)

        await asyncio.sleep(delta_t_s)

        async with OnosClient(self.target_R_prime, self.app_id,
                              self.request_timeout_s) as c2:
            try:
                flow_id_R_prime = await c2.install_flow(seed.device_id, seed.R_prime)
            except Exception as exc:
                flow_id_R_prime = None
                logger.warning("Second injection failed on %s: %s",
                               self.target_R_prime.name, exc)

        return InjectionResult(
            target_node_R=self.target_R.name,
            target_node_R_prime=self.target_R_prime.name,
            flow_id_R=flow_id_R,
            flow_id_R_prime=flow_id_R_prime,
            delta_t_s=delta_t_s,
        )

    @staticmethod
    def _unpack_results(results: list) -> tuple[Optional[str], Optional[str]]:
        out: list[Optional[str]] = []
        for r in results:
            if isinstance(r, BaseException):
                logger.warning("Concurrent injection raised: %s", r)
                out.append(None)
            else:
                out.append(r)
        return out[0], out[1]
