"""Differential Oracle façade (Section 5.3).

Orchestrates the three sub-modules:
  1. Wait delta seconds (delta > T_2, calibrated once on backupPeriod).
  2. Concurrently collect:
     - C_1, ..., C_N via the Cluster State Collector
     - D via the Data Plane Collector
  3. Classify with the Divergence Classifier.

Returns the resulting DivergenceClass plus the raw views (for logging /
post-mortem analysis).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from gapfuzz.core.classes import DivergenceClass
from gapfuzz.engine.seed_generator import Seed
from gapfuzz.oracle.cluster_state_collector import (
    ClusterStateCollector,
    NodeView,
)
from gapfuzz.oracle.data_plane_collector import (
    DataPlaneCollector,
    DataPlaneView,
)
from gapfuzz.oracle.divergence_classifier import classify

logger = logging.getLogger(__name__)


@dataclass
class OracleVerdict:
    """The Oracle's complete output for one observation."""

    classification: DivergenceClass
    node_views: list[NodeView]
    dp_view: DataPlaneView


class DifferentialOracle:
    def __init__(self, cluster: ClusterStateCollector, dp: DataPlaneCollector,
                 delta_s: float):
        if delta_s <= 0:
            raise ValueError(f"delta must be > 0; got {delta_s}")
        self.cluster = cluster
        self.dp = dp
        self.delta_s = delta_s

    async def observe(self, seed: Seed,
                      wait_s: float | None = None) -> OracleVerdict:
        """Wait `wait_s` (defaults to delta_s), then reconstruct S(f, d, t)
        and classify it.

        The override is used by the Timing Analyzer to perform the lifetime
        check (re-observe after additional time, without re-injection).
        """
        delay = self.delta_s if wait_s is None else wait_s
        logger.debug("Oracle: sleeping %.3fs before observation", delay)
        await asyncio.sleep(delay)

        cp_task = asyncio.create_task(self.cluster.collect(seed))
        dp_task = asyncio.create_task(self.dp.collect(seed))
        node_views, dp_view = await asyncio.gather(cp_task, dp_task)

        verdict = classify(node_views, dp_view)
        logger.info(
            "Oracle verdict=%s template=%s |C_i|=%s |D|=%d",
            verdict.value,
            seed.template_name,
            [len(nv.flows) for nv in node_views],
            len(dp_view.flows),
        )
        return OracleVerdict(
            classification=verdict,
            node_views=node_views,
            dp_view=dp_view,
        )
