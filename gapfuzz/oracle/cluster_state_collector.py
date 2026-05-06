"""Cluster State Collector — first sub-module of the Differential Oracle.

Queries each ONOS cluster node through the Northbound REST API and
extracts, for each node i, the set C_i of canonical FlowContents that
match the seed's (selector, priority) signature.

We define the FlowContent for the seed as the set of canonical flows on
node i whose match equals the seed's match AND whose priority equals the
seed's priority. This handles the case where two contradictory flows
coexist briefly on a node (set of size 2) versus only one survived (set
of size 1).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Iterable

from gapfuzz.core.flow_content import (
    CanonicalFlow,
    canonical_flows_from_onos_list,
    from_onos_rest,
)
from gapfuzz.engine.seed_generator import Seed
from gapfuzz.onos_client import OnosClient, OnosNode

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class NodeView:
    """The view C_i returned by node i.

    Stored as a frozenset of CanonicalFlow because the matching flows
    on a node are unordered.
    """

    node_name: str
    flows: frozenset[CanonicalFlow]


class ClusterStateCollector:
    """Queries every cluster node and returns the set {C_1, ..., C_N}."""

    def __init__(self, nodes: Iterable[OnosNode], app_id: str = "gapfuzz",
                 request_timeout_s: float = 10.0):
        self.nodes = list(nodes)
        self.app_id = app_id
        self.request_timeout_s = request_timeout_s

    async def collect(self, seed: Seed) -> list[NodeView]:
        """Query all nodes concurrently. Returns one NodeView per node.

        If a node is unreachable, its NodeView contains an empty frozenset
        and a warning is logged. (CP_DIVERGENT may then be reported even
        if the cluster is actually healthy on the reachable nodes; the
        operator should distinguish unreachability from divergence in
        post-processing.)
        """
        tasks = [self._collect_one(node, seed) for node in self.nodes]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        views: list[NodeView] = []
        for node, result in zip(self.nodes, results):
            if isinstance(result, BaseException):
                logger.warning(
                    "Cluster query failed for node=%s: %s", node.name, result
                )
                views.append(NodeView(node_name=node.name, flows=frozenset()))
            else:
                views.append(result)
        return views

    async def _collect_one(self, node: OnosNode, seed: Seed) -> NodeView:
        async with OnosClient(node, self.app_id, self.request_timeout_s) as c:
            raw = await c.list_flows(seed.device_id)
        canonical = canonical_flows_from_onos_list(raw)
        seed_match = from_onos_rest(seed.R).match
        # Filter to flows whose canonical (priority, match) equals the seed's.
        # The action component varies between R and R'; both are kept.
        kept: set[CanonicalFlow] = set()
        for cf in canonical:
            if cf.priority == seed.priority and cf.match == seed_match:
                kept.add(cf)
        return NodeView(node_name=node.name, flows=frozenset(kept))
