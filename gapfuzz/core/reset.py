"""Reset procedure (Algorithm 1's Reset()).

Two stages, in this order:

  1. Cluster-side: DELETE every flow belonging to GapFuzz's app on the
     targeted device, on every ONOS node. We list flows on each node and
     delete those whose appId equals our app_id, to avoid touching flows
     installed by unrelated applications. Performed in parallel across
     nodes.

  2. Switch-side: best-effort 'ovs-ofctl del-flows' on the OVS bridge,
     invoked through a configurable shell command. This is a safety net
     for any residue not cleared by stage 1; ONOS, being master, will
     normally re-install whatever it still considers active, so stage 1
     must succeed for the reset to actually take effect.

Stage 2 is invoked through a user-provided shell command template (see
config.yaml -> reset.dp_command_template) so the operator can adapt it
to their environment (ssh, kubectl exec, mininet attach, etc.).
"""

from __future__ import annotations

import asyncio
import logging
import shlex
import subprocess
from typing import Iterable

from gapfuzz.onos_client import OnosClient, OnosNode

logger = logging.getLogger(__name__)


class Reset:
    def __init__(self, nodes: Iterable[OnosNode], device_id: str,
                 app_id: str = "gapfuzz",
                 dp_command_template: str | None = None,
                 dp_bridge: str = "br0",
                 dp_command_timeout_s: float = 10.0):
        """
        nodes: cluster nodes to clean up via REST.
        device_id: ONOS device id (e.g. 'of:0000000000000001') to scope
                   the cleanup.
        app_id: only flows installed under this app id are deleted.
        dp_command_template: shell command template. May contain '{bridge}'.
                             Example: 'ssh root@192.168.1.20 ovs-ofctl del-flows {bridge}'.
                             If None, stage 2 is skipped.
        dp_bridge: bridge name substituted into dp_command_template.
        """
        self.nodes = list(nodes)
        self.device_id = device_id
        self.app_id = app_id
        self.dp_command_template = dp_command_template
        self.dp_bridge = dp_bridge
        self.dp_command_timeout_s = dp_command_timeout_s

    async def run(self) -> None:
        await self._reset_cluster_all_nodes()
        self._reset_data_plane()

    # ---- Stage 1: cluster-side ----

    async def _reset_cluster_all_nodes(self) -> None:
        await asyncio.gather(*[self._reset_one_node(n) for n in self.nodes],
                             return_exceptions=False)

    async def _reset_one_node(self, node: OnosNode) -> None:
        async with OnosClient(node, self.app_id) as c:
            try:
                flows = await c.list_flows(self.device_id)
            except Exception as exc:
                logger.warning("Reset: could not list flows on %s: %s",
                               node.name, exc)
                return
            our_flows = [f for f in flows if f.get("appId") == self.app_id]
            if not our_flows:
                logger.debug("Reset: no GapFuzz flows on %s", node.name)
                return
            logger.info("Reset: deleting %d flows on %s",
                        len(our_flows), node.name)
            tasks = [c.delete_flow(self.device_id, f["id"]) for f in our_flows]
            await asyncio.gather(*tasks, return_exceptions=True)

    # ---- Stage 2: switch-side ----

    def _reset_data_plane(self) -> None:
        if not self.dp_command_template:
            logger.debug("Reset: no dp_command_template configured, skipping")
            return
        cmd_str = self.dp_command_template.format(bridge=self.dp_bridge)
        argv = shlex.split(cmd_str)
        try:
            result = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=self.dp_command_timeout_s, check=False,
            )
            if result.returncode != 0:
                logger.warning(
                    "Reset DP command failed (rc=%d): %s | stderr=%s",
                    result.returncode, cmd_str, result.stderr.strip(),
                )
            else:
                logger.debug("Reset DP command ok: %s", cmd_str)
        except subprocess.TimeoutExpired:
            logger.warning("Reset DP command timed out: %s", cmd_str)
        except FileNotFoundError as exc:
            logger.warning("Reset DP command not found: %s (%s)", cmd_str, exc)
