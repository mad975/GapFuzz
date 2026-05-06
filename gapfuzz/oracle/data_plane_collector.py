"""Data Plane Collector — second sub-module of the Differential Oracle.

Queries the kernel datapath ground truth via the companion ryu app's
`/dp/trace/<dpid>` endpoint (which shells out to
`ovs-appctl ofproto/trace`). The endpoint returns the action that the
datapath would actually apply to a packet matching the seed selector;
this is the same ground truth used by the PoC of Section 3.2.

Why kernel datapath, not OF user-space (`ovs-ofctl dump-flows`)?
The PoC empirically shows that the kernel datapath megaflow cache can
hold a stale action long after the OF user-space table has reconciled
with the cluster. Querying the OF user-space view would miss these
divergences. Trace-based collection gives the rule that is *applied*
to traffic, not the rule that *should* be applied.

The Collector returns a single synthetic CanonicalFlow representing the
observed datapath action for the seed's (priority, match). The
Differential Oracle's classifier compares this against the cluster
state.
"""

from __future__ import annotations

import logging
import urllib.parse
from dataclasses import dataclass

import aiohttp

from gapfuzz.core.flow_content import (
    CanonicalAction,
    CanonicalFlow,
    from_onos_rest,
)
from gapfuzz.engine.seed_generator import Seed

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DataPlaneView:
    flows: frozenset[CanonicalFlow]


class DataPlaneCollector:
    """Trace-based DP collector. Queries the ryu /dp/trace endpoint."""

    def __init__(self, ryu_host: str, ryu_port: int = 8080,
                 request_timeout_s: float = 10.0,
                 bridge: str = "s1",
                 trace_in_port: int = 3):
        self.ryu_host = ryu_host
        self.ryu_port = ryu_port
        self.bridge = bridge
        self.trace_in_port = trace_in_port
        self._timeout = aiohttp.ClientTimeout(total=request_timeout_s)

    async def collect(self, seed: Seed) -> DataPlaneView:
        dpid = _device_id_to_dpid_str(seed.device_id)
        seed_canon = from_onos_rest(seed.R)
        flow_spec = _build_trace_flow(seed_canon, self.trace_in_port)

        params = {"bridge": self.bridge, "flow": flow_spec}
        url = (f"http://{self.ryu_host}:{self.ryu_port}/dp/trace/{dpid}"
               f"?{urllib.parse.urlencode(params)}")
        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            async with session.get(url) as resp:
                resp.raise_for_status()
                data = await resp.json()

        action_str = data.get("datapath_action", "unknown")
        canon_action = _parse_dp_action(action_str)
        if canon_action is None:
            logger.debug("DP trace returned unparsable action %r for seed %s",
                         action_str, seed.template_name)
            return DataPlaneView(flows=frozenset())

        synthetic = CanonicalFlow(
            priority=seed_canon.priority,
            match=seed_canon.match,
            actions=(canon_action,),
        )
        return DataPlaneView(flows=frozenset({synthetic}))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _device_id_to_dpid_str(device_id: str) -> str:
    """Convert ONOS deviceId 'of:0000000000000001' to ryu-side hex."""
    if device_id.startswith("of:"):
        return device_id[3:]
    return device_id


def _build_trace_flow(seed_canon: CanonicalFlow, default_in_port: int) -> str:
    """Build the OVS trace flow string from a CanonicalFlow's match.

    `ovs-appctl ofproto/trace` uses the historical OF1.0-style flow
    syntax (dl_type, nw_dst, ...), not the OXM names of OF 1.3.
    `tp_src`/`tp_dst` are L4 ports disambiguated by nw_proto.

    OVS enforces a strict prerequisite ordering on the flow string:
    for example, `tp_dst` requires `nw_proto` to appear earlier; `nw_*`
    requires `dl_type` to appear earlier. Since CanonicalFlow.match is
    a frozenset (non-deterministic iteration order), we explicitly
    bucket fields by prerequisite tier and emit them in tier order.
    """
    # Priority tiers: lower = emitted first (parents before children).
    _TIER = {
        "in_port":     0,
        "dl_type":     1, "dl_src":      1, "dl_dst":      1,
        "dl_vlan":     2, "dl_vlan_pcp": 2,
        "nw_proto":    3,
        "nw_src":      4, "nw_dst":      4,
        "tp_src":      5, "tp_dst":      5, "icmp_type":   5,
    }

    parts: list[tuple[int, str]] = []  # (tier, "field=value")
    has_in_port = False
    for field, value in seed_canon.match:
        if field == "in_port":
            parts.append((_TIER["in_port"], f"in_port={value}"))
            has_in_port = True
        elif field == "eth_type":
            parts.append((_TIER["dl_type"], f"dl_type=0x{value:04x}"))
        elif field == "eth_src":
            parts.append((_TIER["dl_src"], f"dl_src={value}"))
        elif field == "eth_dst":
            parts.append((_TIER["dl_dst"], f"dl_dst={value}"))
        elif field == "ipv4_src":
            addr, prefix = value
            s = f"nw_src={addr}" if prefix == 32 else f"nw_src={addr}/{prefix}"
            parts.append((_TIER["nw_src"], s))
        elif field == "ipv4_dst":
            addr, prefix = value
            s = f"nw_dst={addr}" if prefix == 32 else f"nw_dst={addr}/{prefix}"
            parts.append((_TIER["nw_dst"], s))
        elif field == "vlan_vid":
            parts.append((_TIER["dl_vlan"], f"dl_vlan={value}"))
        elif field == "vlan_pcp":
            parts.append((_TIER["dl_vlan_pcp"], f"dl_vlan_pcp={value}"))
        elif field == "ip_proto":
            parts.append((_TIER["nw_proto"], f"nw_proto={value}"))
        elif field in ("tcp_src", "udp_src"):
            parts.append((_TIER["tp_src"], f"tp_src={value}"))
        elif field in ("tcp_dst", "udp_dst"):
            parts.append((_TIER["tp_dst"], f"tp_dst={value}"))
        elif field == "icmpv4_type":
            parts.append((_TIER["icmp_type"], f"icmp_type={value}"))
    if not has_in_port:
        parts.append((_TIER["in_port"], f"in_port={default_in_port}"))
    parts.sort(key=lambda kv: kv[0])
    return ",".join(p for _, p in parts)


def _parse_dp_action(action_str: str) -> CanonicalAction | None:
    """Convert a parsed datapath action string to a CanonicalAction.

    Inputs come from `_parse_datapath_actions` on the ryu side:
    a numeric port, 'drop', or 'unknown'. Returns None on 'unknown'.
    """
    if action_str == "drop":
        return CanonicalAction(type="DROP", params=())
    if action_str.isdigit():
        return CanonicalAction(type="OUTPUT",
                               params=(("port", int(action_str)),))
    return None
