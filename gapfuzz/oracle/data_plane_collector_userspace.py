"""OF user-space variant of the Data Plane Collector (§7.4 ablation).

Probes the switch's OpenFlow user-space table via `ovs-ofctl dump-flows`
instead of `ovs-appctl ofproto/trace` Datapath actions. This models the
oracle architecture used by prior SDN fuzzers (BEADS, DELTA, Ambusher),
which query either the controller or the switch's OF user-space view but
never the kernel datapath megaflow cache.

The PoC of Section 3.2 shows the kernel megaflow cache can hold a stale
action long after the OF user-space table has reconciled with the
cluster. A user-space oracle is structurally blind to those stale-cache
divergences; this collector lets us quantify that blind spot.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import subprocess
from typing import Optional

from gapfuzz.core.flow_content import (
    CanonicalAction,
    CanonicalFlow,
    from_onos_rest,
)
from gapfuzz.engine.seed_generator import Seed
from gapfuzz.oracle.data_plane_collector import DataPlaneView

logger = logging.getLogger(__name__)


class UserspaceDataPlaneCollector:
    """Resolves the seed packet against `ovs-ofctl dump-flows` output."""

    def __init__(self, bridge: str = "s1",
                 trace_in_port: int = 3,
                 timeout_s: float = 5.0,
                 of_version: str = "OpenFlow13"):
        self.bridge = bridge
        self.trace_in_port = trace_in_port
        self.timeout_s = timeout_s
        self.of_version = of_version

    async def collect(self, seed: Seed) -> DataPlaneView:
        loop = asyncio.get_running_loop()
        try:
            r = await loop.run_in_executor(None, self._dump_flows)
        except subprocess.TimeoutExpired:
            logger.warning("ovs-ofctl dump-flows timed out")
            return DataPlaneView(flows=frozenset())

        if r.returncode != 0:
            logger.warning("ovs-ofctl dump-flows failed (%d): %s",
                           r.returncode, r.stderr.strip())
            return DataPlaneView(flows=frozenset())

        seed_canon = from_onos_rest(seed.R)
        action = _resolve_userspace_action(
            r.stdout, seed_canon, self.trace_in_port,
        )
        if action is None:
            return DataPlaneView(flows=frozenset())

        synthetic = CanonicalFlow(
            priority=seed_canon.priority,
            match=seed_canon.match,
            actions=(action,),
        )
        return DataPlaneView(flows=frozenset({synthetic}))

    def _dump_flows(self):
        return subprocess.run(
            ["sudo", "-n", "ovs-ofctl", "-O", self.of_version,
             "dump-flows", self.bridge],
            capture_output=True, text=True, timeout=self.timeout_s,
        )


# ---------------------------------------------------------------------------
# dump-flows → CanonicalAction
# ---------------------------------------------------------------------------

# Bare flow-protocol shorthands defined by ovs-ofctl(8). Each maps to the
# implicit (field, value) constraint it stands for.
_BARE_FLAGS = {
    "ip":   ("dl_type", "0x0800"),
    "ipv6": ("dl_type", "0x86dd"),
    "arp":  ("dl_type", "0x0806"),
    "tcp":  ("nw_proto", "6"),
    "udp":  ("nw_proto", "17"),
    "sctp": ("nw_proto", "132"),
    "icmp": ("nw_proto", "1"),
}

# Per-line metadata fields that sit in the same comma list as the match
# but are not match constraints.
_NON_MATCH_KEYS = {
    "cookie", "duration", "table", "n_packets", "n_bytes",
    "idle_age", "hard_age", "idle_timeout", "hard_timeout",
}
_NON_MATCH_FLAGS = {"send_flow_rem"}


def _parse_flow_line(line: str) -> Optional[dict]:
    """Parse one dump-flows entry into {priority, match, actions}.

    Returns None if the line is not a flow entry (e.g. the OFPST header).
    """
    if " actions=" not in line:
        return None
    head, _, actions = line.partition(" actions=")
    actions = actions.strip().rstrip(",")

    priority: Optional[int] = None
    match: dict[str, str] = {}
    for tok in (t.strip() for t in head.split(",") if t.strip()):
        # A token may carry a flag prefix separated by spaces, e.g.
        # "send_flow_rem priority=40000". Split it apart.
        for sub in tok.split():
            if sub in _NON_MATCH_FLAGS:
                continue
            if sub.startswith("priority="):
                try:
                    priority = int(sub.split("=", 1)[1])
                except ValueError:
                    return None
                continue
            if sub in _BARE_FLAGS:
                k, v = _BARE_FLAGS[sub]
                match.setdefault(k, v)
                continue
            if "=" in sub:
                k, _, v = sub.partition("=")
                k = k.strip()
                if k in _NON_MATCH_KEYS:
                    continue
                match[k] = v.strip()
    if priority is None:
        return None
    return {"priority": priority, "match": match, "actions": actions}


def _seed_to_packet(seed_canon: CanonicalFlow,
                    default_in_port: int) -> dict[str, str]:
    """Lower a CanonicalFlow.match to a concrete packet representation."""
    pkt: dict[str, str] = {"in_port": str(default_in_port)}
    for field, value in seed_canon.match:
        if field == "in_port":
            pkt["in_port"] = str(value)
        elif field == "eth_type":
            pkt["dl_type"] = f"0x{value:04x}"
        elif field == "eth_src":
            pkt["dl_src"] = str(value)
        elif field == "eth_dst":
            pkt["dl_dst"] = str(value)
        elif field == "ipv4_src":
            addr, prefix = value
            pkt["nw_src"] = addr if prefix == 32 else f"{addr}/{prefix}"
        elif field == "ipv4_dst":
            addr, prefix = value
            pkt["nw_dst"] = addr if prefix == 32 else f"{addr}/{prefix}"
        elif field == "vlan_vid":
            pkt["dl_vlan"] = str(value)
        elif field == "vlan_pcp":
            pkt["dl_vlan_pcp"] = str(value)
        elif field == "ip_proto":
            pkt["nw_proto"] = str(value)
        elif field in ("tcp_src", "udp_src"):
            pkt["tp_src"] = str(value)
        elif field in ("tcp_dst", "udp_dst"):
            pkt["tp_dst"] = str(value)
        elif field == "icmpv4_type":
            pkt["icmp_type"] = str(value)
    return pkt


def _flow_covers_packet(flow_match: dict[str, str],
                        pkt: dict[str, str]) -> bool:
    """True if every constraint in flow_match is satisfied by pkt.

    Conservative: if the flow constrains a field the seed packet does
    not specify, we cannot prove the constraint holds and skip the flow."""
    for k, v in flow_match.items():
        if k not in pkt:
            return False
        if not _value_matches(v, pkt[k]):
            return False
    return True


def _value_matches(constraint: str, value: str) -> bool:
    c, v = constraint.strip(), value.strip()
    if "/" in c:
        c_addr, _, c_prefix = c.partition("/")
        v_addr = v.split("/", 1)[0]
        try:
            return _ipv4_in_cidr(v_addr, c_addr, int(c_prefix))
        except (ValueError, ipaddress.AddressValueError):
            return False
    if c.startswith("0x") and v.startswith("0x"):
        try:
            return int(c, 16) == int(v, 16)
        except ValueError:
            return False
    if "/" in v:
        v_addr, _, v_prefix = v.partition("/")
        return c == v_addr and v_prefix == "32"
    return c == v


def _ipv4_in_cidr(addr: str, cidr_addr: str, prefix: int) -> bool:
    try:
        net = ipaddress.ip_network(f"{cidr_addr}/{prefix}", strict=False)
        return ipaddress.ip_address(addr) in net
    except (ValueError, ipaddress.AddressValueError):
        return False


def _reduce_actions(actions: str) -> Optional[CanonicalAction]:
    """Reduce an OF actions chain to canonical {DROP, OUTPUT(port)}.

    Mirrors the kernel-datapath collector's reduction: scan for the
    first 'output:N' anywhere in the chain (so 'set_field:1->vlan_vid,
    output:2' yields port=2). 'drop' or an empty chain is DROP.
    Anything else (e.g. CONTROLLER, GROUP) returns None to signal an
    action this oracle cannot canonicalize."""
    s = actions.strip().rstrip(",")
    if s == "" or s == "drop":
        return CanonicalAction(type="DROP", params=())
    m = re.search(r"output:(\d+)", s)
    if m:
        return CanonicalAction(type="OUTPUT",
                               params=(("port", int(m.group(1))),))
    return None


def _resolve_userspace_action(dump_output: str,
                              seed_canon: CanonicalFlow,
                              default_in_port: int,
                              ) -> Optional[CanonicalAction]:
    """Pick the highest-priority dumped flow whose match covers the seed
    packet, then reduce its actions."""
    pkt = _seed_to_packet(seed_canon, default_in_port)
    best_priority: Optional[int] = None
    best_actions: Optional[str] = None
    for line in dump_output.splitlines():
        line = line.strip()
        if not line or line.startswith("OFPST_"):
            continue
        flow = _parse_flow_line(line)
        if flow is None:
            continue
        if not _flow_covers_packet(flow["match"], pkt):
            continue
        if best_priority is None or flow["priority"] > best_priority:
            best_priority = flow["priority"]
            best_actions = flow["actions"]
    if best_actions is None:
        return None
    return _reduce_actions(best_actions)
