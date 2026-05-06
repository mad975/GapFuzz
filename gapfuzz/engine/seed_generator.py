"""Seed generator for the Exploration Engine (Section 5.2).

A template specifies one (selector, priority) pair plus two contradictory
forwarding actions (action_a, action_b). GenerateSeed(template) produces
the pair (R, R') of ONOS REST flow bodies, both targeting the same device
with the same selector and priority but with action_a and action_b
respectively.

Template format (YAML):

    name: contradictory_output_action
    device_id: "of:0000000000000001"
    priority: 40000
    selector:
      eth_type: 0x0800
      ipv4_dst: "10.0.0.1/32"
    action_a:
      type: OUTPUT
      port: 1
    action_b:
      type: OUTPUT
      port: 2

Supported action types in the YAML: OUTPUT, GROUP, PUSH_VLAN, POP_VLAN,
SET_FIELD, DROP. These map to the in-scope actions of Section 5.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Seed:
    """A seed: two contradictory flow bodies sharing (device, selector, priority)."""

    template_name: str
    device_id: str
    priority: int
    R: dict   # ONOS flow body for action_a
    R_prime: dict  # ONOS flow body for action_b


# ---------------------------------------------------------------------------
# Selector field -> ONOS criterion encoding
# ---------------------------------------------------------------------------
# Maps a YAML key to (ONOS criterion type, ONOS value-key, value-encoder).

def _enc_int(v: Any) -> int:
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        s = v.strip()
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    raise TypeError(f"Cannot encode as int: {v!r}")


def _enc_hex_str(v: Any) -> str:
    """Encode an int as ONOS hex string (e.g. '0x800') for ETH_TYPE."""
    n = _enc_int(v)
    return f"0x{n:x}"


def _enc_ipv4(v: Any) -> str:
    """Always emit 'a.b.c.d/N'. If no /N given, default to /32."""
    if not isinstance(v, str):
        raise TypeError(f"Cannot encode IPv4: {v!r}")
    return v if "/" in v else f"{v}/32"


def _enc_str(v: Any) -> str:
    return str(v)


_SELECTOR_ENCODERS: dict[str, tuple[str, str, Any]] = {
    "in_port":     ("IN_PORT",     "port",     _enc_str),
    "eth_src":     ("ETH_SRC",     "mac",      _enc_str),
    "eth_dst":     ("ETH_DST",     "mac",      _enc_str),
    "eth_type":    ("ETH_TYPE",    "ethType",  _enc_hex_str),
    "vlan_vid":    ("VLAN_VID",    "vlanId",   _enc_int),
    "vlan_pcp":    ("VLAN_PCP",    "priority", _enc_int),
    "ip_proto":    ("IP_PROTO",    "protocol", _enc_int),
    "ipv4_src":    ("IPV4_SRC",    "ip",       _enc_ipv4),
    "ipv4_dst":    ("IPV4_DST",    "ip",       _enc_ipv4),
    "tcp_src":     ("TCP_SRC",     "tcpPort",  _enc_int),
    "tcp_dst":     ("TCP_DST",     "tcpPort",  _enc_int),
    "udp_src":     ("UDP_SRC",     "udpPort",  _enc_int),
    "udp_dst":     ("UDP_DST",     "udpPort",  _enc_int),
    "icmpv4_type": ("ICMPV4_TYPE", "icmpType", _enc_int),
}


# ---------------------------------------------------------------------------
# Action encoder
# ---------------------------------------------------------------------------

def _encode_action_to_treatment(action: dict) -> dict:
    """Encode a YAML action dict into an ONOS treatment object."""
    atype = action.get("type", "").upper()
    if atype == "DROP":
        return {"instructions": [{"type": "NOACTION"}]}
    if atype == "OUTPUT":
        port = action["port"]
        return {"instructions": [{"type": "OUTPUT", "port": str(port)}]}
    if atype == "GROUP":
        gid = _enc_int(action["group_id"])
        return {"instructions": [{"type": "GROUP", "groupId": gid}]}
    if atype == "PUSH_VLAN":
        eth_type = _enc_int(action.get("eth_type", 0x8100))
        return {
            "instructions": [
                {"type": "L2MODIFICATION", "subtype": "VLAN_PUSH",
                 "ethernetType": eth_type}
            ]
        }
    if atype == "POP_VLAN":
        return {
            "instructions": [
                {"type": "L2MODIFICATION", "subtype": "VLAN_POP"}
            ]
        }
    if atype == "SET_FIELD":
        return _encode_set_field(action)
    raise ValueError(f"Unsupported action type in template: {atype!r}")


def _encode_set_field(action: dict) -> dict:
    field = action["field"].lower()
    value = action["value"]
    if field == "vlan_vid":
        return {
            "instructions": [
                {"type": "L2MODIFICATION", "subtype": "VLAN_ID",
                 "vlanId": _enc_int(value)}
            ]
        }
    if field == "eth_src":
        return {"instructions": [
            {"type": "L2MODIFICATION", "subtype": "ETH_SRC", "mac": str(value)}
        ]}
    if field == "eth_dst":
        return {"instructions": [
            {"type": "L2MODIFICATION", "subtype": "ETH_DST", "mac": str(value)}
        ]}
    if field == "ipv4_src":
        return {"instructions": [
            {"type": "L3MODIFICATION", "subtype": "IPV4_SRC", "ip": _enc_ipv4(value)}
        ]}
    if field == "ipv4_dst":
        return {"instructions": [
            {"type": "L3MODIFICATION", "subtype": "IPV4_DST", "ip": _enc_ipv4(value)}
        ]}
    if field == "tcp_src":
        return {"instructions": [
            {"type": "L4MODIFICATION", "subtype": "TCP_SRC", "tcpPort": _enc_int(value)}
        ]}
    if field == "tcp_dst":
        return {"instructions": [
            {"type": "L4MODIFICATION", "subtype": "TCP_DST", "tcpPort": _enc_int(value)}
        ]}
    if field == "udp_src":
        return {"instructions": [
            {"type": "L4MODIFICATION", "subtype": "UDP_SRC", "udpPort": _enc_int(value)}
        ]}
    if field == "udp_dst":
        return {"instructions": [
            {"type": "L4MODIFICATION", "subtype": "UDP_DST", "udpPort": _enc_int(value)}
        ]}
    raise ValueError(f"Unsupported SET_FIELD target: {field!r}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_seed(template: dict) -> Seed:
    """GenerateSeed(template) -> (R, R') as a Seed object.

    template is a dict already loaded from YAML.
    """
    name = template.get("name") or "<unnamed>"
    device_id = template["device_id"]
    priority = int(template["priority"])
    selector_yaml = template.get("selector") or {}
    action_a = template["action_a"]
    action_b = template["action_b"]

    selector_obj = _build_onos_selector(selector_yaml)
    treatment_a = _encode_action_to_treatment(action_a)
    treatment_b = _encode_action_to_treatment(action_b)

    R = {
        "priority": priority,
        "isPermanent": True,
        "deviceId": device_id,
        "selector": selector_obj,
        "treatment": treatment_a,
    }
    R_prime = {
        "priority": priority,
        "isPermanent": True,
        "deviceId": device_id,
        "selector": selector_obj,
        "treatment": treatment_b,
    }
    return Seed(
        template_name=name,
        device_id=device_id,
        priority=priority,
        R=R,
        R_prime=R_prime,
    )


def _build_onos_selector(selector_yaml: dict) -> dict:
    criteria: list[dict] = []
    for key, raw_value in selector_yaml.items():
        if key not in _SELECTOR_ENCODERS:
            raise ValueError(f"Unsupported selector field: {key!r}")
        ctype, vkey, encoder = _SELECTOR_ENCODERS[key]
        criteria.append({"type": ctype, vkey: encoder(raw_value)})
    return {"criteria": criteria}
