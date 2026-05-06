"""Canonical FlowContent representation and normalization.

Implements the equality semantics for the Differential Oracle (Section 5.3).

A canonical flow has three components: priority (int), match (frozenset of
(field, value) pairs), and actions (tuple of canonical action records).
Two canonical flows are equal iff their components are equal.

Two converters bring source-specific representations into the canonical
form:

  - from_onos_rest(json_dict): ONOS REST API (POST/GET /onos/v1/flows)
  - from_ryu_jsondict(json_dict): ryu OFPFlowStats.to_jsondict()

Scope (validated with the user, see Section 5):
  - Match fields (14, OF 1.3): IN_PORT, ETH_SRC, ETH_DST, ETH_TYPE,
    VLAN_VID, VLAN_PCP, IP_PROTO, IPV4_SRC, IPV4_DST, TCP_SRC, TCP_DST,
    UDP_SRC, UDP_DST, ICMPV4_TYPE.
  - Actions (6): OUTPUT, SET_FIELD, PUSH_VLAN, POP_VLAN, GROUP, drop.
  - IPv6 and ARP are out of scope.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Canonical types
# ---------------------------------------------------------------------------

# A canonical match field is a (field_name, value) pair.
# field_name is the lowercase OXM name, e.g. 'ipv4_dst', 'eth_type'.
# value depends on field_name; see _normalize_*_value below for each.
CanonicalField = tuple[str, Any]


@dataclass(frozen=True)
class CanonicalAction:
    """One action in an APPLY_ACTIONS instruction.

    type is the canonical action name: OUTPUT, SET_FIELD, PUSH_VLAN,
    POP_VLAN, GROUP, DROP.
    params is a sorted tuple of (key, value) pairs that fully specify
    the action's semantics.
    """

    type: str
    params: tuple[tuple[str, Any], ...]


@dataclass(frozen=True)
class CanonicalFlow:
    """A flow content in canonical form.

    Two canonical flows are equal iff (priority, match, actions) match.
    The 'match' is a frozenset because OF match fields are unordered.
    The 'actions' is a tuple because APPLY_ACTIONS preserves order.
    """

    priority: int
    match: frozenset[CanonicalField]
    actions: tuple[CanonicalAction, ...]


# ---------------------------------------------------------------------------
# Symbolic ports (OFPP_*) <-> string mapping
# ---------------------------------------------------------------------------
# ONOS REST emits string symbolic ports; ryu emits integers. We canonicalize
# to the OF 1.3 integer constants.
_OFPP_BY_NAME: dict[str, int] = {
    "IN_PORT": 0xFFFFFFF8,
    "TABLE": 0xFFFFFFF9,
    "NORMAL": 0xFFFFFFFA,
    "FLOOD": 0xFFFFFFFB,
    "ALL": 0xFFFFFFFC,
    "CONTROLLER": 0xFFFFFFFD,
    "LOCAL": 0xFFFFFFFE,
    "ANY": 0xFFFFFFFF,
}


def _port_to_int(value: Any) -> int:
    """Resolve a port value (str symbolic or int) to its OF 1.3 integer."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        v = value.strip()
        if v.upper() in _OFPP_BY_NAME:
            return _OFPP_BY_NAME[v.upper()]
        # Decimal or hex
        try:
            if v.lower().startswith("0x"):
                return int(v, 16)
            return int(v)
        except ValueError as exc:
            raise ValueError(f"Cannot parse port value: {value!r}") from exc
    raise TypeError(f"Unsupported port type: {type(value).__name__}")


# ---------------------------------------------------------------------------
# Match-field value normalizers
# ---------------------------------------------------------------------------
# Each normalizer takes a raw value (from ONOS REST or ryu) and returns
# the canonical representation. The canonical representation MUST be
# identical regardless of the source side.

def _normalize_int(value: Any) -> int:
    """Generic integer field (ETH_TYPE, IP_PROTO, port numbers, etc.)."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s)
    raise TypeError(f"Cannot normalize as int: {value!r}")


def _normalize_mac(value: Any) -> str:
    """MAC address: canonical lowercase 'aa:bb:cc:dd:ee:ff'."""
    if not isinstance(value, str):
        raise TypeError(f"Cannot normalize MAC: {value!r}")
    return value.strip().lower()


def _normalize_ipv4(value: Any) -> tuple[str, int]:
    """IPv4 address with prefix: returns (addr_str, prefix_int).

    Accepts:
      - 'a.b.c.d/N'   (ONOS REST canonical form)
      - 'a.b.c.d'     (treated as /32, mirrors PoC behavior)
      - (addr, mask)  (ryu format with mask, e.g. ('10.0.0.0', '255.255.255.0'))
    """
    if isinstance(value, str):
        s = value.strip()
        if "/" in s:
            addr, prefix = s.split("/", 1)
            return (addr, int(prefix))
        # No mask -> /32 (matches the PoC convention validated by user)
        return (s, 32)
    if isinstance(value, (list, tuple)) and len(value) == 2:
        addr, mask = value
        if isinstance(mask, int):
            return (str(addr), mask)
        if isinstance(mask, str):
            prefix = _netmask_to_prefix(mask)
            return (str(addr), prefix)
    raise TypeError(f"Cannot normalize IPv4: {value!r}")


def _netmask_to_prefix(mask: str) -> int:
    """Convert dotted netmask '255.255.255.0' to prefix length 24."""
    octets = [int(o) for o in mask.split(".")]
    if len(octets) != 4:
        raise ValueError(f"Invalid netmask: {mask!r}")
    bits = 0
    for o in octets:
        bits = (bits << 8) | o
    # Count contiguous leading 1s
    prefix = 0
    saw_zero = False
    for i in range(31, -1, -1):
        if (bits >> i) & 1:
            if saw_zero:
                raise ValueError(f"Non-contiguous netmask: {mask!r}")
            prefix += 1
        else:
            saw_zero = True
    return prefix


def _normalize_vlan_vid(value: Any) -> int:
    """VLAN_VID: strip the OFPVID_PRESENT bit (0x1000) if set."""
    v = _normalize_int(value)
    return v & 0x0FFF


# Mapping: field_name (canonical lowercase) -> normalizer
_FIELD_NORMALIZERS = {
    "in_port": _normalize_int,
    "eth_src": _normalize_mac,
    "eth_dst": _normalize_mac,
    "eth_type": _normalize_int,
    "vlan_vid": _normalize_vlan_vid,
    "vlan_pcp": _normalize_int,
    "ip_proto": _normalize_int,
    "ipv4_src": _normalize_ipv4,
    "ipv4_dst": _normalize_ipv4,
    "tcp_src": _normalize_int,
    "tcp_dst": _normalize_int,
    "udp_src": _normalize_int,
    "udp_dst": _normalize_int,
    "icmpv4_type": _normalize_int,
}


# ---------------------------------------------------------------------------
# ONOS REST parser
# ---------------------------------------------------------------------------
# ONOS uses uppercase criterion type names and field-specific value keys.
_ONOS_CRITERION_FIELD = {
    "IN_PORT": ("in_port", "port"),
    "ETH_SRC": ("eth_src", "mac"),
    "ETH_DST": ("eth_dst", "mac"),
    "ETH_TYPE": ("eth_type", "ethType"),
    "VLAN_VID": ("vlan_vid", "vlanId"),
    "VLAN_PCP": ("vlan_pcp", "priority"),
    "IP_PROTO": ("ip_proto", "protocol"),
    "IPV4_SRC": ("ipv4_src", "ip"),
    "IPV4_DST": ("ipv4_dst", "ip"),
    "TCP_SRC": ("tcp_src", "tcpPort"),
    "TCP_DST": ("tcp_dst", "tcpPort"),
    "UDP_SRC": ("udp_src", "udpPort"),
    "UDP_DST": ("udp_dst", "udpPort"),
    "ICMPV4_TYPE": ("icmpv4_type", "icmpType"),
}


def from_onos_rest(flow_json: dict) -> CanonicalFlow:
    """Convert an ONOS REST flow object to canonical form.

    Accepts the form returned by GET /onos/v1/flows/{deviceId} (one flow).
    """
    priority = int(flow_json["priority"])

    # --- match
    match_fields: list[CanonicalField] = []
    selector = flow_json.get("selector", {}) or {}
    for crit in selector.get("criteria", []) or []:
        ctype = crit.get("type")
        if ctype not in _ONOS_CRITERION_FIELD:
            # Out-of-scope field (IPv6, ARP, MPLS, ...). Skip silently;
            # the user is expected to use only in-scope fields in templates.
            # If an unexpected field appears we keep a tagged tuple so
            # equality still differentiates it.
            match_fields.append(("_unknown", (ctype, _hashable(crit))))
            continue
        canon_name, key = _ONOS_CRITERION_FIELD[ctype]
        if key not in crit:
            raise ValueError(f"ONOS criterion {ctype} missing key {key!r}: {crit!r}")
        value = _FIELD_NORMALIZERS[canon_name](crit[key])
        match_fields.append((canon_name, value))

    # --- actions
    actions = _parse_onos_treatment(flow_json.get("treatment", {}) or {})

    return CanonicalFlow(
        priority=priority,
        match=frozenset(match_fields),
        actions=actions,
    )


def _parse_onos_treatment(treatment: dict) -> tuple[CanonicalAction, ...]:
    """Convert an ONOS treatment.instructions list to canonical actions."""
    instructions = treatment.get("instructions") or []
    if not instructions:
        # ONOS uses an empty/absent treatment for explicit drops; ONOS may
        # also represent drop with a NOACTION instruction. We canonicalize
        # both to a single DROP action.
        return (CanonicalAction(type="DROP", params=()),)

    result: list[CanonicalAction] = []
    for instr in instructions:
        itype = instr.get("type")
        if itype == "OUTPUT":
            port = _port_to_int(instr["port"])
            result.append(CanonicalAction("OUTPUT", (("port", port),)))
        elif itype == "GROUP":
            gid = _normalize_int(instr["groupId"])
            result.append(CanonicalAction("GROUP", (("group_id", gid),)))
        elif itype == "L2MODIFICATION":
            # ONOS subtypes: VLAN_PUSH, VLAN_POP, VLAN_ID, ETH_SRC, ETH_DST, ...
            result.append(_parse_onos_l2mod(instr))
        elif itype == "L3MODIFICATION":
            result.append(_parse_onos_l3mod(instr))
        elif itype == "L4MODIFICATION":
            result.append(_parse_onos_l4mod(instr))
        elif itype == "NOACTION":
            result.append(CanonicalAction("DROP", ()))
        else:
            # Out-of-scope instruction kept as opaque so equality still
            # distinguishes it.
            result.append(CanonicalAction("_unknown", (("raw", _hashable(instr)),)))
    return tuple(result)


def _parse_onos_l2mod(instr: dict) -> CanonicalAction:
    sub = instr.get("subtype")
    if sub == "VLAN_PUSH":
        eth_type = _normalize_int(instr.get("ethernetType", 0x8100))
        return CanonicalAction("PUSH_VLAN", (("eth_type", eth_type),))
    if sub == "VLAN_POP":
        return CanonicalAction("POP_VLAN", ())
    if sub == "VLAN_ID":
        vid = _normalize_vlan_vid(instr["vlanId"])
        return CanonicalAction("SET_FIELD", (("field", "vlan_vid"), ("value", vid)))
    if sub == "ETH_SRC":
        return CanonicalAction(
            "SET_FIELD",
            (("field", "eth_src"), ("value", _normalize_mac(instr["mac"]))),
        )
    if sub == "ETH_DST":
        return CanonicalAction(
            "SET_FIELD",
            (("field", "eth_dst"), ("value", _normalize_mac(instr["mac"]))),
        )
    return CanonicalAction("_unknown", (("raw", _hashable(instr)),))


def _parse_onos_l3mod(instr: dict) -> CanonicalAction:
    sub = instr.get("subtype")
    if sub == "IPV4_SRC":
        return CanonicalAction(
            "SET_FIELD",
            (("field", "ipv4_src"), ("value", _normalize_ipv4(instr["ip"]))),
        )
    if sub == "IPV4_DST":
        return CanonicalAction(
            "SET_FIELD",
            (("field", "ipv4_dst"), ("value", _normalize_ipv4(instr["ip"]))),
        )
    return CanonicalAction("_unknown", (("raw", _hashable(instr)),))


def _parse_onos_l4mod(instr: dict) -> CanonicalAction:
    sub = instr.get("subtype")
    if sub == "TCP_SRC":
        return CanonicalAction(
            "SET_FIELD",
            (("field", "tcp_src"), ("value", _normalize_int(instr["tcpPort"]))),
        )
    if sub == "TCP_DST":
        return CanonicalAction(
            "SET_FIELD",
            (("field", "tcp_dst"), ("value", _normalize_int(instr["tcpPort"]))),
        )
    if sub == "UDP_SRC":
        return CanonicalAction(
            "SET_FIELD",
            (("field", "udp_src"), ("value", _normalize_int(instr["udpPort"]))),
        )
    if sub == "UDP_DST":
        return CanonicalAction(
            "SET_FIELD",
            (("field", "udp_dst"), ("value", _normalize_int(instr["udpPort"]))),
        )
    return CanonicalAction("_unknown", (("raw", _hashable(instr)),))


# ---------------------------------------------------------------------------
# Ryu OFPFlowStats parser
# ---------------------------------------------------------------------------
# ryu's OFPFlowStats.to_jsondict() shape:
# {'OFPFlowStats': {'priority': N, 'match': {'OFPMatch': {'oxm_fields':[...]}},
#                   'instructions': [...], ...}}
# Each oxm_field: {'OXMTlv': {'field': 'ipv4_dst', 'value': ..., 'mask': ...?}}

def from_ryu_jsondict(flow_jsondict: dict) -> CanonicalFlow:
    """Convert a single ryu OFPFlowStats jsondict to canonical form."""
    inner = flow_jsondict.get("OFPFlowStats", flow_jsondict)
    priority = int(inner["priority"])

    # --- match
    match_fields: list[CanonicalField] = []
    match_obj = inner.get("match", {})
    match_inner = match_obj.get("OFPMatch", match_obj)
    for tlv_wrapper in match_inner.get("oxm_fields", []) or []:
        tlv = tlv_wrapper.get("OXMTlv", tlv_wrapper)
        field = tlv.get("field")
        if field not in _FIELD_NORMALIZERS:
            match_fields.append(("_unknown", (field, _hashable(tlv))))
            continue
        value = tlv.get("value")
        mask = tlv.get("mask")
        if field in ("ipv4_src", "ipv4_dst"):
            if mask is not None:
                normalized = _normalize_ipv4((value, mask))
            else:
                normalized = _normalize_ipv4(value)
        else:
            normalized = _FIELD_NORMALIZERS[field](value)
        match_fields.append((field, normalized))

    # --- actions
    actions = _parse_ryu_instructions(inner.get("instructions", []) or [])

    return CanonicalFlow(
        priority=priority,
        match=frozenset(match_fields),
        actions=actions,
    )


def _parse_ryu_instructions(instructions: list) -> tuple[CanonicalAction, ...]:
    """Extract APPLY_ACTIONS from ryu instruction list (preserves order)."""
    result: list[CanonicalAction] = []
    found_apply = False
    for instr_wrapper in instructions:
        # Wrappers can be 'OFPInstructionActions', 'OFPInstructionGotoTable', etc.
        if "OFPInstructionActions" in instr_wrapper:
            inner = instr_wrapper["OFPInstructionActions"]
            # type 4 == OFPIT_APPLY_ACTIONS
            if inner.get("type") == 4:
                found_apply = True
                for act_wrapper in inner.get("actions", []) or []:
                    result.append(_parse_ryu_action(act_wrapper))
            elif inner.get("type") == 3:  # OFPIT_WRITE_ACTIONS
                # WRITE_ACTIONS is an unordered set; we sort for canonical eq.
                # (Out of scope per design but kept harmless.)
                ws = [_parse_ryu_action(a) for a in inner.get("actions", []) or []]
                ws.sort(key=lambda a: (a.type, a.params))
                result.extend(ws)
        # Other instruction kinds (GotoTable, WriteMetadata, etc.) are
        # currently out of scope and ignored. Document if you extend.

    if not found_apply and not result:
        # No APPLY_ACTIONS and no actions extracted -> drop semantics.
        return (CanonicalAction("DROP", ()),)
    if found_apply and not result:
        # APPLY_ACTIONS with empty actions list = explicit drop.
        return (CanonicalAction("DROP", ()),)
    return tuple(result)


def _parse_ryu_action(act_wrapper: dict) -> CanonicalAction:
    if "OFPActionOutput" in act_wrapper:
        port = _port_to_int(act_wrapper["OFPActionOutput"]["port"])
        return CanonicalAction("OUTPUT", (("port", port),))
    if "OFPActionGroup" in act_wrapper:
        gid = _normalize_int(act_wrapper["OFPActionGroup"]["group_id"])
        return CanonicalAction("GROUP", (("group_id", gid),))
    if "OFPActionPushVlan" in act_wrapper:
        eth_type = _normalize_int(act_wrapper["OFPActionPushVlan"]["ethertype"])
        return CanonicalAction("PUSH_VLAN", (("eth_type", eth_type),))
    if "OFPActionPopVlan" in act_wrapper:
        return CanonicalAction("POP_VLAN", ())
    if "OFPActionSetField" in act_wrapper:
        sf = act_wrapper["OFPActionSetField"]
        # sf is typically {'field': {'OXMTlv': {'field': X, 'value': V}}}
        # but may also be {'OXMTlv': {...}} or {'<field>': <value>}
        field_name, value = _extract_set_field(sf)
        return CanonicalAction(
            "SET_FIELD", (("field", field_name), ("value", value))
        )
    return CanonicalAction("_unknown", (("raw", _hashable(act_wrapper)),))


def _extract_set_field(sf: dict) -> tuple[str, Any]:
    """Best-effort extraction of (field_name, value) from a SET_FIELD action."""
    if "field" in sf and isinstance(sf["field"], dict) and "OXMTlv" in sf["field"]:
        tlv = sf["field"]["OXMTlv"]
        name = tlv["field"]
        raw = tlv.get("value")
        normalizer = _FIELD_NORMALIZERS.get(name)
        return (name, normalizer(raw) if normalizer else raw)
    if "OXMTlv" in sf:
        tlv = sf["OXMTlv"]
        name = tlv["field"]
        raw = tlv.get("value")
        normalizer = _FIELD_NORMALIZERS.get(name)
        return (name, normalizer(raw) if normalizer else raw)
    # Older ryu convenience form: {'<field_name>': <value>}
    for k, v in sf.items():
        if k in _FIELD_NORMALIZERS:
            return (k, _FIELD_NORMALIZERS[k](v))
    return ("_unknown", _hashable(sf))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hashable(obj: Any) -> Any:
    """Make a possibly-nested dict/list hashable for inclusion in a tuple."""
    if isinstance(obj, dict):
        return tuple(sorted((k, _hashable(v)) for k, v in obj.items()))
    if isinstance(obj, (list, tuple)):
        return tuple(_hashable(v) for v in obj)
    return obj


def canonical_flows_from_onos_list(flow_list: Iterable[dict]) -> list[CanonicalFlow]:
    """Convert an ONOS REST list of flows (e.g. from GET /flows/{device})
    to canonical flows."""
    return [from_onos_rest(f) for f in flow_list]


def canonical_flows_from_ryu_list(flow_list: Iterable[dict]) -> list[CanonicalFlow]:
    """Convert a list of ryu flow jsondicts to canonical flows."""
    return [from_ryu_jsondict(f) for f in flow_list]
