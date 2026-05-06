"""Configuration loader for GapFuzz.

Reads:
  - config.yaml: cluster topology + injection targets + DP collector
                 endpoint + algorithm parameters (Δt_0, ε, δ).
  - templates/*.yaml: one file per parameterized template.

Returns dataclasses ready to instantiate the modules.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from gapfuzz.onos_client import OnosNode

logger = logging.getLogger(__name__)


@dataclass
class GapFuzzConfig:
    cluster_nodes: list[OnosNode]            # all ONOS nodes (for CP collection)
    injection_target_R: OnosNode             # backup node receiving R
    injection_target_R_prime: OnosNode       # backup node receiving R'
    ryu_host: str
    ryu_port: int
    device_id: str                           # ONOS deviceId, e.g. of:0000000000000001
    dp_bridge: str                           # OVS bridge name, e.g. br0
    dp_trace_in_port: int                    # in_port used by ofproto/trace
    dp_command_template: str | None          # for switch-side reset
    delta_t_0_s: float
    epsilon_s: float
    delta_s: float
    lifetime_s: float                        # post-injection lifetime check window
    app_id: str
    request_timeout_s: float
    output_path: str


def load_config(config_path: str | Path) -> GapFuzzConfig:
    raw = _load_yaml(config_path)

    nodes = [_parse_node(n) for n in raw["cluster"]["nodes"]]
    by_name = {n.name: n for n in nodes}

    inj = raw["injection"]
    target_R = by_name[inj["target_R"]]
    target_R_prime = by_name[inj["target_R_prime"]]
    if target_R.name == target_R_prime.name:
        raise ValueError(
            "config.injection: target_R and target_R_prime must differ "
            "(spatial scheduling requires two distinct backup nodes)."
        )

    dp = raw["data_plane"]
    algo = raw["algorithm"]
    reset_cfg = raw.get("reset", {}) or {}

    return GapFuzzConfig(
        cluster_nodes=nodes,
        injection_target_R=target_R,
        injection_target_R_prime=target_R_prime,
        ryu_host=dp["ryu_host"],
        ryu_port=int(dp.get("ryu_port", 8080)),
        device_id=dp["device_id"],
        dp_bridge=dp.get("bridge", "br0"),
        dp_trace_in_port=int(dp.get("trace_in_port", 3)),
        dp_command_template=reset_cfg.get("dp_command_template"),
        delta_t_0_s=float(algo["delta_t_0_s"]),
        epsilon_s=float(algo["epsilon_s"]),
        delta_s=float(algo["delta_s"]),
        lifetime_s=float(algo.get("lifetime_s", 30.0)),
        app_id=raw.get("app_id", "gapfuzz"),
        request_timeout_s=float(raw.get("request_timeout_s", 10.0)),
        output_path=raw.get("output_path", "results.jsonl"),
    )


def load_templates(templates_dir: str | Path) -> list[dict]:
    templates_path = Path(templates_dir)
    if not templates_path.is_dir():
        raise FileNotFoundError(
            f"Templates directory not found: {templates_path}"
        )
    files = sorted(templates_path.glob("*.yaml")) + sorted(
        templates_path.glob("*.yml")
    )
    if not files:
        raise FileNotFoundError(
            f"No templates (*.yaml/*.yml) found under {templates_path}"
        )
    templates: list[dict] = []
    for f in files:
        loaded = _load_yaml(f)
        loaded.setdefault("name", f.stem)
        _validate_template(loaded, source=str(f))
        templates.append(loaded)
    return templates


def _load_yaml(path: str | Path) -> Any:
    with open(path, "r", encoding="utf-8") as fp:
        return yaml.safe_load(fp)


def _parse_node(d: dict) -> OnosNode:
    return OnosNode(
        name=d["name"],
        host=d["host"],
        port=int(d.get("port", 8181)),
        username=d.get("username", "onos"),
        password=d.get("password", "rocks"),
    )


def _validate_template(t: dict, source: str) -> None:
    required = ["device_id", "priority", "selector", "action_a", "action_b"]
    for key in required:
        if key not in t:
            raise ValueError(f"Template {source} missing key: {key!r}")
    if not isinstance(t["selector"], dict) or not t["selector"]:
        raise ValueError(f"Template {source}: selector must be a non-empty dict")
    if not isinstance(t["action_a"], dict) or "type" not in t["action_a"]:
        raise ValueError(f"Template {source}: action_a must be a dict with 'type'")
    if not isinstance(t["action_b"], dict) or "type" not in t["action_b"]:
        raise ValueError(f"Template {source}: action_b must be a dict with 'type'")
