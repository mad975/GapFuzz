"""GapFuzz CLI entry point.

Usage:

    python -m gapfuzz.run --config config.yaml --templates templates/

Reads configuration, builds the components, runs Algorithm 1 from §5.4,
and writes the per-template results as JSON Lines to the configured
output path.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path
from typing import Iterable

from gapfuzz.config_loader import GapFuzzConfig, load_config, load_templates
from gapfuzz.core.algorithm import FuzzCampaignResult, run_algorithm
from gapfuzz.core.reset import Reset
from gapfuzz.engine.injector import Injector
from gapfuzz.engine.timing_analyzer import TemplateResult, TimingAnalyzer
from gapfuzz.logging_config import configure as configure_logging
from gapfuzz.onos_client import OnosClient, OnosNode
from gapfuzz.oracle.cluster_state_collector import ClusterStateCollector
from gapfuzz.oracle.data_plane_collector import DataPlaneCollector
from gapfuzz.oracle.oracle import DifferentialOracle

logger = logging.getLogger(__name__)


async def _detect_non_master_pair(
    nodes: list[OnosNode], device_id: str, app_id: str, timeout_s: float,
) -> tuple[OnosNode, OnosNode] | None:
    """Identify the master node for `device_id` and return the two
    non-master nodes (in cluster-config order). Returns None if the
    role cannot be determined unambiguously.

    The cluster's mastership can change between runs, so we resolve it
    just before each campaign rather than relying on the static config.
    """
    roles: dict[str, str] = {}
    for node in nodes:
        try:
            async with OnosClient(node, app_id, timeout_s) as c:
                d = await c.get_device(device_id)
            roles[node.name] = d.get("role", "NONE")
        except Exception as exc:
            logger.warning("Mastership probe failed on %s: %s", node.name, exc)
            return None

    masters = [n for n in nodes if roles.get(n.name) == "MASTER"]
    non_master = [n for n in nodes if roles.get(n.name) != "MASTER"]
    if len(masters) != 1 or len(non_master) < 2:
        logger.warning(
            "Mastership ambiguous: roles=%s; cannot pick a non-master pair.",
            roles,
        )
        return None
    return non_master[0], non_master[1]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="GapFuzz iterative exploration.")
    p.add_argument("--config", required=True, type=Path,
                   help="Path to config.yaml.")
    p.add_argument("--templates", required=True, type=Path,
                   help="Path to templates directory.")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--phase1-only", action="store_true",
                   help="Baseline mode: skip Phase 2 (doubling/bisection). "
                        "Reports only Phase-1 verdict and lifetime.")
    p.add_argument("--oracle-mode", choices=["native", "userspace"],
                   default="native",
                   help="Data-plane oracle: 'native' (kernel datapath via "
                        "ovs-appctl ofproto/trace, default) or 'userspace' "
                        "(OF user-space via ovs-ofctl dump-flows; models "
                        "the oracle architecture of prior SDN fuzzers).")
    return p.parse_args()


async def amain(cfg: GapFuzzConfig, templates: list[dict],
                phase1_only: bool = False,
                oracle_mode: str = "native") -> FuzzCampaignResult:
    cluster = ClusterStateCollector(
        cfg.cluster_nodes,
        app_id=cfg.app_id,
        request_timeout_s=cfg.request_timeout_s,
    )
    if oracle_mode == "userspace":
        from gapfuzz.oracle.data_plane_collector_userspace import (
            UserspaceDataPlaneCollector,
        )
        dp = UserspaceDataPlaneCollector(
            bridge=cfg.dp_bridge,
            trace_in_port=cfg.dp_trace_in_port,
            timeout_s=cfg.request_timeout_s,
        )
    else:
        dp = DataPlaneCollector(
            ryu_host=cfg.ryu_host,
            ryu_port=cfg.ryu_port,
            request_timeout_s=cfg.request_timeout_s,
            bridge=cfg.dp_bridge,
            trace_in_port=cfg.dp_trace_in_port,
        )
    oracle = DifferentialOracle(cluster, dp, delta_s=cfg.delta_s)

    target_R = cfg.injection_target_R
    target_R_prime = cfg.injection_target_R_prime
    detected = await _detect_non_master_pair(
        cfg.cluster_nodes, cfg.device_id, cfg.app_id, cfg.request_timeout_s,
    )
    if detected is not None:
        target_R, target_R_prime = detected
        logger.info(
            "Mastership-aware injection: R=%s R'=%s (config said R=%s R'=%s)",
            target_R.name, target_R_prime.name,
            cfg.injection_target_R.name, cfg.injection_target_R_prime.name,
        )
    else:
        logger.info(
            "Falling back to config-defined injection targets: R=%s R'=%s",
            target_R.name, target_R_prime.name,
        )

    injector = Injector(
        target_R=target_R,
        target_R_prime=target_R_prime,
        app_id=cfg.app_id,
        request_timeout_s=cfg.request_timeout_s,
    )

    reset = Reset(
        nodes=cfg.cluster_nodes,
        device_id=cfg.device_id,
        app_id=cfg.app_id,
        dp_command_template=cfg.dp_command_template,
        dp_bridge=cfg.dp_bridge,
    )

    analyzer = TimingAnalyzer(
        injector=injector,
        oracle=oracle,
        reset_fn=reset.run,
        delta_t_0_s=cfg.delta_t_0_s,
        epsilon_s=cfg.epsilon_s,
        doubling_safety_cap=10,
        lifetime_total_s=cfg.lifetime_s,
        phase1_only=phase1_only,
    )

    return await run_algorithm(templates, analyzer)


def write_jsonl(results: Iterable[TemplateResult], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fp:
        for r in results:
            record = {
                "template": r.template_name,
                "delta_t_max_s": r.delta_t_max_s,
                "class": r.classification.value,
                "iterations": r.iterations,
                "lifetime": r.lifetime,
            }
            fp.write(json.dumps(record) + "\n")


def main() -> int:
    args = parse_args()
    configure_logging(args.log_level)
    log = logging.getLogger("gapfuzz.run")

    cfg = load_config(args.config)
    templates = load_templates(args.templates)
    log.info("Loaded %d templates from %s", len(templates), args.templates)
    log.info("Cluster: %s",
             [(n.name, n.host) for n in cfg.cluster_nodes])
    log.info("Injection (config defaults): R=%s R'=%s",
             cfg.injection_target_R.name, cfg.injection_target_R_prime.name)
    log.info("Algorithm: Δt_0=%.3fs ε=%.3fs δ=%.3fs lifetime=%.1fs%s%s",
             cfg.delta_t_0_s, cfg.epsilon_s, cfg.delta_s, cfg.lifetime_s,
             "  [PHASE-1-ONLY BASELINE]" if args.phase1_only else "",
             f"  [ORACLE={args.oracle_mode.upper()}]" if args.oracle_mode != "native" else "")

    result = asyncio.run(amain(cfg, templates,
                               phase1_only=args.phase1_only,
                               oracle_mode=args.oracle_mode))

    output_path = Path(cfg.output_path)
    write_jsonl(result.results, output_path)
    log.info("Wrote %d records to %s", len(result.results), output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
