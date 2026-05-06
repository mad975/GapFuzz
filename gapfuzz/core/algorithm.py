"""Algorithm 1 — GapFuzz Iterative Exploration (Section 5.4).

Pseudocode in the paper:

    R <- empty
    foreach template t in T:
        (R_inj, R'_inj) <- GenerateSeed(t)
        Reset(); Inject(R_inj, R'_inj, 0); class <- Oracle(delta)
        if class == CONSISTENT: continue
        // Phase 2 doubling
        delta_t <- delta_t_0
        Reset(); Inject(R_inj, R'_inj, delta_t); class <- Oracle(delta)
        while class != CONSISTENT:
            delta_t <- 2 * delta_t
            Reset(); Inject(R_inj, R'_inj, delta_t); class <- Oracle(delta)
        // Phase 2 binary search
        (delta_t_max, class) <- BinarySearch(R_inj, R'_inj, delta_t/2, delta_t, eps, delta)
        R <- R + (t, delta_t_max, class)
    return R

The full per-seed Phase 1 + Phase 2 logic is encapsulated in
TimingAnalyzer; this module just iterates over templates, invokes the
analyzer, and accumulates the triplets.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterable

from gapfuzz.engine.seed_generator import generate_seed
from gapfuzz.engine.timing_analyzer import TemplateResult, TimingAnalyzer

logger = logging.getLogger(__name__)


@dataclass
class FuzzCampaignResult:
    """The aggregated output R returned by Algorithm 1."""

    results: list[TemplateResult]


async def run_algorithm(templates: Iterable[dict],
                        analyzer: TimingAnalyzer) -> FuzzCampaignResult:
    """Run Algorithm 1 over the given templates and return the aggregate."""
    accumulated: list[TemplateResult] = []
    for template in templates:
        seed = generate_seed(template)
        logger.info("=== Starting template %s ===", seed.template_name)
        try:
            result = await analyzer.analyze(seed)
        except Exception as exc:
            logger.exception("Template %s aborted: %s",
                             seed.template_name, exc)
            continue
        accumulated.append(result)
        logger.info(
            "=== Done template %s: class=%s Δt_max=%s iters=%d ===",
            result.template_name,
            result.classification.value,
            f"{result.delta_t_max_s:.3f}s" if result.delta_t_max_s is not None else "n/a",
            result.iterations,
        )
    return FuzzCampaignResult(results=accumulated)
