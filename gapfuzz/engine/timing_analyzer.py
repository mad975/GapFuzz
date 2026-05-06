"""Timing Analyzer — second module of the Exploration Engine (Section 5.2).

Two-phase search on the inter-injection delay Δt for one seed:

  Phase 1 — Detection.
      Inject(R, R', 0). If the Oracle returns CONSISTENT, the seed is
      discarded (no divergence reachable for this template).
      Otherwise proceed to Phase 2.

  Phase 2 — Refinement.
      Identify Δt_max, the largest Δt for which a divergence still occurs.
      Step a) Exponential doubling: starting from Δt_0, keep doubling Δt
              until the Oracle returns CONSISTENT. Let the last divergent
              value be lo and the first consistent value be hi.
      Step b) Binary search on [lo, hi] until the interval width falls
              below epsilon. The returned Δt_max is the largest mid-point
              for which the Oracle still returned a divergence.

Note on the "class" returned alongside Δt_max: this is the divergence
class observed at Δt_max. Per §5, this triplet (seed, Δt_max, class) is
GapFuzz's per-seed output.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

from gapfuzz.core.classes import DivergenceClass
from gapfuzz.engine.injector import Injector
from gapfuzz.engine.seed_generator import Seed
from gapfuzz.oracle.oracle import DifferentialOracle

logger = logging.getLogger(__name__)


@dataclass
class TemplateResult:
    """Per-seed output: (seed, Δt_max, class) plus housekeeping fields.

    `lifetime` is set when Phase 1 is divergent: re-observation of the
    same state at t = lifetime_total_s after injection yields either
    'TRANSIENT' (the cluster heals) or 'PERSISTENT' (the divergence
    still holds). It is None when no lifetime check was performed.
    """

    template_name: str
    delta_t_max_s: Optional[float]   # None iff seed discarded in Phase 1
    classification: DivergenceClass
    iterations: int                   # total Inject() calls for this seed
    lifetime: Optional[str] = None    # 'TRANSIENT' | 'PERSISTENT' | None


class TimingAnalyzer:
    """Phase 1 + Phase 2 search on Δt for a single seed."""

    def __init__(self, injector: Injector, oracle: DifferentialOracle,
                 reset_fn: Callable[[], Awaitable[None]],
                 delta_t_0_s: float, epsilon_s: float,
                 doubling_safety_cap: int = 20,
                 lifetime_total_s: float = 30.0,
                 phase1_only: bool = False):
        if delta_t_0_s <= 0:
            raise ValueError(f"delta_t_0 must be > 0; got {delta_t_0_s}")
        if epsilon_s <= 0:
            raise ValueError(f"epsilon must be > 0; got {epsilon_s}")
        if lifetime_total_s < oracle.delta_s:
            raise ValueError(
                f"lifetime_total_s ({lifetime_total_s}) must be >= "
                f"oracle.delta_s ({oracle.delta_s})"
            )
        self.injector = injector
        self.oracle = oracle
        self.reset = reset_fn
        self.delta_t_0_s = delta_t_0_s
        self.epsilon_s = epsilon_s
        self.doubling_safety_cap = doubling_safety_cap
        self.lifetime_total_s = lifetime_total_s
        self.phase1_only = phase1_only

    async def analyze(self, seed: Seed) -> TemplateResult:
        iterations = 0

        # ---- Phase 1: Detection at Δt = 0 ----
        verdict_class = await self._inject_and_observe(seed, 0.0)
        iterations += 1
        if verdict_class == DivergenceClass.CONSISTENT:
            logger.info("Seed %s: Phase 1 -> CONSISTENT, discarding",
                        seed.template_name)
            return TemplateResult(
                template_name=seed.template_name,
                delta_t_max_s=None,
                classification=verdict_class,
                iterations=iterations,
            )
        phase1_class = verdict_class

        # ---- Lifetime check: re-observe at t = lifetime_total_s ----
        # The system is currently in a divergent state at t = delta_s
        # after the Phase-1 injection. Sleep the additional time and
        # re-observe (without re-injection) to determine if the
        # divergence is TRANSIENT or PERSISTENT.
        lifetime = await self._lifetime_check(seed)

        # ---- Baseline mode: skip Phase 2 (no Δt_max characterization) ----
        if self.phase1_only:
            logger.info(
                "Seed %s: Phase-1-only mode, skipping Phase 2 refinement",
                seed.template_name,
            )
            return TemplateResult(
                template_name=seed.template_name,
                delta_t_max_s=None,
                classification=phase1_class,
                iterations=iterations,
                lifetime=lifetime,
            )

        # ---- Phase 2 step a: exponential doubling ----
        delta_t = self.delta_t_0_s
        verdict_class = await self._inject_and_observe(seed, delta_t)
        iterations += 1
        doublings = 0
        while verdict_class != DivergenceClass.CONSISTENT:
            if doublings >= self.doubling_safety_cap:
                logger.warning(
                    "Seed %s: doubling cap (%d) reached at Δt=%.3fs without "
                    "reaching CONSISTENT; reporting current Δt as Δt_max.",
                    seed.template_name, self.doubling_safety_cap, delta_t,
                )
                return TemplateResult(
                    template_name=seed.template_name,
                    delta_t_max_s=delta_t,
                    classification=verdict_class,
                    iterations=iterations,
                    lifetime=lifetime,
                )
            delta_t *= 2.0
            doublings += 1
            verdict_class = await self._inject_and_observe(seed, delta_t)
            iterations += 1

        lo = delta_t / 2.0           # last divergent value
        hi = delta_t                  # first consistent value
        last_div_class = await self._inject_and_observe(seed, lo)
        iterations += 1
        if last_div_class == DivergenceClass.CONSISTENT:
            # Rare: lo was actually consistent (noise, transient). The
            # divergence seen at Δt=0 is sub-Δt_0; fall back to reporting
            # the Phase-1 class so the result reflects the real finding.
            logger.warning(
                "Seed %s: lo=%.3fs returned CONSISTENT during refinement; "
                "Δt_max < delta_t_0 (=%.3fs); reporting Phase-1 class.",
                seed.template_name, lo, self.delta_t_0_s,
            )
            return TemplateResult(
                template_name=seed.template_name,
                delta_t_max_s=lo,
                classification=phase1_class,
                iterations=iterations,
                lifetime=lifetime,
            )

        # ---- Phase 2 step b: binary search ----
        delta_t_max, max_class, bs_iters = await self._binary_search(
            seed, lo, hi, last_div_class,
        )
        iterations += bs_iters
        return TemplateResult(
            template_name=seed.template_name,
            delta_t_max_s=delta_t_max,
            classification=max_class,
            iterations=iterations,
            lifetime=lifetime,
        )

    async def _binary_search(self, seed: Seed, lo: float, hi: float,
                             lo_class: DivergenceClass
                             ) -> tuple[float, DivergenceClass, int]:
        """Narrow [lo, hi] until hi - lo < epsilon.

        Returns (Δt_max, class, iterations_consumed).
        Loop invariant: at lo the Oracle returned a divergence and at hi
        CONSISTENT (modulo noise). We track the largest delta at which a
        divergence was observed and the class observed there.
        """
        best_div = lo
        best_class = lo_class
        iters = 0
        while (hi - lo) > self.epsilon_s:
            mid = (lo + hi) / 2.0
            verdict_class = await self._inject_and_observe(seed, mid)
            iters += 1
            if verdict_class == DivergenceClass.CONSISTENT:
                hi = mid
            else:
                lo = mid
                best_div = mid
                best_class = verdict_class
        return best_div, best_class, iters

    async def _inject_and_observe(self, seed: Seed,
                                  delta_t_s: float) -> DivergenceClass:
        """One Reset -> Inject -> Oracle cycle. Returns the class only."""
        await self.reset()
        await self.injector.inject(seed, delta_t_s)
        verdict = await self.oracle.observe(seed)
        return verdict.classification

    async def _lifetime_check(self, seed: Seed) -> str:
        """Re-observe the divergent state at t = lifetime_total_s post-injection.

        Called immediately after Phase 1 reported divergence at t = delta_s.
        Sleeps the additional time and queries the oracle without re-injection.
        Returns 'TRANSIENT' if the divergence has healed, 'PERSISTENT' otherwise.
        """
        extra = self.lifetime_total_s - self.oracle.delta_s
        if extra <= 0:
            extra = 0.0
        verdict = await self.oracle.observe(seed, wait_s=extra)
        if verdict.classification == DivergenceClass.CONSISTENT:
            logger.info("Seed %s: lifetime=TRANSIENT (healed by t+%.1fs)",
                        seed.template_name, self.lifetime_total_s)
            return "TRANSIENT"
        logger.info("Seed %s: lifetime=PERSISTENT (still %s at t+%.1fs)",
                    seed.template_name, verdict.classification.value,
                    self.lifetime_total_s)
        return "PERSISTENT"
