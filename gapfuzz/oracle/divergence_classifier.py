"""Divergence Classifier — third sub-module of the Differential Oracle.

Implements the 2x2 matrix of Section 4.3:

                                D in C            D not in C
    forall i,j: C_i = C_j   |  CONSISTENT     |  DP_DIVERGENT
    exists i,j: C_i != C_j  |  CP_DIVERGENT   |  FULL_SPLIT

C is the multiset of FlowContent sets across nodes: C = {C_1, ..., C_N}.
- CP convergence holds iff all C_i are equal as sets.
- D in C holds iff D equals at least one C_i (set equality).

The classifier evaluates the two boolean conditions and returns the
corresponding DivergenceClass.
"""

from __future__ import annotations

from gapfuzz.core.classes import DivergenceClass
from gapfuzz.oracle.cluster_state_collector import NodeView
from gapfuzz.oracle.data_plane_collector import DataPlaneView


def classify(node_views: list[NodeView],
             dp_view: DataPlaneView) -> DivergenceClass:
    """Apply the 2x2 matrix to (C_1, ..., C_N) and D."""
    if not node_views:
        raise ValueError("classify() requires at least one NodeView")

    cp_views = [nv.flows for nv in node_views]  # list of frozenset
    cp_converged = all(s == cp_views[0] for s in cp_views[1:])
    dp_in_cluster = dp_view.flows in cp_views

    if cp_converged and dp_in_cluster:
        return DivergenceClass.CONSISTENT
    if cp_converged and not dp_in_cluster:
        return DivergenceClass.DP_DIVERGENT
    if not cp_converged and dp_in_cluster:
        return DivergenceClass.CP_DIVERGENT
    return DivergenceClass.FULL_SPLIT
