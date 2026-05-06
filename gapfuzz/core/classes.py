"""Divergence classes from Section 4.3 of the paper.

The four mutually exclusive classes are defined by the 2x2 matrix of
control-plane convergence and data-plane agreement, evaluated at
t > T_2 (after the asynchronous replication window has closed).
"""

from enum import Enum


class DivergenceClass(str, Enum):
    """Four classes of cross-plane state at t > T_2.

    CONSISTENT:    forall i,j: C_i = C_j  AND  D in C
    DP_DIVERGENT:  forall i,j: C_i = C_j  AND  D not in C
    CP_DIVERGENT:  exists i,j: C_i != C_j AND  D in C
    FULL_SPLIT:    exists i,j: C_i != C_j AND  D not in C
    """

    CONSISTENT = "CONSISTENT"
    DP_DIVERGENT = "DP_DIVERGENT"
    CP_DIVERGENT = "CP_DIVERGENT"
    FULL_SPLIT = "FULL_SPLIT"

    def is_divergent(self) -> bool:
        return self is not DivergenceClass.CONSISTENT
