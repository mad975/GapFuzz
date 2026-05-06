#!/usr/bin/env python3
"""Compute Tables 3 and 4 of the GapFuzz paper from pre-baked campaign data.

Reads (relative to repo root):
  data/all_runs.jsonl                    full mode (Phase 1 + Phase 2)
  data/all_runs_phase1.jsonl             Phase-1-only baseline
  data/all_runs_phase1_userspace.jsonl   oracle ablation

Prints both tables with Wilson 95% confidence intervals.
"""
from __future__ import annotations

import collections
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

TEMPLATES = [
    "contradictory_drop_vs_output",
    "contradictory_eth_dst_rewrite",
    "contradictory_in_port_match",
    "contradictory_output_action",
    "contradictory_pop_vs_set_vlan",
    "contradictory_set_field_vlan",
    "contradictory_tcp_dst_ports",
]

# The three templates whose actions contain no OUTPUT, so neither oracle's
# canonical action set {DROP, OUTPUT(port)} can represent the cluster's
# literal action; both oracles flag DP_DIVERGENT for this structural reason
# (§7.5 of the paper).
ARTIFACT = {
    "contradictory_eth_dst_rewrite",
    "contradictory_pop_vs_set_vlan",
    "contradictory_set_field_vlan",
}


def short(t: str) -> str:
    return t.removeprefix("contradictory_")


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 0.0
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return max(0.0, centre - half), min(1.0, centre + half)


def load(path: Path) -> list[dict]:
    with path.open() as fp:
        return [json.loads(line) for line in fp]


def per_template(rows: list[dict]) -> dict[str, dict]:
    by_t: dict[str, list[dict]] = collections.defaultdict(list)
    for r in rows:
        by_t[r["template"]].append(r)
    out: dict[str, dict] = {}
    for t in TEMPLATES:
        rs = by_t[t]
        n = len(rs)
        div = sum(1 for r in rs if r["class"] != "CONSISTENT")
        per = sum(1 for r in rs if r.get("lifetime") == "PERSISTENT")
        tra = sum(1 for r in rs if r.get("lifetime") == "TRANSIENT")
        dts = [r["delta_t_max_s"] for r in rs
               if r.get("delta_t_max_s") is not None]
        lo, hi = wilson(div, n)
        out[t] = {
            "n": n, "div": div, "lo": lo, "hi": hi,
            "per": per, "tra": tra,
            "dt_max": max(dts) if dts else None,
        }
    return out


def fmt_pct(x: float) -> str:
    return f"{100 * x:.1f}"


def fmt_ci(lo: float, hi: float) -> str:
    return f"[{fmt_pct(lo)}, {fmt_pct(hi)}]"


def fmt_dt(d: float | None) -> str:
    if d is None:
        return "—"
    return f"{d * 1000:.0f} ms" if d < 1 else f"{d:.2f} s"


def fmt_life(per: int, tra: int) -> str:
    return f"{per} P" if tra == 0 else f"{per} P / {tra} T"


def total_row(stats: dict[str, dict]) -> tuple[int, int, int, int]:
    n = sum(s["n"] for s in stats.values())
    div = sum(s["div"] for s in stats.values())
    per = sum(s["per"] for s in stats.values())
    tra = sum(s["tra"] for s in stats.values())
    return n, div, per, tra


def restricted_total(stats: dict[str, dict]) -> tuple[int, int]:
    n = sum(stats[t]["n"] for t in TEMPLATES if t not in ARTIFACT)
    div = sum(stats[t]["div"] for t in TEMPLATES if t not in ARTIFACT)
    return n, div


def print_table_3(full: dict, base: dict) -> None:
    print("=" * 118)
    print("Table 3 — Per-template results across both campaigns")
    print("=" * 118)
    h = (f"{'Template':24}|{'F hits/n':>16}{'F 95% CI':>16}"
         f"{'F Δt_max':>10}{'F lifetime':>12}|"
         f"{'B hits/n':>16}{'B 95% CI':>16}{'B lifetime':>12}")
    print(h)
    print("-" * 118)
    for t in TEMPLATES:
        f, b = full[t], base[t]
        nm = short(t)
        f_hits = f"{f['div']}/{f['n']} ({fmt_pct(f['div']/f['n'])}%)"
        b_hits = f"{b['div']}/{b['n']} ({fmt_pct(b['div']/b['n'])}%)"
        print(f"{nm:24}|{f_hits:>16}{fmt_ci(f['lo'], f['hi']):>16}"
              f"{fmt_dt(f['dt_max']):>10}{fmt_life(f['per'], f['tra']):>12}|"
              f"{b_hits:>16}{fmt_ci(b['lo'], b['hi']):>16}"
              f"{fmt_life(b['per'], b['tra']):>12}")
    print("-" * 118)
    fn, fd, fp, ft = total_row(full)
    bn, bd, bp, bt = total_row(base)
    flo, fhi = wilson(fd, fn)
    blo, bhi = wilson(bd, bn)
    print(f"{'Overall':24}|"
          f"{f'{fd}/{fn} ({fmt_pct(fd/fn)}%)':>16}{fmt_ci(flo, fhi):>16}"
          f"{'—':>10}{fmt_life(fp, ft):>12}|"
          f"{f'{bd}/{bn} ({fmt_pct(bd/bn)}%)':>16}{fmt_ci(blo, bhi):>16}"
          f"{fmt_life(bp, bt):>12}")
    print()


def print_table_4(native: dict, userspace: dict) -> None:
    print("=" * 110)
    print("Table 4 — Oracle ablation per template (N=50 Phase-1-only baseline)")
    print("=" * 110)
    h = (f"{'Template':24}|"
         f"{'Native hits/n':>16}{'Native 95% CI':>16}|"
         f"{'User-space hits/n':>20}{'User-space 95% CI':>20}|"
         f"{'Δ (pts)':>10}")
    print(h)
    print("-" * 110)
    for t in TEMPLATES:
        n_, u = native[t], userspace[t]
        nm = short(t)
        delta = 100 * (n_["div"] / n_["n"] - u["div"] / u["n"])
        print(f"{nm:24}|"
              f"{f'{n_["div"]}/{n_["n"]} ({fmt_pct(n_["div"]/n_["n"])}%)':>16}"
              f"{fmt_ci(n_['lo'], n_['hi']):>16}|"
              f"{f'{u["div"]}/{u["n"]} ({fmt_pct(u["div"]/u["n"])}%)':>20}"
              f"{fmt_ci(u['lo'], u['hi']):>20}|"
              f"{delta:+10.1f}")
    print("-" * 110)
    nn, nd, _, _ = total_row(native)
    un, ud, _, _ = total_row(userspace)
    nlo, nhi = wilson(nd, nn)
    ulo, uhi = wilson(ud, un)
    delta = 100 * (nd / nn - ud / un)
    print(f"{'Overall':24}|"
          f"{f'{nd}/{nn} ({fmt_pct(nd/nn)}%)':>16}{fmt_ci(nlo, nhi):>16}|"
          f"{f'{ud}/{un} ({fmt_pct(ud/un)}%)':>20}{fmt_ci(ulo, uhi):>20}|"
          f"{delta:+10.1f}")
    rn_n, rn_d = restricted_total(native)
    ru_n, ru_d = restricted_total(userspace)
    rdelta = 100 * (rn_d / rn_n - ru_d / ru_n)
    print(f"{'Restricted (4 templates)':24}|"
          f"{f'{rn_d}/{rn_n} ({fmt_pct(rn_d/rn_n)}%)':>16}{'—':>16}|"
          f"{f'{ru_d}/{ru_n} ({fmt_pct(ru_d/ru_n)}%)':>20}{'—':>20}|"
          f"{rdelta:+10.1f}")
    print()


def main() -> None:
    full = per_template(load(DATA / "all_runs.jsonl"))
    base = per_template(load(DATA / "all_runs_phase1.jsonl"))
    usersp = per_template(load(DATA / "all_runs_phase1_userspace.jsonl"))
    print_table_3(full, base)
    print_table_4(base, usersp)


if __name__ == "__main__":
    main()
