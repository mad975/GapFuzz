# GapFuzz: Cross-Plane Divergence Fuzzing for Distributed SDN Controllers

Replication package for the GapFuzz paper: a stateful concurrency fuzzer
that detects cross-plane divergences in distributed SDN clusters.

## Claims supported

| Claim | Paper § | Source |
|---|---|---|
| 81.7% hit rate ($N=50$, 95% CI 77.3–85.4%) | §7.3 RQ1 | `data/all_runs_phase1.jsonl` |
| $\Delta t_{\max}$ collapses to 5 ms or 10.24 s | §7.3 RQ2, Fig 5 | `data/all_runs.jsonl` |
| 99% of divergences persist past 30 s | §7.3 RQ3 | both above |
| Oracle ablation: 26.6 / 46.5 pt drop | §7.5, Table 4 | three JSONL files |

## Reproduce paper tables (~5 min)

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python analysis/compute_stats.py
```

Output matches the paper to the first decimal. The JSONL files in `data/`
were produced by `scripts/run_paper_evaluation.sh` and
`scripts/run_userspace_baseline.sh` on the configuration described in §7.3.

## Run GapFuzz

With the setup of §7.3 in place (ONOS cluster, Atomix, OVS, Mininet, Ryu
companion) and `sudo` NOPASSWD for `ovs-appctl` and `ovs-ofctl`:

```bash
python -m gapfuzz.run --config config.yaml \
                     --templates templates/ \
                     --phase1-only \
                     --oracle-mode={native,userspace}
```

Campaign scripts in `scripts/` wrap this for multi-run aggregation.

## Layout

```
gapfuzz/                            # Algorithm 1, oracle, injector, reset
ryu_app/                            # /dp/trace endpoint over ovs-appctl
poc/motivating_example.py           # PoC of §4.2
templates/                          # 7 contradictory-flow templates
scripts/                            # campaign runners
data/                               # pre-baked campaign JSONL
analysis/                           # compute_stats.py
config.yaml
requirements.txt
LICENSE
```

## License

MIT — see [LICENSE](LICENSE).
