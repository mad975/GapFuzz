"""Companion ryu app: Data Plane Collector backend.

This app runs as a separate process under `ryu-manager`. It:
  1. Accepts the OVS connection (the OVS bridge must list this controller
     in addition to the ONOS cluster).
  2. Sends OFPRoleRequest to fix its role to SLAVE on every datapath, so
     ONOS retains MASTER and this app cannot perturb the data plane.
  3. Exposes two REST endpoints:
         GET /dp/flows/<dpid>           -- OF user-space view (OFPFlowStatsRequest)
         GET /dp/trace/<dpid>?bridge=&flow=
                                         -- kernel datapath ground truth
                                         (ovs-appctl ofproto/trace)

Run:
    ryu-manager --wsapi-host 127.0.0.1 --wsapi-port 8080 \\
                ryu_app/dp_collector_app.py

The GapFuzz Data Plane Collector queries the trace endpoint to retrieve
the actual datapath action applied to a packet matching the seed
selector. This is the same ground truth used by the PoC of Section 3.2
of the paper.

Notes
-----
* ryu uses eventlet under the hood; do NOT mix this file with asyncio code.
* The trace endpoint shells out to `sudo -n ovs-appctl ofproto/trace`,
  which requires a sudoers rule allowing this binary without password.
"""

from __future__ import annotations

import json
import subprocess

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    HANDSHAKE_DISPATCHER,
    MAIN_DISPATCHER,
    set_ev_cls,
)
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3
from webob import Response


class DpCollectorApp(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths: dict[int, object] = {}
        # xid -> {'event': hub.Event, 'flows': [OFPFlowStats]}
        self._pending: dict[int, dict] = {}

        wsgi: WSGIApplication = kwargs["wsgi"]
        wsgi.register(DpCollectorController, {"app": self})

    # ---- datapath lifecycle ----

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        # Generation id 0 is fine for SLAVE (must be monotonically
        # increasing if we ever upgraded to MASTER, which we don't).
        req = parser.OFPRoleRequest(dp, ofp.OFPCR_ROLE_SLAVE, 0)
        dp.send_msg(req)
        self.logger.info("datapath %016x connected; role -> SLAVE", dp.id)

    @set_ev_cls(ofp_event.EventOFPRoleReply, MAIN_DISPATCHER)
    def _role_reply(self, ev):
        msg = ev.msg
        self.logger.info(
            "datapath %016x role-reply role=%d", msg.datapath.id, msg.role
        )

    # ---- multipart flow stats ----

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply(self, ev):
        msg = ev.msg
        xid = msg.xid
        slot = self._pending.get(xid)
        if slot is None:
            return
        slot["flows"].extend(msg.body)
        ofp = msg.datapath.ofproto
        if msg.flags & ofp.OFPMPF_REPLY_MORE:
            return
        slot["event"].set()

    def query_flows(self, dpid: int, timeout_s: float = 5.0) -> list:
        if dpid not in self.datapaths:
            raise KeyError(f"unknown datapath: {dpid:016x}")
        dp = self.datapaths[dpid]
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        # OFPFlowStatsRequest with wildcard match -> all flows in table 0
        # (we use OFPTT_ALL to match all tables).
        req = parser.OFPFlowStatsRequest(
            datapath=dp,
            flags=0,
            table_id=ofp.OFPTT_ALL,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            cookie=0,
            cookie_mask=0,
        )
        dp.set_xid(req)
        ev = hub.Event()
        self._pending[req.xid] = {"event": ev, "flows": []}
        try:
            dp.send_msg(req)
            if not ev.wait(timeout=timeout_s):
                raise TimeoutError(
                    f"flow-stats timeout for datapath {dpid:016x}"
                )
            return self._pending[req.xid]["flows"]
        finally:
            self._pending.pop(req.xid, None)


class DpCollectorController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app: DpCollectorApp = data["app"]

    @route("dp", "/dp/trace/{dpid}", methods=["GET"])
    def get_trace(self, req, **kwargs):
        bridge = req.GET.get("bridge", "s1")
        flow = req.GET.get("flow", "").strip()
        if not flow:
            return Response(
                status=400,
                text=json.dumps({"error": "missing query param: flow"}),
                content_type="application/json", charset="utf-8",
            )
        try:
            r = subprocess.run(
                ["sudo", "-n", "ovs-appctl", "ofproto/trace", bridge, flow],
                capture_output=True, text=True, timeout=5,
            )
        except subprocess.TimeoutExpired:
            return Response(
                status=504,
                text=json.dumps({"error": "ovs-appctl ofproto/trace timeout"}),
                content_type="application/json", charset="utf-8",
            )
        except FileNotFoundError:
            return Response(
                status=500,
                text=json.dumps({"error": "ovs-appctl not found in PATH"}),
                content_type="application/json", charset="utf-8",
            )
        if r.returncode != 0:
            return Response(
                status=500,
                text=json.dumps({
                    "error": "ovs-appctl failed",
                    "stderr": r.stderr.strip(),
                    "returncode": r.returncode,
                }),
                content_type="application/json", charset="utf-8",
            )
        action = _parse_datapath_actions(r.stdout)
        return Response(
            text=json.dumps({"datapath_action": action, "raw": r.stdout}),
            content_type="application/json", charset="utf-8",
        )

    @route("dp", "/dp/flows/{dpid}", methods=["GET"])
    def get_flows(self, req, **kwargs):
        dpid_str: str = kwargs["dpid"]
        try:
            dpid = _parse_dpid(dpid_str)
        except ValueError as exc:
            return Response(
                status=400,
                text=json.dumps({"error": f"bad dpid: {exc}"}),
                content_type="application/json",
                charset="utf-8",
            )
        try:
            stats = self.app.query_flows(dpid)
        except KeyError as exc:
            return Response(
                status=404, text=json.dumps({"error": str(exc)}),
                content_type="application/json", charset="utf-8",
            )
        except TimeoutError as exc:
            return Response(
                status=504, text=json.dumps({"error": str(exc)}),
                content_type="application/json", charset="utf-8",
            )
        except Exception as exc:  # pragma: no cover  (defensive)
            return Response(
                status=500, text=json.dumps({"error": repr(exc)}),
                content_type="application/json", charset="utf-8",
            )

        out = [s.to_jsondict() for s in stats]
        return Response(
            content_type="application/json",
            text=json.dumps(out),
            charset="utf-8",
        )


def _parse_dpid(s: str) -> int:
    s = s.strip()
    if s.startswith("of:"):
        s = s[3:]
    return int(s, 16)


# ---------------------------------------------------------------------------
# Kernel datapath ground truth via `ovs-appctl ofproto/trace`
# ---------------------------------------------------------------------------

def _parse_datapath_actions(trace_output: str) -> str:
    """Extract the 'Datapath actions:' line and reduce it to a single token.

    Returns 'drop', a numeric port string ('1', '2', ...), or 'unknown'.
    """
    for line in trace_output.split("\n"):
        if "Datapath actions:" not in line:
            continue
        actions = line.split("Datapath actions:", 1)[1].strip()
        if "drop" in actions:
            return "drop"
        if "output:" in actions:
            return actions.split("output:", 1)[1].strip().split(",")[0]
        first = actions.split(",")[0].strip()
        if first.isdigit():
            return first
        return "unknown"
    return "unknown"


