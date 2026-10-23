"""A fake Nexus switch for the tests: renders normalized state back into raw NX-API output.

render() writes what NX-API would return for netauto.nxos.commands(device), in the NX-OS
JSON shapes (TABLE_x/ROW_x, numbers as strings, a single row as an object rather than a
list) and text formats the parser expects. FakeNxapiServer serves those outputs over the
NX-API JSON-RPC interface on 127.0.0.1, so the client and the CLI run end to end.
"""

from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List

from netauto import nxos
from netauto.expected import ROLE_BGW, ROLE_SPINE, Design, Device


def table(name: str, items: List[Dict[str, Any]]) -> Dict[str, Any]:
    row = items[0] if len(items) == 1 else items
    return {f"TABLE_{name}": {f"ROW_{name}": row}}


def short_ifname(name: str) -> str:
    return name.replace("Ethernet", "Eth").replace("port-channel", "Po")


def running_config(design: Design, device: Device, state: Dict[str, Any]) -> str:
    lines = [f"hostname {device.hostname}", ""]
    vnis = {v.vni: v for v in device.vnis}
    rts = {v["vni"]: v for v in state["evpn"]["vnis"]}
    l2 = [v for v in state["vni_map"] if v["type"] == "L2"]
    l3 = [v for v in state["vni_map"] if v["type"] == "L3"]
    for v in l3:
        rt = rts[v["vni"]]
        lines += [f"vrf context {v['vrf']}", f"  vni {v['vni']}", "  rd auto", "  address-family ipv4 unicast"]
        lines += [f"    route-target import {x} evpn" for x in rt["rt_import"]]
        lines += [f"    route-target export {x} evpn" for x in rt["rt_export"]]
    if "vpc" in state:
        vpc = state["vpc"]
        lines += [f"vpc domain {vpc['domain']}", "  peer-switch",
                  f"  peer-keepalive destination {vpc['keepalive_destination']} source 10.0.0.1 vrf KEEPALIVE"]
    if "multisite" in state:
        lines += [f"evpn multisite border-gateway {state['multisite']['site_id']}", "  delay-restore time 300",
                  "interface loopback100", f"  ip address {state['multisite']['vip']}/32"]
    for h in {(h["vlan"], h["vrf"]) for h in state.get("hosts", [])}:
        lines += [f"interface Vlan{h[0]}", "  no shutdown", f"  vrf member {h[1]}"]
    if l2:
        lines.append("evpn")
        for v in l2:
            rt = rts[v["vni"]]
            lines += [f"  vni {v['vni']} l2", "    rd auto"]
            lines += [f"    route-target import {x}" for x in rt["rt_import"]]
            lines += [f"    route-target export {x}" for x in rt["rt_export"]]
    if device.role != ROLE_SPINE:
        lines += ["interface nve1", "  no shutdown", "  source-interface loopback1"]
        if device.role == ROLE_BGW:
            lines.append("  multisite border-gateway interface loopback100")
        lines += [f"  member vni {v}" + (" associate-vrf" if vnis[v].type == "L3" else "") for v in sorted(vnis)]
    return "\n".join(lines) + "\n"


def bgp_summary(state: Dict[str, Any], afi: str) -> Dict[str, Any]:
    sessions = [s for s in state["bgp"]["sessions"] if s["afi"] == afi]
    vrfs = ["default"] + sorted({s["vrf"] for s in sessions} - {"default"})
    rows = []
    for vrf in vrfs:
        nbrs = [{"neighborid": s["neighbor"], "neighborversion": "4", "msgrecvd": "100", "msgsent": "100",
                 "neighboras": str(s["remote_as"]), "time": "21w0d",
                 "state": s["state"], "prefixreceived": "3"}
                for s in sessions if s["vrf"] == vrf]
        saf = {"safi": "1" if afi == "ipv4" else "70", "af-name": "IPv4 Unicast" if afi == "ipv4" else "L2VPN EVPN"}
        if nbrs:
            saf.update(table("neighbor", nbrs))
        rows.append({"vrf-name-out": vrf, "vrf-router-id": state["bgp"]["router_id"],
                     "vrf-local-as": str(state["bgp"]["local_as"]),
                     **table("af", [{"af-id": "1" if afi == "ipv4" else "25", **table("saf", [saf])}])})
    return table("vrf", rows)


def route_table(state: Dict[str, Any]) -> Dict[str, Any]:
    by_vrf: Dict[str, List[Dict[str, Any]]] = {"default": [], "management": []}
    for r in state["routes"]:
        by_vrf.setdefault(r["vrf"], []).append(r)
    by_vrf["management"].append({"prefix": "0.0.0.0/0", "protocol": "static", "next_hops": ["10.0.0.1"], "encap": None})
    # The switch's own loopback shows up as a local route, which the parser must skip.
    by_vrf["default"].append({"prefix": state["bgp"]["router_id"] + "/32", "protocol": "local",
                              "next_hops": ["loopback0"], "encap": None})
    vrfs = []
    for vrf, routes in by_vrf.items():
        prefixes = []
        for r in routes:
            paths = []
            for nh in r["next_hops"]:
                path = {"uptime": "P21DT4H", "pref": "20", "metric": "0", "clientname": r["protocol"], "ubest": "true"}
                if nh[0].isdigit():
                    path["ipnexthop"] = nh
                else:
                    path["ifname"] = nh
                if r["encap"] == "vxlan":
                    path.update(segid="50010", tunnelid="0x0a6ef1c8", encap="vxlan")
                paths.append(path)
            prefixes.append({"ipprefix": r["prefix"], "ucast-nhops": str(len(paths)), "attached": "false",
                             **table("path", paths)})
        af = {"addrf": "ipv4", **(table("prefix", prefixes) if prefixes else {})}
        vrfs.append({"vrf-name-out": vrf, **table("addrf", [af])})
    return table("vrf", vrfs)


def render(design: Design, device: Device, state: Dict[str, Any]) -> Dict[str, Any]:
    ifaces = []
    for name, i in state["interfaces"].items():
        if name.startswith("Vlan"):
            ifaces.append({"interface": name, "svi_admin_state": "up", "svi_line_proto": i["oper_status"],
                           "svi_mtu": str(i["mtu"])})
        else:
            ifaces.append({"interface": name, "state": i["oper_status"], "admin_state": "up", "eth_mtu": str(i["mtu"])})
    raw: Dict[str, Any] = {
        nxos.SHOW_INTERFACE: table("interface", ifaces),
        nxos.SHOW_BGP_IPV4: bgp_summary(state, "ipv4"),
        nxos.SHOW_BGP_EVPN: bgp_summary(state, "evpn"),
        nxos.SHOW_BFD: table("bfdNeighbor", [{"src_ip_addr": "0.0.0.0", "dest_ip_addr": b["neighbor"],
                                              "local_state": b["state"], "remote_state": b["state"],
                                              "vrf_name": "default"} for b in state["bfd"]])
        if state["bfd"] else None,
        nxos.SHOW_RUN: running_config(design, device, state),
    }
    if device.role == ROLE_SPINE:
        return raw
    raw[nxos.SHOW_NVE_VNI] = table("nve_vni", [
        {"if-name": "nve1", "vni": str(v["vni"]), "mcast": "UnicastBGP", "vni-state": v["state"], "mode": "CP",
         "type": f"L2 [{v['vlan']}]" if v["type"] == "L2" else f"L3 [{v['vrf']}]", "flags": "SA" if v["type"] == "L2" else ""}
        for v in state["vni_map"]])
    nve = state["nve"]
    row = {"if-name": "nve1", "if-state": nve["state"], "encap-type": "VXLAN", "src-if": nve["source_interface"],
           "primary-ip": nve["primary"], "secondary-ip": nve["secondary"] or "0.0.0.0"}
    if device.role == ROLE_BGW:
        row["multisite-bgw-if"] = "loopback100"
        row["multisite-bgw-if-ip"] = state["multisite"]["vip"]
    raw[nxos.SHOW_NVE_IF] = table("nve_if", [row])
    raw[nxos.SHOW_ROUTE] = route_table(state)
    raw[nxos.SHOW_EVPN_RD] = "\n".join(
        f"Route Distinguisher: {v['rd']}    ({'L2' if any(m['vni'] == v['vni'] and m['type'] == 'L2' for m in state['vni_map']) else 'L3'}VNI {v['vni']})"
        for v in state["evpn"]["vnis"]) + "\n"
    if device.role == ROLE_BGW:
        for cmd, key in ((nxos.SHOW_MS_FABRIC, "fabric_links"), (nxos.SHOW_MS_DCI, "dci_links")):
            raw[cmd] = "Interface      State\n---------      -----\n" + "".join(
                f"{short_ifname(p):<15}{s}\n" for p, s in state["multisite"][key].items())
    else:
        raw[nxos.SHOW_L2ROUTE] = table("l2route_mac_ip_all", [
            {"topo-id": str(h["vlan"]), "mac-addr": h["mac"], "prod-type": "BGP" if h["source"] == "evpn" else "HMM",
             "flags": "--" if h["source"] == "evpn" else "L,", "seq-num": "0", "host-ip": h["ip"],
             "next-hop1": h["vtep"] if h["source"] == "evpn" else short_ifname(h["interface"])}
            for h in state["hosts"]]) if state["hosts"] else None
        vpc = state["vpc"]
        raw[nxos.SHOW_VPC] = {
            "vpc-domain-id": str(vpc["domain"]), "vpc-peer-status": vpc["peer_status"],
            "vpc-peer-status-reason": "SUCCESS", "vpc-peer-keepalive-status": vpc["keepalive_status"],
            "vpc-peer-consistency": "consistent" if vpc["consistency"] == "success" else vpc["consistency"],
            "vpc-role": "primary",
            **table("peerlink", [{"peer-link-id": "1", "peerlink-ifindex": short_ifname(vpc["peer_link"]),
                                  "peer-link-port-state": "1" if vpc["peer_link_status"] == "up" else "0"}]),
        }
    return raw


class FakeNxapiServer:
    """Serves rendered outputs per switch at http://127.0.0.1:<port>/ins, one port per switch."""

    def __init__(self, outputs: Dict[str, Any], username: str = "admin", password: str = "secret") -> None:
        expected_auth = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
        self.requests: List[List[Dict[str, Any]]] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_POST(self) -> None:
                if self.headers.get("Authorization") != expected_auth:
                    self.send_response(401)
                    self.end_headers()
                    return
                calls = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                server.requests.append(calls)
                answers = []
                for c in calls:
                    cmd = c["params"]["cmd"]
                    if cmd not in outputs:
                        answers.append({"jsonrpc": "2.0", "id": c["id"], "error": {
                            "code": -32602, "message": "Invalid params", "data": {"msg": "% Invalid command\n"}}})
                    elif c["method"] == "cli_ascii":
                        answers.append({"jsonrpc": "2.0", "id": c["id"], "result": {"msg": outputs[cmd]}})
                    else:
                        out = outputs[cmd]
                        answers.append({"jsonrpc": "2.0", "id": c["id"], "result": {"body": out} if out else None})
                body = json.dumps(answers if len(answers) > 1 else answers[0]).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json-rpc")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    def __enter__(self) -> "FakeNxapiServer":
        self.thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
