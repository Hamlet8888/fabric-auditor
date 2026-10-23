"""
Compliant state snapshots, synthesized from the design.

    python3 -m netauto.mock examples/demo/expected-state.json --out examples/demo/state [--step M5]

For each switch it writes the normalized state document (:mod:`netauto.collector`) that a
correctly built fabric would return at the given migration step: sessions of later steps
are configured but Idle, retired ones are gone, and a placeholder neighbor (an address the
design leaves to the operator) gets one from 192.0.2.0/24 (TEST-NET-1). The snapshots are
the baseline for the tests and for trying the auditor without a lab.

Standard library only (Python 3.9+).
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from netauto.collector import SCHEMA_VERSION
from netauto.expected import Design, DesignError, Device, load_design

COLLECTED_AT = "2026-10-23T14:00:00Z"


def device_state(design: Design, device: Device, step: Optional[str] = None) -> Dict[str, Any]:
    step = step or design.final_step
    ids = design.step_ids

    def due(s: str) -> bool:
        return ids.index(s) <= ids.index(step)

    rid = device.router_id
    interfaces = {"mgmt0": {"mtu": 1500, "oper_status": "up"}, "loopback0": {"mtu": 1500, "oper_status": "up"}}
    for i in device.interfaces:
        interfaces[i.name] = {"mtu": i.mtu, "oper_status": "up" if due(design.interface_step(device, i)) else "down"}

    sessions, bfd = [], []
    placeholders = 0
    for s in device.sessions:
        if design.retired(s, step):
            continue
        neighbor = s.neighbor
        if s.placeholder:
            placeholders += 1
            neighbor = f"192.0.2.{placeholders}"
        up = design.active(s, step)
        sessions.append({"vrf": s.vrf, "afi": s.afi, "neighbor": neighbor, "remote_as": s.remote_as,
                         "state": "Established" if up else "Idle", "uptime": "3w2d" if up else "never"})
        if s.bfd:
            bfd.append({"neighbor": neighbor, "state": "Up" if up else "Down"})

    state: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "hostname": device.hostname,
        "collected_at": COLLECTED_AT,
        "platform": "nxos",
        "interfaces": interfaces,
        "bgp": {"router_id": rid, "local_as": device.asn, "sessions": sessions},
        "bfd": bfd,
        "evpn": {"vnis": [
            {"vni": v.vni, "rd": f"{rid}:{32767 + v.vlan}" if v.type == "L2" else f"{rid}:3",
             "rt_import": [v.route_target], "rt_export": [v.route_target]}
            for v in device.vnis
        ]},
        "vni_map": [
            {"vni": v.vni, "type": v.type, **({"vlan": v.vlan} if v.type == "L2" else {"vrf": v.vrf}), "state": "Up"}
            for v in device.vnis
        ],
    }
    if device.nve:
        state["nve"] = {"state": "Up", "source_interface": device.nve.source_interface,
                        "primary": device.nve.primary, "secondary": device.nve.secondary}
    if device.vpc:
        state["vpc"] = {"domain": device.vpc.domain, "peer_status": "peer-ok", "keepalive_status": "peer-alive",
                        "keepalive_destination": device.vpc.keepalive, "peer_link": device.vpc.peer_link,
                        "peer_link_status": "up", "consistency": "success"}
    if device.multisite:
        ms = device.multisite
        state["multisite"] = {
            "site_id": ms.site_id, "vip": ms.vip,
            "fabric_links": {p: "Up" for p in ms.fabric_links},
            "dci_links": {p: interfaces[p]["oper_status"].capitalize() for p in ms.dci_links},
        }
    if device.nve:
        state["routes"] = routes(design, device, step, sessions)
    if device.vpc:
        state["hosts"] = hosts(design, device)
    return state


# ---------------------------------------------------------------------------
# Routes and hosts
# ---------------------------------------------------------------------------
# What a healthy fabric shows in its tables, from the design alone: every leaf pair has one host
# per L2 subnet (.10 for the first pair, .11 for the next, ...), learned locally on its vPC
# port-channel and over EVPN everywhere else in the site. Tenant routes follow the Multi-Site
# model: local subnets direct or via the leaf VTEPs, the other site's via the local BGW VIP, the
# default via the firewall on the border leafs. The underlay carries the VTEP addresses.


def _pairs(design: Design, site: str) -> List[Device]:
    """The first member of each vPC pair in a site, in order."""
    return [a for a, _ in design.vpc_pairs(site)]


def host_entries(design: Design, site: str) -> List[Dict[str, Any]]:
    """(entry, owning pair's first member) for every demo host in a site."""
    out = []
    site_idx = [x.code for x in design.sites].index(site)
    for p, leaf in enumerate(_pairs(design, site)):
        l3 = next((v.vrf for v in leaf.vnis if v.type == "L3"), None)
        for v in leaf.vnis:
            if v.type != "L2" or not v.subnet:
                continue
            ip = str(ipaddress.ip_network(v.subnet)[10 + p])
            mac = f"0050.56{site_idx:02x}.{p:02x}{v.vlan % 256:02x}"
            out.append({"vrf": l3, "vlan": v.vlan, "ip": ip, "mac": mac, "pair": leaf.hostname, "index": p})
    return out


def hosts(design: Design, device: Device) -> List[Dict[str, Any]]:
    mine = {device.hostname, device.vpc.peer} if device.vpc else {device.hostname}
    out = []
    for h in host_entries(design, device.site):
        entry = {k: h[k] for k in ("vrf", "vlan", "ip", "mac")}
        if h["pair"] in mine:
            entry.update(source="local", interface=f"port-channel{100 + h['index']}")
        else:
            entry.update(source="evpn", vtep=design.device(h["pair"]).nve.secondary)
        out.append(entry)
    return out


def routes(design: Design, device: Device, step: str, sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    site = device.site
    other = next(s.code for s in design.sites if s.code != site)
    vip = {s.code: s.multisite_vip for s in design.sites}
    vrf = next((v.vrf for v in device.vnis if v.type == "L3"), None)
    leafs = [d for d in design.select(site) if d.vpc]
    border = [d for d in leafs if d.role == "border-leaf"]
    bgws = [d for d in design.select(site) if d.multisite]
    out: List[Dict[str, Any]] = []

    def add(vrf_: str, prefix: str, nhs: List[str], protocol: str = "bgp", encap: Optional[str] = None) -> None:
        out.append({"vrf": vrf_, "prefix": prefix, "protocol": protocol, "next_hops": nhs, "encap": encap})

    def established(v: str, afi: str) -> List[Dict[str, Any]]:
        return [s for s in sessions if s["vrf"] == v and s["afi"] == afi and s["state"] == "Established"]

    # The other site is reachable once the BGWs' DCI overlay sessions are due.
    remote_bgws = {d.hostname for d in design.select(other) if d.multisite}
    dci_up = any(design.active(s, step) for b in bgws for s in b.sessions if s.afi == "evpn" and s.peer in remote_bgws)

    # Tenant VRF
    local_subnets: Dict[str, List[Device]] = {}
    for leaf in leafs:
        for v in leaf.vnis:
            if v.type == "L2" and v.subnet:
                local_subnets.setdefault(v.subnet, []).append(leaf)
    remote_subnets = sorted({v.subnet for d in design.select(other) for v in d.vnis if v.type == "L2" and v.subnet})
    for subnet, owners in sorted(local_subnets.items()):
        if device in owners:
            vlan = next(v.vlan for v in device.vnis if v.subnet == subnet)
            add(vrf, subnet, [f"Vlan{vlan}"], "direct")
        else:
            add(vrf, subnet, sorted(d.nve.primary for d in owners), encap="vxlan")
    if dci_up:
        for subnet in remote_subnets:
            add(vrf, subnet, [vip[site] if device not in bgws else vip[other]], encap="vxlan")
    if device in border:
        exits = [s for s in established(vrf, "ipv4") if not s["neighbor"].startswith("192.0.2.")]
        exits = exits or established(vrf, "ipv4")
        if exits:
            add(vrf, "0.0.0.0/0", [exits[-1]["neighbor"]])
    elif any(design.active(s, step) for b in border for s in b.sessions if s.vrf == vrf):
        add(vrf, "0.0.0.0/0", sorted(d.nve.primary for d in border), encap="vxlan")

    # Underlay: every loopback and VTEP address in the site, and the other site's VIP on the BGWs over the DCI.
    def far_end(iface) -> str:
        net = ipaddress.ip_interface(iface.address)
        return next(str(a) for a in ([net.network.network_address, net.network.broadcast_address]
                                     if net.network.prefixlen == 31 else net.network.hosts()) if a != net.ip)

    uplinks = sorted(far_end(i) for i in device.interfaces if not i.dci_carrier and not i.name.startswith("Vlan"))
    own = {device.router_id, device.nve.primary, device.nve.secondary, device.multisite.vip if device.multisite else None}
    for d in design.select(site):
        addrs = {d.router_id} | ({d.nve.primary, d.nve.secondary} if d.nve else set())
        for addr in sorted((addrs | {d.multisite.vip if d.multisite else None}) - {None}):
            if addr in own:
                continue
            if not any(r["prefix"] == f"{addr}/32" for r in out):
                add("default", f"{addr}/32", uplinks)
    if device in bgws and dci_up:
        add("default", f"{vip[other]}/32", sorted(far_end(i) for i in device.interfaces if i.dci_carrier))
    return sorted(out, key=lambda r: (r["vrf"], ipaddress.ip_network(r["prefix"]).network_address,
                                      ipaddress.ip_network(r["prefix"]).prefixlen))


def write_snapshots(design: Design, out: Path, step: Optional[str] = None) -> int:
    out.mkdir(parents=True, exist_ok=True)
    for d in design.devices:
        (out / f"{d.hostname}.json").write_text(json.dumps(device_state(design, d, step), indent=1) + "\n",
                                                encoding="utf-8")
    return len(design.devices)


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="netauto.mock", description=__doc__.strip().splitlines()[0])
    ap.add_argument("expected", type=Path, help="expected-state.json from network-design")
    ap.add_argument("--out", type=Path, required=True, help="folder for <hostname>.json snapshots")
    ap.add_argument("--step", help="migration step the fabric has reached (default: the last)")
    args = ap.parse_args(argv)
    try:
        design = load_design(args.expected)
        if args.step:
            design.check_step(args.step)
    except DesignError as exc:
        print(f"netauto.mock: error: {exc}", file=sys.stderr)
        return 2
    n = write_snapshots(design, args.out, args.step)
    print(f"wrote {n} snapshots to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
