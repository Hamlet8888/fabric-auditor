"""
Host-to-host path explainer: why can't A reach B?

    netauto path 10.110.10.10 10.120.20.11 --expected E [--source nxapi | --state-dir DIR]

:func:`trace` follows a packet from the leaf where the source host is learned, hop by hop,
using each switch's own tables (``hosts`` and ``routes`` in the normalized state):

1. Find the source: the leaf (and its vPC peer) where the source address is learned locally.
2. On each switch, in the source host's VRF: is the destination learned locally? Then it is
   delivered. Otherwise take the longest-prefix route:
   - a directly connected subnet: the destination must be learned somewhere in the site (an
     EVPN host entry names its VTEP), or the host is silent or down;
   - a VXLAN route: the next hop is a VTEP. The underlay must have a route to it, and the
     next switch is whoever owns that address (a leaf, a vPC pair, a site's BGW VIP);
   - a route to a BGP neighbor in the VRF (firewall, cloud, legacy core): the packet leaves
     the fabric there;
   - no route: the path breaks here.
3. Crossing sites, the BGW must have a DCI link up and an Established EVPN session to the
   other site's BGWs.

Every hop records what was checked; the first failed check is where the path breaks.

Standard library only (Python 3.9+).
"""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from netauto.expected import Design

MAX_HOPS = 12


@dataclass
class Hop:
    device: str
    action: str
    ok: bool = True
    detail: List[str] = field(default_factory=list)


@dataclass
class Trace:
    source: str
    destination: str
    vrf: Optional[str]
    hops: List[Hop]
    result: str  # "delivered", "leaves fabric", "broken"

    @property
    def ok(self) -> bool:
        return self.result != "broken"

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "destination": self.destination, "vrf": self.vrf,
                "result": self.result, "hops": [asdict(h) for h in self.hops]}


def _lpm(routes: List[Dict[str, Any]], vrf: Optional[str], ip: str) -> Optional[Dict[str, Any]]:
    addr = ipaddress.ip_address(ip)
    best, best_len = None, -1
    for r in routes:
        if r.get("vrf") != vrf:
            continue
        try:
            net = ipaddress.ip_network(r["prefix"], strict=False)
        except ValueError:
            continue
        if addr in net and net.prefixlen > best_len:
            best, best_len = r, net.prefixlen
    return best


def _host(state: Dict[str, Any], ip: str, source: Optional[str] = None) -> Optional[Dict[str, Any]]:
    for h in state.get("hosts", []):
        if h.get("ip") == ip and (source is None or h.get("source") == source):
            return h
    return None


def trace(design: Design, states: Dict[str, Dict[str, Any]], src: str, dst: str) -> Trace:
    for ip in (src, dst):
        ipaddress.ip_address(ip)  # raises ValueError on a bad address
    owners = design.vtep_owners()
    names = {s.code: s for s in design.sites}

    # 1. Where is the source?
    homes = [h for h, st in states.items() if _host(st, src, "local")]
    if not homes:
        subnet = next(((d.hostname, v) for d in design.devices for v in d.vnis
                       if v.subnet and ipaddress.ip_address(src) in ipaddress.ip_network(v.subnet)), None)
        hint = (f"{src} is in {subnet[1].subnet} (VLAN {subnet[1].vlan}): check the host is up and has sent "
                "traffic (ARP) toward its gateway" if subnet else f"{src} is not in any fabric subnet")
        return Trace(src, dst, None, [Hop("-", f"source {src} is not learned on any leaf", False, [hint])], "broken")
    homes.sort()
    vrf = _host(states[homes[0]], src, "local").get("vrf")
    first = Hop(homes[0], f"source {src} learned locally on "
                          f"{_host(states[homes[0]], src, 'local').get('interface')}" +
                (f" (also on vPC peer {', '.join(homes[1:])})" if len(homes) > 1 else ""),
                detail=[f"VRF {vrf}"])
    hops = [first]

    current = homes[0]
    visited = set()
    for _ in range(MAX_HOPS):
        if current in visited:
            hops.append(Hop(current, "forwarding loop: this switch was already on the path", False))
            return Trace(src, dst, vrf, hops, "broken")
        visited.add(current)
        state = states.get(current)
        if state is None:
            hops.append(Hop(current, "no state collected from this switch", False))
            return Trace(src, dst, vrf, hops, "broken")
        dev = design.device(current)

        # Delivered here?
        local = _host(state, dst, "local")
        if local:
            hops.append(Hop(current, f"destination {dst} is learned locally on {local.get('interface')}: delivered",
                            detail=[f"MAC {local.get('mac')}, VLAN {local.get('vlan')}"]))
            return Trace(src, dst, vrf, hops, "delivered")

        route = _lpm(state.get("routes", []), vrf, dst)
        if route is None:
            hops.append(Hop(current, f"no route to {dst} in VRF {vrf}", False,
                            ["not even a default route: check the BGP sessions that should supply one"]))
            return Trace(src, dst, vrf, hops, "broken")
        via = route.get("next_hops", [])
        detail = [f"route {route['prefix']} ({route.get('protocol')}) via {', '.join(via) or '(none)'}"]

        # A connected subnet: the destination must be a known host somewhere in the site.
        if route.get("protocol") == "direct" and route.get("encap") != "vxlan":
            remote = _host(state, dst, "evpn")
            if remote is None:
                hops.append(Hop(current, f"{dst} is in a local subnet but not learned anywhere", False,
                                detail + ["the host is silent, down, or in the wrong VLAN"]))
                return Trace(src, dst, vrf, hops, "broken")
            via = [remote["vtep"]]
            detail.append(f"host {dst} ({remote.get('mac')}) learned over EVPN behind VTEP {remote['vtep']}")

        # The packet leaves the fabric to a BGP neighbor in the VRF (firewall, cloud, legacy core).
        sessions = {s["neighbor"]: s for s in state.get("bgp", {}).get("sessions", []) if s.get("vrf") == vrf}
        exits = [nh for nh in via if nh in sessions]
        if exits:
            s = sessions[exits[0]]
            peer = next((x.peer for x in dev.sessions if x.neighbor == exits[0] and x.vrf == vrf), f"AS {s.get('remote_as')}")
            ok = str(s.get("state", "")).lower() == "established"
            hops.append(Hop(current, f"leaves the fabric to {peer} ({exits[0]})", ok,
                            detail + ([] if ok else [f"but the BGP session is {s.get('state')}"])))
            return Trace(src, dst, vrf, hops, "leaves fabric" if ok else "broken")

        # A VXLAN next hop: underlay reachability, then whoever owns that VTEP address.
        vteps = [nh for nh in via if nh in owners]
        if not vteps:
            hops.append(Hop(current, f"next hop {', '.join(via)} is neither a VTEP nor a BGP neighbor in VRF {vrf}",
                            False, detail))
            return Trace(src, dst, vrf, hops, "broken")
        # ECMP: prefer the VTEP whose switches have the destination learned (a BGW's /32 host route).
        vtep = next((v for v in vteps if any(_host(states.get(h, {}), dst, "local") for h in owners[v])), vteps[0])
        owner_devs = [design.device(h) for h in owners[vtep]]
        crossing = owner_devs[0].site != dev.site
        if crossing:
            ms = state.get("multisite") or {}
            dci_up = [p for p, st in (ms.get("dci_links") or {}).items() if str(st).lower() == "up"]
            remote_bgws = {d.router_id for d in owner_devs}
            evpn = [s for s in state.get("bgp", {}).get("sessions", [])
                    if s.get("afi") == "evpn" and s["neighbor"] in remote_bgws
                    and str(s.get("state", "")).lower() == "established"]
            detail.append(f"DCI links up: {', '.join(sorted(dci_up)) or 'none'}; "
                          f"EVPN sessions to {owner_devs[0].site} BGWs: {len(evpn)}/{len(remote_bgws)}")
            if not dci_up or not evpn:
                hops.append(Hop(current, f"cannot cross to {owner_devs[0].site}: the DCI is down", False, detail))
                return Trace(src, dst, vrf, hops, "broken")
        else:
            underlay = _lpm(state.get("routes", []), "default", vtep)
            if underlay is None:
                hops.append(Hop(current, f"the underlay has no route to VTEP {vtep}", False,
                                detail + ["check the underlay BGP sessions and links toward the spines"]))
                return Trace(src, dst, vrf, hops, "broken")
            detail.append(f"underlay {underlay['prefix']} via {', '.join(underlay.get('next_hops', []))}")
        who = ", ".join(owners[vtep])
        what = "Multi-Site VIP of " + owner_devs[0].site if vtep in {s.multisite_vip for s in names.values()} \
            else "VTEP"
        hops.append(Hop(current, f"VXLAN to {vtep} ({what}: {who})", True, detail))
        current = sorted(owners[vtep])[0]

    hops.append(Hop(current, f"gave up after {MAX_HOPS} hops", False))
    return Trace(src, dst, vrf, hops, "broken")
