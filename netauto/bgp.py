"""
BGP session doctor: which sessions are down, and why.

    netauto bgp --expected E [--site DC1] [--device DC1-NXLF-01] [--step M4] [--source nxapi]

:func:`examine` takes every session the design expects up at ``--step`` and looks at it from
both ends, then works through the usual causes, in the order an engineer would check them:

- the session is not configured on the switch, or with another remote AS;
- the peer runs another AS, or has no session back to this switch (or sees it in Active);
- the link it runs over is down at either end, or the two ends have different MTUs;
- a loopback session has no underlay route to the peer's loopback, or (across sites) the
  DCI links are down;
- BFD is down while the link is up;
- a session that is Established but came up within the last hour has been reset recently.

When nothing in the collected state explains a down session, the finding says so and points
at ``show bgp ... neighbors`` on the switch for the last reset reason (password,
update-source, multihop).

Standard library only (Python 3.9+).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from netauto.expected import Design, Device, Session

OK = "ok"
DOWN = "down"
MISSING = "missing"
FLAPPED = "flapped"
STATUSES = (MISSING, DOWN, FLAPPED, OK)

RECENT = 3600  # an Established session younger than this (seconds) was reset recently


@dataclass
class Finding:
    device: str
    peer: str
    vrf: str
    afi: str
    neighbor: str
    status: str
    state: Optional[str] = None
    uptime: Optional[str] = None
    causes: List[str] = field(default_factory=list)


def uptime_seconds(text: Optional[str]) -> Optional[int]:
    """NX-OS up/down time ("00:12:05", "1d02h", "3w2d", "never") in seconds; None if unknown."""
    if not text or text == "never":
        return None
    m = re.fullmatch(r"(\d+):(\d+):(\d+)", text)
    if m:
        h, mi, s = map(int, m.groups())
        return h * 3600 + mi * 60 + s
    units = {"y": 31536000, "w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    parts = re.findall(r"(\d+)([ywdhms])", text)
    if not parts or "".join(n + u for n, u in parts) != text:
        return None
    return sum(int(n) * units[u] for n, u in parts)


def _show(s: Session) -> str:
    vrf = f"vrf {s.vrf} " if s.vrf != "default" else ""
    return f"show bgp {vrf}{'l2vpn evpn' if s.afi == 'evpn' else 'ipv4 unicast'} neighbors {s.neighbor}"


def _established(s: Optional[Dict[str, Any]]) -> bool:
    return s is not None and str(s.get("state", "")).lower() == "established"


def _sessions(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    return state.get("bgp", {}).get("sessions", [])


def _find(state: Dict[str, Any], vrf: str, afi: str, neighbor: str) -> Optional[Dict[str, Any]]:
    return next((s for s in _sessions(state) if (s.get("vrf"), s.get("afi"), s.get("neighbor")) == (vrf, afi, neighbor)),
                None)


def _link(device: Device, neighbor: str):
    """The design interface whose subnet holds ``neighbor`` (a single-hop session runs over it)."""
    try:
        addr = ipaddress.ip_address(neighbor)
    except ValueError:
        return None
    return next((i for i in device.interfaces if addr in ipaddress.ip_interface(i.address).network), None)


def _has_route(state: Dict[str, Any], vrf: str, ip: str) -> Optional[bool]:
    """Whether the routing table reaches ``ip`` (None when the routes were not collected)."""
    if "routes" not in state:
        return None
    addr = ipaddress.ip_address(ip)
    for r in state["routes"]:
        try:
            if r.get("vrf") == vrf and addr in ipaddress.ip_network(r["prefix"], strict=False):
                return True
        except ValueError:
            continue
    return False


class Doctor:
    def __init__(self, design: Design, states: Dict[str, Dict[str, Any]], step: Optional[str] = None) -> None:
        self.design = design
        self.states = states
        self.step = step or design.final_step
        self.hosts = {d.hostname for d in design.devices}

    def examine(self, devices: Iterable[Device]) -> List[Finding]:
        out: List[Finding] = []
        for dev in devices:
            state = self.states.get(dev.hostname)
            for s in dev.sessions:
                if s.placeholder or not self.design.active(s, self.step):
                    continue
                if state is None:
                    out.append(Finding(dev.hostname, s.peer, s.vrf, s.afi, s.neighbor, MISSING,
                                       causes=["no state collected from this switch"]))
                    continue
                out.append(self.session(dev, state, s))
        return out

    def session(self, dev: Device, state: Dict[str, Any], s: Session) -> Finding:
        actual = _find(state, s.vrf, s.afi, s.neighbor)
        f = Finding(dev.hostname, s.peer, s.vrf, s.afi, s.neighbor, OK,
                    actual.get("state") if actual else None, actual.get("uptime") if actual else None)
        if _established(actual):
            age = uptime_seconds(f.uptime)
            if age is not None and age < RECENT:
                f.status = FLAPPED
                f.causes.append(f"Established for only {f.uptime}: it was reset recently "
                                f"(`{_show(s)}` gives the reason)")
            return f

        f.status = MISSING if actual is None else DOWN
        causes = f.causes
        if actual is None:
            causes.append(f"not configured on {dev.hostname} (no {s.afi} session to {s.neighbor} in VRF {s.vrf})")
        elif actual.get("remote_as") not in (None, s.remote_as):
            causes.append(f"remote-as is {actual['remote_as']} on {dev.hostname}, the design says {s.remote_as}")

        peer_dev = self.design.device(s.peer) if s.peer in self.hosts else None
        peer_state = self.states.get(s.peer) if peer_dev else None
        link = _link(dev, s.neighbor)
        mine = str(ipaddress.ip_interface(link.address).ip) if link else dev.router_id

        if peer_dev and peer_state is None:
            causes.append(f"no state collected from {s.peer}, so its side is unknown")
        elif peer_dev:
            local_as = peer_state.get("bgp", {}).get("local_as")
            if local_as not in (None, s.remote_as):
                causes.append(f"{s.peer} runs AS {local_as}, but {dev.hostname} expects AS {s.remote_as}")
            back = _find(peer_state, s.vrf, s.afi, mine)
            if back is None:
                causes.append(f"{s.peer} has no {s.afi} session back to {mine}")
            elif back.get("remote_as") not in (None, dev.asn):
                causes.append(f"{s.peer} expects AS {back['remote_as']} at {mine}, but {dev.hostname} is AS {dev.asn}")
            elif not _established(back):
                causes.append(f"{s.peer} sees the session as {back.get('state')}")

        if link:
            causes += self.link_causes(dev, state, link, peer_dev, peer_state)
            bfd = next((b for b in state.get("bfd", []) if b.get("neighbor") == s.neighbor), None)
            link_up = str(state.get("interfaces", {}).get(link.name, {}).get("oper_status", "")).lower() == "up"
            if s.bfd and bfd and str(bfd.get("state", "")).lower() != "up" and link_up:
                causes.append(f"BFD to {s.neighbor} is {bfd.get('state')} while {link.name} is up: "
                              "check BFD timers and the link's error counters")
        else:
            causes += self.loopback_causes(dev, state, s, peer_dev)

        if not causes:
            causes.append(f"nothing in the collected state explains it: check `{_show(s)}` "
                          "for the last reset reason (password, update-source, ebgp-multihop)")
        return f

    def link_causes(self, dev: Device, state: Dict[str, Any], link, peer_dev: Optional[Device],
                    peer_state: Optional[Dict[str, Any]]) -> List[str]:
        causes = []
        iface = state.get("interfaces", {}).get(link.name)
        if iface is None:
            return [f"{link.name} does not exist on {dev.hostname}"]
        if str(iface.get("oper_status", "")).lower() != "up":
            causes.append(f"{link.name} is {iface.get('oper_status')} on {dev.hostname}")
        if iface.get("mtu") != link.mtu:
            causes.append(f"{link.name} MTU is {iface.get('mtu')} on {dev.hostname}, the design says {link.mtu}")
        if peer_dev and peer_state:
            net = ipaddress.ip_interface(link.address).network
            far = next((i for i in peer_dev.interfaces if ipaddress.ip_interface(i.address).network == net), None)
            far_state = peer_state.get("interfaces", {}).get(far.name) if far else None
            if far and far_state:
                if str(far_state.get("oper_status", "")).lower() != "up":
                    causes.append(f"{far.name} is {far_state.get('oper_status')} on {peer_dev.hostname}")
                if far_state.get("mtu") != iface.get("mtu"):
                    causes.append(f"MTU mismatch: {iface.get('mtu')} on {dev.hostname} {link.name}, "
                                  f"{far_state.get('mtu')} on {peer_dev.hostname} {far.name}")
        return causes

    def loopback_causes(self, dev: Device, state: Dict[str, Any], s: Session,
                        peer_dev: Optional[Device]) -> List[str]:
        """A session between loopbacks (the EVPN overlay): the underlay must carry it."""
        causes = []
        if peer_dev and peer_dev.site != dev.site and dev.multisite:
            dci = (state.get("multisite") or {}).get("dci_links") or {}
            if dci and not any(str(v).lower() == "up" for v in dci.values()):
                causes.append(f"all DCI links are down on {dev.hostname}: {', '.join(sorted(dci))}")
            return causes
        reach = _has_route(state, "default", s.neighbor)
        if reach is False:
            causes.append(f"no underlay route to {s.neighbor} on {dev.hostname}")
        underlay = [x for x in dev.sessions if x.afi == "ipv4" and x.vrf == "default" and not x.placeholder
                    and self.design.active(x, self.step) and _link(dev, x.neighbor)]
        down = [x for x in underlay if not _established(_find(state, x.vrf, x.afi, x.neighbor))]
        if underlay and len(down) == len(underlay):
            causes.append(f"every underlay session on {dev.hostname} is down, so the overlay cannot come up")
        return causes


def to_dict(findings: List[Finding]) -> Dict[str, Any]:
    return {"summary": {k: sum(1 for f in findings if f.status == k) for k in STATUSES},
            "sessions": [asdict(f) for f in findings]}
