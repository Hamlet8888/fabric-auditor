"""
NX-OS show-command parsing: raw NX-API output -> the normalized device state.

:func:`commands` lists what to run on a switch of a given role, and :func:`parse` turns
the raw outputs (``{command: output}``) into the document described in
:mod:`netauto.collector`. Operational state comes from the structured (JSON) output of
the show commands; configuration facts that the show commands don't carry reliably
(route targets, the vPC keepalive destination, the Multi-Site site ID and VIP) come from
the running-config.

NX-API wraps every table as ``TABLE_x: {ROW_x: [...]}``, but a table with one row
comes back as a single object instead of a list, and numbers often arrive as strings.
:func:`rows` and :func:`_int` absorb both.

The field names follow the NX-OS 9.3/10.x JSON output. A release that names a field
differently shows up as a mismatch in the audit, not as a crash: capture the raw output
with ``netauto collect --raw`` and adjust the parser here.

Standard library only (Python 3.9+).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from netauto.collector import SCHEMA_VERSION, StateError
from netauto.expected import ROLE_BGW, ROLE_SPINE, Device

SHOW_INTERFACE = "show interface"
SHOW_BGP_IPV4 = "show bgp ipv4 unicast summary vrf all"
SHOW_BGP_EVPN = "show bgp l2vpn evpn summary"
SHOW_BFD = "show bfd neighbors vrf all"
SHOW_NVE_VNI = "show nve vni"
SHOW_NVE_IF = "show nve interface nve1 detail"
SHOW_VPC = "show vpc brief"
SHOW_RUN = "show running-config"
SHOW_EVPN_RD = 'show bgp l2vpn evpn | include "Route Distinguisher"'
SHOW_MS_FABRIC = "show nve multisite fabric-links"
SHOW_MS_DCI = "show nve multisite dci-links"
SHOW_ROUTE = "show ip route vrf all"
SHOW_L2ROUTE = "show l2route evpn mac-ip all"
SHOW_LOG = "show logging logfile"  # netauto timeline; not part of the state

#: Commands whose output is plain text (NX-API ``cli_ascii``); the rest are JSON (``cli``).
ASCII = {SHOW_RUN, SHOW_EVPN_RD, SHOW_MS_FABRIC, SHOW_MS_DCI}


def commands(device: Device) -> List[str]:
    """The show commands to run on ``device``, by role."""
    cmds = [SHOW_INTERFACE, SHOW_BGP_IPV4, SHOW_BGP_EVPN, SHOW_BFD, SHOW_RUN]
    if device.role == ROLE_SPINE:
        return cmds
    cmds += [SHOW_NVE_VNI, SHOW_NVE_IF, SHOW_EVPN_RD, SHOW_ROUTE]
    if device.role == ROLE_BGW:
        cmds += [SHOW_MS_FABRIC, SHOW_MS_DCI]
    else:
        cmds += [SHOW_VPC, SHOW_L2ROUTE]
    return cmds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def rows(obj: Any, table: str, row: str) -> List[Dict[str, Any]]:
    """The rows of an NX-API table, as a list whether there are none, one or many."""
    if not isinstance(obj, dict):
        return []
    r = (obj.get(table) or {}).get(row) if isinstance(obj.get(table), dict) else None
    if r is None:
        return []
    return r if isinstance(r, list) else [r]


def _int(v: Any) -> Optional[int]:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _first(row: Dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if row.get(k) not in (None, ""):
            return row[k]
    return None


def long_ifname(name: str) -> str:
    """'Eth1/49' -> 'Ethernet1/49', 'Po10' -> 'port-channel10', 'Lo1' -> 'loopback1'."""
    for short, full in (("Eth", "Ethernet"), ("Po", "port-channel"), ("Lo", "loopback")):
        if re.fullmatch(rf"{short}\d.*", name):
            return full + name[len(short):]
    return name


# ---------------------------------------------------------------------------
# Running-config
# ---------------------------------------------------------------------------


class Stanza:
    def __init__(self, line: str, depth: int) -> None:
        self.line, self.depth, self.children = line, depth, []  # type: str, int, List[Stanza]

    def find(self, prefix: str) -> List["Stanza"]:
        return [c for c in self.children if c.line == prefix or c.line.startswith(prefix + " ")]

    def values(self, prefix: str) -> List[str]:
        return [c.line[len(prefix):].strip() for c in self.find(prefix)]


def parse_config(text: str) -> Stanza:
    """Parse running-config text into a tree of indentation-based stanzas."""
    root = Stanza("", -1)
    stack = [root]
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("!"):
            continue
        line = raw.rstrip()
        depth = len(line) - len(line.lstrip(" "))
        while stack[-1].depth >= depth:
            stack.pop()
        node = Stanza(line.strip(), depth)
        stack[-1].children.append(node)
        stack.append(node)
    return root


def _rts(node: Stanza) -> Dict[str, List[str]]:
    """Route targets under a stanza; 'both' counts for import and export, 'auto' is reported as such."""
    out: Dict[str, List[str]] = {"import": [], "export": []}
    for v in node.values("route-target"):
        p = v.split()
        if len(p) < 2:
            continue
        for d in (("import", "export") if p[0] == "both" else (p[0],)):
            if d in out and p[1] not in out[d]:
                out[d].append(p[1])
    return out


def config_rts(cfg: Stanza) -> Dict[int, Dict[str, List[str]]]:
    """VNI -> route targets: L2VNIs from the evpn stanza, L3VNIs from the EVPN RTs of their VRF."""
    out: Dict[int, Dict[str, List[str]]] = {}
    for evpn in cfg.find("evpn"):
        for v in evpn.find("vni"):
            p = v.line.split()
            if len(p) >= 3 and p[2] == "l2" and _int(p[1]) is not None:
                out[int(p[1])] = _rts(v)
    for vrf in cfg.find("vrf context"):
        vni = next((_int(x) for x in vrf.values("vni")), None)
        if vni is None:
            continue
        rts: Dict[str, List[str]] = {"import": [], "export": []}
        for af in vrf.find("address-family"):
            for line in af.values("route-target"):
                p = line.split()
                if len(p) >= 3 and p[2] == "evpn":
                    for d in (("import", "export") if p[0] == "both" else (p[0],)):
                        if d in rts and p[1] not in rts[d]:
                            rts[d].append(p[1])
        out[vni] = rts
    return out


def _interface_ip(cfg: Stanza, ifname: str) -> Optional[str]:
    for node in cfg.find(f"interface {ifname}"):
        for v in node.values("ip address"):
            p = v.split()
            if "secondary" not in p:
                return p[0].split("/")[0]
    return None


# ---------------------------------------------------------------------------
# Show commands
# ---------------------------------------------------------------------------


def parse_interfaces(out: Any) -> Dict[str, Dict[str, Any]]:
    ifaces = {}
    for r in rows(out, "TABLE_interface", "ROW_interface"):
        name = r.get("interface")
        mtu = _int(_first(r, "eth_mtu", "svi_mtu", "mtu"))
        if not name or mtu is None:
            continue
        status = _first(r, "state", "svi_line_proto", "svi_admin_state")
        ifaces[long_ifname(name)] = {"mtu": mtu, "oper_status": str(status or "unknown").lower()}
    return ifaces


def parse_bgp(out: Any, afi: str, bgp: Dict[str, Any]) -> None:
    """Add the sessions of one ``show bgp ... summary`` to ``bgp``; router-ID and AS from VRF default."""
    for vrf in rows(out, "TABLE_vrf", "ROW_vrf"):
        name = vrf.get("vrf-name-out", "default")
        if name == "default":
            bgp.setdefault("router_id", vrf.get("vrf-router-id"))
            bgp.setdefault("local_as", _int(vrf.get("vrf-local-as")))
        for af in rows(vrf, "TABLE_af", "ROW_af"):
            for saf in rows(af, "TABLE_saf", "ROW_saf"):
                for n in rows(saf, "TABLE_neighbor", "ROW_neighbor"):
                    state = str(n.get("state", ""))
                    bgp["sessions"].append({
                        "vrf": name, "afi": afi, "neighbor": str(n.get("neighborid")),
                        "remote_as": _int(n.get("neighboras")),
                        # NX-OS shows a prefix count instead of a state once a session is up.
                        "state": "Established" if state.isdigit() else state,
                        # Up/down time: how long the session has been in its current state.
                        **({"uptime": str(n["time"])} if n.get("time") else {}),
                    })


def parse_bfd(out: Any) -> List[Dict[str, str]]:
    return [{"neighbor": str(_first(r, "dest_ip_addr", "neighbor_ip", "dst_ip_addr")),
             "state": str(_first(r, "local_state", "state", "ses_state") or "")}
            for r in rows(out, "TABLE_bfdNeighbor", "ROW_bfdNeighbor")]


def parse_nve_vni(out: Any) -> List[Dict[str, Any]]:
    vmap = []
    for r in rows(out, "TABLE_nve_vni", "ROW_nve_vni"):
        vni = _int(r.get("vni"))
        m = re.fullmatch(r"\s*(L2|L3)\s*\[(.*)\]\s*", str(r.get("type", "")))
        if vni is None or not m:
            continue
        entry: Dict[str, Any] = {"vni": vni, "type": m.group(1)}
        if m.group(1) == "L2":
            entry["vlan"] = _int(m.group(2))
        else:
            entry["vrf"] = m.group(2)
        entry["state"] = str(r.get("vni-state", ""))
        vmap.append(entry)
    return vmap


def parse_evpn_rds(text: str) -> Dict[int, str]:
    """'Route Distinguisher: 10.110.240.13:32777    (L2VNI 110010)' -> {110010: '10.110.240.13:32777'}"""
    out = {}
    for m in re.finditer(r"Route Distinguisher:\s*(\S+)\s+\(L[23]VNI\s+(\d+)\)", text or ""):
        out[int(m.group(2))] = m.group(1)
    return out


def parse_multisite_links(text: str) -> Dict[str, str]:
    """'Ethernet1/49     Up' lines of show nve multisite fabric-links / dci-links."""
    out = {}
    for line in (text or "").splitlines():
        p = line.split()
        if len(p) >= 2 and re.fullmatch(r"(Ethernet|Eth)\d+/\d+(\.\d+)?", p[0]):
            out[long_ifname(p[0])] = p[1]
    return out


#: Route sources that are the switch's own addresses, not paths anywhere.
_OWN_ROUTES = {"local", "hsrp", "vrrp", "am"}


def parse_routes(out: Any) -> List[Dict[str, Any]]:
    """Every IPv4 route except the management VRF and the switch's own /32s."""
    routes = []
    for vrf in rows(out, "TABLE_vrf", "ROW_vrf"):
        name = vrf.get("vrf-name-out", "default")
        if name == "management":
            continue
        for af in rows(vrf, "TABLE_addrf", "ROW_addrf"):
            for p in rows(af, "TABLE_prefix", "ROW_prefix"):
                paths = [x for x in rows(p, "TABLE_path", "ROW_path")
                         if str(x.get("ubest", "true")).lower() == "true"]
                protocols = [str(x.get("clientname", "")).split("-")[0] for x in paths]
                if not paths or all(pr in _OWN_ROUTES for pr in protocols):
                    continue
                vxlan = any(x.get("encap") == "vxlan" or x.get("segid") for x in paths)
                routes.append({
                    "vrf": name, "prefix": p.get("ipprefix"), "protocol": protocols[0] or None,
                    "next_hops": sorted({str(x.get("ipnexthop") or long_ifname(str(x.get("ifname", "")))) for x in paths}),
                    "encap": "vxlan" if vxlan else None,
                })
    return routes


def parse_hosts(out: Any, cfg: Stanza) -> List[Dict[str, Any]]:
    """MAC-IP bindings: local ones on a port, EVPN-learned ones behind a VTEP. VRF from the VLAN's SVI."""
    svi_vrf = {}
    for node in cfg.find("interface"):
        name = node.line.split(None, 1)[1]
        if name.startswith("Vlan") and node.values("vrf member"):
            svi_vrf[_int(name[4:])] = node.values("vrf member")[0]
    hosts = []
    for r in rows(out, "TABLE_l2route_mac_ip_all", "ROW_l2route_mac_ip_all"):
        vlan, ip = _int(r.get("topo-id")), r.get("host-ip")
        if vlan is None or not ip:
            continue
        nh = str(r.get("next-hop1", ""))
        entry = {"vrf": svi_vrf.get(vlan), "vlan": vlan, "ip": ip, "mac": r.get("mac-addr")}
        if str(r.get("prod-type", "")).upper() == "BGP":
            entry.update(source="evpn", vtep=nh)
        else:
            entry.update(source="local", interface=long_ifname(nh))
        hosts.append(entry)
    return hosts


def parse_vpc(out: Any, cfg: Stanza) -> Dict[str, Any]:
    if not isinstance(out, dict):
        return {}
    links = rows(out, "TABLE_peerlink", "ROW_peerlink")
    link = links[0] if links else {}
    port_state = str(link.get("peer-link-port-state", ""))
    consistency = str(out.get("vpc-peer-consistency", ""))
    keepalive = None
    for domain in cfg.find("vpc domain"):
        for v in domain.values("peer-keepalive destination"):
            keepalive = v.split()[0]
    return {
        "domain": _int(out.get("vpc-domain-id")),
        "peer_status": out.get("vpc-peer-status"),
        "keepalive_status": out.get("vpc-peer-keepalive-status"),
        "keepalive_destination": keepalive,
        "peer_link": long_ifname(str(link.get("peerlink-ifindex", ""))) or None,
        "peer_link_status": "up" if port_state in ("1", "up") else (port_state or None),
        "consistency": "success" if consistency in ("consistent", "success") else consistency,
    }


# ---------------------------------------------------------------------------
# Whole device
# ---------------------------------------------------------------------------


def parse(device: Device, raw: Dict[str, Any], collected_at: Optional[str] = None) -> Dict[str, Any]:
    """The normalized state of ``device`` from its raw command outputs."""
    missing = [c for c in commands(device) if c not in raw]
    if missing:
        raise StateError(f"no output for: {', '.join(missing)}")
    cfg = parse_config(raw[SHOW_RUN])

    bgp: Dict[str, Any] = {"sessions": []}
    parse_bgp(raw[SHOW_BGP_IPV4], "ipv4", bgp)
    parse_bgp(raw[SHOW_BGP_EVPN], "evpn", bgp)
    state: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "hostname": device.hostname,
        "platform": "nxos",
        "interfaces": parse_interfaces(raw[SHOW_INTERFACE]),
        "bgp": {"router_id": bgp.get("router_id"), "local_as": bgp.get("local_as"), "sessions": bgp["sessions"]},
        "bfd": parse_bfd(raw[SHOW_BFD]),
        "evpn": {"vnis": []},
        "vni_map": [],
    }
    if collected_at:
        state["collected_at"] = collected_at
    if device.role == ROLE_SPINE:
        return state

    vmap = parse_nve_vni(raw[SHOW_NVE_VNI])
    rds = parse_evpn_rds(raw[SHOW_EVPN_RD])
    rts = config_rts(cfg)
    state["vni_map"] = vmap
    state["evpn"]["vnis"] = [
        {"vni": v["vni"], "rd": rds.get(v["vni"]),
         "rt_import": rts.get(v["vni"], {}).get("import", []), "rt_export": rts.get(v["vni"], {}).get("export", [])}
        for v in vmap
    ]
    nve_rows = rows(raw[SHOW_NVE_IF], "TABLE_nve_if", "ROW_nve_if")
    nve = nve_rows[0] if nve_rows else {}
    state["nve"] = {
        "state": nve.get("if-state"),
        "source_interface": long_ifname(str(nve.get("src-if", ""))) or None,
        "primary": nve.get("primary-ip"),
        "secondary": None if nve.get("secondary-ip") in (None, "", "0.0.0.0") else nve.get("secondary-ip"),
    }
    state["routes"] = parse_routes(raw[SHOW_ROUTE])
    if device.role == ROLE_BGW:
        site_id = next((_int(n.line.split()[-1]) for n in cfg.find("evpn multisite border-gateway")), None)
        bgw_if = next((v.split()[-1] for n in cfg.find("interface nve1")
                       for v in n.values("multisite border-gateway interface")), None)
        state["multisite"] = {
            "site_id": site_id,
            "vip": nve.get("multisite-bgw-if-ip") or (_interface_ip(cfg, bgw_if) if bgw_if else None),
            "fabric_links": parse_multisite_links(raw[SHOW_MS_FABRIC]),
            "dci_links": parse_multisite_links(raw[SHOW_MS_DCI]),
        }
    else:
        state["vpc"] = parse_vpc(raw[SHOW_VPC], cfg)
        state["hosts"] = parse_hosts(raw[SHOW_L2ROUTE], cfg)
    return state

