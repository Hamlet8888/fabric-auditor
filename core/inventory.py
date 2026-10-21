"""
Intent loader for multi-site BGP EVPN/VXLAN spine-leaf fabrics.

Reads ``spine_leaf_intent.yaml`` into an immutable object model
(:class:`Fabric` -> :class:`Site` -> :class:`Pod` -> :class:`Device`) and
derives what the auditor needs from it: the BGP peers each device should
have, and the VNIs, route targets and route distinguishers each leaf should
carry.

The loader validates the intent itself before anything is compared with the
network: duplicate hostnames, loopbacks, VLANs or VNIs, leaf pairs without
exactly two members, and references to undefined segments or VRFs all raise
:class:`IntentError`.

Standard library only (Python 3.9+).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from core import miniyaml

ROLE_SPINE = "spine"
ROLE_LEAF = "leaf"


class IntentError(ValueError):
    """The intent file is malformed or internally inconsistent."""


# ---------------------------------------------------------------------------
# Object model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Segment:
    """An L2VNI: one VLAN mapped to one VNI with one route target."""

    vlan: int
    vni: int
    name: str
    route_target: str


@dataclass(frozen=True)
class Vrf:
    """An L3VNI (symmetric IRB)."""

    name: str
    id: int
    vni: int
    route_target: str


@dataclass(frozen=True)
class Device:
    hostname: str
    role: str
    site: str
    pod: str
    asn: int
    loopback: str
    fabric_interfaces: Tuple[str, ...]
    pair: Optional[str] = None  # leaf pair name, leaves only

    @property
    def is_leaf(self) -> bool:
        return self.role == ROLE_LEAF


@dataclass(frozen=True)
class LeafPair:
    name: str
    asn: int
    leaves: Tuple[Device, Device]
    segments: Tuple[Segment, ...]
    vrfs: Tuple[Vrf, ...]


@dataclass(frozen=True)
class Pod:
    name: str
    site: str
    spine_asn: int
    spines: Tuple[Device, ...]
    leaf_pairs: Tuple[LeafPair, ...]

    @property
    def leaves(self) -> Tuple[Device, ...]:
        return tuple(leaf for pair in self.leaf_pairs for leaf in pair.leaves)

    @property
    def devices(self) -> Tuple[Device, ...]:
        return self.spines + self.leaves


@dataclass(frozen=True)
class Site:
    name: str
    location: str
    pods: Tuple[Pod, ...]


@dataclass(frozen=True)
class ExpectedPeer:
    """A BGP session a device should have, keyed by the peer's router-id/loopback."""

    hostname: str
    router_id: str
    remote_as: int


@dataclass(frozen=True)
class ExpectedVni:
    """What a leaf should advertise for one VNI."""

    vni: int
    type: str  # "L2" or "L3"
    vlan: Optional[int]
    vrf: Optional[str]
    rd: str
    route_target: str


@dataclass(frozen=True)
class Fabric:
    name: str
    mtu: int
    rd_formats: Dict[str, str]
    segments: Tuple[Segment, ...]
    vrfs: Tuple[Vrf, ...]
    sites: Tuple[Site, ...]
    source: Optional[Path] = field(default=None, compare=False)

    # -- lookups -----------------------------------------------------------
    def pods(self, site: Optional[str] = None) -> Iterator[Pod]:
        for s in self.sites:
            if site is None or s.name == site:
                yield from s.pods

    def devices(self, site: Optional[str] = None) -> List[Device]:
        return [d for pod in self.pods(site) for d in pod.devices]

    def device(self, hostname: str) -> Device:
        for d in self.devices():
            if d.hostname == hostname:
                return d
        raise KeyError(hostname)

    def pod_of(self, device: Device) -> Pod:
        for pod in self.pods(device.site):
            if pod.name == device.pod:
                return pod
        raise KeyError(device.pod)

    def leaf_pairs(self, site: Optional[str] = None) -> List[LeafPair]:
        return [pair for pod in self.pods(site) for pair in pod.leaf_pairs]

    def pair_of(self, device: Device) -> Optional[LeafPair]:
        if not device.is_leaf:
            return None
        for pair in self.pod_of(device).leaf_pairs:
            if pair.name == device.pair:
                return pair
        return None

    # -- derived intent ----------------------------------------------------
    def expected_peers(self, device: Device) -> List[ExpectedPeer]:
        """BGP peers for ``device``. Underlay and overlay use the same peer set:
        each leaf peers with every spine in its pod, and vice versa."""
        pod = self.pod_of(device)
        others = pod.spines if device.is_leaf else pod.leaves
        return [ExpectedPeer(o.hostname, o.loopback, o.asn) for o in others]

    def expected_vnis(self, device: Device) -> List[ExpectedVni]:
        """VNIs a leaf should carry, with their expected RD and RT. Empty for spines."""
        pair = self.pair_of(device)
        if pair is None:
            return []
        out = [
            ExpectedVni(
                vni=s.vni, type="L2", vlan=s.vlan, vrf=None,
                rd=self.rd_formats["l2"].format(router_id=device.loopback, vlan=s.vlan, vni=s.vni),
                route_target=s.route_target,
            )
            for s in pair.segments
        ]
        out += [
            ExpectedVni(
                vni=v.vni, type="L3", vlan=None, vrf=v.name,
                rd=self.rd_formats["l3"].format(router_id=device.loopback, vrf_id=v.id, vni=v.vni),
                route_target=v.route_target,
            )
            for v in pair.vrfs
        ]
        return out


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_intent(path) -> Fabric:
    """Load and validate an intent YAML file."""
    path = Path(path)
    try:
        data = miniyaml.load(path)
    except OSError as exc:
        raise IntentError(f"cannot read intent file {path}: {exc}") from exc
    except ValueError as exc:
        raise IntentError(f"{path}: {exc}") from exc
    return parse_intent(data, source=path)


def parse_intent(data: Any, source: Optional[Path] = None) -> Fabric:
    """Build a :class:`Fabric` from already-parsed intent data."""
    if not isinstance(data, dict):
        raise IntentError("intent must be a mapping with 'fabric', 'segments', 'vrfs' and 'sites'")

    fab = _mapping(data, "fabric", "intent")
    mtu = _int(fab, "mtu", "fabric")
    rd = _mapping(fab, "route_distinguisher", "fabric")
    rd_formats = {"l2": _str(rd, "l2", "fabric.route_distinguisher"),
                  "l3": _str(rd, "l3", "fabric.route_distinguisher")}

    segments = tuple(
        Segment(
            vlan=_int(s, "vlan", f"segments[{i}]"),
            vni=_int(s, "vni", f"segments[{i}]"),
            name=_str(s, "name", f"segments[{i}]"),
            route_target=_rt(s, f"segments[{i}]"),
        )
        for i, s in enumerate(_list(data, "segments", "intent"))
    )
    vrfs = tuple(
        Vrf(
            name=_str(v, "name", f"vrfs[{i}]"),
            id=_int(v, "id", f"vrfs[{i}]"),
            vni=_int(v, "vni", f"vrfs[{i}]"),
            route_target=_rt(v, f"vrfs[{i}]"),
        )
        for i, v in enumerate(_list(data, "vrfs", "intent"))
    )
    _unique([s.vlan for s in segments], "segment VLAN")
    _unique([s.vni for s in segments] + [v.vni for v in vrfs], "VNI")
    _unique([v.name for v in vrfs], "VRF name")
    _unique([v.id for v in vrfs], "VRF id")
    seg_by_vlan = {s.vlan: s for s in segments}
    vrf_by_name = {v.name: v for v in vrfs}

    sites = []
    for si, s in enumerate(_list(data, "sites", "intent")):
        where = f"sites[{si}]"
        site_name = _str(s, "name", where)
        pods = tuple(
            _parse_pod(p, site_name, f"{site_name}.pods[{pi}]", seg_by_vlan, vrf_by_name)
            for pi, p in enumerate(_list(s, "pods", where))
        )
        sites.append(Site(name=site_name, location=str(s.get("location", "")), pods=pods))

    fabric = Fabric(
        name=_str(fab, "name", "fabric"), mtu=mtu, rd_formats=rd_formats,
        segments=segments, vrfs=vrfs, sites=tuple(sites), source=source,
    )
    devices = fabric.devices()
    _unique([s.name for s in fabric.sites], "site name")
    _unique([p.name for p in fabric.pods()], "pod name")
    _unique([d.hostname for d in devices], "hostname")
    _unique([d.loopback for d in devices], "loopback")
    _unique([lp.name for lp in fabric.leaf_pairs()], "leaf pair name")
    return fabric


def _parse_pod(p: Any, site: str, where: str,
               seg_by_vlan: Dict[int, Segment], vrf_by_name: Dict[str, Vrf]) -> Pod:
    if not isinstance(p, dict):
        raise IntentError(f"{where}: expected a mapping")
    pod_name = _str(p, "name", where)
    spine_asn = _int(p, "spine_asn", where)
    spines = tuple(
        _parse_device(d, ROLE_SPINE, site, pod_name, spine_asn, None, f"{pod_name}.spines[{i}]")
        for i, d in enumerate(_list(p, "spines", where))
    )
    pairs = []
    for i, lp in enumerate(_list(p, "leaf_pairs", where)):
        lp_where = f"{pod_name}.leaf_pairs[{i}]"
        name = _str(lp, "name", lp_where)
        asn = _int(lp, "asn", lp_where)
        raw_leaves = _list(lp, "leaves", lp_where)
        if len(raw_leaves) != 2:
            raise IntentError(f"{lp_where} ({name}): a leaf pair needs exactly 2 leaves, got {len(raw_leaves)}")
        leaves = tuple(
            _parse_device(d, ROLE_LEAF, site, pod_name, asn, name, f"{name}.leaves[{j}]")
            for j, d in enumerate(raw_leaves)
        )
        try:
            segs = tuple(seg_by_vlan[int(v)] for v in lp.get("segments") or [])
        except (KeyError, ValueError) as exc:
            raise IntentError(f"{lp_where} ({name}): unknown segment VLAN {exc}") from None
        try:
            vrfs = tuple(vrf_by_name[str(v)] for v in lp.get("vrfs") or [])
        except KeyError as exc:
            raise IntentError(f"{lp_where} ({name}): unknown VRF {exc}") from None
        pairs.append(LeafPair(name=name, asn=asn, leaves=leaves, segments=segs, vrfs=vrfs))  # type: ignore[arg-type]
    return Pod(name=pod_name, site=site, spine_asn=spine_asn, spines=spines, leaf_pairs=tuple(pairs))


def _parse_device(d: Any, role: str, site: str, pod: str, asn: int,
                  pair: Optional[str], where: str) -> Device:
    if not isinstance(d, dict):
        raise IntentError(f"{where}: expected a mapping")
    hostname = _str(d, "hostname", where)
    loopback = _str(d, "loopback", where)
    try:
        ipaddress.IPv4Address(loopback)
    except ValueError:
        raise IntentError(f"{where} ({hostname}): loopback {loopback!r} is not an IPv4 address") from None
    ifaces = tuple(str(i) for i in _list(d, "fabric_interfaces", where))
    _unique(list(ifaces), f"fabric interface on {hostname}")
    return Device(hostname=hostname, role=role, site=site, pod=pod, asn=asn,
                  loopback=loopback, fabric_interfaces=ifaces, pair=pair)


# -- field helpers -----------------------------------------------------------


def _mapping(d: Dict[str, Any], key: str, where: str) -> Dict[str, Any]:
    val = d.get(key)
    if not isinstance(val, dict):
        raise IntentError(f"{where}: '{key}' must be a mapping")
    return val


def _list(d: Any, key: str, where: str) -> List[Any]:
    if not isinstance(d, dict):
        raise IntentError(f"{where}: expected a mapping")
    val = d.get(key)
    if not isinstance(val, list):
        raise IntentError(f"{where}: '{key}' must be a list")
    return val


def _str(d: Any, key: str, where: str) -> str:
    if not isinstance(d, dict):
        raise IntentError(f"{where}: expected a mapping")
    val = d.get(key)
    if val is None or isinstance(val, (dict, list)) or str(val).strip() == "":
        raise IntentError(f"{where}: '{key}' is required")
    return str(val)


def _int(d: Any, key: str, where: str) -> int:
    if not isinstance(d, dict):
        raise IntentError(f"{where}: expected a mapping")
    val = d.get(key)
    if isinstance(val, bool) or not isinstance(val, int):
        raise IntentError(f"{where}: '{key}' must be an integer, got {val!r}")
    return val


def _rt(d: Dict[str, Any], where: str) -> str:
    val = d.get("route_target")
    if isinstance(val, int):
        raise IntentError(f"{where}: route_target was read as the number {val}; quote it, e.g. \"65000:10100\"")
    rt = _str(d, "route_target", where)
    left, sep, right = rt.partition(":")
    if not sep or not left or not right.isdigit():
        raise IntentError(f"{where}: route_target {rt!r} is not in ASN:NN or IP:NN form")
    return rt


def _unique(values: List[Any], what: str) -> None:
    seen, dupes = set(), set()
    for v in values:
        (dupes if v in seen else seen).add(v)
    if dupes:
        raise IntentError(f"duplicate {what}: {', '.join(sorted(map(str, dupes)))}")
