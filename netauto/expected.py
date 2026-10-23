"""
Loader for the design's expected state.

The expected state is ``expected-state.json``, written by the network-design generator
(https://github.com/Hamlet8888/network-design) from the same model as the switch configs.
This module reads it into an immutable object model (:class:`Design` -> :class:`Device`)
and validates it before anything is compared with the network: unknown schema versions,
duplicate hostnames or router-IDs, unknown migration steps, VNIs a device lists twice and
vPC peers that are not in the design all raise :class:`DesignError`.

Migration steps: every BGP session carries the step that brings it up and, optionally,
``until``, the step that removes it. :meth:`Design.active` tells which sessions should be
up at a given step, so a fabric can be audited part-way through the migration.

Standard library only (Python 3.9+).
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA_VERSION = 1

ROLE_SPINE = "spine"
ROLE_LEAF = "leaf"
ROLE_BORDER_LEAF = "border-leaf"
ROLE_BGW = "bgw"
ROLES = (ROLE_SPINE, ROLE_LEAF, ROLE_BORDER_LEAF, ROLE_BGW)


class DesignError(ValueError):
    """The expected-state file is malformed or internally inconsistent."""


# ---------------------------------------------------------------------------
# Object model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Interface:
    name: str
    mtu: int
    peer: str
    address: str  # "10.110.242.5/31"
    dci_carrier: Optional[str] = None


@dataclass(frozen=True)
class Session:
    step: str
    vrf: str
    afi: str  # "ipv4" or "evpn"
    neighbor: str  # an IP, or a "<PLACEHOLDER>" the design leaves to the operator
    remote_as: int
    peer: str
    bfd: bool
    until: Optional[str] = None

    @property
    def placeholder(self) -> bool:
        return self.neighbor.startswith("<")


@dataclass(frozen=True)
class Vni:
    vni: int
    type: str  # "L2" or "L3"
    vlan: Optional[int]
    vrf: Optional[str]
    rd: str  # "auto": the RD's administrator field is the router-ID
    route_target: str
    subnet: Optional[str] = None  # L2VNIs: host subnet and anycast gateway
    gateway: Optional[str] = None


@dataclass(frozen=True)
class Nve:
    source_interface: str
    primary: str
    secondary: Optional[str] = None  # vPC anycast VTEP


@dataclass(frozen=True)
class Vpc:
    domain: int
    peer: str
    keepalive: str
    peer_link: str


@dataclass(frozen=True)
class Multisite:
    site_id: int
    vip: str
    fabric_links: Tuple[str, ...]
    dci_links: Tuple[str, ...]


@dataclass(frozen=True)
class Device:
    hostname: str
    site: str
    role: str
    asn: int
    router_id: str
    interfaces: Tuple[Interface, ...]
    sessions: Tuple[Session, ...]
    vnis: Tuple[Vni, ...] = ()
    nve: Optional[Nve] = None
    vpc: Optional[Vpc] = None
    multisite: Optional[Multisite] = None
    mgmt: Optional[str] = None  # mgmt0 address: where collectors connect

    @property
    def is_vtep(self) -> bool:
        return self.nve is not None


@dataclass(frozen=True)
class Site:
    code: str
    multisite_site_id: int
    multisite_vip: str


@dataclass(frozen=True)
class Design:
    source: str
    generator: str
    dci_mode: str
    steps: Tuple[Tuple[str, str], ...]  # (id, title) in migration order
    sites: Tuple[Site, ...]
    devices: Tuple[Device, ...]

    @property
    def step_ids(self) -> List[str]:
        return [s for s, _ in self.steps]

    @property
    def final_step(self) -> str:
        return self.steps[-1][0]

    def device(self, hostname: str) -> Device:
        for d in self.devices:
            if d.hostname == hostname:
                return d
        raise KeyError(hostname)

    def select(self, site: Optional[str] = None) -> List[Device]:
        return [d for d in self.devices if site is None or d.site == site]

    def check_step(self, step: str) -> str:
        if step not in self.step_ids:
            raise DesignError(f"unknown step {step!r} (the design defines {', '.join(self.step_ids)})")
        return step

    def active(self, session: Session, step: str) -> bool:
        """Whether ``session`` should be up once ``step`` is done."""
        ids = self.step_ids
        at = ids.index(step)
        if ids.index(session.step) > at:
            return False
        return session.until is None or at < ids.index(session.until)

    def retired(self, session: Session, step: str) -> bool:
        """Whether ``session`` should already have been removed at ``step``."""
        return session.until is not None and self.step_ids.index(step) >= self.step_ids.index(session.until)

    def interface_step(self, device: Device, iface: Interface) -> str:
        """The step from which a fabric link must be up: that of the BGP session running over it."""
        net = ipaddress.ip_interface(iface.address).network
        steps = [s.step for s in device.sessions
                 if not s.placeholder and s.afi == "ipv4" and ipaddress.ip_address(s.neighbor) in net]
        return min(steps, key=self.step_ids.index) if steps else self.step_ids[0]

    def vtep_owners(self) -> Dict[str, List[str]]:
        """VTEP address -> the switches answering on it: a primary, a vPC anycast VTEP, a Multi-Site VIP."""
        owners: Dict[str, List[str]] = {}
        for d in self.devices:
            addrs = [d.nve.primary, d.nve.secondary] if d.nve else []
            addrs += [d.multisite.vip] if d.multisite else []
            for a in addrs:
                if a and d.hostname not in owners.setdefault(a, []):
                    owners[a].append(d.hostname)
        return owners

    def vpc_pairs(self, site: Optional[str] = None) -> List[Tuple[Device, Device]]:
        pairs = []
        for d in self.select(site):
            if d.vpc and d.hostname < d.vpc.peer:
                pairs.append((d, self.device(d.vpc.peer)))
        return pairs


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def load_design(path) -> Design:
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise DesignError(f"expected-state file not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise DesignError(f"{path.name}: invalid JSON at line {exc.lineno}: {exc.msg}") from None
    return parse_design(data, source=str(path))


def parse_design(data: Any, source: str = "<memory>") -> Design:
    if not isinstance(data, dict):
        raise DesignError("expected state must be a JSON object")
    version = data.get("schema_version")
    if version != SCHEMA_VERSION:
        raise DesignError(f"unsupported schema_version {version!r} (expected {SCHEMA_VERSION}); "
                          "rebuild it with a matching network-design")
    try:
        steps = tuple((s["id"], s.get("title", "")) for s in data["steps"])
        sites = tuple(Site(s["code"], int(s["multisite_site_id"]), s["multisite_vip"]) for s in data["sites"])
        devices = tuple(_device(d) for d in data["devices"])
    except (KeyError, TypeError) as exc:
        raise DesignError(f"malformed expected state: missing or invalid {exc}") from None
    design = Design(source=source, generator=str(data.get("generator", "")), dci_mode=str(data.get("dci_mode", "")),
                    steps=steps, sites=sites, devices=devices)
    _validate(design)
    return design


def _device(d: Dict[str, Any]) -> Device:
    nve = d.get("nve")
    vpc = d.get("vpc")
    ms = d.get("multisite")
    return Device(
        hostname=d["hostname"], site=d["site"], role=d["role"], asn=int(d["asn"]), router_id=d["router_id"],
        interfaces=tuple(Interface(name, int(i["mtu"]), i["peer"], i["address"], i.get("dci_carrier"))
                         for name, i in d["interfaces"].items()),
        sessions=tuple(Session(s["step"], s["vrf"], s["afi"], s["neighbor"], int(s["remote_as"]), s["peer"],
                               bool(s["bfd"]), s.get("until")) for s in d["bgp"]),
        vnis=tuple(Vni(int(v["vni"]), v["type"], v.get("vlan"), v.get("vrf"), v["rd"], v["route_target"],
                       v.get("subnet"), v.get("gateway"))
                   for v in d.get("vnis", [])),
        nve=Nve(nve["source_interface"], nve["primary"], nve.get("secondary")) if nve else None,
        vpc=Vpc(int(vpc["domain"]), vpc["peer"], vpc["keepalive"], vpc["peer_link"]) if vpc else None,
        multisite=Multisite(int(ms["site_id"]), ms["vip"], tuple(ms["fabric_links"]), tuple(ms["dci_links"]))
        if ms else None,
        mgmt=d.get("mgmt"),
    )


def _validate(design: Design) -> None:
    errors = []

    def unique(label, values):
        seen = set()
        for v in values:
            if v in seen:
                errors.append(f"duplicate {label}: {v}")
            seen.add(v)

    if not design.steps:
        errors.append("no migration steps")
    unique("step", design.step_ids)
    unique("site", [s.code for s in design.sites])
    unique("hostname", [d.hostname for d in design.devices])
    unique("router-ID", [d.router_id for d in design.devices])
    sites = {s.code for s in design.sites}
    hosts = {d.hostname for d in design.devices}
    for d in design.devices:
        if d.role not in ROLES:
            errors.append(f"{d.hostname}: unknown role {d.role!r}")
        if d.site not in sites:
            errors.append(f"{d.hostname}: unknown site {d.site!r}")
        for s in d.sessions:
            for step in (s.step, s.until):
                if step is not None and step not in design.step_ids:
                    errors.append(f"{d.hostname}: session to {s.neighbor} uses unknown step {step!r}")
            if s.afi not in ("ipv4", "evpn"):
                errors.append(f"{d.hostname}: session to {s.neighbor} has unknown address family {s.afi!r}")
        unique(f"VNI on {d.hostname}", [v.vni for v in d.vnis])
        for v in d.vnis:
            if v.type not in ("L2", "L3"):
                errors.append(f"{d.hostname}: VNI {v.vni} has unknown type {v.type!r}")
        if d.vpc and d.vpc.peer not in hosts:
            errors.append(f"{d.hostname}: vPC peer {d.vpc.peer} is not in the design")
    if errors:
        raise DesignError("invalid expected state:\n  " + "\n  ".join(errors))
