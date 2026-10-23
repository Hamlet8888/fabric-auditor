"""
Design vs. state validation for BGP EVPN/VXLAN fabrics.

:class:`Auditor` compares the collected state of every switch (:mod:`netauto.collector`)
with the design's expected state (:mod:`netauto.expected`) at one migration step, and
returns an :class:`AuditReport` of per-device, per-check results. Every failure carries
explicit :class:`Mismatch` records (item, expected, actual).

Checks:

==========  ==================================================================
links       Each routed fabric link (spine links, vPC backup underlay, DCI)
            exists, has the design MTU (9216) and is up once its step is done.
bgp         Every session active at the step is present, Established, with
            the right remote AS; BFD is up where the design runs it; local AS
            and router-ID match; no session outside the design, and none the
            design has already retired.
evpn-rt-rd  Each VNI has exactly the intended import/export route targets and
            an RD whose administrator field is the router-ID (``rd auto``).
vni-vlan    VNI-to-VLAN (L2) and VNI-to-VRF (L3) mappings match, are Up and
            nothing extra is configured.
nve         NVE is up with the right source interface and VTEP addresses; on
            BGWs also the Multi-Site site ID, VIP, fabric links and (from the
            DCI step) DCI links.
vpc         Domain, peer adjacency, keepalive destination and status, peer
            link and type-1 consistency.
==========  ==================================================================

Checks that don't apply to a role (VNIs on spines, vPC on BGWs) are ``SKIP``. Both members
of each vPC pair are also compared with each other, which shows which one diverged. A
device whose state could not be collected gets a failed ``collection`` result and
``ERROR`` for every check that applies to it.

Standard library only (Python 3.9+).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from netauto.collector import CollectionResult
from netauto.expected import Design, Device, Session

PASS = "PASS"
FAIL = "FAIL"
ERROR = "ERROR"
SKIP = "SKIP"

CHECK_COLLECTION = "collection"
CHECK_LINKS = "links"
CHECK_BGP = "bgp"
CHECK_EVPN = "evpn-rt-rd"
CHECK_VNI = "vni-vlan"
CHECK_NVE = "nve"
CHECK_VPC = "vpc"

#: The compliance checks, in report order.
CHECKS: Tuple[str, ...] = (CHECK_LINKS, CHECK_BGP, CHECK_EVPN, CHECK_VNI, CHECK_NVE, CHECK_VPC)

CHECK_TITLES = {
    CHECK_COLLECTION: "State collection",
    CHECK_LINKS: "Fabric links",
    CHECK_BGP: "BGP and BFD",
    CHECK_EVPN: "EVPN RT/RD",
    CHECK_VNI: "VNI-to-VLAN",
    CHECK_NVE: "NVE / Multi-Site",
    CHECK_VPC: "vPC",
}

ESTABLISHED = "established"


@dataclass(frozen=True)
class Mismatch:
    item: str
    expected: Any
    actual: Any
    detail: str = ""


@dataclass
class CheckResult:
    check: str
    target: str  # device hostname, or "a / b" for vPC pair comparisons
    site: str
    status: str
    checked: int = 0  # items evaluated (interfaces, sessions, VNIs, ...)
    mismatches: List[Mismatch] = field(default_factory=list)
    is_pair: bool = False

    @property
    def passed(self) -> bool:
        return self.status in (PASS, SKIP)


@dataclass
class AuditReport:
    generator: str
    step: str
    results: List[CheckResult]

    @property
    def compliant(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def failures(self) -> List[CheckResult]:
        return [r for r in self.results if not r.passed]

    def select(self, *, check: Optional[str] = None, target: Optional[str] = None,
               site: Optional[str] = None) -> List[CheckResult]:
        return [
            r for r in self.results
            if (check is None or r.check == check)
            and (target is None or r.target == target)
            and (site is None or r.site == site)
        ]

    def result(self, check: str, target: str) -> CheckResult:
        """The device-level result of one check. Pair comparisons are excluded."""
        for r in self.results:
            if r.check == check and r.target == target and not r.is_pair:
                return r
        raise KeyError((check, target))

    def site_compliant(self, site: str) -> bool:
        return all(r.passed for r in self.select(site=site))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generator": self.generator,
            "step": self.step,
            "compliant": self.compliant,
            "summary": {s: sum(1 for r in self.results if r.status == s) for s in (PASS, FAIL, ERROR, SKIP)},
            "results": [asdict(r) for r in self.results],
        }


def applies(check: str, device: Device) -> bool:
    if check in (CHECK_EVPN, CHECK_VNI, CHECK_NVE):
        return device.is_vtep
    if check == CHECK_VPC:
        return device.vpc is not None
    return True


class Auditor:
    """Validates collected state against the design at one migration step (default: the last)."""

    def __init__(self, design: Design, step: Optional[str] = None) -> None:
        self.design = design
        self.step = design.check_step(step) if step else design.final_step

    def audit(self, collection: CollectionResult, site: Optional[str] = None) -> AuditReport:
        results: List[CheckResult] = []
        for device in self.design.select(site):
            results += self._audit_device(device, collection)
        for a, b in self.design.vpc_pairs(site):
            results += self._audit_pair(a, b, collection)
        return AuditReport(generator=self.design.generator, step=self.step, results=results)

    # -- per device ----------------------------------------------------------
    def _audit_device(self, device: Device, collection: CollectionResult) -> List[CheckResult]:
        def result(check: str, status: str, checked: int = 0,
                   mismatches: Optional[List[Mismatch]] = None) -> CheckResult:
            return CheckResult(check=check, target=device.hostname, site=device.site,
                               status=status, checked=checked, mismatches=mismatches or [])

        state = collection.states.get(device.hostname)
        if state is None:
            error = collection.errors.get(device.hostname, "no state collected")
            out = [result(CHECK_COLLECTION, FAIL, 1, [Mismatch("state", "collected", None, error)])]
            out += [result(check, ERROR if applies(check, device) else SKIP) for check in CHECKS]
            return out

        fns: Dict[str, Callable[[Device, Dict[str, Any]], Tuple[int, List[Mismatch]]]] = {
            CHECK_LINKS: self.check_links, CHECK_BGP: self.check_bgp, CHECK_EVPN: self.check_evpn,
            CHECK_VNI: self.check_vni_map, CHECK_NVE: self.check_nve, CHECK_VPC: self.check_vpc,
        }
        out = []
        for check in CHECKS:
            if not applies(check, device):
                out.append(result(check, SKIP))
                continue
            checked, mismatches = fns[check](device, state)
            out.append(result(check, FAIL if mismatches else PASS, checked, mismatches))
        return out

    def _due(self, step: str) -> bool:
        ids = self.design.step_ids
        return ids.index(step) <= ids.index(self.step)

    def check_links(self, device: Device, state: Dict[str, Any]) -> Tuple[int, List[Mismatch]]:
        ifaces = state.get("interfaces", {})
        mismatches = []
        for want in device.interfaces:
            item = f"{want.name} (to {want.peer})"
            got = ifaces.get(want.name)
            if got is None:
                mismatches.append(Mismatch(item, f"MTU {want.mtu}", None, "interface not found on device"))
                continue
            if got.get("mtu") != want.mtu:
                mismatches.append(Mismatch(f"{item} MTU", want.mtu, got.get("mtu"), "MTU mismatch"))
            if self._due(self.design.interface_step(device, want)) and \
                    str(got.get("oper_status", "")).lower() != "up":
                mismatches.append(Mismatch(f"{item} status", "up", got.get("oper_status"), "link is not up"))
        return len(device.interfaces), mismatches

    def check_bgp(self, device: Device, state: Dict[str, Any]) -> Tuple[int, List[Mismatch]]:
        bgp = state.get("bgp", {})
        mismatches = []
        if bgp.get("local_as") != device.asn:
            mismatches.append(Mismatch("local AS", device.asn, bgp.get("local_as")))
        if bgp.get("router_id") != device.router_id:
            mismatches.append(Mismatch("router-ID", device.router_id, bgp.get("router_id")))

        actual = {(s["vrf"], s["afi"], s["neighbor"]): s for s in bgp.get("sessions", [])}
        bfd = {b["neighbor"]: str(b.get("state", "")) for b in state.get("bfd", [])}
        claimed = set()
        checked = 2
        for want in device.sessions:
            key = _match_session(want, actual, claimed)
            if key is not None:
                claimed.add(key)
            item = f"{_afi_label(want)} {want.neighbor} ({want.peer})"
            if self.design.retired(want, self.step):
                if key is not None:
                    mismatches.append(Mismatch(item, None, actual[key].get("state"),
                                               f"session should have been removed at {want.until}"))
                continue
            if not self.design.active(want, self.step):
                continue  # configured ahead of its step; nothing to require yet
            checked += 1
            if key is None:
                mismatches.append(Mismatch(item, "Established", None, "session not configured"))
                continue
            got = actual[key]
            if str(got.get("state", "")).lower() != ESTABLISHED:
                mismatches.append(Mismatch(item, "Established", got.get("state"), "session not established"))
            if got.get("remote_as") != want.remote_as:
                mismatches.append(Mismatch(f"{item} remote AS", want.remote_as, got.get("remote_as")))
            if want.bfd and bfd.get(got["neighbor"], "").lower() != "up":
                mismatches.append(Mismatch(f"{item} BFD", "Up", bfd.get(got["neighbor"]), "BFD session not up"))
        for key in sorted(set(actual) - claimed):
            vrf, afi, neighbor = key
            label = f"{'EVPN' if afi == 'evpn' else 'IPv4'}{'' if vrf == 'default' else f' vrf {vrf}'}"
            mismatches.append(Mismatch(f"{label} {neighbor}", None, actual[key].get("state"),
                                       "BGP neighbor not in the design"))
        return checked, mismatches

    def check_evpn(self, device: Device, state: Dict[str, Any]) -> Tuple[int, List[Mismatch]]:
        actual = {v["vni"]: v for v in state.get("evpn", {}).get("vnis", [])}
        mismatches = []
        for want in device.vnis:
            item = _vni_label(want.vni, want.vlan, want.vrf)
            got = actual.get(want.vni)
            if got is None:
                mismatches.append(Mismatch(item, f"RT {want.route_target}", None, "VNI not present in EVPN"))
                continue
            rd = str(got.get("rd", ""))
            if want.rd == "auto":
                if rd.split(":")[0] != device.router_id:
                    mismatches.append(Mismatch(f"{item} RD", f"{device.router_id}:<auto>", rd or None,
                                               "RD is not derived from the router-ID"))
            elif rd != want.rd:
                mismatches.append(Mismatch(f"{item} RD", want.rd, rd or None, "route distinguisher mismatch"))
            for direction in ("import", "export"):
                rts = sorted(set(got.get(f"rt_{direction}", [])))
                if rts != [want.route_target]:
                    mismatches.append(Mismatch(f"{item} RT {direction}", [want.route_target], rts,
                                               "route target mismatch"))
        for vni in sorted(set(actual) - {v.vni for v in device.vnis}):
            mismatches.append(Mismatch(f"VNI {vni}", None, _rt_summary(actual[vni]), "VNI in EVPN but not in the design"))
        return len(device.vnis), mismatches

    def check_vni_map(self, device: Device, state: Dict[str, Any]) -> Tuple[int, List[Mismatch]]:
        actual: Dict[int, List[Dict[str, Any]]] = {}
        for entry in state.get("vni_map", []):
            actual.setdefault(entry["vni"], []).append(entry)

        mismatches = []
        for want in device.vnis:
            item = _vni_label(want.vni, want.vlan, want.vrf)
            text = _mapping_text(want.type, want.vlan, want.vrf)
            entries = actual.get(want.vni)
            if not entries:
                mismatches.append(Mismatch(item, text, None, "VNI not configured on NVE"))
                continue
            got = entries[0]
            have = _mapping_text(got.get("type"), got.get("vlan"), got.get("vrf"))
            if len(entries) > 1:
                mismatches.append(Mismatch(item, text, [_mapping_text(e.get("type"), e.get("vlan"), e.get("vrf"))
                                                        for e in entries], "VNI mapped more than once"))
            elif have != text:
                mismatches.append(Mismatch(item, text, have, "VNI mapped to the wrong VLAN/VRF"))
            elif str(got.get("state", "")).lower() != "up":
                mismatches.append(Mismatch(f"{item} state", "Up", got.get("state"), "VNI is not up"))

        for vni in sorted(set(actual) - {v.vni for v in device.vnis}):
            got = actual[vni][0]
            mismatches.append(Mismatch(f"VNI {vni}", None, _mapping_text(got.get("type"), got.get("vlan"), got.get("vrf")),
                                       "VNI configured on device but not in the design"))
        # The same VLAN on two VNIs breaks the 1:1 mapping even if both are "extra".
        by_vlan: Dict[int, List[int]] = {}
        for vni, entries in actual.items():
            for e in entries:
                if str(e.get("type", "L2")).upper() == "L2" and e.get("vlan") is not None:
                    by_vlan.setdefault(e["vlan"], []).append(vni)
        for vlan, vnis in sorted(by_vlan.items()):
            if len(vnis) > 1:
                mismatches.append(Mismatch(f"VLAN {vlan}", "one VNI", sorted(vnis), "VLAN mapped to several VNIs"))
        return len(device.vnis), mismatches

    def check_nve(self, device: Device, state: Dict[str, Any]) -> Tuple[int, List[Mismatch]]:
        want = device.nve
        got = state.get("nve") or {}
        mismatches = []
        if str(got.get("state", "")).lower() != "up":
            mismatches.append(Mismatch("nve1 state", "Up", got.get("state")))
        for key, label in (("source_interface", "source interface"), ("primary", "primary VTEP"),
                           ("secondary", "anycast VTEP")):
            if getattr(want, key) != got.get(key):
                mismatches.append(Mismatch(f"nve1 {label}", getattr(want, key), got.get(key)))
        checked = 4
        ms = device.multisite
        if ms:
            have = state.get("multisite") or {}
            checked += 2
            if have.get("site_id") != ms.site_id:
                mismatches.append(Mismatch("Multi-Site site ID", ms.site_id, have.get("site_id")))
            if have.get("vip") != ms.vip:
                mismatches.append(Mismatch("Multi-Site VIP", ms.vip, have.get("vip")))
            dci_step = min((self.design.interface_step(device, i) for i in device.interfaces if i.dci_carrier),
                           key=self.design.step_ids.index, default=self.design.final_step)
            links = [("fabric", ms.fabric_links, True), ("DCI", ms.dci_links, self._due(dci_step))]
            for kind, ports, due in links:
                states = have.get(f"{kind.lower()}_links") or {}
                checked += len(ports)
                for port in ports:
                    status = states.get(port)
                    if status is None:
                        mismatches.append(Mismatch(f"{kind} link {port}", "tracked", None,
                                                   f"not a Multi-Site {kind} tracking link"))
                    elif due and str(status).lower() != "up":
                        mismatches.append(Mismatch(f"{kind} link {port}", "Up", status))
                for port in sorted(set(states) - set(ports)):
                    mismatches.append(Mismatch(f"{kind} link {port}", None, states[port],
                                               f"{kind} tracking on a port the design doesn't use"))
        return checked, mismatches

    def check_vpc(self, device: Device, state: Dict[str, Any]) -> Tuple[int, List[Mismatch]]:
        want = device.vpc
        got = state.get("vpc") or {}
        expected = [
            ("domain", "domain", want.domain),
            ("peer adjacency", "peer_status", "peer-ok"),
            ("keepalive destination", "keepalive_destination", want.keepalive),
            ("keepalive", "keepalive_status", "peer-alive"),
            ("peer link", "peer_link", want.peer_link),
            ("peer link status", "peer_link_status", "up"),
            ("type-1 consistency", "consistency", "success"),
        ]
        mismatches = []
        for label, key, value in expected:
            have = got.get(key)
            same = have == value if not isinstance(value, str) else str(have).lower() == value.lower()
            if not same:
                mismatches.append(Mismatch(f"vPC {label}", value, have))
        return len(expected), mismatches

    # -- per vPC pair ----------------------------------------------------------
    def _audit_pair(self, a: Device, b: Device, collection: CollectionResult) -> List[CheckResult]:
        """Both members of a vPC pair must present the same VNI/RT view to the fabric.

        Each member is already compared with the design. This adds the side-by-side view
        that shows which member diverged.
        """
        sa, sb = collection.states.get(a.hostname), collection.states.get(b.hostname)
        name = f"{a.hostname} / {b.hostname}"

        def result(check: str, status: str, checked: int = 0,
                   mismatches: Optional[List[Mismatch]] = None) -> CheckResult:
            return CheckResult(check=check, target=name, site=a.site, status=status,
                               checked=checked, mismatches=mismatches or [], is_pair=True)

        if sa is None or sb is None:
            return [result(CHECK_EVPN, ERROR), result(CHECK_VNI, ERROR)]

        out = []
        for check, view in ((CHECK_EVPN, _rt_view), (CHECK_VNI, _map_view)):
            va, vb = view(sa), view(sb)
            mismatches = [
                Mismatch(f"VNI {vni}", f"{a.hostname}: {va.get(vni, 'absent')}",
                         f"{b.hostname}: {vb.get(vni, 'absent')}", "vPC pair members disagree")
                for vni in sorted(set(va) | set(vb))
                if va.get(vni) != vb.get(vni)
            ]
            out.append(result(check, FAIL if mismatches else PASS, len(set(va) | set(vb)), mismatches))
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _match_session(want: Session, actual: Dict[Tuple[str, str, str], Dict[str, Any]],
                   claimed: set) -> Optional[Tuple[str, str, str]]:
    """The collected session that implements ``want``.

    A placeholder neighbor (an address the design leaves to the operator) matches any
    unclaimed session in the same VRF and address family with the expected remote AS.
    """
    if not want.placeholder:
        key = (want.vrf, want.afi, want.neighbor)
        return key if key in actual else None
    for key, got in sorted(actual.items()):
        if key[:2] == (want.vrf, want.afi) and key not in claimed and got.get("remote_as") == want.remote_as:
            return key
    return None


def _afi_label(s: Session) -> str:
    label = "EVPN" if s.afi == "evpn" else "IPv4"
    return label if s.vrf == "default" else f"{label} vrf {s.vrf}"


def _vni_label(vni: int, vlan: Optional[int], vrf: Optional[str]) -> str:
    if vrf is not None:
        return f"VNI {vni} (VRF {vrf})"
    return f"VNI {vni} (VLAN {vlan})"


def _mapping_text(vtype: Any, vlan: Any, vrf: Any) -> str:
    if str(vtype).upper() == "L3":
        return f"L3 VRF {vrf}"
    return f"L2 VLAN {vlan}"


def _rt_summary(v: Dict[str, Any]) -> str:
    return (f"RD {v.get('rd')}, import {sorted(set(v.get('rt_import', [])))}, "
            f"export {sorted(set(v.get('rt_export', [])))}")


def _rt_view(state: Dict[str, Any]) -> Dict[int, str]:
    # RDs are unique per device by design, so only route targets are compared across the pair.
    return {
        v["vni"]: f"import {sorted(set(v.get('rt_import', [])))}, export {sorted(set(v.get('rt_export', [])))}"
        for v in state.get("evpn", {}).get("vnis", [])
    }


def _map_view(state: Dict[str, Any]) -> Dict[int, str]:
    return {e["vni"]: _mapping_text(e.get("type"), e.get("vlan"), e.get("vrf"))
            for e in state.get("vni_map", [])}

