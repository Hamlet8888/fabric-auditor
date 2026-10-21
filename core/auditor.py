"""
Intent vs. state validation for BGP EVPN/VXLAN spine-leaf fabrics.

:class:`Auditor` compares the collected state of every device
(:mod:`core.collector`) with the intent (:mod:`core.inventory`) and returns an
:class:`AuditReport` of per-device, per-check results. Every failure carries
explicit :class:`Mismatch` records (item, expected, actual).

Checks:

============  ===============================================================
mtu           Each fabric interface exists and its MTU equals ``fabric.mtu``
              (9216 for RoCEv2 readiness).
bgp           Underlay (IPv4 unicast) and EVPN overlay sessions: every
              expected peer is present, Established and has the right remote
              AS; no unexpected peers; local AS and router-id match.
evpn-rt-rd    Each VNI a leaf carries has the intended route distinguisher
              and exactly the intended import/export route targets. Leaf pair
              members must also agree with each other.
vni-vlan      VNI-to-VLAN (L2) and VNI-to-VRF (L3) mappings match the intent,
              are Up, contain nothing extra, and are identical on both
              members of a leaf pair.
============  ===============================================================

``evpn-rt-rd`` and ``vni-vlan`` don't apply to spines (status ``SKIP``). A
device whose state could not be collected gets a failed ``collection`` result
and ``ERROR`` for every check that applies to it.

Standard library only (Python 3.9+).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.collector import CollectionResult
from core.inventory import Device, ExpectedPeer, Fabric, LeafPair

PASS = "PASS"
FAIL = "FAIL"
ERROR = "ERROR"
SKIP = "SKIP"

CHECK_COLLECTION = "collection"
CHECK_MTU = "mtu"
CHECK_BGP = "bgp"
CHECK_EVPN = "evpn-rt-rd"
CHECK_VNI = "vni-vlan"

#: The four compliance checks, in report order.
CHECKS: Tuple[str, ...] = (CHECK_MTU, CHECK_BGP, CHECK_EVPN, CHECK_VNI)

CHECK_TITLES = {
    CHECK_COLLECTION: "State collection",
    CHECK_MTU: "Underlay MTU",
    CHECK_BGP: "BGP underlay/EVPN overlay",
    CHECK_EVPN: "EVPN RT/RD",
    CHECK_VNI: "VNI-to-VLAN",
}

ESTABLISHED = "established"
LEAF_ONLY = (CHECK_EVPN, CHECK_VNI)


@dataclass(frozen=True)
class Mismatch:
    item: str
    expected: Any
    actual: Any
    detail: str = ""


@dataclass
class CheckResult:
    check: str
    target: str  # device hostname, or leaf pair name for pair-consistency results
    site: str
    pod: str
    status: str
    checked: int = 0  # items evaluated (interfaces, sessions, VNIs, ...)
    mismatches: List[Mismatch] = field(default_factory=list)
    is_pair: bool = False

    @property
    def passed(self) -> bool:
        return self.status in (PASS, SKIP)


@dataclass
class AuditReport:
    fabric: str
    mtu: int
    results: List[CheckResult]

    @property
    def compliant(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def failures(self) -> List[CheckResult]:
        return [r for r in self.results if not r.passed]

    def select(self, *, check: Optional[str] = None, target: Optional[str] = None,
               site: Optional[str] = None, pod: Optional[str] = None) -> List[CheckResult]:
        return [
            r for r in self.results
            if (check is None or r.check == check)
            and (target is None or r.target == target)
            and (site is None or r.site == site)
            and (pod is None or r.pod == pod)
        ]

    def result(self, check: str, target: str) -> CheckResult:
        """The device-level result of one check. Pair-consistency results are excluded."""
        for r in self.results:
            if r.check == check and r.target == target and not r.is_pair:
                return r
        raise KeyError((check, target))

    def pod_compliant(self, site: str, pod: str) -> bool:
        return all(r.passed for r in self.select(site=site, pod=pod))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fabric": self.fabric,
            "mtu": self.mtu,
            "compliant": self.compliant,
            "summary": {s: sum(1 for r in self.results if r.status == s) for s in (PASS, FAIL, ERROR, SKIP)},
            "results": [asdict(r) for r in self.results],
        }


class Auditor:
    """Validates collected state against the intent."""

    def __init__(self, fabric: Fabric) -> None:
        self.fabric = fabric

    def audit(self, collection: CollectionResult, site: Optional[str] = None) -> AuditReport:
        results: List[CheckResult] = []
        for pod in self.fabric.pods(site):
            for device in pod.spines:
                results += self._audit_device(device, collection)
            for pair in pod.leaf_pairs:
                for leaf in pair.leaves:
                    results += self._audit_device(leaf, collection)
                results += self._audit_pair(pair, pod.site, pod.name, collection)
        return AuditReport(fabric=self.fabric.name, mtu=self.fabric.mtu, results=results)

    # -- per device ----------------------------------------------------------
    def _audit_device(self, device: Device, collection: CollectionResult) -> List[CheckResult]:
        def result(check: str, status: str, checked: int = 0,
                   mismatches: Optional[List[Mismatch]] = None) -> CheckResult:
            return CheckResult(check=check, target=device.hostname, site=device.site, pod=device.pod,
                               status=status, checked=checked, mismatches=mismatches or [])

        state = collection.states.get(device.hostname)
        if state is None:
            error = collection.errors.get(device.hostname, "no state collected")
            out = [result(CHECK_COLLECTION, FAIL, 1, [Mismatch("state", "collected", None, error)])]
            for check in CHECKS:
                applies = device.is_leaf or check not in LEAF_ONLY
                out.append(result(check, ERROR if applies else SKIP))
            return out

        out = []
        for check, fn in ((CHECK_MTU, self.check_mtu), (CHECK_BGP, self.check_bgp),
                          (CHECK_EVPN, self.check_evpn), (CHECK_VNI, self.check_vni_map)):
            if check in LEAF_ONLY and not device.is_leaf:
                out.append(result(check, SKIP))
                continue
            checked, mismatches = fn(device, state)
            out.append(result(check, FAIL if mismatches else PASS, checked, mismatches))
        return out

    def check_mtu(self, device: Device, state: Dict[str, Any]) -> Tuple[int, List[Mismatch]]:
        expected = self.fabric.mtu
        ifaces = state.get("interfaces", {})
        mismatches = []
        for name in device.fabric_interfaces:
            iface = ifaces.get(name)
            if iface is None:
                mismatches.append(Mismatch(name, expected, None, "interface not found on device"))
            elif iface.get("mtu") != expected:
                mismatches.append(Mismatch(name, expected, iface.get("mtu"), "MTU mismatch"))
        return len(device.fabric_interfaces), mismatches

    def check_bgp(self, device: Device, state: Dict[str, Any]) -> Tuple[int, List[Mismatch]]:
        bgp = state.get("bgp", {})
        mismatches = []
        if bgp.get("local_as") != device.asn:
            mismatches.append(Mismatch("local AS", device.asn, bgp.get("local_as")))
        if bgp.get("router_id") != device.loopback:
            mismatches.append(Mismatch("router-id", device.loopback, bgp.get("router_id")))

        peers = self.fabric.expected_peers(device)
        checked = 2
        # Underlay sessions run on point-to-point link addresses, so they are
        # matched by the peer's router-id. Overlay sessions run loopback to
        # loopback and are matched by neighbor address.
        for afi, label, key in (("underlay", "underlay", "router_id"), ("evpn", "EVPN", "neighbor")):
            checked += len(peers)
            mismatches += _compare_sessions(label, peers, bgp.get(afi, []), key)
        return checked, mismatches

    def check_evpn(self, device: Device, state: Dict[str, Any]) -> Tuple[int, List[Mismatch]]:
        expected = self.fabric.expected_vnis(device)
        actual = {v["vni"]: v for v in state.get("evpn", {}).get("vnis", [])}
        mismatches = []
        for exp in expected:
            item = _vni_label(exp.vni, exp.vlan, exp.vrf)
            got = actual.get(exp.vni)
            if got is None:
                mismatches.append(Mismatch(item, f"RD {exp.rd}, RT {exp.route_target}", None,
                                           "VNI not present in EVPN table"))
                continue
            if got.get("rd") != exp.rd:
                mismatches.append(Mismatch(f"{item} RD", exp.rd, got.get("rd"), "route distinguisher mismatch"))
            for direction in ("import", "export"):
                rts = sorted(set(got.get(f"rt_{direction}", [])))
                if rts != [exp.route_target]:
                    mismatches.append(Mismatch(f"{item} RT {direction}", [exp.route_target], rts,
                                               "route target mismatch"))
        intended = {e.vni for e in expected}
        for vni in sorted(set(actual) - intended):
            mismatches.append(Mismatch(f"VNI {vni}", None, _rt_summary(actual[vni]),
                                       "VNI in EVPN table but not in intent"))
        return len(expected), mismatches

    def check_vni_map(self, device: Device, state: Dict[str, Any]) -> Tuple[int, List[Mismatch]]:
        expected = self.fabric.expected_vnis(device)
        actual: Dict[int, List[Dict[str, Any]]] = {}
        for entry in state.get("vni_map", []):
            actual.setdefault(entry["vni"], []).append(entry)

        mismatches = []
        for exp in expected:
            item = _vni_label(exp.vni, exp.vlan, exp.vrf)
            want = _mapping_text(exp.type, exp.vlan, exp.vrf)
            entries = actual.get(exp.vni)
            if not entries:
                mismatches.append(Mismatch(item, want, None, "VNI not configured on NVE"))
                continue
            got = entries[0]
            have = _mapping_text(got.get("type"), got.get("vlan"), got.get("vrf"))
            if len(entries) > 1:
                mismatches.append(Mismatch(item, want, [_mapping_text(e.get("type"), e.get("vlan"), e.get("vrf"))
                                                        for e in entries], "VNI mapped more than once"))
            elif have != want:
                mismatches.append(Mismatch(item, want, have, "VNI mapped to the wrong VLAN/VRF"))
            elif str(got.get("state", "")).lower() != "up":
                mismatches.append(Mismatch(f"{item} state", "Up", got.get("state"), "VNI is not up"))

        intended = {e.vni for e in expected}
        for vni in sorted(set(actual) - intended):
            got = actual[vni][0]
            mismatches.append(Mismatch(f"VNI {vni}", None, _mapping_text(got.get("type"), got.get("vlan"),
                                                                         got.get("vrf")),
                                       "VNI configured on device but not in intent"))
        # The same VLAN on two VNIs breaks the 1:1 mapping even if both are "extra".
        by_vlan: Dict[int, List[int]] = {}
        for vni, entries in actual.items():
            for e in entries:
                if e.get("vlan") is not None:
                    by_vlan.setdefault(e["vlan"], []).append(vni)
        for vlan, vnis in sorted(by_vlan.items()):
            if len(vnis) > 1:
                mismatches.append(Mismatch(f"VLAN {vlan}", "one VNI", sorted(vnis), "VLAN mapped to several VNIs"))
        return len(expected), mismatches

    # -- per leaf pair ---------------------------------------------------------
    def _audit_pair(self, pair: LeafPair, site: str, pod: str,
                    collection: CollectionResult) -> List[CheckResult]:
        """Both members of a leaf pair must present the same VNI/RT view to the fabric.

        Each member is already compared with the intent. This adds the
        side-by-side view that shows which member diverged.
        """
        a, b = pair.leaves
        sa, sb = collection.states.get(a.hostname), collection.states.get(b.hostname)

        def result(check: str, status: str, checked: int = 0,
                   mismatches: Optional[List[Mismatch]] = None) -> CheckResult:
            return CheckResult(check=check, target=pair.name, site=site, pod=pod, status=status,
                               checked=checked, mismatches=mismatches or [], is_pair=True)

        if sa is None or sb is None:
            return [result(CHECK_EVPN, ERROR), result(CHECK_VNI, ERROR)]

        out = []
        for check, view in ((CHECK_EVPN, _rt_view), (CHECK_VNI, _map_view)):
            va, vb = view(sa), view(sb)
            mismatches = [
                Mismatch(f"VNI {vni}", f"{a.hostname}: {va.get(vni, 'absent')}",
                         f"{b.hostname}: {vb.get(vni, 'absent')}", "leaf pair members disagree")
                for vni in sorted(set(va) | set(vb))
                if va.get(vni) != vb.get(vni)
            ]
            out.append(result(check, FAIL if mismatches else PASS, len(set(va) | set(vb)), mismatches))
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _compare_sessions(label: str, expected: List[ExpectedPeer],
                      actual: List[Dict[str, Any]], key: str) -> List[Mismatch]:
    by_key = {str(p.get(key) or p.get("neighbor")): p for p in actual}
    mismatches = []
    for peer in expected:
        item = f"{label} {peer.hostname} ({peer.router_id})"
        got = by_key.pop(peer.router_id, None)
        if got is None:
            mismatches.append(Mismatch(item, "Established", None, "session not configured"))
            continue
        if str(got.get("state", "")).lower() != ESTABLISHED:
            mismatches.append(Mismatch(item, "Established", got.get("state"), "session not established"))
        if got.get("remote_as") != peer.remote_as:
            mismatches.append(Mismatch(f"{item} remote AS", peer.remote_as, got.get("remote_as")))
    for rid, got in sorted(by_key.items()):
        mismatches.append(Mismatch(f"{label} {got.get('neighbor')} (router-id {rid})", None, got.get("state"),
                                   "unexpected BGP neighbor"))
    return mismatches


def _vni_label(vni: int, vlan: Optional[int], vrf: Optional[str]) -> str:
    if vlan is not None:
        return f"VNI {vni} (VLAN {vlan})"
    return f"VNI {vni} (VRF {vrf})"


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
