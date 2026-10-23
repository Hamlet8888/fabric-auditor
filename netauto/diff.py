"""
Before/after comparison of fabric state: the change guard.

    netauto collect --expected E --out private/state/before --source nxapi
    ... make the change ...
    netauto collect --expected E --out private/state/after
    netauto diff private/state/before private/state/after

:func:`flatten` turns a device's normalized state (:mod:`netauto.collector`) into
``{fact: value}``, where a fact names one thing that can change: a link's status, a BGP
session's state, a VNI's mapping, a route's next hops. :func:`diff_fabric` compares two
collections fact by fact and classifies every difference:

``LOST``     something that was healthy is now down or gone (a session left Established,
             a link or VNI went down or disappeared, a route was withdrawn, a switch no
             longer answers). These are what to roll back for.
``CHANGED``  a value changed without a clear health direction (remote AS, MTU, RTs).
``GAINED``   something new, or something that came up.

Standard library only (Python 3.9+).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

LOST = "LOST"
CHANGED = "CHANGED"
GAINED = "GAINED"
KINDS = (LOST, CHANGED, GAINED)

HEALTHY = {"up", "established", "peer-ok", "peer-alive", "success", "present"}

Fact = Tuple[str, ...]


@dataclass(frozen=True)
class Difference:
    device: str
    kind: str
    fact: str
    before: Any
    after: Any


def _healthy(value: Any) -> bool:
    return str(value).lower() in HEALTHY


def _list(v: Any) -> str:
    return ", ".join(sorted(map(str, v))) if v else "(none)"


def flatten(state: Dict[str, Any]) -> Dict[Fact, Any]:
    """Every comparable fact in one device's state."""
    f: Dict[Fact, Any] = {}
    for name, i in state.get("interfaces", {}).items():
        f[("interface", name, "status")] = i.get("oper_status")
        f[("interface", name, "mtu")] = i.get("mtu")
    bgp = state.get("bgp", {})
    f[("bgp", "router-id")] = bgp.get("router_id")
    f[("bgp", "local AS")] = bgp.get("local_as")
    for s in bgp.get("sessions", []):
        label = "EVPN" if s["afi"] == "evpn" else "IPv4"
        key = ("bgp", f"{label}{'' if s['vrf'] == 'default' else ' vrf ' + s['vrf']}", s["neighbor"])
        f[key + ("state",)] = s.get("state")
        f[key + ("remote AS",)] = s.get("remote_as")
        if s.get("prefixes_received") is not None:
            f[key + ("prefixes",)] = s.get("prefixes_received")
    for b in state.get("bfd", []):
        f[("bfd", b["neighbor"])] = b.get("state")
    for v in state.get("vni_map", []):
        target = f"VLAN {v.get('vlan')}" if v.get("type") == "L2" else f"VRF {v.get('vrf')}"
        f[("vni", str(v["vni"]), "mapping")] = f"{v.get('type')} {target}"
        f[("vni", str(v["vni"]), "state")] = v.get("state")
    for v in state.get("evpn", {}).get("vnis", []):
        f[("evpn", str(v["vni"]), "RT import")] = _list(v.get("rt_import"))
        f[("evpn", str(v["vni"]), "RT export")] = _list(v.get("rt_export"))
    for section in ("nve", "vpc"):
        for k, v in (state.get(section) or {}).items():
            f[(section, k)] = v
    ms = state.get("multisite") or {}
    for k in ("site_id", "vip"):
        if k in ms:
            f[("multisite", k)] = ms[k]
    for kind in ("fabric_links", "dci_links"):
        for port, status in (ms.get(kind) or {}).items():
            f[("multisite", kind.replace("_", " "), port)] = status
    for r in state.get("routes", []):
        f[("route", r["vrf"], r["prefix"])] = _list(r.get("next_hops"))
    for h in state.get("hosts", []):
        f[("host", h["vrf"], h["ip"])] = f"{h.get('mac')} on {h.get('interface') or h.get('vtep')}"
    return f


def _kind(fact: Fact, before: Any, after: Any) -> str:
    if after is None:
        # A route, host or session disappearing is a loss; so is any fact whose value was healthy.
        return LOST if fact[0] in ("route", "host", "bgp", "bfd", "vni", "interface") or _healthy(before) else CHANGED
    if before is None:
        return GAINED
    if _healthy(before) and not _healthy(after):
        return LOST
    if not _healthy(before) and _healthy(after):
        return GAINED
    return CHANGED


def diff_device(device: str, before: Dict[str, Any], after: Dict[str, Any]) -> List[Difference]:
    fb, fa = flatten(before), flatten(after)
    out = []
    for fact in sorted(set(fb) | set(fa)):
        b, a = fb.get(fact), fa.get(fact)
        if b == a:
            continue
        # A whole session/VNI going away shows once (as its state), not once per attribute.
        if a is None and fact[-1] in ("remote AS", "prefixes", "mapping", "mtu"):
            continue
        out.append(Difference(device, _kind(fact, b, a), " ".join(fact), b, a))
    return out


def diff_fabric(before: Dict[str, Dict[str, Any]], after: Dict[str, Dict[str, Any]],
                devices: Optional[Iterable[str]] = None) -> List[Difference]:
    names = list(devices) if devices is not None else sorted(set(before) | set(after))
    out: List[Difference] = []
    for name in names:
        b, a = before.get(name), after.get(name)
        if b is None and a is None:
            continue
        if a is None:
            out.append(Difference(name, LOST, "state", "collected", None))
        elif b is None:
            out.append(Difference(name, GAINED, "state", None, "collected"))
        else:
            out += diff_device(name, b, a)
    order = {k: i for i, k in enumerate(KINDS)}
    return sorted(out, key=lambda d: (order[d.kind], names.index(d.device) if d.device in names else 0))


def load_states(folder) -> Dict[str, Dict[str, Any]]:
    """{hostname: state} from a folder of <hostname>.json snapshots (as `netauto collect` writes)."""
    folder = Path(folder)
    if not folder.is_dir():
        raise ValueError(f"not a folder: {folder}")
    states = {}
    for path in sorted(folder.glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: invalid JSON at line {exc.lineno}: {exc.msg}") from None
        if isinstance(doc, dict) and "hostname" in doc:
            states[doc["hostname"]] = doc
    if not states:
        raise ValueError(f"no state snapshots in {folder}")
    return states


def to_dict(diffs: List[Difference]) -> Dict[str, Any]:
    return {"summary": {k: sum(1 for d in diffs if d.kind == k) for k in KINDS},
            "differences": [asdict(d) for d in diffs]}
