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
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

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
                         "state": "Established" if up else "Idle"})
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
    return state


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
