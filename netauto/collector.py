"""
State collection.

:class:`FabricCollector` gathers the operational state of every device in the design,
concurrently, from a :class:`StateSource`. The auditor only ever sees the normalized
per-device document described below, so a live driver (NX-API, gNMI, ...) plugs in by
subclassing :class:`StateSource` and returning the same shape. This module ships
:class:`SnapshotSource`, which reads offline snapshots from ``<state-dir>/<hostname>.json``
for pre-flight validation and tests, and :class:`StaticStateSource` for in-memory states.

Normalized device state (schema version 2)::

    {
      "schema_version": 2,
      "hostname": "DC1-NXLF-03",
      "collected_at": "2026-10-23T14:00:00Z",           # optional
      "interfaces": {                                    # show interface
        "Ethernet1/49": {"mtu": 9216, "oper_status": "up"}
      },
      "bgp": {                                           # show bgp [vrf all] ... summary
        "router_id": "10.110.240.13",
        "local_as": 65213,
        "sessions": [
          {"vrf": "default", "afi": "ipv4", "neighbor": "10.110.242.4",
           "remote_as": 65210, "state": "Established", "uptime": "3w2d"}   # uptime optional
        ]
      },
      "bfd": [{"neighbor": "10.110.242.4", "state": "Up"}],      # show bfd neighbors
      "evpn": {                                          # show bgp l2vpn evpn vni-id / show vrf detail
        "vnis": [{"vni": 110010, "rd": "10.110.240.13:32777",
                  "rt_import": ["65110:110010"], "rt_export": ["65110:110010"]}]
      },
      "vni_map": [                                       # show nve vni
        {"vni": 110010, "type": "L2", "vlan": 10, "state": "Up"},
        {"vni": 50010, "type": "L3", "vrf": "TRUST", "state": "Up"}
      ],
      "nve": {"state": "Up", "source_interface": "loopback1",        # show nve interface nve1 detail
              "primary": "10.110.241.13", "secondary": "10.110.241.102"},
      "vpc": {"domain": 112, "peer_status": "peer-ok", "keepalive_status": "peer-alive",   # show vpc brief
              "keepalive_destination": "10.110.243.10", "peer_link": "port-channel10",
              "peer_link_status": "up", "consistency": "success"},
      "multisite": {"site_id": 110, "vip": "10.110.241.200",         # show nve multisite ...
                    "fabric_links": {"Ethernet1/49": "Up"}, "dci_links": {"Ethernet1/51": "Up"}}
    }

Two optional sections feed the troubleshooting commands (``netauto path``, ``netauto diff``)::

      "routes": [                                        # show ip route vrf all
        {"vrf": "TRUST", "prefix": "10.120.10.0/24", "protocol": "bgp",
         "next_hops": ["10.110.241.200"], "encap": "vxlan"}
      ],
      "hosts": [                                         # show l2route evpn mac-ip all
        {"vrf": "TRUST", "vlan": 10, "ip": "10.110.10.10", "mac": "0050.5601.000a",
         "source": "local", "interface": "port-channel100"},
        {"vrf": "TRUST", "vlan": 10, "ip": "10.110.10.11", "mac": "0050.5601.010a",
         "source": "evpn", "vtep": "10.110.241.102"}
      ]

Spines carry no ``evpn.vnis``, ``vni_map``, ``nve``, ``vpc`` or ``multisite``. Only leafs
carry ``vpc`` and only border gateways ``multisite``.

A device that cannot be collected (missing file, malformed JSON, timeout, schema
violation) doesn't abort the run. It is recorded in :attr:`CollectionResult.errors` and
the auditor reports it as a failure.

Standard library only (Python 3.9+).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from netauto.expected import Design, Device

SCHEMA_VERSION = 2


class StateError(Exception):
    """State for one device could not be retrieved or is malformed."""


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------


class StateSource:
    """Where device state comes from. Subclasses implement :meth:`fetch`."""

    name = "abstract"

    async def fetch(self, device: Device) -> Dict[str, Any]:  # pragma: no cover - interface
        """Return the normalized state document for ``device`` or raise :class:`StateError`."""
        raise NotImplementedError


class SnapshotSource(StateSource):
    """Reads offline snapshots from ``<state_dir>/<hostname>.json``."""

    name = "snapshots"

    def __init__(self, state_dir) -> None:
        self.state_dir = Path(state_dir)

    def path_for(self, device: Device) -> Path:
        return self.state_dir / f"{device.hostname}.json"

    async def fetch(self, device: Device) -> Dict[str, Any]:
        path = self.path_for(device)
        # File reads block, so hand them to a worker thread and keep the loop free.
        try:
            text = await asyncio.to_thread(path.read_text, encoding="utf-8")
        except FileNotFoundError:
            raise StateError(f"no state snapshot at {path}") from None
        except OSError as exc:
            raise StateError(f"cannot read {path}: {exc}") from exc
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise StateError(f"{path.name}: invalid JSON at line {exc.lineno}: {exc.msg}") from None


class StaticStateSource(StateSource):
    """Serves state documents held in memory. Useful for tests and for replaying captures."""

    name = "static"

    def __init__(self, states: Dict[str, Dict[str, Any]]) -> None:
        self.states = states

    async def fetch(self, device: Device) -> Dict[str, Any]:
        try:
            return self.states[device.hostname]
        except KeyError:
            raise StateError("no state provided") from None


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


@dataclass
class CollectionResult:
    states: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)
    source: str = ""

    @property
    def ok(self) -> bool:
        return not self.errors


class FabricCollector:
    """Collects state for the devices in ``design`` with bounded concurrency.

    ``concurrency`` caps how many devices are queried at once and ``timeout`` (seconds)
    applies to each device separately.
    """

    def __init__(self, design: Design, source: StateSource,
                 concurrency: int = 16, timeout: float = 30.0) -> None:
        if concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        self.design = design
        self.source = source
        self.concurrency = concurrency
        self.timeout = timeout

    def collect(self, devices: Optional[Iterable[Device]] = None) -> CollectionResult:
        """Synchronous wrapper around :meth:`collect_async`."""
        return asyncio.run(self.collect_async(devices))

    async def collect_async(self, devices: Optional[Iterable[Device]] = None) -> CollectionResult:
        targets: List[Device] = list(devices) if devices is not None else list(self.design.devices)
        sem = asyncio.Semaphore(self.concurrency)
        result = CollectionResult(source=self.source.name)

        async def one(device: Device) -> None:
            async with sem:
                try:
                    data = await asyncio.wait_for(self.source.fetch(device), self.timeout)
                    validate_state(device.hostname, data)
                except asyncio.TimeoutError:
                    result.errors[device.hostname] = f"timed out after {self.timeout:g}s"
                except StateError as exc:
                    result.errors[device.hostname] = str(exc)
                else:
                    result.states[device.hostname] = data

        await asyncio.gather(*(one(d) for d in targets))
        return result


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


def validate_state(hostname: str, data: Any) -> None:
    """Check the structural shape of a state document. Raises :class:`StateError`.

    Only structure and types are checked here. Whether the values match the design is the
    auditor's job.
    """
    if not isinstance(data, dict):
        raise StateError("state document must be a JSON object")
    version = data.get("schema_version")
    if version != SCHEMA_VERSION:
        raise StateError(f"unsupported schema_version {version!r} (expected {SCHEMA_VERSION})")
    if data.get("hostname") != hostname:
        raise StateError(f"state is for {data.get('hostname')!r}, not {hostname!r}")

    ifaces = data.get("interfaces")
    if not isinstance(ifaces, dict):
        raise StateError("'interfaces' must be an object keyed by interface name")
    for name, iface in ifaces.items():
        if not isinstance(iface, dict) or not _is_int(iface.get("mtu")):
            raise StateError(f"interfaces.{name}: 'mtu' must be an integer")

    bgp = data.get("bgp")
    if not isinstance(bgp, dict) or not isinstance(bgp.get("sessions"), list):
        raise StateError("'bgp.sessions' must be a list")
    for i, s in enumerate(bgp["sessions"]):
        if not isinstance(s, dict) or not all(isinstance(s.get(k), str) for k in ("vrf", "afi", "neighbor", "state")):
            raise StateError(f"bgp.sessions[{i}]: 'vrf', 'afi', 'neighbor' and 'state' are required strings")

    bfd = data.get("bfd", [])
    if not isinstance(bfd, list) or not all(isinstance(b, dict) and isinstance(b.get("neighbor"), str) for b in bfd):
        raise StateError("'bfd' must be a list of {neighbor, state}")

    evpn = data.get("evpn")
    if not isinstance(evpn, dict) or not isinstance(evpn.get("vnis"), list):
        raise StateError("'evpn.vnis' must be a list")
    for i, v in enumerate(evpn["vnis"]):
        if not isinstance(v, dict) or not _is_int(v.get("vni")):
            raise StateError(f"evpn.vnis[{i}]: 'vni' must be an integer")
        for key in ("rt_import", "rt_export"):
            if not isinstance(v.get(key, []), list):
                raise StateError(f"evpn.vnis[{i}]: '{key}' must be a list")

    vmap = data.get("vni_map")
    if not isinstance(vmap, list):
        raise StateError("'vni_map' must be a list")
    for i, v in enumerate(vmap):
        if not isinstance(v, dict) or not _is_int(v.get("vni")):
            raise StateError(f"vni_map[{i}]: 'vni' must be an integer")

    for i, r in enumerate(data.get("routes", [])):
        if not isinstance(r, dict) or not isinstance(r.get("prefix"), str) or not isinstance(r.get("next_hops"), list):
            raise StateError(f"routes[{i}]: 'prefix' (string) and 'next_hops' (list) are required")
    for i, h in enumerate(data.get("hosts", [])):
        if not isinstance(h, dict) or not isinstance(h.get("ip"), str):
            raise StateError(f"hosts[{i}]: 'ip' is required")

    for key in ("nve", "vpc", "multisite"):
        if data.get(key) is not None and not isinstance(data[key], dict):
            raise StateError(f"'{key}' must be an object")


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)
