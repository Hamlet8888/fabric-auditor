"""
State collection for fabric-auditor.

:class:`FabricCollector` gathers the operational state of every device in the
intent, concurrently, from a :class:`StateSource`. The auditor only ever sees
the normalized per-device document described below, so a live driver
(NX-API, eAPI, gNMI, ...) plugs in by subclassing :class:`StateSource` and
returning the same shape. This module ships :class:`MockStateSource`, which
reads offline snapshots from ``examples/mock_states/<hostname>.json`` for
pre-flight validation and tests.

Normalized device state (schema version 1)::

    {
      "schema_version": 1,
      "hostname": "lvd-lf01a",
      "collected_at": "2026-10-21T14:00:00Z",          # optional
      "interfaces": {
        "Ethernet1/49": {"mtu": 9216, "oper_status": "up"}
      },
      "bgp": {
        "router_id": "10.11.0.11",
        "local_as": 65111,
        "underlay": [                                   # show bgp ipv4 unicast summary
          {"neighbor": "10.11.1.0", "router_id": "10.11.0.1",
           "remote_as": 65100, "state": "Established", "prefixes_received": 8}
        ],
        "evpn": [                                       # show bgp l2vpn evpn summary
          {"neighbor": "10.11.0.1", "router_id": "10.11.0.1",
           "remote_as": 65100, "state": "Established", "prefixes_received": 42}
        ]
      },
      "evpn": {                                         # show bgp l2vpn evpn vni-id / show evpn evi
        "vnis": [
          {"vni": 10100, "type": "L2", "rd": "10.11.0.11:100",
           "rt_import": ["65000:10100"], "rt_export": ["65000:10100"]}
        ]
      },
      "vni_map": [                                      # show nve vni
        {"vni": 10100, "type": "L2", "vlan": 100, "state": "Up"},
        {"vni": 50010, "type": "L3", "vrf": "TENANT-A", "state": "Up"}
      ]
    }

Spines carry no ``evpn.vnis`` or ``vni_map`` entries.

A device that cannot be collected (missing file, malformed JSON, timeout,
schema violation) doesn't abort the run. It is recorded in
:attr:`CollectionResult.errors` and the auditor reports it as a failure.

Standard library only (Python 3.9+).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from core.inventory import Device, Fabric

SCHEMA_VERSION = 1


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


class MockStateSource(StateSource):
    """Reads offline snapshots from ``<state_dir>/<hostname>.json``."""

    name = "mock"

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
            raise StateError(f"no mock state file at {path}") from None
        except OSError as exc:
            raise StateError(f"cannot read {path}: {exc}") from exc
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise StateError(f"{path.name}: invalid JSON at line {exc.lineno}: {exc.msg}") from None
        return data


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
    """Collects state for the devices in ``fabric`` with bounded concurrency.

    ``concurrency`` caps how many devices are queried at once and ``timeout``
    (seconds) applies to each device separately.
    """

    def __init__(self, fabric: Fabric, source: StateSource,
                 concurrency: int = 16, timeout: float = 30.0) -> None:
        if concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        self.fabric = fabric
        self.source = source
        self.concurrency = concurrency
        self.timeout = timeout

    def collect(self, devices: Optional[Iterable[Device]] = None) -> CollectionResult:
        """Synchronous wrapper around :meth:`collect_async`."""
        return asyncio.run(self.collect_async(devices))

    async def collect_async(self, devices: Optional[Iterable[Device]] = None) -> CollectionResult:
        targets: List[Device] = list(devices) if devices is not None else self.fabric.devices()
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

    Only structure and types are checked here. Whether the values match the
    intent is the auditor's job.
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
    if not isinstance(bgp, dict):
        raise StateError("'bgp' must be an object")
    for afi in ("underlay", "evpn"):
        peers = bgp.get(afi)
        if not isinstance(peers, list):
            raise StateError(f"bgp.{afi} must be a list of neighbors")
        for i, peer in enumerate(peers):
            if not isinstance(peer, dict) or not isinstance(peer.get("neighbor"), str) \
                    or not isinstance(peer.get("state"), str):
                raise StateError(f"bgp.{afi}[{i}]: 'neighbor' and 'state' are required strings")

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


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)
