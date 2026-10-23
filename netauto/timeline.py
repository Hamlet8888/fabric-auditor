"""
Event timeline: what happened, in what order, across the fabric.

    netauto timeline --logs DIR [--since 30m] [--device H] [--all]
    netauto timeline --expected E --source nxapi [--since "2026-10-23 14:00"]

Reads each switch's log (``show logging logfile``; saved by ``netauto collect --logs`` as
``<dir>/logs/<hostname>.log``, or fetched live), keeps the events that matter when
something breaks, merges them into one timeline and points at the first failure, which is
usually the cause, with the rest as its consequences:

- links: ``ETHPORT`` / ``ETH_PORT_CHANNEL`` interface and port-channel down and up;
- BGP neighbors (``BGP-5-ADJCHANGE``) and BFD sessions going down and up;
- vPC peer-link, keepalive and suspension messages, NVE and Multi-Site state changes;
- MAC moves and flaps (``L2FM``), duplicate addresses (``ARP``, ``HMM``);
- anything at severity 0-2 (emergency, alert, critical).

``--all`` keeps every line. Lines look like
``2026 Oct 23 14:02:11 DC1-NXLF-01 %BGP-5-ADJCHANGE: bgp-65211 [8121] neighbor 10.110.242.0 Down - ...``;
NX-OS writes them in the switch's clock, so switches must share NTP (and a time zone) for
the order across switches to be right.

Standard library only (Python 3.9+).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

DOWN = "down"
UP = "up"
WARN = "warn"
INFO = "info"

_LINE = re.compile(
    r"^(?P<ts>\d{4}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})(?:\.\d+)?"
    r"(?P<mid>[^%]*)%(?P<fac>[A-Z0-9_]+)-(?:SLOT\d+-)?(?P<sev>\d)-(?P<mnem>[A-Z0-9_]+):\s*(?P<msg>.*)$")

#: (facility pattern, mnemonic pattern, message pattern) -> kind. First match wins.
_RULES: List[Tuple[str, str, str, str]] = [
    (r"BGP", r"ADJCHANGE", r"\bUp\b", UP),
    (r"BGP", r"ADJCHANGE", r"\bDown\b", DOWN),
    (r"BFD", r"SESSION_STATE_DOWN|SESSION_REMOVED", r"", DOWN),
    (r"BFD", r"SESSION_STATE_UP|SESSION_CREATED", r"", UP),
    (r"ETHPORT|ETH_PORT_CHANNEL|IF", r"IF_DOWN.*|PORT_DOWN|PORT_INDIVIDUAL_DOWN|ALL_PORTS_DOWN", r"", DOWN),
    (r"ETHPORT|ETH_PORT_CHANNEL|IF", r"IF_UP|PORT_UP|FOP_CHANGED", r"", UP),
    (r"VPC", r".*(FAIL|SUSP|DOWN|TIMEOUT|MISMATCH|INCONSISTEN).*", r"", DOWN),
    (r"VPC", r".*(SUCCESS|UP|RESUM|RECOVER).*", r"", UP),
    (r"NVE", r".*", r"\b[Dd]own\b|\bDOWN\b", DOWN),
    (r"NVE", r".*", r"\b[Uu]p\b|\bUP\b", UP),
    (r"L2FM|ARP|HMM|IPV4|ICMPV6", r".*(MOVE|FLAP|DUP|DUPLICATE|CONFLICT).*", r"", WARN),
]


@dataclass
class Event:
    time: datetime
    device: str
    facility: str
    severity: int
    mnemonic: str
    message: str
    kind: str

    @property
    def tag(self) -> str:
        return f"{self.facility}-{self.severity}-{self.mnemonic}"

    def to_dict(self) -> Dict[str, object]:
        return {"time": self.time.isoformat(sep=" "), "device": self.device, "tag": self.tag,
                "kind": self.kind, "message": self.message}


def classify(facility: str, severity: int, mnemonic: str, message: str) -> str:
    for fac, mnem, msg, kind in _RULES:
        if re.fullmatch(fac, facility) and re.fullmatch(mnem, mnemonic) and (not msg or re.search(msg, message)):
            return kind
    return DOWN if severity <= 2 else INFO


def parse_log(text: str, device: str) -> List[Event]:
    """Every syslog line of one switch's log; lines that are not syslog messages are skipped."""
    events = []
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue
        try:
            ts = datetime.strptime(" ".join(m["ts"].split()), "%Y %b %d %H:%M:%S")
        except ValueError:
            continue
        sev = int(m["sev"])
        msg = " ".join(m["msg"].split())
        events.append(Event(ts, device, m["fac"], sev, m["mnem"], msg, classify(m["fac"], sev, m["mnem"], msg)))
    return events


def load_logs(folder) -> Dict[str, str]:
    """{hostname: log text} from ``<folder>/<hostname>.log`` (or ``<folder>/logs/``)."""
    folder = Path(folder)
    if (folder / "logs").is_dir():
        folder = folder / "logs"
    if not folder.is_dir():
        raise ValueError(f"not a folder: {folder}")
    logs = {p.stem: p.read_text(encoding="utf-8", errors="replace") for p in sorted(folder.glob("*.log"))}
    if not logs:
        raise ValueError(f"no <hostname>.log files in {folder}")
    return logs


def parse_when(text: str, latest: datetime) -> datetime:
    """An absolute time ("2026-10-23 14:00[:ss]") or one relative to ``latest`` ("30m", "2h", "1d")."""
    m = re.fullmatch(r"(\d+)([smhd])", text.strip())
    if m:
        unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[m[2]]
        return latest - timedelta(**{unit: int(m[1])})
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(text.strip(), fmt)
        except ValueError:
            continue
    raise ValueError(f"cannot read time {text!r}: use e.g. 30m, 2h, 1d or '2026-10-23 14:00'")


@dataclass
class Timeline:
    events: List[Event]
    first_failure: Optional[Event]
    devices: List[str]

    def to_dict(self) -> Dict[str, object]:
        return {"devices": self.devices,
                "first_failure": self.first_failure.to_dict() if self.first_failure else None,
                "summary": {k: sum(1 for e in self.events if e.kind == k) for k in (DOWN, WARN, UP, INFO)},
                "events": [e.to_dict() for e in self.events]}


def build(logs: Dict[str, str], devices: Optional[Iterable[str]] = None, since: Optional[str] = None,
          until: Optional[str] = None, everything: bool = False) -> Timeline:
    wanted = set(devices) if devices is not None else None
    events: List[Event] = []
    for host, text in logs.items():
        if wanted is None or host in wanted:
            events += parse_log(text, host)
    # Relative times count back from the newest line in the logs, so saved logs read the same later.
    latest = max((e.time for e in events), default=datetime.now())
    start = parse_when(since, latest) if since else None
    end = parse_when(until, latest) if until else None
    events = [e for e in events if (start is None or e.time >= start) and (end is None or e.time <= end)
              and (everything or e.kind != INFO)]
    events.sort(key=lambda e: (e.time, e.device))
    first = next((e for e in events if e.kind == DOWN), None)
    return Timeline(events, first, sorted({h for h in logs if wanted is None or h in wanted}))
