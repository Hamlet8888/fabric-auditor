"""
fabric-auditor command-line interface.

    python3 -m core.cli audit --intent examples/spine_leaf_intent.yaml
    python3 -m core.cli audit --intent examples/spine_leaf_intent.yaml --site LVD
    python3 -m core.cli audit --intent examples/spine_leaf_intent.yaml --format json
    python3 -m core.cli inventory --intent examples/spine_leaf_intent.yaml

``audit`` loads state from ``--state-dir`` (default: ``mock_states/`` next to
the intent file), runs the four compliance checks and prints a status table
per site and pod, followed by every mismatch with its expected and actual
value.

Exit status: 0 when everything audited is compliant, 1 when any check fails
or a device's state could not be collected, 2 for usage or input errors.

Colour is used when stdout is a terminal, unless ``NO_COLOR`` is set or
``--color never`` is given.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional, Sequence, TextIO

from core import __version__
from core.auditor import (CHECK_COLLECTION, CHECK_TITLES, CHECKS, ERROR, FAIL, PASS, SKIP,
                          AuditReport, Auditor, CheckResult)
from core.collector import FabricCollector, MockStateSource
from core.inventory import Fabric, IntentError, load_intent

EXIT_OK = 0
EXIT_NONCOMPLIANT = 1
EXIT_USAGE = 2

_COLUMNS = {
    "mtu": "UNDERLAY MTU",
    "bgp": "BGP UL/OVL",
    "evpn-rt-rd": "EVPN RT/RD",
    "vni-vlan": "VNI-VLAN",
}


# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------


class Style:
    _CODES = {"green": "32", "red": "31", "yellow": "33", "dim": "2", "bold": "1", "cyan": "36"}

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, *styles: str) -> str:
        if not self.enabled or not styles:
            return text
        codes = ";".join(self._CODES[s] for s in styles)
        return f"\033[{codes}m{text}\033[0m"

    def status(self, status: str, text: Optional[str] = None) -> str:
        text = status if text is None else text
        colour = {PASS: ("green",), FAIL: ("red", "bold"), ERROR: ("yellow", "bold"), SKIP: ("dim",)}
        return self(text, *colour.get(status, ()))


def _use_color(mode: str, stream: TextIO) -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _pad(styled: str, plain: str, width: int) -> str:
    """Left-justify a possibly coloured string by the width of its plain text."""
    return styled + " " * max(0, width - len(plain))


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _cell(result: Optional[CheckResult]) -> str:
    if result is None or result.status == SKIP:
        return "-"
    if result.status == FAIL:
        return f"FAIL ({len(result.mismatches)})"
    if result.status == PASS:
        return f"PASS {result.checked}/{result.checked}" if result.checked else "PASS"
    return result.status


def render_table(fabric: Fabric, report: AuditReport, site: Optional[str], style: Style,
                 out: TextIO, source_desc: str) -> None:
    w = out.write
    w(style(f"fabric-auditor {__version__}", "bold") + f"  fabric {fabric.name}  "
      f"expected MTU {fabric.mtu}\n")
    w(style(f"intent: {fabric.source}   state: {source_desc}", "dim") + "\n")

    headers = ["DEVICE", "ROLE"] + [_COLUMNS[c] for c in CHECKS]
    widths = [max(12, max((len(d.hostname) for d in fabric.devices()), default=0) + 2), 7] + \
             [max(len(_COLUMNS[c]), 10) + 2 for c in CHECKS]

    for s in fabric.sites:
        if site and s.name != site:
            continue
        w("\n" + style(f"{s.name}", "bold", "cyan") + (style(f"  {s.location}", "dim") if s.location else "") + "\n")
        for pod in s.pods:
            ok = report.pod_compliant(s.name, pod.name)
            verdict = style("COMPLIANT", "green", "bold") if ok else style("NON-COMPLIANT", "red", "bold")
            w(f"  {style(pod.name, 'bold')}  {verdict}\n")
            w("    " + "".join(style(h.ljust(widths[i]), "dim") for i, h in enumerate(headers)).rstrip() + "\n")

            rows = [(d.hostname, d.role, False) for d in pod.spines]
            for pair in pod.leaf_pairs:
                rows += [(leaf.hostname, leaf.role, False) for leaf in pair.leaves]
                rows.append((pair.name, "pair", True))
            for target, role, is_pair in rows:
                results = {r.check: r for r in report.select(target=target, pod=pod.name) if r.is_pair == is_pair}
                collect = results.get(CHECK_COLLECTION)
                name = target if not is_pair else f"  {target}"
                line = _pad(style(name, "dim") if is_pair else name, name, widths[0])
                line += role.ljust(widths[1])
                for i, check in enumerate(CHECKS, start=2):
                    r = results.get(check)
                    plain = _cell(r)
                    line += _pad(style.status(r.status, plain) if r else plain, plain, widths[i])
                if collect is not None and not collect.passed:
                    line += style("state unavailable", "yellow")
                w("    " + line.rstrip() + "\n")

    failures = report.failures
    mismatch_rows = [(r, m) for r in failures for m in r.mismatches]
    errored = [r for r in failures if not r.mismatches]
    if mismatch_rows:
        w("\n" + style(f"Mismatches ({len(mismatch_rows)})", "bold") + "\n")
        for r, m in mismatch_rows:
            title = CHECK_TITLES.get(r.check, r.check)
            head = f"  {style.status(r.status, r.status.ljust(5))} {r.target}  {style(title, 'bold')}  {m.item}"
            w(head + "\n")
            w(f"        expected: {_fmt(m.expected)}\n")
            w(f"        actual:   {style(_fmt(m.actual), 'red')}" + (style(f"   ({m.detail})", "dim") if m.detail else "")
              + "\n")
    if errored:
        not_run = sorted({r.target for r in errored})
        w("\n" + style(f"Checks not run (no state): {', '.join(not_run)}", "yellow") + "\n")

    w("\n" + style("Summary", "bold") + "\n")
    for s in fabric.sites:
        if site and s.name != site:
            continue
        for pod in s.pods:
            pod_results = report.select(site=s.name, pod=pod.name)
            failed = sum(1 for r in pod_results if not r.passed)
            ok = failed == 0
            label = style("COMPLIANT", "green") if ok else style(f"NON-COMPLIANT ({failed} failed checks)", "red")
            w(f"  {s.name:<5} {pod.name:<12} {label}\n")
    overall = style("COMPLIANT", "green", "bold") if report.compliant else style("NON-COMPLIANT", "red", "bold")
    w(f"  Overall: {overall}\n")


def _fmt(value) -> str:
    if value is None:
        return "(none)"
    if isinstance(value, list):
        return ", ".join(map(str, value)) if value else "(none)"
    return str(value)


def render_inventory(fabric: Fabric, site: Optional[str], style: Style, out: TextIO) -> None:
    w = out.write
    w(style(f"{fabric.name}", "bold") + f"  MTU {fabric.mtu}  "
      f"{len(fabric.segments)} L2VNIs, {len(fabric.vrfs)} L3VNIs\n")
    for s in fabric.sites:
        if site and s.name != site:
            continue
        w("\n" + style(s.name, "bold", "cyan") + (style(f"  {s.location}", "dim") if s.location else "") + "\n")
        for pod in s.pods:
            w(f"  {style(pod.name, 'bold')}  spine AS {pod.spine_asn}\n")
            for d in pod.spines:
                w(f"    {d.hostname:<14} spine  {d.loopback:<15} AS {d.asn}\n")
            for pair in pod.leaf_pairs:
                vnis = ", ".join([str(x.vni) for x in pair.segments] + [f"{v.vni} ({v.name})" for v in pair.vrfs])
                w(f"    {style(pair.name, 'dim')}  AS {pair.asn}  VNIs {vnis}\n")
                for d in pair.leaves:
                    w(f"      {d.hostname:<12} leaf   {d.loopback:<15} AS {d.asn}\n")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _load(args: argparse.Namespace) -> Fabric:
    fabric = load_intent(args.intent)
    if args.site and args.site not in {s.name for s in fabric.sites}:
        known = ", ".join(s.name for s in fabric.sites)
        raise IntentError(f"unknown site {args.site!r} (intent defines: {known})")
    return fabric


def cmd_audit(args: argparse.Namespace, out: TextIO) -> int:
    fabric = _load(args)
    state_dir = Path(args.state_dir) if args.state_dir else Path(args.intent).resolve().parent / "mock_states"
    if not state_dir.is_dir():
        raise IntentError(f"state directory not found: {state_dir}")

    collector = FabricCollector(fabric, MockStateSource(state_dir),
                                concurrency=args.concurrency, timeout=args.timeout)
    collection = collector.collect(fabric.devices(args.site))
    report = Auditor(fabric).audit(collection, site=args.site)

    if args.format == "json":
        doc = report.to_dict()
        doc["collection_errors"] = collection.errors
        json.dump(doc, out, indent=2, default=str)
        out.write("\n")
    else:
        style = Style(_use_color(args.color, out))
        render_table(fabric, report, args.site, style, out, f"{collection.source} ({state_dir})")
    return EXIT_OK if report.compliant else EXIT_NONCOMPLIANT


def cmd_inventory(args: argparse.Namespace, out: TextIO) -> int:
    fabric = _load(args)
    render_inventory(fabric, args.site, Style(_use_color(args.color, out)), out)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fabric-auditor",
        description="Validate a BGP EVPN/VXLAN spine-leaf fabric against its intent.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--intent", required=True, metavar="FILE", help="fabric intent YAML")
    common.add_argument("--site", metavar="NAME", help="limit to one site, e.g. LVD or SAC")
    common.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                        help="colourize output (default: auto)")

    audit = sub.add_parser("audit", parents=[common], help="compare fabric state with the intent",
                           description="Run the MTU, BGP, EVPN RT/RD and VNI-to-VLAN compliance checks.")
    audit.add_argument("--state-dir", metavar="DIR",
                       help="directory of <hostname>.json state snapshots "
                            "(default: mock_states/ next to the intent file)")
    audit.add_argument("--format", choices=("table", "json"), default="table", help="output format")
    audit.add_argument("--concurrency", type=_positive_int, default=16, metavar="N",
                       help="devices collected in parallel (default: 16)")
    audit.add_argument("--timeout", type=float, default=30.0, metavar="SECONDS",
                       help="per-device collection timeout (default: 30)")
    audit.set_defaults(func=cmd_audit)

    inv = sub.add_parser("inventory", parents=[common], help="show the devices and VNIs defined in the intent")
    inv.set_defaults(func=cmd_inventory)
    return parser


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def main(argv: Optional[Sequence[str]] = None, out: TextIO = sys.stdout) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args, out)
    except IntentError as exc:
        print(f"fabric-auditor: error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
