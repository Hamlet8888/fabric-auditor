"""
network-automation-tools command-line interface.

    python3 -m netauto.cli audit --expected examples/demo/expected-state.json
    python3 -m netauto.cli audit --expected examples/demo/expected-state.json --site DC1 --step M4
    python3 -m netauto.cli audit --expected examples/demo/expected-state.json --format json
    python3 -m netauto.cli inventory --expected examples/demo/expected-state.json

    # live, over NX-API (credentials from NETAUTO_USERNAME / NETAUTO_PASSWORD or a prompt)
    python3 -m netauto.cli audit --expected private/expected-state.json --source nxapi
    python3 -m netauto.cli collect --expected private/expected-state.json --out private/state --raw

    # troubleshooting
    python3 -m netauto.cli diff private/state/before private/state/after

``--expected`` is the ``expected-state.json`` that network-design writes next to the
configs. ``audit`` loads state from ``--state-dir`` (default: ``state/`` next to that
file) or, with ``--source nxapi``, from the switches themselves; runs the compliance checks at ``--step`` (default: the last migration step) and
prints a status table per site, followed by every mismatch with its expected and actual
value. ``collect`` saves live state as snapshots (and, with ``--raw``, the raw NX-API
output) to audit later or offline.

Exit status: 0 when everything audited is compliant, 1 when any check fails or a device's
state could not be collected, 2 for usage or input errors.

Colour is used when stdout is a terminal, unless ``NO_COLOR`` is set or ``--color never``
is given.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import List, Optional, Sequence, TextIO, Tuple

from netauto import __version__
from netauto.auditor import (CHECK_COLLECTION, CHECK_TITLES, CHECKS, ERROR, FAIL, PASS, SKIP,
                             AuditReport, Auditor, CheckResult)
from netauto.collector import CollectionResult, FabricCollector, SnapshotSource, StateSource
from netauto.expected import Design, DesignError, load_design

EXIT_OK = 0
EXIT_NONCOMPLIANT = 1
EXIT_USAGE = 2

_COLUMNS = {
    "links": "LINKS",
    "bgp": "BGP/BFD",
    "evpn-rt-rd": "EVPN RT/RD",
    "vni-vlan": "VNI-VLAN",
    "nve": "NVE/MS",
    "vpc": "VPC",
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


def _rows(design: Design, site: str) -> List[Tuple[str, str, bool]]:
    """(target, role, is_pair) in table order: each vPC pair row follows its second member."""
    rows = []
    pairs = {b.hostname: f"{a.hostname} / {b.hostname}" for a, b in design.vpc_pairs(site)}
    for d in design.select(site):
        rows.append((d.hostname, d.role, False))
        if d.hostname in pairs:
            rows.append((pairs[d.hostname], "pair", True))
    return rows


def render_table(design: Design, report: AuditReport, site: Optional[str], style: Style,
                 out: TextIO, source_desc: str) -> None:
    w = out.write
    step_title = dict(design.steps).get(report.step, "")
    w(style(f"network-automation-tools {__version__}", "bold") + f"  step {report.step}"
      + (f" ({step_title})" if step_title else "") + "\n")
    w(style(f"expected: {design.source}   state: {source_desc}", "dim") + "\n")

    headers = ["DEVICE", "ROLE"] + [_COLUMNS[c] for c in CHECKS]
    longest = max((len(d.hostname) for d in design.devices), default=10)
    widths = [2 * longest + 7, 13] + \
             [max(len(_COLUMNS[c]), 10) + 2 for c in CHECKS]

    sites = [s.code for s in design.sites if site in (None, s.code)]
    for code in sites:
        ok = report.site_compliant(code)
        verdict = style("COMPLIANT", "green", "bold") if ok else style("NON-COMPLIANT", "red", "bold")
        w("\n" + style(code, "bold", "cyan") + f"  {verdict}\n")
        w("  " + "".join(style(h.ljust(widths[i]), "dim") for i, h in enumerate(headers)).rstrip() + "\n")
        for target, role, is_pair in _rows(design, code):
            results = {r.check: r for r in report.select(target=target, site=code) if r.is_pair == is_pair}
            collect = results.get(CHECK_COLLECTION)
            name = f"  {target}" if is_pair else target
            line = _pad(style(name, "dim") if is_pair else name, name, widths[0])
            line += role.ljust(widths[1])
            for i, check in enumerate(CHECKS, start=2):
                r = results.get(check)
                plain = _cell(r)
                line += _pad(style.status(r.status, plain) if r else plain, plain, widths[i])
            if collect is not None and not collect.passed:
                line += style("state unavailable", "yellow")
            w("  " + line.rstrip() + "\n")

    failures = report.failures
    mismatch_rows = [(r, m) for r in failures for m in r.mismatches]
    errored = [r for r in failures if not r.mismatches]
    if mismatch_rows:
        w("\n" + style(f"Mismatches ({len(mismatch_rows)})", "bold") + "\n")
        for r, m in mismatch_rows:
            title = CHECK_TITLES.get(r.check, r.check)
            w(f"  {style.status(r.status, r.status.ljust(5))} {r.target}  {style(title, 'bold')}  {m.item}\n")
            w(f"        expected: {_fmt(m.expected)}\n")
            w(f"        actual:   {style(_fmt(m.actual), 'red')}" + (style(f"   ({m.detail})", "dim") if m.detail else "")
              + "\n")
    if errored:
        not_run = sorted({r.target for r in errored})
        w("\n" + style(f"Checks not run (no state): {', '.join(not_run)}", "yellow") + "\n")

    w("\n" + style("Summary", "bold") + "\n")
    for code in sites:
        failed = sum(1 for r in report.select(site=code) if not r.passed)
        label = style("COMPLIANT", "green") if failed == 0 else style(f"NON-COMPLIANT ({failed} failed checks)", "red")
        w(f"  {code:<6} {label}\n")
    overall = style("COMPLIANT", "green", "bold") if report.compliant else style("NON-COMPLIANT", "red", "bold")
    w(f"  Overall: {overall}\n")


def _fmt(value) -> str:
    if value is None:
        return "(none)"
    if isinstance(value, list):
        return ", ".join(map(str, value)) if value else "(none)"
    return str(value)


def render_inventory(design: Design, site: Optional[str], style: Style, out: TextIO) -> None:
    w = out.write
    w(style(f"{design.source}", "bold") + f"  generator {design.generator or '?'}  DCI {design.dci_mode or '?'}\n")
    w("steps: " + ", ".join(f"{s} {t}".strip() for s, t in design.steps) + "\n")
    for s in design.sites:
        if site and s.code != site:
            continue
        w("\n" + style(s.code, "bold", "cyan") + f"  Multi-Site site ID {s.multisite_site_id}, VIP {s.multisite_vip}\n")
        for d in design.select(s.code):
            l2 = sum(1 for v in d.vnis if v.type == "L2")
            l3 = sum(1 for v in d.vnis if v.type == "L3")
            vnis = f"  {l2} L2VNIs, {l3} L3VNIs" if d.vnis else ""
            w(f"  {d.hostname:<16} {d.role:<12} {d.router_id:<15} AS {d.asn:<6} "
              f"{len(d.sessions)} BGP sessions{vnis}\n")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _load(args: argparse.Namespace) -> Design:
    design = load_design(args.expected)
    if args.site and args.site not in {s.code for s in design.sites}:
        known = ", ".join(s.code for s in design.sites)
        raise DesignError(f"unknown site {args.site!r} (the design defines: {known})")
    return design


def _nxapi_source(args: argparse.Namespace, keep_raw: bool = False) -> StateSource:
    from netauto.nxapi import NxapiSource

    username = os.environ.get("NETAUTO_USERNAME")
    password = os.environ.get("NETAUTO_PASSWORD")
    if not username or not password:
        if not sys.stdin.isatty():
            raise DesignError("set NETAUTO_USERNAME and NETAUTO_PASSWORD (no terminal to prompt on)")
        username = username or input("NX-API username: ")
        password = password or getpass.getpass("NX-API password: ")
    hosts = {}
    if args.hosts:
        try:
            hosts = json.loads(Path(args.hosts).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise DesignError(f"cannot read --hosts {args.hosts}: {exc}") from None
        if not isinstance(hosts, dict):
            raise DesignError("--hosts must be a JSON object of hostname -> address")
    return NxapiSource(username, password, hosts=hosts, keep_raw=keep_raw, scheme=args.scheme, port=args.port,
                       verify=not args.insecure, ca_file=args.ca_file, timeout=args.timeout)


def _collect(args: argparse.Namespace, design: Design, source: StateSource) -> CollectionResult:
    collector = FabricCollector(design, source, concurrency=args.concurrency, timeout=args.timeout)
    return collector.collect(design.select(args.site))


def cmd_audit(args: argparse.Namespace, out: TextIO) -> int:
    design = _load(args)
    auditor = Auditor(design, args.step)
    if args.source == "nxapi":
        source = _nxapi_source(args)
        where = "live"
    else:
        state_dir = Path(args.state_dir) if args.state_dir else Path(args.expected).resolve().parent / "state"
        if not state_dir.is_dir():
            raise DesignError(f"state directory not found: {state_dir}")
        source, where = SnapshotSource(state_dir), str(state_dir)

    collection = _collect(args, design, source)
    report = auditor.audit(collection, site=args.site)

    if args.format == "json":
        doc = report.to_dict()
        doc["collection_errors"] = collection.errors
        json.dump(doc, out, indent=2, default=str)
        out.write("\n")
    else:
        style = Style(_use_color(args.color, out))
        render_table(design, report, args.site, style, out, f"{collection.source} ({where})")
    return EXIT_OK if report.compliant else EXIT_NONCOMPLIANT


def cmd_collect(args: argparse.Namespace, out: TextIO) -> int:
    design = _load(args)
    source = _nxapi_source(args, keep_raw=args.raw)
    collection = _collect(args, design, source)
    target = Path(args.out)
    target.mkdir(parents=True, exist_ok=True)
    for hostname, state in sorted(collection.states.items()):
        (target / f"{hostname}.json").write_text(json.dumps(state, indent=1) + "\n", encoding="utf-8")
    if args.raw:
        raw_dir = target / "raw"
        raw_dir.mkdir(exist_ok=True)
        for hostname, raw in sorted(source.raw.items()):  # type: ignore[attr-defined]
            (raw_dir / f"{hostname}.json").write_text(json.dumps(raw, indent=1) + "\n", encoding="utf-8")
    out.write(f"wrote {len(collection.states)} snapshots to {target}\n")
    for hostname, error in sorted(collection.errors.items()):
        out.write(f"  {hostname}: {error}\n")
    return EXIT_OK if collection.ok else EXIT_NONCOMPLIANT


def cmd_diff(args: argparse.Namespace, out: TextIO) -> int:
    from netauto import diff

    try:
        before, after = diff.load_states(args.before), diff.load_states(args.after)
    except ValueError as exc:
        raise DesignError(str(exc)) from None
    devices = None
    if args.expected:
        design = _load(args)
        devices = [d.hostname for d in design.select(args.site)]
    elif args.site:
        raise DesignError("--site needs --expected to know which switches belong to the site")
    diffs = diff.diff_fabric(before, after, devices)

    if args.format == "json":
        json.dump(diff.to_dict(diffs), out, indent=2, default=str)
        out.write("\n")
    else:
        style = Style(_use_color(args.color, out))
        colour = {diff.LOST: ("red", "bold"), diff.CHANGED: ("yellow",), diff.GAINED: ("green",)}
        w = out.write
        w(style("netauto diff", "bold") + f"  {args.before}  ->  {args.after}\n")
        if not diffs:
            w("\nNo differences.\n")
        for kind in diff.KINDS:
            rows = [d for d in diffs if d.kind == kind]
            if not rows:
                continue
            w("\n" + style(f"{kind} ({len(rows)})", *colour[kind]) + "\n")
            for d in rows:
                w(f"  {d.device:<16} {d.fact}\n")
                w(style(f"      {_fmt(d.before)}  ->  {_fmt(d.after)}", "dim") + "\n")
        counts = ", ".join(f"{sum(1 for d in diffs if d.kind == k)} {k.lower()}" for k in diff.KINDS)
        w(f"\nSummary: {counts}\n")
    kinds = {d.kind for d in diffs}
    failing = {"lost": {diff.LOST}, "changed": {diff.LOST, diff.CHANGED}, "any": set(diff.KINDS)}[args.fail_on]
    return EXIT_NONCOMPLIANT if kinds & failing else EXIT_OK


def cmd_inventory(args: argparse.Namespace, out: TextIO) -> int:
    design = _load(args)
    render_inventory(design, args.site, Style(_use_color(args.color, out)), out)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netauto",
        description="Check a BGP EVPN/VXLAN fabric against the expected state from network-design.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--expected", required=True, metavar="FILE", help="expected-state.json from network-design")
    common.add_argument("--site", metavar="CODE", help="limit to one site, e.g. DC1")
    common.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                        help="colourize output (default: auto)")

    live = argparse.ArgumentParser(add_help=False)
    live.add_argument("--hosts", metavar="FILE",
                      help="JSON of hostname -> address to connect to (default: mgmt0 from the expected state)")
    live.add_argument("--insecure", action="store_true", help="don't verify the switches' TLS certificates")
    live.add_argument("--ca-file", metavar="FILE", help="CA bundle that signed the switches' certificates")
    live.add_argument("--port", type=_positive_int, metavar="N", help="NX-API port (default: 443 for https)")
    live.add_argument("--scheme", choices=("https", "http"), default="https", help=argparse.SUPPRESS)
    live.add_argument("--concurrency", type=_positive_int, default=16, metavar="N",
                      help="devices collected in parallel (default: 16)")
    live.add_argument("--timeout", type=float, default=30.0, metavar="SECONDS",
                      help="per-device collection timeout (default: 30)")

    audit = sub.add_parser("audit", parents=[common, live], help="compare fabric state with the design",
                           description="Run the links, BGP/BFD, EVPN RT/RD, VNI-to-VLAN, NVE/Multi-Site "
                                       "and vPC compliance checks.")
    audit.add_argument("--state-dir", metavar="DIR",
                       help="directory of <hostname>.json state snapshots (default: state/ next to the "
                            "expected-state file)")
    audit.add_argument("--source", choices=("snapshots", "nxapi"), default="snapshots",
                       help="where state comes from (default: snapshots)")
    audit.add_argument("--step", metavar="ID", help="migration step the fabric has reached (default: the last)")
    audit.add_argument("--format", choices=("table", "json"), default="table", help="output format")
    audit.set_defaults(func=cmd_audit)

    collect = sub.add_parser("collect", parents=[common, live], help="save live NX-API state as snapshots",
                             description="Collect every switch over NX-API and write <hostname>.json snapshots.")
    collect.add_argument("--out", required=True, metavar="DIR", help="folder for the snapshots")
    collect.add_argument("--raw", action="store_true", help="also save the raw NX-API output under DIR/raw/")
    collect.set_defaults(func=cmd_collect)

    dif = sub.add_parser("diff", help="compare two state snapshots (before/after a change)",
                         description="Compare two folders of state snapshots, e.g. from `netauto collect` before "
                                     "and after a change, and list what was lost, changed or gained.")
    dif.add_argument("before", metavar="BEFORE", help="folder of <hostname>.json snapshots before the change")
    dif.add_argument("after", metavar="AFTER", help="folder of <hostname>.json snapshots after the change")
    dif.add_argument("--expected", metavar="FILE", help="expected-state.json, to order switches and use --site")
    dif.add_argument("--site", metavar="CODE", help="limit to one site (needs --expected)")
    dif.add_argument("--format", choices=("table", "json"), default="table", help="output format")
    dif.add_argument("--fail-on", choices=("lost", "changed", "any"), default="lost",
                     help="exit 1 when there is anything of this kind or worse (default: lost)")
    dif.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                     help="colourize output (default: auto)")
    dif.set_defaults(func=cmd_diff)

    inv = sub.add_parser("inventory", parents=[common], help="show the devices and steps the design defines")
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
    except DesignError as exc:
        print(f"netauto: error: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
