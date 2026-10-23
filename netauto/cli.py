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
    python3 -m netauto.cli path 10.110.10.10 10.120.30.11 --expected examples/demo/expected-state.json
    python3 -m netauto.cli bgp --expected examples/demo/expected-state.json --site DC1
    python3 -m netauto.cli timeline --logs examples/demo/logs --since 30m

``--expected`` is the ``expected-state.json`` that network-design writes next to the
configs. ``audit`` loads state from ``--state-dir`` (default: ``state/`` next to that
file) or, with ``--source nxapi``, from the switches themselves; runs the compliance checks at ``--step`` (default: the last migration step) and
prints a status table per site, followed by every mismatch with its expected and actual
value. ``collect`` saves live state as snapshots (and, with ``--raw``, the raw NX-API
output, and with ``--logs`` the switch logs) to audit later or offline. ``diff``, ``path``,
``bgp`` and ``timeline`` are the troubleshooting commands; see their ``--help``.

Exit status: 0 when everything audited is compliant (or, for the troubleshooting commands,
nothing is wrong), 1 when any check fails, a problem is found or a device's state could not be
collected, 2 for usage or input errors.

Colour is used when stdout is a terminal, unless ``NO_COLOR`` is set or ``--color never``
is given.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from datetime import timedelta
from pathlib import Path
from typing import Dict, List, Optional, Sequence, TextIO, Tuple

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


def _source(args: argparse.Namespace) -> Tuple[StateSource, str]:
    """Snapshots from --state-dir (default: state/ next to --expected) or live NX-API with --source nxapi."""
    if args.source == "nxapi":
        return _nxapi_source(args), "live"
    state_dir = Path(args.state_dir) if args.state_dir else Path(args.expected).resolve().parent / "state"
    if not state_dir.is_dir():
        raise DesignError(f"state directory not found: {state_dir}")
    return SnapshotSource(state_dir), str(state_dir)


def cmd_audit(args: argparse.Namespace, out: TextIO) -> int:
    design = _load(args)
    auditor = Auditor(design, args.step)
    source, where = _source(args)
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
    errors = dict(collection.errors)
    if args.logs:
        import asyncio

        from netauto.nxapi import collect_logs

        logs, log_errors = asyncio.run(collect_logs(source, design.select(args.site),  # type: ignore[arg-type]
                                                    args.concurrency, args.timeout))
        log_dir = target / "logs"
        log_dir.mkdir(exist_ok=True)
        for hostname, text in sorted(logs.items()):
            (log_dir / f"{hostname}.log").write_text(text, encoding="utf-8")
        out.write(f"wrote {len(logs)} logs to {log_dir}\n")
        for hostname, error in log_errors.items():
            errors.setdefault(hostname, f"log: {error}")
    for hostname, error in sorted(errors.items()):
        out.write(f"  {hostname}: {error}\n")
    return EXIT_OK if not errors else EXIT_NONCOMPLIANT


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


def cmd_path(args: argparse.Namespace, out: TextIO) -> int:
    from netauto import path

    design = _load(args)
    source, where = _source(args)
    collection = _collect(args, design, source)
    try:
        result = path.trace(design, collection.states, args.src, args.dst)
    except ValueError as exc:
        raise DesignError(str(exc)) from None

    if args.format == "json":
        doc = result.to_dict()
        doc["collection_errors"] = collection.errors
        json.dump(doc, out, indent=2)
        out.write("\n")
    else:
        style = Style(_use_color(args.color, out))
        w = out.write
        w(style("netauto path", "bold") + f"  {args.src} -> {args.dst}  "
          + style(f"[{collection.source} ({where})]", "dim") + "\n\n")
        for n, hop in enumerate(result.hops, 1):
            mark = style("ok", "green") if hop.ok else style("BROKEN", "red", "bold")
            w(f"{n:>2}. {hop.device:<16} {_pad(mark, 'ok' if hop.ok else 'BROKEN', 7)} {hop.action}\n")
            for line in hop.detail:
                w(style(f"{'':<28}{line}", "dim") + "\n")
        verdict = {"delivered": style("delivered", "green"), "leaves fabric": style("leaves the fabric", "green"),
                   "broken": style("broken", "red", "bold")}[result.result]
        w(f"\nResult: {verdict}" + (f" at {result.hops[-1].device}" if not result.ok else "") + "\n")
        for hostname, error in sorted(collection.errors.items()):
            w(style(f"  not collected: {hostname}: {error}", "yellow") + "\n")
    return EXIT_OK if result.ok else EXIT_NONCOMPLIANT


def cmd_bgp(args: argparse.Namespace, out: TextIO) -> int:
    from netauto import bgp

    design = _load(args)
    if args.step:
        design.check_step(args.step)
    devices = design.select(args.site)
    if args.device:
        devices = [d for d in devices if d.hostname in args.device]
        unknown = set(args.device) - {d.hostname for d in devices}
        if unknown:
            raise DesignError(f"not in the design{' at site ' + args.site if args.site else ''}: "
                              f"{', '.join(sorted(unknown))}")
    source, where = _source(args)
    # The peers' side matters too, so collect every switch the selected ones peer with.
    peers = {s.peer for d in devices for s in d.sessions}
    targets = [d for d in design.devices if d in devices or d.hostname in peers]
    collector = FabricCollector(design, source, concurrency=args.concurrency, timeout=args.timeout)
    collection = collector.collect(targets)
    findings = bgp.Doctor(design, collection.states, args.step).examine(devices)
    failed = [f for f in findings if f.status in (bgp.MISSING, bgp.DOWN)]

    if args.format == "json":
        doc = bgp.to_dict(findings)
        doc["collection_errors"] = collection.errors
        json.dump(doc, out, indent=2)
        out.write("\n")
    else:
        style = Style(_use_color(args.color, out))
        colour = {bgp.MISSING: ("red", "bold"), bgp.DOWN: ("red", "bold"), bgp.FLAPPED: ("yellow",),
                  bgp.OK: ("green",)}
        w = out.write
        w(style("netauto bgp", "bold") + f"  step {args.step or design.final_step}  "
          + style(f"[{collection.source} ({where})]", "dim") + "\n\n")
        shown = [f for f in findings if args.all or f.status != bgp.OK]
        if not shown:
            w(f"All {len(findings)} sessions the design expects up are Established.\n")
        for f in shown:
            label = f.status.upper()
            w(f"{f.device:<16} -> {f.peer:<20} {f.vrf}/{f.afi} {f.neighbor}  "
              + style(label, *colour[f.status])
              + (f" ({f.state}{', ' + f.uptime if f.uptime and f.uptime != 'never' else ''})" if f.state else "")
              + "\n")
            for c in f.causes:
                w(f"    - {c}\n")
            if f.causes:
                w("\n")
        counts = ", ".join(f"{sum(1 for f in findings if f.status == k)} {k}" for k in bgp.STATUSES)
        w(f"\nSummary: {counts}\n")
        for hostname, error in sorted(collection.errors.items()):
            w(style(f"  not collected: {hostname}: {error}", "yellow") + "\n")
    return EXIT_NONCOMPLIANT if failed else EXIT_OK


def cmd_timeline(args: argparse.Namespace, out: TextIO) -> int:
    from netauto import timeline

    devices = args.device
    if args.expected:
        design = _load(args)
        site_hosts = [d.hostname for d in design.select(args.site)]
        devices = [h for h in site_hosts if not args.device or h in args.device]
    elif args.site or args.source == "nxapi":
        raise DesignError("--site and --source nxapi need --expected to know the switches")
    errors: Dict[str, str] = {}
    if args.source == "nxapi":
        import asyncio

        from netauto.nxapi import collect_logs

        source = _nxapi_source(args)
        targets = [design.device(h) for h in devices]
        logs, errors = asyncio.run(collect_logs(source, targets, args.concurrency, args.timeout))  # type: ignore
        where = "live"
    else:
        if not args.logs:
            raise DesignError("give --logs DIR (from `netauto collect --logs`) or --source nxapi")
        try:
            logs = timeline.load_logs(args.logs)
        except ValueError as exc:
            raise DesignError(str(exc)) from None
        where = str(args.logs)
    try:
        tl = timeline.build(logs, devices, args.since, args.until, args.all)
    except ValueError as exc:
        raise DesignError(str(exc)) from None

    if args.format == "json":
        doc = tl.to_dict()
        doc["collection_errors"] = errors
        json.dump(doc, out, indent=2)
        out.write("\n")
        return EXIT_NONCOMPLIANT if tl.first_failure else EXIT_OK

    style = Style(_use_color(args.color, out))
    colour = {timeline.DOWN: ("red", "bold"), timeline.WARN: ("yellow",), timeline.UP: ("green",),
              timeline.INFO: ("dim",)}
    w = out.write
    span = f", {tl.events[0].time:%Y-%m-%d %H:%M:%S} to {tl.events[-1].time:%Y-%m-%d %H:%M:%S}" if tl.events else ""
    w(style("netauto timeline", "bold") + f"  {len(tl.events)} events from {len(tl.devices)} switches{span}  "
      + style(f"[{where}]", "dim") + "\n")
    day = None
    width = max((len(e.device) for e in tl.events), default=0)
    for e in tl.events:
        if e.time.date() != day:
            day = e.time.date()
            w(f"\n{day:%Y-%m-%d}\n")
        mark = style(f"{e.kind.upper():<4}", *colour[e.kind])
        first = style(" <- first failure", "red", "bold") if e is tl.first_failure else ""
        w(f"  {e.time:%H:%M:%S}  {e.device:<{width}}  {mark}  {e.message}" + style(f"  [{e.tag}]", "dim")
          + first + "\n")
    if not tl.events:
        w("\nNo events" + (" (use --all to see every log line)" if not args.all else "") + ".\n")
    if tl.first_failure:
        f = tl.first_failure
        after = [e for e in tl.events if f.time <= e.time <= f.time + timedelta(seconds=args.window)
                 and e is not f and e.kind in (timeline.DOWN, timeline.WARN)]
        w("\n" + style("First failure: ", "bold") + f"{f.time:%Y-%m-%d %H:%M:%S} {f.device}: {f.message}\n")
        if after:
            hosts = sorted({e.device for e in after})
            w(f"  followed within {args.window}s by {len(after)} more failure(s) on {', '.join(hosts)}: "
              "most likely consequences of it\n")
    for hostname, error in sorted(errors.items()):
        w(style(f"  not collected: {hostname}: {error}", "yellow") + "\n")
    return EXIT_NONCOMPLIANT if tl.first_failure else EXIT_OK


def cmd_inventory(args: argparse.Namespace, out: TextIO) -> int:
    design = _load(args)
    render_inventory(design, args.site, Style(_use_color(args.color, out)), out)
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netauto",
        description="Check and troubleshoot a BGP EVPN/VXLAN fabric against the expected state from network-design.",
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

    snapshots = argparse.ArgumentParser(add_help=False)
    snapshots.add_argument("--state-dir", metavar="DIR",
                           help="directory of <hostname>.json state snapshots (default: state/ next to the "
                                "expected-state file)")
    snapshots.add_argument("--source", choices=("snapshots", "nxapi"), default="snapshots",
                           help="where state comes from (default: snapshots)")

    audit = sub.add_parser("audit", parents=[common, live, snapshots], help="compare fabric state with the design",
                           description="Run the links, BGP/BFD, EVPN RT/RD, VNI-to-VLAN, NVE/Multi-Site "
                                       "and vPC compliance checks.")
    audit.add_argument("--step", metavar="ID", help="migration step the fabric has reached (default: the last)")
    audit.add_argument("--format", choices=("table", "json"), default="table", help="output format")
    audit.set_defaults(func=cmd_audit)

    collect = sub.add_parser("collect", parents=[common, live], help="save live NX-API state as snapshots",
                             description="Collect every switch over NX-API and write <hostname>.json snapshots.")
    collect.add_argument("--out", required=True, metavar="DIR", help="folder for the snapshots")
    collect.add_argument("--raw", action="store_true", help="also save the raw NX-API output under DIR/raw/")
    collect.add_argument("--logs", action="store_true",
                         help="also save each switch's `show logging logfile` under DIR/logs/ (for `netauto timeline`)")
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

    pth = sub.add_parser("path", parents=[common, live, snapshots], help="explain how (or why not) A reaches B",
                         description="Follow a packet from host SRC to DST through the fabric, switch by switch, "
                                     "using each switch's host and route tables, and show where the path breaks.")
    pth.add_argument("src", metavar="SRC", help="source host IP, e.g. 10.110.10.10")
    pth.add_argument("dst", metavar="DST", help="destination IP: a host, or anything outside the fabric")
    pth.add_argument("--format", choices=("table", "json"), default="table", help="output format")
    pth.set_defaults(func=cmd_path)

    bg = sub.add_parser("bgp", parents=[common, live, snapshots], help="find down BGP sessions and why",
                        description="Check every BGP session the design expects up at --step from both ends, and "
                                    "for each one that is down, list the likely causes: config, AS numbers, links, "
                                    "MTU, BFD, underlay reachability, the DCI.")
    bg.add_argument("--step", metavar="ID", help="migration step the fabric has reached (default: the last)")
    bg.add_argument("--device", action="append", metavar="HOSTNAME", help="only this switch (repeatable)")
    bg.add_argument("--all", action="store_true", help="also list the sessions that are fine")
    bg.add_argument("--format", choices=("table", "json"), default="table", help="output format")
    bg.set_defaults(func=cmd_bgp)

    tln = sub.add_parser("timeline", parents=[live], help="merge the switches' logs into one event timeline",
                         description="Merge link, BGP, BFD, vPC, NVE and MAC-move events from every switch's log "
                                     "into one timeline and point at the first failure.")
    tln.add_argument("--logs", metavar="DIR", help="folder of <hostname>.log files (from `netauto collect --logs`)")
    tln.add_argument("--expected", metavar="FILE", help="expected-state.json (needed for --source nxapi and --site)")
    tln.add_argument("--source", choices=("logs", "nxapi"), default="logs",
                     help="read --logs, or fetch `show logging logfile` live (default: logs)")
    tln.add_argument("--site", metavar="CODE", help="limit to one site (needs --expected)")
    tln.add_argument("--device", action="append", metavar="HOSTNAME", help="only this switch (repeatable)")
    tln.add_argument("--since", metavar="WHEN", help="from this time: '2026-10-23 14:00', or 30m / 2h / 1d before "
                                                     "the newest log line")
    tln.add_argument("--until", metavar="WHEN", help="up to this time (same forms as --since)")
    tln.add_argument("--window", type=_positive_int, default=60, metavar="SECONDS",
                     help="failures this soon after the first one count as its consequences (default: 60)")
    tln.add_argument("--all", action="store_true", help="keep every log line, not only the events that matter")
    tln.add_argument("--format", choices=("table", "json"), default="table", help="output format")
    tln.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                     help="colourize output (default: auto)")
    tln.set_defaults(func=cmd_timeline)

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
