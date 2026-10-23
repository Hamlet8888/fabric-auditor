"""Tests for `netauto timeline`, the merged event timeline."""

from __future__ import annotations

import io
import json
import unittest
from datetime import datetime
from pathlib import Path

from netauto import cli, timeline

ROOT = Path(__file__).resolve().parent.parent
LOGS = ROOT / "examples" / "demo" / "logs"
EXPECTED = ROOT / "examples" / "demo" / "expected-state.json"


class TestParse(unittest.TestCase):
    def test_line_formats(self):
        text = "\n".join([
            "2026 Oct 23 13:41:07 DC1-NXLF-01 %ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/49 is down",
            "2026 Oct  3 01:02:03.456 DC1-NXLF-01 %BGP-5-ADJCHANGE:  bgp- [8121] (default) neighbor 10.0.0.1 Up",
            "2026 Oct 23 13:41:08 %VPC-2-PEER_KEEP_ALIVE_RECV_FAIL: In domain 112, VPC peer keep-alive receive failed",
            "2026 Oct 23 13:41:09 DC1-NXLF-01 %MODULE-SLOT1-2-MOD_FAIL: Module 1 failed",
            "show logging logfile",
            "garbage %NOT-A-LINE",
        ])
        events = timeline.parse_log(text, "DC1-NXLF-01")
        self.assertEqual([(e.tag, e.kind) for e in events], [
            ("ETHPORT-5-IF_DOWN_LINK_FAILURE", timeline.DOWN), ("BGP-5-ADJCHANGE", timeline.UP),
            ("VPC-2-PEER_KEEP_ALIVE_RECV_FAIL", timeline.DOWN), ("MODULE-2-MOD_FAIL", timeline.DOWN)])
        self.assertEqual(events[1].time, datetime(2026, 10, 3, 1, 2, 3))
        self.assertEqual(events[1].message, "bgp- [8121] (default) neighbor 10.0.0.1 Up")

    def test_classify(self):
        cases = [("BGP", 5, "ADJCHANGE", "neighbor 1.1.1.1 Down - holdtimer expired", timeline.DOWN),
                 ("BFD", 5, "SESSION_STATE_UP", "BFD session up", timeline.UP),
                 ("ETH_PORT_CHANNEL", 5, "PORT_DOWN", "port-channel10: Ethernet1/53 is down", timeline.DOWN),
                 ("L2FM", 2, "L2FM_MAC_FLAP_DISABLE_LEARN", "MAC flap", timeline.WARN),
                 ("NVE", 5, "NVE_INTF_STATE", "nve1 Down", timeline.DOWN),
                 ("VSHD", 5, "VSHD_SYSLOG_CONFIG_I", "Configured from vty", timeline.INFO)]
        for fac, sev, mnem, msg, want in cases:
            self.assertEqual(timeline.classify(fac, sev, mnem, msg), want, mnem)

    def test_when(self):
        latest = datetime(2026, 10, 23, 14, 0, 0)
        self.assertEqual(timeline.parse_when("30m", latest), datetime(2026, 10, 23, 13, 30))
        self.assertEqual(timeline.parse_when("2026-10-23 13:41", latest), datetime(2026, 10, 23, 13, 41))
        with self.assertRaises(ValueError):
            timeline.parse_when("yesterday", latest)


class TestBuild(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.logs = timeline.load_logs(LOGS)

    def test_demo_incident(self):
        tl = timeline.build(self.logs)
        self.assertEqual(tl.devices, ["DC1-NXLF-01", "DC1-NXLF-03", "DC1-NXSP-01"])
        self.assertEqual((tl.first_failure.device, tl.first_failure.tag),
                         ("DC1-NXLF-01", "ETHPORT-5-IF_DOWN_LINK_FAILURE"))
        self.assertTrue(all(e.kind != timeline.INFO for e in tl.events))
        self.assertEqual([e.time for e in tl.events], sorted(e.time for e in tl.events))

    def test_filters(self):
        self.assertEqual(len(timeline.build(self.logs, everything=True).events),
                         sum(len(t.splitlines()) for t in self.logs.values()))
        tl = timeline.build(self.logs, devices=["DC1-NXLF-03"])
        self.assertEqual(({e.kind for e in tl.events}, tl.first_failure), ({timeline.WARN}, None))
        tl = timeline.build(self.logs, since="5m")
        self.assertEqual({e.kind for e in tl.events}, {timeline.UP})
        tl = timeline.build(self.logs, since="2026-10-23 13:00", until="2026-10-23 13:45")
        self.assertEqual({e.kind for e in tl.events}, {timeline.DOWN})


class TestTimelineCli(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        return cli.main(["timeline", "--color", "never", *argv], out=out), out.getvalue()

    def test_table_and_json(self):
        code, text = self.run_cli("--logs", str(LOGS))
        self.assertEqual(code, cli.EXIT_NONCOMPLIANT)
        self.assertIn("<- first failure", text)
        self.assertIn("followed within 60s by 5 more failure(s)", text)
        code, text = self.run_cli("--logs", str(LOGS), "--expected", str(EXPECTED), "--site", "DC2",
                                  "--format", "json")
        self.assertEqual((code, json.loads(text)["events"]), (cli.EXIT_OK, []))

    def test_usage_errors(self):
        self.assertEqual(self.run_cli()[0], cli.EXIT_USAGE)
        self.assertEqual(self.run_cli("--source", "nxapi")[0], cli.EXIT_USAGE)
        self.assertEqual(self.run_cli("--logs", str(LOGS), "--since", "soon")[0], cli.EXIT_USAGE)
        self.assertEqual(self.run_cli("--logs", "/nonexistent")[0], cli.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
