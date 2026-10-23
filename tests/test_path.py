"""Tests for `netauto path`, the host-to-host path explainer."""

from __future__ import annotations

import copy
import io
import json
import unittest
from pathlib import Path

from netauto import cli, diff, path
from netauto.expected import load_design

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = ROOT / "examples" / "demo" / "expected-state.json"
STATE_DIR = ROOT / "examples" / "demo" / "state"


class TestTrace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.design = load_design(EXPECTED)
        cls.baseline = diff.load_states(STATE_DIR)

    def setUp(self):
        self.states = copy.deepcopy(self.baseline)

    def trace(self, src, dst):
        return path.trace(self.design, self.states, src, dst)

    def devices(self, t):
        return [h.device for h in t.hops]

    def test_same_pair(self):
        t = self.trace("10.110.10.10", "10.110.20.10")
        self.assertEqual(t.result, "delivered")
        self.assertEqual(self.devices(t), ["DC1-NXLF-01", "DC1-NXLF-01"])
        self.assertEqual(t.vrf, "TRUST")

    def test_other_pair_same_site(self):
        t = self.trace("10.110.10.10", "10.110.20.11")
        self.assertEqual(t.result, "delivered")
        self.assertEqual(self.devices(t), ["DC1-NXLF-01", "DC1-NXLF-01", "DC1-NXLF-03"])
        self.assertIn("10.110.241.102", t.hops[1].action)  # the pair's anycast VTEP

    def test_other_site_crosses_the_bgws(self):
        t = self.trace("10.110.10.10", "10.120.30.11")
        self.assertEqual(t.result, "delivered")
        self.assertEqual(self.devices(t), ["DC1-NXLF-01", "DC1-NXLF-01", "DC1-NXBGW-01", "DC2-NXBGW-01",
                                           "DC2-NXLF-03"])
        self.assertIn("Multi-Site VIP of DC2", t.hops[2].action)

    def test_outside_leaves_through_the_firewall(self):
        t = self.trace("10.120.10.11", "8.8.8.8")
        self.assertEqual(t.result, "leaves fabric")
        self.assertTrue(t.ok)
        self.assertIn("leaves the fabric", t.hops[-1].action)

    def test_unknown_source_and_silent_destination(self):
        t = self.trace("10.110.10.99", "10.110.10.10")
        self.assertEqual((t.result, len(t.hops)), ("broken", 1))
        self.assertIn("VLAN 10", t.hops[0].detail[0])
        t = self.trace("10.110.10.10", "10.110.10.99")
        self.assertEqual(t.result, "broken")
        self.assertIn("not learned anywhere", t.hops[-1].action)

    def test_dci_down_breaks_at_the_bgw(self):
        for h in ("DC1-NXBGW-01", "DC1-NXBGW-02"):
            ms = self.states[h]["multisite"]
            ms["dci_links"] = {p: "Down" for p in ms["dci_links"]}
        t = self.trace("10.110.10.10", "10.120.30.11")
        self.assertEqual((t.result, t.hops[-1].device), ("broken", "DC1-NXBGW-01"))
        self.assertIn("DCI is down", t.hops[-1].action)

    def test_missing_underlay_route(self):
        routes = self.states["DC1-NXLF-01"]["routes"]
        self.states["DC1-NXLF-01"]["routes"] = [r for r in routes if r["prefix"] != "10.110.241.102/32"]
        t = self.trace("10.110.10.10", "10.110.20.11")
        self.assertEqual(t.result, "broken")
        self.assertIn("underlay has no route", t.hops[-1].action)

    def test_firewall_session_down(self):
        for h in ("DC1-NXLF-03", "DC1-NXLF-04"):
            for s in self.states[h]["bgp"]["sessions"]:
                if s["vrf"] == "TRUST":
                    s["state"] = "Active"
        t = self.trace("10.110.10.10", "8.8.8.8")
        self.assertEqual(t.result, "broken")
        self.assertIn("Active", t.hops[-1].detail[-1])

    def test_no_route_and_missing_switch(self):
        self.states["DC1-NXLF-01"]["routes"] = []
        t = self.trace("10.110.10.10", "8.8.8.8")
        self.assertIn("no route", t.hops[-1].action)
        self.states = copy.deepcopy(self.baseline)
        del self.states["DC1-NXLF-03"]
        t = self.trace("10.110.10.10", "10.110.20.11")
        self.assertEqual((t.result, t.hops[-1].device), ("broken", "DC1-NXLF-03"))

    def test_bad_address(self):
        with self.assertRaises(ValueError):
            self.trace("10.110.10.10", "not-an-ip")


class TestPathCli(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        code = cli.main(["path", *argv, "--expected", str(EXPECTED), "--color", "never"], out=out)
        return code, out.getvalue()

    def test_table_and_json(self):
        code, text = self.run_cli("10.110.10.10", "10.120.30.11")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("Result: delivered", text)
        code, text = self.run_cli("10.110.10.10", "10.110.10.99", "--format", "json")
        self.assertEqual(code, cli.EXIT_NONCOMPLIANT)
        self.assertEqual(json.loads(text)["result"], "broken")

    def test_bad_address_is_usage_error(self):
        self.assertEqual(self.run_cli("10.110.10.10", "nope")[0], cli.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
