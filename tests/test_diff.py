"""Tests for `netauto diff`, the before/after change guard."""

from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from netauto import cli, diff, mock
from netauto.expected import load_design

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = ROOT / "examples" / "demo" / "expected-state.json"
STATE_DIR = ROOT / "examples" / "demo" / "state"


class TestDiff(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.design = load_design(EXPECTED)
        cls.before = diff.load_states(STATE_DIR)

    def setUp(self):
        self.after = copy.deepcopy(self.before)

    def kinds(self, diffs):
        return {(d.device, d.kind, d.fact) for d in diffs}

    def test_identical_states_have_no_differences(self):
        self.assertEqual(diff.diff_fabric(self.before, self.after), [])

    def test_session_down_is_lost(self):
        s = self.after["DC1-NXLF-01"]["bgp"]["sessions"][0]
        s["state"] = "Idle"
        d = diff.diff_fabric(self.before, self.after)
        self.assertEqual(len(d), 1)
        self.assertEqual((d[0].kind, d[0].before, d[0].after), (diff.LOST, "Established", "Idle"))

    def test_removed_session_and_link_are_lost_once(self):
        self.after["DC1-NXLF-01"]["bgp"]["sessions"].pop(0)
        del self.after["DC1-NXSP-01"]["interfaces"]["Ethernet1/1"]
        d = diff.diff_fabric(self.before, self.after)
        self.assertEqual([x.kind for x in d], [diff.LOST, diff.LOST])
        self.assertEqual({x.fact.split()[-1] for x in d}, {"state", "status"})

    def test_vni_rt_change_is_changed(self):
        self.after["DC1-NXLF-01"]["evpn"]["vnis"][1]["rt_import"] = ["65000:1"]
        d = diff.diff_fabric(self.before, self.after)
        self.assertEqual([(x.kind, x.fact.endswith("RT import")) for x in d], [(diff.CHANGED, True)])

    def test_new_session_and_recovery_are_gained(self):
        self.after["DC1-NXLF-01"]["bgp"]["sessions"].append(
            {"vrf": "default", "afi": "ipv4", "neighbor": "10.0.0.9", "remote_as": 65000, "state": "Established"})
        d = diff.diff_fabric(self.before, self.after)
        self.assertEqual({x.kind for x in d}, {diff.GAINED})

    def test_missing_switch_is_lost(self):
        del self.after["DC2-NXBGW-02"]
        d = diff.diff_fabric(self.before, self.after)
        self.assertEqual([(x.device, x.kind, x.fact) for x in d], [("DC2-NXBGW-02", diff.LOST, "state")])

    def test_migration_step_shows_what_comes_up(self):
        """M4 -> M5 brings the DCI and cloud up: everything is gained, nothing lost."""
        m4 = {d.hostname: mock.device_state(self.design, d, "M4") for d in self.design.devices}
        m5 = {d.hostname: mock.device_state(self.design, d, "M5") for d in self.design.devices}
        d = diff.diff_fabric(m4, m5)
        self.assertTrue(d)
        self.assertEqual({x.kind for x in d}, {diff.GAINED})
        self.assertEqual({x.device for x in d}, {h.hostname for h in self.design.devices if h.role == "bgw"})

    def test_routes_and_hosts_are_compared_when_present(self):
        self.before["DC1-NXLF-01"]["routes"] = [{"vrf": "TRUST", "prefix": "0.0.0.0/0", "next_hops": ["10.1.1.1"]}]
        self.before["DC1-NXLF-01"]["hosts"] = [{"vrf": "TRUST", "ip": "10.110.10.5", "mac": "aaaa.bbbb.cccc",
                                                "interface": "Ethernet1/1"}]
        self.after = copy.deepcopy(self.before)
        self.after["DC1-NXLF-01"]["routes"] = []
        self.after["DC1-NXLF-01"]["hosts"][0]["interface"] = "Ethernet1/2"
        d = {x.fact: x.kind for x in diff.diff_fabric(self.before, self.after)}
        self.assertEqual(d, {"route TRUST 0.0.0.0/0": diff.LOST, "host TRUST 10.110.10.5": diff.CHANGED})
        del self.before["DC1-NXLF-01"]["routes"], self.before["DC1-NXLF-01"]["hosts"]


class TestDiffCli(unittest.TestCase):
    def run_cli(self, before, after, *argv):
        out = io.StringIO()
        return cli.main(["diff", str(before), str(after), "--color", "never", *argv], out=out), out.getvalue()

    def test_no_change(self):
        code, text = self.run_cli(STATE_DIR, STATE_DIR)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("No differences.", text)

    def test_lost_fails_and_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            for f in STATE_DIR.glob("*.json"):
                doc = json.loads(f.read_text())
                if doc["hostname"] == "DC1-NXLF-02":
                    doc["vpc"]["keepalive_status"] = "peer-not-alive"
                Path(tmp, f.name).write_text(json.dumps(doc))
            code, text = self.run_cli(STATE_DIR, tmp, "--format", "json")
            self.assertEqual(code, cli.EXIT_NONCOMPLIANT)
            doc = json.loads(text)
            self.assertEqual(doc["summary"], {"LOST": 1, "CHANGED": 0, "GAINED": 0})
            self.assertEqual(doc["differences"][0]["fact"], "vpc keepalive_status")
            code, text = self.run_cli(STATE_DIR, tmp, "--expected", str(EXPECTED), "--site", "DC2")
            self.assertEqual(code, cli.EXIT_OK)

    def test_fail_on_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            for f in STATE_DIR.glob("*.json"):
                doc = json.loads(f.read_text())
                if doc["hostname"] == "DC1-NXSP-01":
                    doc["interfaces"]["Ethernet1/1"]["mtu"] = 1500
                Path(tmp, f.name).write_text(json.dumps(doc))
            self.assertEqual(self.run_cli(STATE_DIR, tmp)[0], cli.EXIT_OK)
            self.assertEqual(self.run_cli(STATE_DIR, tmp, "--fail-on", "changed")[0], cli.EXIT_NONCOMPLIANT)

    def test_site_needs_expected_and_bad_folder(self):
        self.assertEqual(self.run_cli(STATE_DIR, STATE_DIR, "--site", "DC1")[0], cli.EXIT_USAGE)
        self.assertEqual(self.run_cli(STATE_DIR, "/nonexistent")[0], cli.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
