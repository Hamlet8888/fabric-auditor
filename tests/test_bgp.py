"""Tests for `netauto bgp`, the BGP session doctor."""

from __future__ import annotations

import copy
import io
import ipaddress
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from netauto import bgp, cli, diff
from netauto.expected import load_design

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = ROOT / "examples" / "demo" / "expected-state.json"
STATE_DIR = ROOT / "examples" / "demo" / "state"


def session(state, neighbor, afi="ipv4", vrf="default"):
    return next(s for s in state["bgp"]["sessions"] if (s["neighbor"], s["afi"], s["vrf"]) == (neighbor, afi, vrf))


class TestDoctor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.design = load_design(EXPECTED)
        cls.baseline = diff.load_states(STATE_DIR)

    def setUp(self):
        self.states = copy.deepcopy(self.baseline)
        self.leaf = self.design.device("DC1-NXLF-01")
        # The leaf's first spine uplink and the sessions over it.
        self.link = next(i for i in self.leaf.interfaces if i.peer == "DC1-NXSP-01")
        self.spine_ip = next(s.neighbor for s in self.leaf.sessions if s.peer == "DC1-NXSP-01" and s.afi == "ipv4")

    def problems(self, device="DC1-NXLF-01", step=None):
        found = bgp.Doctor(self.design, self.states, step).examine([self.design.device(device)])
        return [f for f in found if f.status != bgp.OK]

    def test_healthy_fabric(self):
        found = bgp.Doctor(self.design, self.states).examine(self.design.devices)
        self.assertTrue(found)
        self.assertEqual({f.status for f in found}, {bgp.OK})

    def test_link_down_at_the_far_end(self):
        session(self.states["DC1-NXLF-01"], self.spine_ip)["state"] = "Idle"
        spine_if = next(i.name for i in self.design.device("DC1-NXSP-01").interfaces if i.peer == "DC1-NXLF-01")
        self.states["DC1-NXSP-01"]["interfaces"][spine_if]["oper_status"] = "down"
        (f,) = self.problems()
        self.assertEqual((f.status, f.state, f.neighbor), (bgp.DOWN, "Idle", self.spine_ip))
        self.assertIn(f"{spine_if} is down on DC1-NXSP-01", f.causes)

    def test_mtu_mismatch(self):
        session(self.states["DC1-NXLF-01"], self.spine_ip)["state"] = "Active"
        self.states["DC1-NXLF-01"]["interfaces"][self.link.name]["mtu"] = 1500
        (f,) = self.problems()
        self.assertTrue(any(c.startswith("MTU mismatch: 1500 on DC1-NXLF-01") for c in f.causes))

    def test_missing_and_wrong_as(self):
        sessions = self.states["DC1-NXLF-01"]["bgp"]["sessions"]
        sessions.remove(session(self.states["DC1-NXLF-01"], self.spine_ip))
        (f,) = self.problems()
        self.assertEqual(f.status, bgp.MISSING)
        self.assertIn("not configured on DC1-NXLF-01", f.causes[0])
        self.states = copy.deepcopy(self.baseline)
        s = session(self.states["DC1-NXLF-01"], self.spine_ip)
        s.update(state="Idle", remote_as=65999)
        (f,) = self.problems()
        self.assertIn("remote-as is 65999", f.causes[0])

    def test_peer_side_missing(self):
        session(self.states["DC1-NXLF-01"], self.spine_ip)["state"] = "Active"
        mine = str(ipaddress.ip_interface(self.link.address).ip)
        self.states["DC1-NXSP-01"]["bgp"]["sessions"].remove(session(self.states["DC1-NXSP-01"], mine))
        (f,) = self.problems()
        self.assertIn(f"DC1-NXSP-01 has no ipv4 session back to {mine}", f.causes)

    def test_bfd_down_on_an_up_link(self):
        session(self.states["DC1-NXLF-01"], self.spine_ip)["state"] = "Idle"
        for b in self.states["DC1-NXLF-01"]["bfd"]:
            if b["neighbor"] == self.spine_ip:
                b["state"] = "Down"
        (f,) = self.problems()
        self.assertTrue(any(c.startswith("BFD") for c in f.causes))

    def test_overlay_without_underlay(self):
        spine_lo = self.design.device("DC1-NXSP-01").router_id
        session(self.states["DC1-NXLF-01"], spine_lo, "evpn")["state"] = "Active"
        self.states["DC1-NXLF-01"]["routes"] = [r for r in self.states["DC1-NXLF-01"]["routes"]
                                                if r["prefix"] != f"{spine_lo}/32"]
        (f,) = self.problems()
        self.assertEqual(f.afi, "evpn")
        self.assertIn(f"no underlay route to {spine_lo} on DC1-NXLF-01", f.causes)

    def test_dci_down_explains_the_multisite_overlay(self):
        bgw = self.states["DC1-NXBGW-01"]
        bgw["multisite"]["dci_links"] = {p: "Down" for p in bgw["multisite"]["dci_links"]}
        remote = [d.router_id for d in self.design.devices if d.site == "DC2" and d.multisite]
        for s in bgw["bgp"]["sessions"]:
            if s["afi"] == "evpn" and s["neighbor"] in remote:
                s["state"] = "Idle"
        found = self.problems("DC1-NXBGW-01")
        self.assertEqual(len(found), 2)
        self.assertTrue(all(any("DCI links are down" in c for c in f.causes) for f in found))

    def test_recent_reset_and_unexplained(self):
        session(self.states["DC1-NXLF-01"], self.spine_ip)["uptime"] = "00:04:10"
        (f,) = self.problems()
        self.assertEqual(f.status, bgp.FLAPPED)
        self.states = copy.deepcopy(self.baseline)
        session(self.states["DC1-NXLF-01"], self.spine_ip)["state"] = "Idle"
        (f,) = self.problems()
        self.assertIn("nothing in the collected state explains it", f.causes[0])

    def test_sessions_of_later_steps_are_not_expected(self):
        self.assertEqual(self.problems("DC1-NXBGW-01", "M1"), [])

    def test_uptime_seconds(self):
        cases = {"00:01:05": 65, "1d02h": 93600, "3w2d": 1987200, "never": None, "": None, "junk": None}
        for text, want in cases.items():
            self.assertEqual(bgp.uptime_seconds(text), want, text)


class TestBgpCli(unittest.TestCase):
    def run_cli(self, *argv, state_dir=STATE_DIR):
        out = io.StringIO()
        code = cli.main(["bgp", "--expected", str(EXPECTED), "--state-dir", str(state_dir), "--color", "never",
                         *argv], out=out)
        return code, out.getvalue()

    def test_healthy_and_filters(self):
        code, text = self.run_cli()
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("are Established", text)
        code, text = self.run_cli("--device", "DC1-NXLF-01", "--all", "--format", "json")
        doc = json.loads(text)
        self.assertEqual({s["device"] for s in doc["sessions"]}, {"DC1-NXLF-01"})
        self.assertEqual(self.run_cli("--device", "NOPE")[0], cli.EXIT_USAGE)

    def test_down_session_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            for f in STATE_DIR.glob("*.json"):
                shutil.copy(f, tmp)
            p = Path(tmp, "DC2-NXLF-02.json")
            doc = json.loads(p.read_text())
            doc["bgp"]["sessions"][0]["state"] = "Idle"
            p.write_text(json.dumps(doc))
            code, text = self.run_cli("--site", "DC2", state_dir=tmp)
            self.assertEqual(code, cli.EXIT_NONCOMPLIANT)
            self.assertIn("DOWN (Idle", text)
            self.assertIn("1 down", text)


if __name__ == "__main__":
    unittest.main()
