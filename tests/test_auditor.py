"""Unit tests for core.auditor (with the collector and intent loader it depends on).

Run with either:

    python3 -m unittest discover -s tests
    python3 -m pytest
"""

from __future__ import annotations

import copy
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from core import cli
from core.auditor import (CHECK_BGP, CHECK_COLLECTION, CHECK_EVPN, CHECK_MTU, CHECK_VNI, CHECKS, ERROR,
                          FAIL, PASS, SKIP, Auditor)
from core.collector import CollectionResult, FabricCollector, MockStateSource, StaticStateSource
from core.inventory import IntentError, load_intent, parse_intent
from core import miniyaml

ROOT = Path(__file__).resolve().parent.parent
INTENT = ROOT / "examples" / "spine_leaf_intent.yaml"
STATE_DIR = ROOT / "examples" / "mock_states"


class AuditorTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fabric = load_intent(INTENT)
        cls.baseline = FabricCollector(cls.fabric, MockStateSource(STATE_DIR)).collect()

    def setUp(self) -> None:
        # Each test drifts its own copy of the compliant baseline.
        self.states = copy.deepcopy(self.baseline.states)

    def audit(self, errors=None, site=None):
        return Auditor(self.fabric).audit(CollectionResult(states=self.states, errors=errors or {}), site=site)

    def evpn_vni(self, hostname, vni):
        return next(v for v in self.states[hostname]["evpn"]["vnis"] if v["vni"] == vni)

    def nve_vni(self, hostname, vni):
        return next(v for v in self.states[hostname]["vni_map"] if v["vni"] == vni)

    def assert_only_failure(self, report, check, target):
        failed = {(r.check, r.target) for r in report.failures if not r.is_pair}
        self.assertEqual(failed, {(check, target)})


class TestCompliantFabric(AuditorTestCase):
    def test_baseline_collects_every_device(self):
        self.assertTrue(self.baseline.ok, self.baseline.errors)
        self.assertEqual(set(self.baseline.states), {d.hostname for d in self.fabric.devices()})

    def test_matching_state_is_compliant(self):
        report = self.audit()
        self.assertTrue(report.compliant, [(r.check, r.target, r.mismatches) for r in report.failures])
        self.assertEqual(report.failures, [])
        for site in ("LVD", "SAC"):
            for pod in self.fabric.pods(site):
                self.assertTrue(report.pod_compliant(site, pod.name))

    def test_every_device_gets_all_four_checks(self):
        report = self.audit()
        for device in self.fabric.devices():
            for check in CHECKS:
                result = report.result(check, device.hostname)
                expected = PASS if device.is_leaf or check in (CHECK_MTU, CHECK_BGP) else SKIP
                self.assertEqual(result.status, expected, (check, device.hostname))

    def test_site_filter(self):
        report = self.audit(site="SAC")
        self.assertTrue(report.results)
        self.assertEqual({r.site for r in report.results}, {"SAC"})


class TestMtuCheck(AuditorTestCase):
    def test_mtu_mismatch_is_detected(self):
        self.states["lvd-lf01a"]["interfaces"]["Ethernet1/49"]["mtu"] = 1500
        report = self.audit()

        self.assertFalse(report.compliant)
        self.assertFalse(report.pod_compliant("LVD", "LVD-POD1"))
        self.assertTrue(report.pod_compliant("SAC", "SAC-POD1"))
        self.assert_only_failure(report, CHECK_MTU, "lvd-lf01a")

        result = report.result(CHECK_MTU, "lvd-lf01a")
        self.assertEqual(result.status, FAIL)
        self.assertEqual(len(result.mismatches), 1)
        m = result.mismatches[0]
        self.assertEqual((m.item, m.expected, m.actual), ("Ethernet1/49", 9216, 1500))

    def test_spine_mtu_mismatch(self):
        self.states["sac-sp02"]["interfaces"]["Ethernet1/3"]["mtu"] = 9000
        report = self.audit()
        self.assert_only_failure(report, CHECK_MTU, "sac-sp02")
        self.assertEqual(report.result(CHECK_MTU, "sac-sp02").mismatches[0].actual, 9000)

    def test_missing_fabric_interface(self):
        del self.states["lvd-lf02b"]["interfaces"]["Ethernet1/50"]
        m = self.audit().result(CHECK_MTU, "lvd-lf02b").mismatches[0]
        self.assertEqual((m.item, m.expected, m.actual), ("Ethernet1/50", 9216, None))

    def test_non_fabric_interfaces_are_ignored(self):
        self.assertEqual(self.states["lvd-lf01a"]["interfaces"]["mgmt0"]["mtu"], 1500)
        self.assertEqual(self.audit().result(CHECK_MTU, "lvd-lf01a").status, PASS)


class TestRouteTargetAndDistinguisher(AuditorTestCase):
    def test_wrong_route_target_is_detected(self):
        self.evpn_vni("lvd-lf01b", 10200)["rt_import"] = ["65000:10299"]
        report = self.audit()

        self.assertFalse(report.compliant)
        self.assert_only_failure(report, CHECK_EVPN, "lvd-lf01b")
        mismatches = report.result(CHECK_EVPN, "lvd-lf01b").mismatches
        self.assertEqual(len(mismatches), 1)
        m = mismatches[0]
        self.assertEqual(m.item, "VNI 10200 (VLAN 200) RT import")
        self.assertEqual(m.expected, ["65000:10200"])
        self.assertEqual(m.actual, ["65000:10299"])

        # The pair view shows which member diverged.
        pair = [r for r in report.failures if r.is_pair]
        self.assertEqual([(r.check, r.target) for r in pair], [(CHECK_EVPN, "lvd-lp01")])
        self.assertIn("65000:10299", pair[0].mismatches[0].actual)
        self.assertTrue(pair[0].mismatches[0].actual.startswith("lvd-lf01b:"))

    def test_extra_route_target_is_detected(self):
        self.evpn_vni("sac-lf02a", 50020)["rt_export"].append("65000:99999")
        m = self.audit().result(CHECK_EVPN, "sac-lf02a").mismatches[0]
        self.assertEqual(m.item, "VNI 50020 (VRF TENANT-B) RT export")
        self.assertEqual(m.actual, ["65000:50020", "65000:99999"])

    def test_auto_derived_route_target_is_detected(self):
        # "route-target auto" under eBGP yields ASN:VNI with the leaf pair's own ASN.
        vni = self.evpn_vni("lvd-lf02a", 10300)
        vni["rt_import"] = vni["rt_export"] = ["65112:10300"]
        self.assertEqual(len(self.audit().result(CHECK_EVPN, "lvd-lf02a").mismatches), 2)

    def test_wrong_route_distinguisher(self):
        self.evpn_vni("sac-lf01a", 10100)["rd"] = "10.21.0.12:100"  # copied from its pair peer
        m = self.audit().result(CHECK_EVPN, "sac-lf01a").mismatches[0]
        self.assertEqual((m.expected, m.actual), ("10.21.0.11:100", "10.21.0.12:100"))

    def test_missing_vni_in_evpn_table(self):
        vnis = self.states["lvd-lf01a"]["evpn"]["vnis"]
        vnis[:] = [v for v in vnis if v["vni"] != 50010]
        m = self.audit().result(CHECK_EVPN, "lvd-lf01a").mismatches[0]
        self.assertEqual((m.item, m.actual), ("VNI 50010 (VRF TENANT-A)", None))


class TestBgpCheck(AuditorTestCase):
    def test_idle_evpn_session(self):
        self.states["lvd-lf02a"]["bgp"]["evpn"][1]["state"] = "Idle"
        report = self.audit()
        self.assert_only_failure(report, CHECK_BGP, "lvd-lf02a")
        m = report.result(CHECK_BGP, "lvd-lf02a").mismatches[0]
        self.assertEqual((m.item, m.expected, m.actual), ("EVPN lvd-sp02 (10.11.0.2)", "Established", "Idle"))

    def test_missing_underlay_session(self):
        self.states["sac-sp01"]["bgp"]["underlay"].pop(0)
        m = self.audit().result(CHECK_BGP, "sac-sp01").mismatches[0]
        self.assertTrue(m.item.startswith("underlay sac-lf01a"))
        self.assertIsNone(m.actual)

    def test_wrong_remote_as_and_unexpected_peer(self):
        peers = self.states["lvd-lf01a"]["bgp"]["underlay"]
        peers[0]["remote_as"] = 65999
        peers.append({"neighbor": "192.0.2.1", "router_id": "192.0.2.1", "remote_as": 64999, "state": "Active"})
        items = [m.item for m in self.audit().result(CHECK_BGP, "lvd-lf01a").mismatches]
        self.assertEqual(items, ["underlay lvd-sp01 (10.11.0.1) remote AS",
                                 "underlay 192.0.2.1 (router-id 192.0.2.1)"])


class TestVniVlanMapping(AuditorTestCase):
    def test_vni_on_wrong_vlan(self):
        self.nve_vni("sac-lf01b", 10200)["vlan"] = 201
        report = self.audit()
        failed = {(r.check, r.target) for r in report.failures}
        self.assertEqual(failed, {(CHECK_VNI, "sac-lf01b"), (CHECK_VNI, "sac-lp01")})
        m = report.result(CHECK_VNI, "sac-lf01b").mismatches[0]
        self.assertEqual((m.expected, m.actual), ("L2 VLAN 200", "L2 VLAN 201"))

    def test_vni_missing_on_one_pair_member(self):
        vmap = self.states["lvd-lf02b"]["vni_map"]
        vmap[:] = [v for v in vmap if v["vni"] != 10400]
        report = self.audit()
        self.assertIsNone(report.result(CHECK_VNI, "lvd-lf02b").mismatches[0].actual)
        pair = next(r for r in report.failures if r.is_pair and r.check == CHECK_VNI)
        self.assertEqual(pair.mismatches[0].actual, "lvd-lf02b: absent")

    def test_vni_not_in_intent(self):
        self.states["lvd-lf01a"]["vni_map"].append({"vni": 10300, "type": "L2", "vlan": 300, "state": "Up"})
        m = self.audit().result(CHECK_VNI, "lvd-lf01a").mismatches[0]
        self.assertEqual((m.item, m.expected), ("VNI 10300", None))

    def test_vni_down(self):
        self.nve_vni("sac-lf02a", 10300)["state"] = "Down"
        m = self.audit().result(CHECK_VNI, "sac-lf02a").mismatches[0]
        self.assertEqual((m.expected, m.actual), ("Up", "Down"))


class TestCollection(AuditorTestCase):
    def test_unreachable_device_is_an_error_not_a_crash(self):
        del self.states["lvd-sp01"]
        report = self.audit(errors={"lvd-sp01": "timed out after 30s"})
        self.assertFalse(report.compliant)
        collect = report.result(CHECK_COLLECTION, "lvd-sp01")
        self.assertEqual(collect.status, FAIL)
        self.assertEqual(collect.mismatches[0].detail, "timed out after 30s")
        self.assertEqual(report.result(CHECK_MTU, "lvd-sp01").status, ERROR)
        self.assertEqual(report.result(CHECK_EVPN, "lvd-sp01").status, SKIP)

    def test_mock_source_reports_missing_and_malformed_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            for f in STATE_DIR.glob("*.json"):
                shutil.copy(f, tmp)
            Path(tmp, "lvd-lf01a.json").unlink()
            Path(tmp, "sac-sp01.json").write_text("{not json")
            doc = json.loads(Path(tmp, "sac-lf02b.json").read_text())
            doc["hostname"] = "sac-lf02a"
            Path(tmp, "sac-lf02b.json").write_text(json.dumps(doc))

            result = FabricCollector(self.fabric, MockStateSource(tmp), concurrency=3).collect()

        self.assertEqual(set(result.errors), {"lvd-lf01a", "sac-sp01", "sac-lf02b"})
        self.assertIn("no mock state file", result.errors["lvd-lf01a"])
        self.assertIn("invalid JSON", result.errors["sac-sp01"])
        self.assertIn("not 'sac-lf02b'", result.errors["sac-lf02b"])
        self.assertEqual(len(result.states), len(self.fabric.devices()) - 3)

    def test_static_source_validates_schema(self):
        states = copy.deepcopy(self.states)
        states["lvd-lf01a"]["interfaces"]["Ethernet1/49"]["mtu"] = "9216"
        result = FabricCollector(self.fabric, StaticStateSource(states)).collect()
        self.assertEqual(list(result.errors), ["lvd-lf01a"])


class TestIntent(unittest.TestCase):
    def setUp(self) -> None:
        self.data = miniyaml.load(INTENT)

    def test_duplicate_vni_is_rejected(self):
        self.data["vrfs"][0]["vni"] = 10100
        with self.assertRaisesRegex(IntentError, "duplicate VNI: 10100"):
            parse_intent(self.data)

    def test_unquoted_route_target_is_rejected(self):
        self.data["segments"][0]["route_target"] = 234010100  # what PyYAML makes of 65000:10100
        with self.assertRaisesRegex(IntentError, "quote it"):
            parse_intent(self.data)

    def test_unknown_segment_reference(self):
        self.data["sites"][0]["pods"][0]["leaf_pairs"][0]["segments"].append(999)
        with self.assertRaisesRegex(IntentError, "unknown segment VLAN 999"):
            parse_intent(self.data)


class TestCli(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        code = cli.main(["audit", "--intent", str(INTENT), "--color", "never", *argv], out=out)
        return code, out.getvalue()

    def test_compliant_exit_code_and_table(self):
        code, text = self.run_cli()
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("LVD-POD1  COMPLIANT", text)
        self.assertIn("SAC-POD1  COMPLIANT", text)
        self.assertIn("Overall: COMPLIANT", text)

    def test_drift_exit_code_and_details(self):
        with tempfile.TemporaryDirectory() as tmp:
            for f in STATE_DIR.glob("*.json"):
                shutil.copy(f, tmp)
            path = Path(tmp, "sac-lf01a.json")
            doc = json.loads(path.read_text())
            doc["interfaces"]["Ethernet1/50"]["mtu"] = 1500
            path.write_text(json.dumps(doc))
            code, text = self.run_cli("--state-dir", tmp, "--format", "json")
        self.assertEqual(code, cli.EXIT_NONCOMPLIANT)
        doc = json.loads(text)
        self.assertFalse(doc["compliant"])
        failed = [r for r in doc["results"] if r["status"] == FAIL]
        self.assertEqual([(r["check"], r["target"]) for r in failed], [(CHECK_MTU, "sac-lf01a")])
        self.assertEqual(failed[0]["mismatches"][0]["actual"], 1500)


if __name__ == "__main__":
    unittest.main()
