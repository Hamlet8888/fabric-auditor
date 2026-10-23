"""Unit tests for netauto (auditor, collector, expected-state loader, snapshots and CLI).

Each test drifts a copy of the compliant demo snapshots in examples/demo/state, which
netauto.mock synthesizes from examples/demo/expected-state.json (written by network-design).

    python3 -m unittest discover -s tests -t .
"""

from __future__ import annotations

import copy
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from netauto import cli, mock
from netauto.auditor import (CHECK_BGP, CHECK_COLLECTION, CHECK_EVPN, CHECK_LINKS, CHECK_NVE, CHECK_VNI,
                             CHECK_VPC, CHECKS, ERROR, FAIL, PASS, SKIP, Auditor)
from netauto.collector import CollectionResult, FabricCollector, SnapshotSource, StaticStateSource
from netauto.expected import DesignError, load_design, parse_design

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = ROOT / "examples" / "demo" / "expected-state.json"
STATE_DIR = ROOT / "examples" / "demo" / "state"

LEAF = "DC1-NXLF-01"
MATE = "DC1-NXLF-02"
BORDER = "DC1-NXLF-03"
BGW = "DC1-NXBGW-01"
SPINE = "DC1-NXSP-01"


class AuditorTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.design = load_design(EXPECTED)
        cls.baseline = FabricCollector(cls.design, SnapshotSource(STATE_DIR)).collect()

    def setUp(self) -> None:
        self.states = copy.deepcopy(self.baseline.states)

    def audit(self, errors=None, site=None, step=None):
        return Auditor(self.design, step).audit(CollectionResult(states=self.states, errors=errors or {}), site=site)

    def at_step(self, step):
        """Swap the baseline for the compliant state at an earlier migration step."""
        self.states = {d.hostname: mock.device_state(self.design, d, step) for d in self.design.devices}

    def session(self, hostname, neighbor, afi="ipv4"):
        return next(s for s in self.states[hostname]["bgp"]["sessions"] if s["neighbor"] == neighbor and s["afi"] == afi)

    def evpn_vni(self, hostname, vni):
        return next(v for v in self.states[hostname]["evpn"]["vnis"] if v["vni"] == vni)

    def nve_vni(self, hostname, vni):
        return next(v for v in self.states[hostname]["vni_map"] if v["vni"] == vni)

    def l2vni(self, hostname):
        return next(v for v in self.design.device(hostname).vnis if v.type == "L2")

    def assert_only_failure(self, report, check, target):
        failed = {(r.check, r.target) for r in report.failures if not r.is_pair}
        self.assertEqual(failed, {(check, target)})


class TestCompliantFabric(AuditorTestCase):
    def test_baseline_collects_every_device(self):
        self.assertTrue(self.baseline.ok, self.baseline.errors)
        self.assertEqual(set(self.baseline.states), {d.hostname for d in self.design.devices})

    def test_matching_state_is_compliant(self):
        report = self.audit()
        self.assertTrue(report.compliant, [(r.check, r.target, r.mismatches) for r in report.failures])
        self.assertEqual(report.step, "M6")

    def test_checks_apply_by_role(self):
        report = self.audit()
        for target, skipped in ((SPINE, {CHECK_EVPN, CHECK_VNI, CHECK_NVE, CHECK_VPC}), (LEAF, set()),
                                (BGW, {CHECK_VPC})):
            for check in CHECKS:
                status = report.result(check, target).status
                self.assertEqual(status, SKIP if check in skipped else PASS, (target, check))
        pairs = [r for r in report.results if r.is_pair]
        self.assertEqual(len(pairs), 2 * len(self.design.vpc_pairs()))

    def test_site_filter(self):
        report = self.audit(site="DC2")
        self.assertEqual({r.site for r in report.results}, {"DC2"})

    def test_snapshots_are_current(self):
        """examples/demo/state is what netauto.mock makes of examples/demo/expected-state.json."""
        for d in self.design.devices:
            committed = json.loads((STATE_DIR / f"{d.hostname}.json").read_text())
            self.assertEqual(committed, mock.device_state(self.design, d), d.hostname)

    def test_every_step_of_a_synthesized_migration_is_compliant(self):
        for step in self.design.step_ids:
            states = {d.hostname: mock.device_state(self.design, d, step) for d in self.design.devices}
            report = Auditor(self.design, step).audit(CollectionResult(states=states))
            self.assertTrue(report.compliant, (step, [(r.check, r.target, r.mismatches) for r in report.failures]))


class TestLinks(AuditorTestCase):
    def test_mtu_mismatch_is_detected(self):
        self.states[LEAF]["interfaces"]["Ethernet1/50"]["mtu"] = 1500
        report = self.audit()
        self.assert_only_failure(report, CHECK_LINKS, LEAF)
        m = report.result(CHECK_LINKS, LEAF).mismatches[0]
        self.assertEqual((m.expected, m.actual), (9216, 1500))
        self.assertIn("DC1-NXSP-02", m.item)

    def test_missing_fabric_interface(self):
        del self.states[SPINE]["interfaces"]["Ethernet1/3"]
        report = self.audit()
        self.assert_only_failure(report, CHECK_LINKS, SPINE)
        self.assertEqual(report.result(CHECK_LINKS, SPINE).mismatches[0].detail, "interface not found on device")

    def test_non_fabric_interfaces_are_ignored(self):
        self.states[LEAF]["interfaces"]["mgmt0"]["mtu"] = 1400
        self.assertTrue(self.audit().compliant)

    def test_link_down(self):
        self.states[LEAF]["interfaces"]["Vlan3900"]["oper_status"] = "down"
        self.assert_only_failure(self.audit(), CHECK_LINKS, LEAF)

    def test_dci_link_may_be_down_before_its_step(self):
        self.at_step("M4")
        port = self.design.device(BGW).multisite.dci_links[0]
        self.states[BGW]["interfaces"][port]["oper_status"] = "down"
        self.states[BGW]["multisite"]["dci_links"][port] = "Down"
        self.assertTrue(self.audit(step="M4").compliant)
        failed = {(r.check, r.target) for r in self.audit(step="M5").failures}  # all DCI is still down at M4
        self.assertTrue({(CHECK_LINKS, BGW), (CHECK_NVE, BGW), (CHECK_BGP, BGW)} <= failed)


class TestBgp(AuditorTestCase):
    def test_idle_evpn_session(self):
        self.session(LEAF, "10.110.240.1", "evpn")["state"] = "Idle"
        report = self.audit()
        self.assert_only_failure(report, CHECK_BGP, LEAF)
        m = report.result(CHECK_BGP, LEAF).mismatches[0]
        self.assertEqual((m.expected, m.actual, m.detail), ("Established", "Idle", "session not established"))

    def test_missing_underlay_session(self):
        sessions = self.states[SPINE]["bgp"]["sessions"]
        sessions.remove(self.session(SPINE, "10.110.242.1"))
        report = self.audit()
        self.assert_only_failure(report, CHECK_BGP, SPINE)
        self.assertEqual(report.result(CHECK_BGP, SPINE).mismatches[0].detail, "session not configured")

    def test_wrong_remote_as_and_unexpected_peer(self):
        self.session(LEAF, "10.110.242.0")["remote_as"] = 65999
        self.states[LEAF]["bgp"]["sessions"].append(
            {"vrf": "default", "afi": "ipv4", "neighbor": "10.99.0.1", "remote_as": 65999, "state": "Established"})
        mismatches = self.audit().result(CHECK_BGP, LEAF).mismatches
        self.assertEqual({m.detail for m in mismatches}, {"", "BGP neighbor not in the design"})
        self.assertIn(65999, {m.actual for m in mismatches if m.item.endswith("remote AS")})

    def test_wrong_router_id_and_local_as(self):
        self.states[LEAF]["bgp"]["router_id"] = "10.110.240.99"
        self.states[LEAF]["bgp"]["local_as"] = 65000
        items = {m.item for m in self.audit().result(CHECK_BGP, LEAF).mismatches}
        self.assertEqual(items, {"router-ID", "local AS"})

    def test_bfd_down(self):
        self.states[LEAF]["bfd"][0]["state"] = "Down"
        report = self.audit()
        self.assert_only_failure(report, CHECK_BGP, LEAF)
        self.assertIn("BFD", report.result(CHECK_BGP, LEAF).mismatches[0].item)

    def test_later_sessions_are_not_required_yet(self):
        self.at_step("M4")
        dci = [s for s in self.states[BGW]["bgp"]["sessions"] if not s["neighbor"].startswith("10.110.24")]
        for s in dci:
            s["state"] = "Idle"
        self.assertTrue(self.audit(step="M4").compliant)
        self.assertFalse(self.audit(step="M5").compliant)

    def test_placeholder_neighbor_matches_by_remote_as(self):
        """The legacy core address is a placeholder; any session in VRF TRUST with its AS stands for it."""
        legacy = next(s for s in self.design.device(BORDER).sessions if s.placeholder)
        self.at_step("M2")
        core = next(s for s in self.states[BORDER]["bgp"]["sessions"] if s["remote_as"] == legacy.remote_as)
        core["neighbor"] = "10.110.99.2"
        self.assertTrue(self.audit(step="M2").compliant)
        core["state"] = "Active"
        self.assert_only_failure(self.audit(step="M2"), CHECK_BGP, BORDER)

    def test_retired_session_still_configured(self):
        legacy = next(s for s in self.design.device(BORDER).sessions if s.placeholder)
        self.states[BORDER]["bgp"]["sessions"].append(
            {"vrf": legacy.vrf, "afi": "ipv4", "neighbor": "10.110.99.2", "remote_as": legacy.remote_as,
             "state": "Established"})
        report = self.audit()
        self.assert_only_failure(report, CHECK_BGP, BORDER)
        self.assertIn("removed at M6", report.result(CHECK_BGP, BORDER).mismatches[0].detail)


class TestEvpn(AuditorTestCase):
    def test_wrong_route_target_is_detected(self):
        vni = self.l2vni(LEAF).vni
        self.evpn_vni(LEAF, vni)["rt_import"] = ["65110:999"]
        report = self.audit()
        self.assert_only_failure(report, CHECK_EVPN, LEAF)
        m = report.result(CHECK_EVPN, LEAF).mismatches[0]
        self.assertEqual(m.actual, ["65110:999"])
        pair = [r for r in report.failures if r.is_pair]
        self.assertEqual([(r.check, r.target) for r in pair], [(CHECK_EVPN, f"{LEAF} / {MATE}")])

    def test_extra_route_target_is_detected(self):
        vni = self.l2vni(LEAF).vni
        self.evpn_vni(LEAF, vni)["rt_export"].append("65000:1")
        self.assertIn("RT export", self.audit().result(CHECK_EVPN, LEAF).mismatches[0].item)

    def test_auto_derived_route_target_is_detected(self):
        """'route-target auto' gives ASN:VNI with each leaf's own ASN, which no other leaf imports."""
        want = self.l2vni(LEAF)
        self.evpn_vni(LEAF, want.vni)["rt_import"] = [f"65211:{want.vni}"]
        self.evpn_vni(LEAF, want.vni)["rt_export"] = [f"65211:{want.vni}"]
        self.assertEqual(len(self.audit().result(CHECK_EVPN, LEAF).mismatches), 2)

    def test_rd_not_derived_from_router_id(self):
        vni = self.l2vni(LEAF).vni
        self.evpn_vni(LEAF, vni)["rd"] = "10.110.240.12:32777"
        m = self.audit().result(CHECK_EVPN, LEAF).mismatches[0]
        self.assertEqual(m.detail, "RD is not derived from the router-ID")

    def test_missing_vni_in_evpn(self):
        vni = self.l2vni(LEAF).vni
        self.states[LEAF]["evpn"]["vnis"].remove(self.evpn_vni(LEAF, vni))
        self.assert_only_failure(self.audit(), CHECK_EVPN, LEAF)

    def test_bgw_carrying_an_l2vni(self):
        self.states[BGW]["evpn"]["vnis"].append({"vni": 110010, "rd": "10.110.240.21:32777",
                                                 "rt_import": ["65110:110010"], "rt_export": ["65110:110010"]})
        m = self.audit().result(CHECK_EVPN, BGW).mismatches[0]
        self.assertEqual(m.detail, "VNI in EVPN but not in the design")


class TestVniMap(AuditorTestCase):
    def test_vni_on_wrong_vlan(self):
        want = self.l2vni(LEAF)
        self.nve_vni(LEAF, want.vni)["vlan"] = 999
        report = self.audit()
        self.assert_only_failure(report, CHECK_VNI, LEAF)
        m = report.result(CHECK_VNI, LEAF).mismatches[0]
        self.assertEqual((m.expected, m.actual), (f"L2 VLAN {want.vlan}", "L2 VLAN 999"))

    def test_vni_missing_on_one_pair_member(self):
        want = self.l2vni(MATE)
        self.states[MATE]["vni_map"].remove(self.nve_vni(MATE, want.vni))
        report = self.audit()
        self.assert_only_failure(report, CHECK_VNI, MATE)
        pair = next(r for r in report.failures if r.is_pair)
        self.assertIn("absent", pair.mismatches[0].actual)

    def test_vni_not_in_design(self):
        self.states[LEAF]["vni_map"].append({"vni": 119999, "type": "L2", "vlan": 999, "state": "Up"})
        m = self.audit().result(CHECK_VNI, LEAF).mismatches[0]
        self.assertEqual(m.detail, "VNI configured on device but not in the design")

    def test_vni_down(self):
        self.nve_vni(LEAF, 50010)["state"] = "Down"
        m = self.audit().result(CHECK_VNI, LEAF).mismatches[0]
        self.assertEqual((m.expected, m.actual), ("Up", "Down"))

    def test_vlan_on_two_vnis(self):
        want = self.l2vni(LEAF)
        self.states[LEAF]["vni_map"].append({"vni": 119999, "type": "L2", "vlan": want.vlan, "state": "Up"})
        details = {m.detail for m in self.audit().result(CHECK_VNI, LEAF).mismatches}
        self.assertIn("VLAN mapped to several VNIs", details)


class TestNveAndMultisite(AuditorTestCase):
    def test_wrong_anycast_vtep(self):
        self.states[LEAF]["nve"]["secondary"] = "10.110.241.11"
        self.assert_only_failure(self.audit(), CHECK_NVE, LEAF)

    def test_multisite_site_id_and_vip(self):
        self.states[BGW]["multisite"]["site_id"] = 120
        self.states[BGW]["multisite"]["vip"] = "10.110.241.201"
        items = {m.item for m in self.audit().result(CHECK_NVE, BGW).mismatches}
        self.assertEqual(items, {"Multi-Site site ID", "Multi-Site VIP"})

    def test_fabric_tracking_missing(self):
        del self.states[BGW]["multisite"]["fabric_links"]["Ethernet1/49"]
        m = self.audit().result(CHECK_NVE, BGW).mismatches[0]
        self.assertEqual(m.detail, "not a Multi-Site fabric tracking link")


class TestVpc(AuditorTestCase):
    def test_keepalive_lost(self):
        self.states[LEAF]["vpc"]["keepalive_status"] = "peer-not-alive"
        report = self.audit()
        self.assert_only_failure(report, CHECK_VPC, LEAF)
        self.assertEqual(report.result(CHECK_VPC, LEAF).mismatches[0].item, "vPC keepalive")

    def test_wrong_domain_and_inconsistency(self):
        self.states[LEAF]["vpc"]["domain"] = 999
        self.states[LEAF]["vpc"]["consistency"] = "failed"
        self.assertEqual(len(self.audit().result(CHECK_VPC, LEAF).mismatches), 2)


class TestCollection(AuditorTestCase):
    def test_unreachable_device_is_an_error_not_a_crash(self):
        del self.states[SPINE]
        report = self.audit(errors={SPINE: "timed out after 30s"})
        self.assertFalse(report.compliant)
        collect = report.result(CHECK_COLLECTION, SPINE)
        self.assertEqual(collect.status, FAIL)
        self.assertEqual(collect.mismatches[0].detail, "timed out after 30s")
        self.assertEqual(report.result(CHECK_LINKS, SPINE).status, ERROR)
        self.assertEqual(report.result(CHECK_EVPN, SPINE).status, SKIP)

    def test_missing_pair_member_errors_the_pair(self):
        del self.states[MATE]
        report = self.audit(errors={MATE: "unreachable"})
        pair = [r for r in report.results if r.is_pair and r.target == f"{LEAF} / {MATE}"]
        self.assertEqual({r.status for r in pair}, {ERROR})

    def test_snapshot_source_reports_missing_and_malformed_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            for f in STATE_DIR.glob("*.json"):
                shutil.copy(f, tmp)
            Path(tmp, f"{LEAF}.json").unlink()
            Path(tmp, f"{SPINE}.json").write_text("{not json")
            doc = json.loads(Path(tmp, f"{MATE}.json").read_text())
            doc["hostname"] = LEAF
            Path(tmp, f"{MATE}.json").write_text(json.dumps(doc))

            result = FabricCollector(self.design, SnapshotSource(tmp), concurrency=3).collect()

        self.assertEqual(set(result.errors), {LEAF, SPINE, MATE})
        self.assertIn("no state snapshot", result.errors[LEAF])
        self.assertIn("invalid JSON", result.errors[SPINE])
        self.assertIn(f"not '{MATE}'", result.errors[MATE])
        self.assertEqual(len(result.states), len(self.design.devices) - 3)

    def test_static_source_validates_schema(self):
        states = copy.deepcopy(self.states)
        states[LEAF]["interfaces"]["Ethernet1/49"]["mtu"] = "9216"
        states[SPINE]["schema_version"] = 1
        result = FabricCollector(self.design, StaticStateSource(states)).collect()
        self.assertEqual(set(result.errors), {LEAF, SPINE})
        self.assertIn("schema_version", result.errors[SPINE])


class TestDesign(unittest.TestCase):
    def setUp(self) -> None:
        self.data = json.loads(EXPECTED.read_text())

    def test_schema_version_must_match(self):
        self.data["schema_version"] = 2
        with self.assertRaisesRegex(DesignError, "unsupported schema_version"):
            parse_design(self.data)

    def test_duplicate_hostname_and_router_id(self):
        self.data["devices"].append(copy.deepcopy(self.data["devices"][0]))
        with self.assertRaisesRegex(DesignError, "duplicate hostname") as ctx:
            parse_design(self.data)
        self.assertIn("duplicate router-ID", str(ctx.exception))

    def test_unknown_step(self):
        self.data["devices"][0]["bgp"][0]["step"] = "M9"
        with self.assertRaisesRegex(DesignError, "unknown step 'M9'"):
            parse_design(self.data)

    def test_unknown_vpc_peer(self):
        leaf = next(d for d in self.data["devices"] if "vpc" in d)
        leaf["vpc"]["peer"] = "NOWHERE"
        with self.assertRaisesRegex(DesignError, "vPC peer NOWHERE"):
            parse_design(self.data)

    def test_missing_field(self):
        del self.data["devices"][0]["router_id"]
        with self.assertRaisesRegex(DesignError, "router_id"):
            parse_design(self.data)

    def test_step_must_exist(self):
        with self.assertRaisesRegex(DesignError, "unknown step 'M0'"):
            Auditor(parse_design(self.data), "M0")


class TestCli(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        code = cli.main(["audit", "--expected", str(EXPECTED), "--color", "never", *argv], out=out)
        return code, out.getvalue()

    def test_compliant_exit_code_and_table(self):
        code, text = self.run_cli()
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("DC1  COMPLIANT", text)
        self.assertIn("DC2  COMPLIANT", text)
        self.assertIn("Overall: COMPLIANT", text)
        self.assertIn(f"{LEAF} / {MATE}", text)

    def test_drift_exit_code_and_details(self):
        with tempfile.TemporaryDirectory() as tmp:
            for f in STATE_DIR.glob("*.json"):
                shutil.copy(f, tmp)
            path = Path(tmp, f"{BGW}.json")
            doc = json.loads(path.read_text())
            doc["interfaces"]["Ethernet1/49"]["mtu"] = 1500
            path.write_text(json.dumps(doc))
            code, text = self.run_cli("--state-dir", tmp, "--format", "json")
        self.assertEqual(code, cli.EXIT_NONCOMPLIANT)
        doc = json.loads(text)
        self.assertFalse(doc["compliant"])
        failed = [r for r in doc["results"] if r["status"] == FAIL]
        self.assertEqual([(r["check"], r["target"]) for r in failed], [(CHECK_LINKS, BGW)])
        self.assertEqual(failed[0]["mismatches"][0]["actual"], 1500)

    def test_unknown_site_and_step_are_usage_errors(self):
        self.assertEqual(self.run_cli("--site", "DC9")[0], cli.EXIT_USAGE)
        self.assertEqual(self.run_cli("--step", "M9")[0], cli.EXIT_USAGE)

    def test_inventory(self):
        out = io.StringIO()
        self.assertEqual(cli.main(["inventory", "--expected", str(EXPECTED), "--color", "never"], out=out), 0)
        self.assertIn("Multi-Site site ID 110", out.getvalue())


if __name__ == "__main__":
    unittest.main()
