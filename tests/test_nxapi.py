"""Tests for live collection: the NX-OS parsers, the NX-API client and `netauto audit --source nxapi`.

A fake switch (tests/fake_nxos.py) renders each demo switch's state as raw NX-API output
and serves it over JSON-RPC on 127.0.0.1.

    python3 -m unittest discover -s tests -t .
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock as patch

from netauto import cli, mock, nxos
from netauto.collector import StateError
from netauto.expected import load_design
from netauto.nxapi import NxapiClient, NxapiSource
from tests.fake_nxos import FakeNxapiServer, render

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = ROOT / "examples" / "demo" / "expected-state.json"


def normalized(state):
    s = json.loads(json.dumps(state))
    s["bgp"]["sessions"].sort(key=lambda x: (x["vrf"], x["afi"], x["neighbor"]))
    return s


class TestParsers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.design = load_design(EXPECTED)

    def test_round_trip_every_switch_at_every_step(self):
        """Rendering a switch's state as NX-API output and parsing it back gives the same state."""
        for step in self.design.step_ids:
            for d in self.design.devices:
                state = mock.device_state(self.design, d, step)
                parsed = nxos.parse(d, render(self.design, d, state), collected_at=mock.COLLECTED_AT)
                self.assertEqual(normalized(parsed), normalized(state), f"{d.hostname} at {step}")

    def test_commands_by_role(self):
        spine, leaf, bgw = (self.design.device(h) for h in ("DC1-NXSP-01", "DC1-NXLF-01", "DC1-NXBGW-01"))
        self.assertNotIn(nxos.SHOW_NVE_VNI, nxos.commands(spine))
        self.assertIn(nxos.SHOW_VPC, nxos.commands(leaf))
        self.assertNotIn(nxos.SHOW_MS_DCI, nxos.commands(leaf))
        self.assertIn(nxos.SHOW_MS_DCI, nxos.commands(bgw))
        self.assertNotIn(nxos.SHOW_VPC, nxos.commands(bgw))

    def test_missing_output_is_a_state_error(self):
        d = self.design.device("DC1-NXSP-01")
        raw = render(self.design, d, mock.device_state(self.design, d))
        del raw[nxos.SHOW_BFD]
        with self.assertRaisesRegex(StateError, "no output for: show bfd"):
            nxos.parse(d, raw)

    def test_rows_handles_one_none_and_many(self):
        self.assertEqual(nxos.rows({"TABLE_x": {"ROW_x": {"a": 1}}}, "TABLE_x", "ROW_x"), [{"a": 1}])
        self.assertEqual(nxos.rows({"TABLE_x": {"ROW_x": [{"a": 1}, {"a": 2}]}}, "TABLE_x", "ROW_x"),
                         [{"a": 1}, {"a": 2}])
        self.assertEqual(nxos.rows({}, "TABLE_x", "ROW_x"), [])
        self.assertEqual(nxos.rows(None, "TABLE_x", "ROW_x"), [])

    def test_route_targets_from_running_config(self):
        cfg = nxos.parse_config("\n".join([
            "vrf context TRUST", "  vni 50010", "  rd auto", "  address-family ipv4 unicast",
            "    route-target both 65000:50010", "    route-target both 65000:50010 evpn",
            "evpn", "  vni 110010 l2", "    rd auto", "    route-target both 65110:110010",
            "  vni 110020 l2", "    route-target import 65110:110020", "    route-target export auto",
        ]))
        rts = nxos.config_rts(cfg)
        self.assertEqual(rts[50010], {"import": ["65000:50010"], "export": ["65000:50010"]})
        self.assertEqual(rts[110010], {"import": ["65110:110010"], "export": ["65110:110010"]})
        self.assertEqual(rts[110020], {"import": ["65110:110020"], "export": ["auto"]})

    def test_route_distinguishers(self):
        text = ("Route Distinguisher: 10.110.240.13:32777    (L2VNI 110010)\n"
                "Route Distinguisher: 10.110.240.13:3    (L3VNI 50010)\n"
                "Route Distinguisher: 10.110.240.11:32777\n")
        self.assertEqual(nxos.parse_evpn_rds(text), {110010: "10.110.240.13:32777", 50010: "10.110.240.13:3"})

    def test_nve_vni_types(self):
        out = {"TABLE_nve_vni": {"ROW_nve_vni": [
            {"vni": "110010", "type": "L2 [10]", "vni-state": "Up"},
            {"vni": "50010", "type": "L3 [TRUST]", "vni-state": "Down"},
            {"vni": "bogus", "type": "L2 [1]"},
        ]}}
        self.assertEqual(nxos.parse_nve_vni(out), [
            {"vni": 110010, "type": "L2", "vlan": 10, "state": "Up"},
            {"vni": 50010, "type": "L3", "vrf": "TRUST", "state": "Down"},
        ])

    def test_short_interface_names(self):
        self.assertEqual(nxos.long_ifname("Eth1/49"), "Ethernet1/49")
        self.assertEqual(nxos.long_ifname("Po10"), "port-channel10")
        self.assertEqual(nxos.long_ifname("Ethernet1/49"), "Ethernet1/49")
        self.assertEqual(nxos.long_ifname("Vlan3900"), "Vlan3900")


class TestClient(unittest.TestCase):
    def test_runs_json_and_ascii_commands(self):
        outputs = {"show version": {"host_name": "sw1"}, "show running-config": "hostname sw1\n"}
        with FakeNxapiServer(outputs) as srv:
            client = NxapiClient("127.0.0.1", "admin", "secret", scheme="http", port=srv.port)
            got = client.run(["show version", "show running-config"], ["show running-config"])
        self.assertEqual(got, {"show version": {"host_name": "sw1"}, "show running-config": "hostname sw1\n"})
        methods = [c["method"] for c in srv.requests[0]]
        self.assertEqual(methods, ["cli", "cli_ascii"])

    def test_single_command_and_empty_table(self):
        with FakeNxapiServer({"show bfd neighbors vrf all": None}) as srv:
            client = NxapiClient("127.0.0.1", "admin", "secret", scheme="http", port=srv.port)
            self.assertEqual(client.run(["show bfd neighbors vrf all"]), {"show bfd neighbors vrf all": {}})

    def test_bad_login(self):
        with FakeNxapiServer({}) as srv:
            client = NxapiClient("127.0.0.1", "admin", "wrong", scheme="http", port=srv.port)
            with self.assertRaisesRegex(StateError, "refused the login"):
                client.run(["show version"])

    def test_command_error_names_the_command(self):
        with FakeNxapiServer({"show version": {}}) as srv:
            client = NxapiClient("127.0.0.1", "admin", "secret", scheme="http", port=srv.port)
            with self.assertRaisesRegex(StateError, "'show nve vni' failed on the switch: % Invalid command"):
                client.run(["show version", "show nve vni"])

    def test_unreachable(self):
        with FakeNxapiServer({}) as srv:
            port = srv.port
        client = NxapiClient("127.0.0.1", "admin", "secret", scheme="http", port=port, timeout=2)
        with self.assertRaisesRegex(StateError, "cannot reach"):
            client.run(["show version"])

    def test_host_port_and_mgmt_addressing(self):
        design = load_design(EXPECTED)
        d = design.device("DC1-NXLF-01")
        source = NxapiSource("u", "p", hosts={"DC1-NXLF-01": "127.0.0.1:8443"}, scheme="http")
        self.assertEqual(source.client(d).url, "http://127.0.0.1:8443/ins")
        self.assertEqual(NxapiSource("u", "p").client(d).url, f"https://{d.mgmt}/ins")
        self.assertEqual(NxapiSource("u", "p", hosts={"DC1-NXLF-01": "fd00::1"}).client(d).url, "https://[fd00::1]/ins")


class TestLiveCli(unittest.TestCase):
    """`netauto audit --source nxapi` and `netauto collect` against one fake switch per demo switch."""

    def setUp(self):
        self.design = load_design(EXPECTED)
        self.outputs = {d.hostname: render(self.design, d, mock.device_state(self.design, d))
                        for d in self.design.devices}
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.patch.dict(os.environ, {"NETAUTO_USERNAME": "admin", "NETAUTO_PASSWORD": "secret"})
        env.start()
        self.addCleanup(env.stop)

    def run_cli(self, command, *argv):
        with ExitStack() as stack:
            servers = {h: stack.enter_context(FakeNxapiServer(o)) for h, o in self.outputs.items()}
            hosts = Path(self.tmp.name, "hosts.json")
            hosts.write_text(json.dumps({h: f"127.0.0.1:{s.port}" for h, s in servers.items()}))
            out = io.StringIO()
            code = cli.main([command, "--expected", str(EXPECTED), "--hosts", str(hosts), "--scheme", "http",
                             "--color", "never", *argv], out=out)
        return code, out.getvalue()

    def test_live_audit_is_compliant(self):
        code, text = self.run_cli("audit", "--source", "nxapi")
        self.assertEqual(code, cli.EXIT_OK, text)
        self.assertIn("state: nxapi (live)", text)
        self.assertIn("Overall: COMPLIANT", text)

    def test_live_audit_reports_drift(self):
        raw = self.outputs["DC1-NXLF-02"]
        raw[nxos.SHOW_VPC]["vpc-peer-keepalive-status"] = "peer-not-alive"
        code, text = self.run_cli("audit", "--source", "nxapi", "--format", "json")
        self.assertEqual(code, cli.EXIT_NONCOMPLIANT)
        failed = [(r["check"], r["target"]) for r in json.loads(text)["results"] if r["status"] == "FAIL"]
        self.assertEqual(failed, [("vpc", "DC1-NXLF-02")])

    def test_unreachable_switch_is_reported_not_fatal(self):
        del self.outputs["DC2-NXSP-02"][nxos.SHOW_INTERFACE]
        code, text = self.run_cli("audit", "--source", "nxapi", "--site", "DC2")
        self.assertEqual(code, cli.EXIT_NONCOMPLIANT)
        self.assertIn("Checks not run (no state): DC2-NXSP-02", text)

    def test_collect_writes_snapshots_and_raw_output(self):
        out_dir = Path(self.tmp.name, "state")
        code, text = self.run_cli("collect", "--out", str(out_dir), "--raw")
        self.assertEqual(code, cli.EXIT_OK, text)
        self.assertEqual(len(list(out_dir.glob("*.json"))), len(self.design.devices))
        self.assertEqual(len(list((out_dir / "raw").glob("*.json"))), len(self.design.devices))
        # The collected snapshots audit offline like any other.
        code = cli.main(["audit", "--expected", str(EXPECTED), "--state-dir", str(out_dir), "--color", "never"],
                        out=io.StringIO())
        self.assertEqual(code, cli.EXIT_OK)

    def test_missing_credentials_without_a_terminal(self):
        with patch.patch.dict(os.environ, {"NETAUTO_PASSWORD": ""}), \
                patch.patch("sys.stdin", io.StringIO()):
            code, _ = self.run_cli("audit", "--source", "nxapi")
        self.assertEqual(code, cli.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
