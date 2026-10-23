# network-automation-tools

Tools that check a running **BGP EVPN/VXLAN Multi-Site fabric** against its design. The design itself (the
options, the address plan, the NX-OS and PAN-OS configs) lives in
[network-design](https://github.com/Hamlet8888/network-design). This repository reads the
`expected-state.json` that network-design writes next to the configs, compares it with the state collected from
every switch, and reports each deviation with its expected and actual value.

Standard library only (Python 3.9+).

```bash
python3 -m netauto.cli audit --expected examples/demo/expected-state.json                 # whole fabric, last step
python3 -m netauto.cli audit --expected examples/demo/expected-state.json --site DC1 --step M4
python3 -m netauto.cli audit --expected examples/demo/expected-state.json --format json
python3 -m netauto.cli inventory --expected examples/demo/expected-state.json             # what the design defines
```

Exit status: `0` compliant, `1` a check failed or a device's state could not be collected, `2` usage or input error.

## How the two repositories fit together

```
network-design                               network-automation-tools
  site data JSON                               expected-state.json ──┐
     │  python3 -m fabric_design.build                               ├─► netauto audit ─► PASS / FAIL per check
     ├─► configs/*.cfg, workbook, checks/      state/<switch>.json ──┘
     └─► expected-state.json  ─────────────►
```

The expected state comes from the same model as the configs, and network-design tests that the two agree. There
is no second description of the fabric to keep in sync. When the design changes, rebuild it and copy the new
`expected-state.json` here (or point `--expected` at the network-design output).

## Checks

| Check | What must hold |
|---|---|
| **Links** | Every routed fabric link (spine links, vPC backup underlay, DCI) exists, has MTU 9216 and is up once its migration step is done |
| **BGP and BFD** | Every session active at the step is Established with the right remote AS, BFD is up where the design runs it, local AS and router-ID match. No session outside the design, and none the design has retired (the legacy core after M6) |
| **EVPN RT/RD** | Each VNI has exactly the intended import/export route targets and an RD derived from the router-ID (`rd auto`) |
| **VNI-to-VLAN** | Each L2VNI maps to its VLAN and the L3VNI to its VRF, is Up, nothing extra is configured, no VLAN sits on two VNIs |
| **NVE / Multi-Site** | NVE is up with the design's source interface and VTEP addresses. On BGWs also the Multi-Site site ID, VIP, fabric-tracking links and, from the DCI step, the DCI-tracking links |
| **vPC** | Domain, peer adjacency, keepalive destination and status, peer-link and type-1 consistency |

Both members of each vPC pair are also compared with each other (route targets and VNI mappings), so the table
shows which one diverged.

### Migration steps

Every BGP session in the expected state carries the step that brings it up (M1 build to M6 legacy retirement)
and, for the legacy core, the step that removes it. `--step` audits the fabric as it should be at that point:
sessions of later steps may be configured but are not required, and retired ones must be gone. The default is
the last step.

## Layout

| Path | Purpose |
|---|---|
| `netauto/expected.py` | Loads and validates `expected-state.json` from network-design |
| `netauto/collector.py` | `FabricCollector`: concurrent (asyncio) collection from a `StateSource`; documents the state schema |
| `netauto/auditor.py` | `Auditor`: the six checks and the vPC pair comparison, returning an `AuditReport` |
| `netauto/cli.py` | `argparse` CLI with colourized per-site tables or JSON |
| `netauto/mock.py` | Synthesizes compliant state snapshots from the expected state, at any step |
| `examples/demo/expected-state.json` | The fictional DC1/DC2 demo fabric, as network-design writes it |
| `examples/demo/state/` | Compliant snapshots of every demo switch at the last step |

## State sources

The auditor only reads the normalized per-device document described in [`netauto/collector.py`](netauto/collector.py).
`SnapshotSource` reads it from `<state-dir>/<hostname>.json`. A live driver (NX-API, gNMI) plugs in by subclassing
`StateSource` and returning the same shape. **No live driver ships yet.**

To try the auditor without a lab, synthesize snapshots for any step and edit them:

```bash
python3 -m netauto.mock examples/demo/expected-state.json --out /tmp/state --step M4
python3 -m netauto.cli audit --expected examples/demo/expected-state.json --state-dir /tmp/state --step M4
```

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

GitHub Actions runs them on Python 3.9 and 3.13 for every push and pull request.

## Data handling

This repository holds code, docs and **fictional** example data only. Real device state, expected state for real
sites, credentials and generated reports stay local and are excluded by [`.gitignore`](.gitignore).
