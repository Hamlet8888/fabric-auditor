# fabric-auditor

Intent-based validation for **multi-site BGP EVPN/VXLAN spine-leaf fabrics**. It compares the operational state of
every spine and leaf in the LVD (Las Vegas) and SAC (Sacramento) data centers with a single intent file, and reports
each deviation with its expected and actual value.

Standard library only (Python 3.9+). PyYAML is used if it is installed, but it isn't required.

```bash
python3 -m core.cli audit --intent examples/spine_leaf_intent.yaml             # all sites
python3 -m core.cli audit --intent examples/spine_leaf_intent.yaml --site LVD
python3 -m core.cli audit --intent examples/spine_leaf_intent.yaml --format json
python3 -m core.cli inventory --intent examples/spine_leaf_intent.yaml         # what the intent defines
```

Exit status: `0` compliant, `1` a check failed or a device's state could not be collected, `2` usage or intent error.

## Checks

| Check | What must hold |
|---|---|
| **Underlay MTU** | Every fabric interface exists and has MTU `fabric.mtu` (9216, for RoCEv2 readiness) |
| **BGP underlay / EVPN overlay** | Every leaf has an Established IPv4 underlay session and an Established EVPN session with every spine in its pod (and the reverse), with the right remote AS. No unexpected peers; local AS and router-id match |
| **EVPN RT/RD** | Each VNI on a leaf has the intended route distinguisher and exactly the intended import/export route targets. Both members of a leaf pair agree |
| **VNI-to-VLAN** | Each L2VNI maps to its VLAN and each L3VNI to its VRF, is Up, nothing extra is configured, and both members of a leaf pair are identical |

Leaf pair rows in the table show the side-by-side comparison of the two members, so you can see which one diverged.

## Layout

| Path | Purpose |
|---|---|
| `examples/spine_leaf_intent.yaml` | Fabric intent: MTU, RD formats, segments (L2VNIs), VRFs (L3VNIs), sites, pods, spines and leaf pairs |
| `examples/mock_states/<hostname>.json` | Offline state snapshots for pre-flight validation (compliant baseline) |
| `core/inventory.py` | Loads and validates the intent; derives expected BGP peers, VNIs, RTs and RDs per device |
| `core/collector.py` | `FabricCollector`: concurrent (asyncio) state collection from a `StateSource`; documents the state schema |
| `core/auditor.py` | `Auditor`: the four checks, returning an `AuditReport` of `CheckResult`s and `Mismatch`es |
| `core/cli.py` | `argparse` CLI with colourized per-pod tables or JSON |

## State sources

The auditor only reads the normalized per-device document described in [`core/collector.py`](core/collector.py).
`MockStateSource` reads it from `<state-dir>/<hostname>.json`. A live driver (NX-API, eAPI, gNMI) plugs in by
subclassing `StateSource` and returning the same shape. **No live driver ships yet.**

## Tests

```bash
python3 -m unittest discover -s tests -t .
```

`python3 -m pytest` also works if pytest is installed.

## Data handling

This repository holds code, docs and **fictional** example data only. Real device state, inventories, credentials and
generated reports stay local and are excluded by [`.gitignore`](.gitignore).
