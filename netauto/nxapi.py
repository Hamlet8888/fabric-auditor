"""
Live state from Nexus switches over NX-API.

:class:`NxapiClient` sends show commands to one switch with NX-API's JSON-RPC interface
(``POST https://<switch>/ins``). :class:`NxapiSource` plugs it into the collector: for each
switch it runs the commands :mod:`netauto.nxos` asks for, on the switch's mgmt0 address
from the expected state (or a ``--hosts`` override), and returns the normalized state.

On the switch, NX-API must be enabled (``feature nxapi``) and reachable from where this
runs. In the network-design configs, mgmt0 sits in VRF management with SSH and the vty
ACL; NX-API also needs ``nxapi use-vrf management`` and HTTPS allowed from the same
management subnets.

Credentials come from the environment (``NETAUTO_USERNAME`` and ``NETAUTO_PASSWORD``) or
an interactive prompt, never from a file in the repository. TLS certificates are verified
unless ``verify=False`` (``--insecure``) is set for a lab with self-signed certificates;
``ca_file`` trusts a private CA.

Standard library only (Python 3.9+).
"""

from __future__ import annotations

import asyncio
import base64
import json
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from netauto import nxos
from netauto.collector import StateError, StateSource
from netauto.expected import Device


class NxapiClient:
    """Runs show commands on one switch through NX-API JSON-RPC."""

    def __init__(self, address: str, username: str, password: str, *, scheme: str = "https",
                 port: Optional[int] = None, verify: bool = True, ca_file: Optional[str] = None,
                 timeout: float = 30.0) -> None:
        host = f"[{address}]" if ":" in address else address
        self.url = f"{scheme}://{host}{f':{port}' if port else ''}/ins"
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        self.headers = {"Content-Type": "application/json-rpc", "Authorization": f"Basic {token}"}
        self.timeout = timeout
        self.context = None
        if scheme == "https":
            self.context = ssl.create_default_context(cafile=ca_file)
            if not verify:
                self.context.check_hostname = False
                self.context.verify_mode = ssl.CERT_NONE

    def run(self, commands: Sequence[str], ascii_commands: Sequence[str] = ()) -> Dict[str, Any]:
        """{command: output}: parsed JSON for structured commands, text for ``ascii_commands``."""
        payload = [{"jsonrpc": "2.0", "method": "cli_ascii" if c in ascii_commands else "cli",
                    "params": {"cmd": c, "version": 1}, "id": i + 1} for i, c in enumerate(commands)]
        request = urllib.request.Request(self.url, data=json.dumps(payload).encode(), headers=self.headers,
                                         method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise StateError(f"NX-API refused the login ({exc.code})") from None
            raise StateError(f"NX-API HTTP {exc.code} from {self.url}") from None
        except urllib.error.URLError as exc:
            raise StateError(f"cannot reach {self.url}: {exc.reason}") from None
        except (OSError, json.JSONDecodeError) as exc:
            raise StateError(f"bad NX-API response from {self.url}: {exc}") from None

        answers = body if isinstance(body, list) else [body]
        by_id = {a.get("id"): a for a in answers if isinstance(a, dict)}
        out: Dict[str, Any] = {}
        for i, cmd in enumerate(commands):
            a = by_id.get(i + 1)
            if a is None:
                raise StateError(f"no NX-API answer for {cmd!r}")
            if a.get("error"):
                err = a["error"]
                detail = (err.get("data") or {}).get("msg") or err.get("message")
                raise StateError(f"{cmd!r} failed on the switch: {str(detail).strip()}")
            result = a.get("result") or {}
            # An empty table comes back as a null result.
            out[cmd] = (result.get("msg") or result.get("body") or "") if cmd in ascii_commands \
                else (result.get("body") or {})
        return out


class NxapiSource(StateSource):
    """Collects normalized state from each switch over NX-API.

    ``hosts`` maps hostname to the address to connect to (``host`` or ``host:port``); a switch not in it is reached on
    its mgmt0 address from the expected state. Raw outputs are kept in :attr:`raw` (by
    hostname) when ``keep_raw`` is set, so ``netauto collect --raw`` can save them.
    """

    name = "nxapi"

    def __init__(self, username: str, password: str, *, hosts: Optional[Dict[str, str]] = None,
                 keep_raw: bool = False, **client_options: Any) -> None:
        self.username, self.password = username, password
        self.hosts = hosts or {}
        self.client_options = client_options
        self.keep_raw = keep_raw
        self.raw: Dict[str, Dict[str, Any]] = {}

    def address(self, device: Device) -> str:
        address = self.hosts.get(device.hostname) or device.mgmt
        if not address:
            raise StateError("no address: not in --hosts and the expected state has no mgmt0 address")
        return address

    def client(self, device: Device) -> NxapiClient:
        address, options = self.address(device), dict(self.client_options)
        host, sep, port = address.rpartition(":")
        if sep and host.count(":") == 0 and port.isdigit():  # "host:port"; an IPv6 address has more colons
            address, options["port"] = host, int(port)
        return NxapiClient(address, self.username, self.password, **options)

    async def fetch(self, device: Device) -> Dict[str, Any]:
        cmds: List[str] = nxos.commands(device)
        client = self.client(device)
        # urllib blocks, so each switch gets a worker thread and the collector stays concurrent.
        raw = await asyncio.to_thread(client.run, cmds, [c for c in cmds if c in nxos.ASCII])
        if self.keep_raw:
            self.raw[device.hostname] = raw
        stamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        return nxos.parse(device, raw, collected_at=stamp)
