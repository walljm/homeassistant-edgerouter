"""EdgeRouter API client."""
from __future__ import annotations

import logging
import re
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import paramiko

_LOGGER = logging.getLogger(__name__)


class EdgeRouterConnectionError(Exception):
    """Error connecting to EdgeRouter."""


class EdgeRouterAuthenticationError(EdgeRouterConnectionError):
    """Authentication error connecting to EdgeRouter."""


@dataclass
class ClientInfo:
    """Information about a connected client."""

    mac: str
    ip: str | None = None
    hostname: str | None = None
    interface: str | None = None
    lease_expires: str | None = None
    in_arp: bool = False
    in_ndp: bool = False
    has_dhcp_lease: bool = False
    last_seen: datetime = field(default_factory=datetime.now)
    ipv6_addr: str | None = None
    ipv6_duid: str | None = None
    ipv6_lease_state: str | None = None
    ipv6_lease_ends: str | None = None
    ipv6_connection_type: str | None = None
    has_dhcpv6_lease: bool = False
    has_static_reservation: bool = False
    ipv6_addrs: list[str] = field(default_factory=list)
    synthetic: bool = False

    @property
    def name(self) -> str:
        """Return the best name for this client."""
        if self.hostname and self.hostname != "?":
            return self.hostname
        if self.ip:
            return self.ip
        return self.mac



_DHCPV6_LEASES_CMD = (
    "for f in /var/run/dhcpv6-*-pd.leases; do "
    '[ -f "$f" ] && b=$(basename "$f" -pd.leases) && '
    'echo "===${b#dhcpv6-}===" && cat "$f"; '
    "done"
)

_DHCPV6_CONF_CMD = (
    "for f in /var/run/dhcpv6-*-pd.conf; do "
    '[ -f "$f" ] && cat "$f"; '
    "done"
)


def _decode_octal_string(s: str) -> bytes:
    """Decode a dhcpd.leases quoted string (C-style octal escapes) to raw bytes."""
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\":
            if i + 1 < len(s) and s[i + 1] in "01234567":
                j = i + 1
                digits = ""
                while j < len(s) and len(digits) < 3 and s[j] in "01234567":
                    digits += s[j]
                    j += 1
                out.append(int(digits, 8) & 0xFF)
                i = j
                continue
            elif i + 1 < len(s):
                out.append(ord(s[i + 1]))
                i += 2
                continue
        out.append(ord(c) & 0xFF)
        i += 1
    return bytes(out)


def _decode_duid(duid_bytes: bytes) -> dict:
    """Decode a DUID blob; returns type, raw hex, and MAC if derivable."""
    if len(duid_bytes) < 2:
        return {"type": "unknown", "raw": duid_bytes.hex(), "mac": None}
    dtype = int.from_bytes(duid_bytes[0:2], "big")
    if dtype == 1 and len(duid_bytes) >= 8:  # DUID-LLT
        return {"type": "LLT", "raw": duid_bytes.hex(), "mac": duid_bytes[8:].hex(":")}
    if dtype == 2:  # DUID-EN
        return {"type": "EN", "raw": duid_bytes.hex(), "mac": None}
    if dtype == 3 and len(duid_bytes) >= 4:  # DUID-LL
        return {"type": "LL", "raw": duid_bytes.hex(), "mac": duid_bytes[4:].hex(":")}
    if dtype == 4:  # DUID-UUID
        return {"type": "UUID", "raw": duid_bytes.hex(), "mac": None}
    return {"type": f"unknown({dtype})", "raw": duid_bytes.hex(), "mac": None}


def _parse_dhcpv6_conf(output: str) -> dict[str, str]:
    """Parse concatenated dhcpv6 conf file output into DUID raw hex → IPv6 address."""
    mappings: dict[str, str] = {}
    host_block = re.compile(r"host\s+([\w-]+)\s*\{([^}]+)\}", re.DOTALL)
    id_pat = re.compile(r"host-identifier option dhcp6\.client-id ([0-9a-fA-F:]+);")
    addr_pat = re.compile(r"fixed-address6\s+([0-9a-fA-F:]+);")
    for block in host_block.finditer(output):
        body = block.group(2)
        id_m = id_pat.search(body)
        addr_m = addr_pat.search(body)
        if id_m and addr_m:
            duid = id_m.group(1).replace(":", "").lower()
            mappings[duid] = addr_m.group(1)
    return mappings


def _parse_dhcpv6_conf_hostnames(output: str) -> dict[str, str]:
    """Parse concatenated dhcpv6 conf file output into DUID raw hex → hostname."""
    names: dict[str, str] = {}
    host_block = re.compile(r"host\s+([\w-]+)\s*\{([^}]+)\}", re.DOTALL)
    id_pat = re.compile(r"host-identifier option dhcp6\.client-id ([0-9a-fA-F:]+);")
    for block in host_block.finditer(output):
        name = block.group(1)
        body = block.group(2)
        id_m = id_pat.search(body)
        if id_m:
            duid = id_m.group(1).replace(":", "").lower()
            names[duid] = name
    return names


def _parse_dhcpv6_segment(text: str, vlan: str) -> list[dict]:
    """Parse one DHCPv6 leases file into a list of per-stanza dicts."""
    pattern = re.compile(r'ia-na "((?:[^"\\]|\\.)*)" \{')
    blocks = []
    pos = 0
    while True:
        m = pattern.search(text, pos)
        if not m:
            break
        depth, i = 1, m.end()
        while depth > 0 and i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        blocks.append((m.group(1), text[m.end():i - 1]))
        pos = i

    results = []
    for ident_str, body in blocks:
        raw = _decode_octal_string(ident_str)
        if len(raw) < 4:
            continue
        duid = _decode_duid(raw[4:])
        iaaddr = re.search(r"iaaddr\s+([0-9a-fA-F:]+)\s*\{", body)
        state = re.search(r"binding state (\w+);", body)
        ends = re.search(r"ends\s+\d+\s+([\d/]+\s+[\d:]+);", body)
        results.append({
            "duid_raw": duid["raw"],
            "duid_type": duid["type"],
            "mac": duid["mac"],
            "addr": iaaddr.group(1) if iaaddr else None,
            "state": state.group(1) if state else None,
            "ends": ends.group(1) if ends else None,
            "vlan": vlan,
        })
    return results


class EdgeRouterAPI:
    """API client for EdgeRouter devices via SSH."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str | None = None,
        port: int = 22,
        timeout: int = 10,
        key_filename: str | None = None,
    ) -> None:
        """Initialize the EdgeRouter API client."""
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout
        self.key_filename = key_filename
        self._client: paramiko.SSHClient | None = None
        self._lock = threading.Lock()

    def _connect(self) -> paramiko.SSHClient:
        """Open and return an authenticated SSH connection."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": self.timeout,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if self.key_filename:
            kwargs["key_filename"] = self.key_filename
        else:
            kwargs["password"] = self.password
        try:
            client.connect(**kwargs)
        except paramiko.AuthenticationException as err:
            raise EdgeRouterAuthenticationError(
                f"Authentication failed for {self.username}@{self.host}"
            ) from err
        except paramiko.SSHException as err:
            raise EdgeRouterConnectionError(
                f"SSH error connecting to {self.host}: {err}"
            ) from err
        except TimeoutError as err:
            raise EdgeRouterConnectionError(
                f"Timeout connecting to {self.host}"
            ) from err
        except OSError as err:
            raise EdgeRouterConnectionError(
                f"Network error connecting to {self.host}: {err}"
            ) from err
        transport = client.get_transport()
        if transport is not None:
            # Keep the socket alive across the idle gap between poll cycles so a
            # NAT/firewall timeout doesn't silently drop it before we notice.
            transport.set_keepalive(15)
        return client

    def _close_client_locked(self) -> None:
        """Close and forget the persistent connection. Caller must hold self._lock."""
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
            self._client = None

    def close(self) -> None:
        """Close the persistent SSH connection, if any."""
        with self._lock:
            self._close_client_locked()

    def _get_client_locked(self) -> paramiko.SSHClient:
        """Return the persistent connection, reconnecting if it has dropped."""
        if self._client is not None:
            transport = self._client.get_transport()
            if transport is not None and transport.is_active():
                return self._client
            self._close_client_locked()
        self._client = self._connect()
        _LOGGER.debug("Connected to EdgeRouter at %s", self.host)
        return self._client

    @contextmanager
    def _connection(self):
        """Yield the persistent SSH connection, reconnecting only if needed.

        The connection is kept open across calls instead of being torn down and
        re-established every time, since a fresh SSH handshake is the expensive
        part of each poll. Held for the whole `with` block so a poll cycle
        (several commands run back to back) can't interleave with another
        thread reconnecting the same client.
        """
        with self._lock:
            yield self._get_client_locked()

    def _run_command(self, client: paramiko.SSHClient, command: str) -> str:
        """Run a vyatta-wrapped operational command on an already-open client."""
        wrapped = f"/opt/vyatta/bin/vyatta-op-cmd-wrapper {command}"
        try:
            _, stdout, stderr = client.exec_command(wrapped, timeout=self.timeout)
            output = stdout.read().decode("utf-8")
            error = stderr.read().decode("utf-8")
            if error:
                _LOGGER.warning("Command '%s' produced stderr: %s", command, error)
            return output
        except (paramiko.SSHException, OSError) as err:
            self._close_client_locked()
            raise EdgeRouterConnectionError(
                f"SSH error running '{command}' on {self.host}: {err}"
            ) from err

    def _run_raw(self, client: paramiko.SSHClient, command: str) -> str:
        """Run a raw shell command on an already-open client."""
        try:
            _, stdout, stderr = client.exec_command(command, timeout=self.timeout)
            output = stdout.read().decode("utf-8")
            error = stderr.read().decode("utf-8")
            if error:
                _LOGGER.warning("Raw command produced stderr: %s", error)
            return output
        except (paramiko.SSHException, OSError) as err:
            self._close_client_locked()
            raise EdgeRouterConnectionError(
                f"SSH error running command on {self.host}: {err}"
            ) from err

    def _exec_command(self, command: str) -> str:
        """Execute an EdgeOS operational command (opens and closes its own connection)."""
        with self._connection() as client:
            return self._run_command(client, command)

    def _exec_raw_command(self, command: str) -> str:
        """Execute a raw shell command (opens and closes its own connection)."""
        with self._connection() as client:
            return self._run_raw(client, command)

    def test_connection(self) -> bool:
        """Test the connection to the EdgeRouter."""
        try:
            self._exec_command("show version")
            return True
        except EdgeRouterConnectionError:
            return False

    def get_system_info(self) -> dict[str, Any]:
        """Get system information from the EdgeRouter."""
        output = self._exec_command("show version")
        info = {}

        for line in output.strip().split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                info[key.strip().lower().replace(" ", "_")] = value.strip()

        return info

    @staticmethod
    def _parse_arp_output(output: str) -> list[dict[str, str]]:
        entries = []
        mac_pattern = r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"
        for line in output.strip().split("\n"):
            if not line or "Address" in line or "---" in line:
                continue
            parts = line.split()
            if len(parts) >= 4:
                mac_match = re.search(mac_pattern, line)
                if mac_match:
                    entries.append({
                        "ip": parts[0],
                        "mac": mac_match.group(0).lower().replace("-", ":"),
                        "interface": parts[-1] if len(parts) > 4 else "",
                    })
        _LOGGER.debug("Parsed %d ARP entries", len(entries))
        return entries

    @staticmethod
    def _parse_ndp_output(output: str) -> list[dict[str, str]]:
        entries = []
        for line in output.strip().split("\n"):
            parts = line.split()
            if len(parts) < 4 or "lladdr" not in parts:
                continue
            state = parts[-1]
            if state in ("FAILED", "INCOMPLETE"):
                continue
            dev_idx = parts.index("dev")
            lladdr_idx = parts.index("lladdr")
            if dev_idx + 1 >= len(parts) or lladdr_idx + 1 >= len(parts):
                continue
            entries.append({
                "ipv6": parts[0],
                "mac": parts[lladdr_idx + 1].lower(),
                "interface": parts[dev_idx + 1],
                "state": state,
            })
        _LOGGER.debug("Parsed %d NDP entries", len(entries))
        return entries

    @staticmethod
    def _parse_dhcp_leases_output(output: str) -> list[dict[str, str | None]]:
        leases = []
        mac_pattern = r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"
        date_pattern = r"\d{4}/\d{2}/\d{2}"
        in_data = False
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            if "IP address" in line or "---" in line:
                in_data = True
                continue
            if not in_data:
                continue
            parts = line.split()
            if len(parts) < 3:
                continue
            mac_match = re.search(mac_pattern, line)
            if not mac_match:
                continue
            remaining = line[mac_match.end():].strip()
            remaining_parts = remaining.split()
            hostname = remaining_parts[-1] if len(remaining_parts) >= 3 and remaining_parts[-1] != "?" else None
            date_match = re.search(date_pattern, remaining)
            expires = remaining[date_match.start():date_match.start() + 19] if date_match else None
            leases.append({
                "ip": parts[0],
                "mac": mac_match.group(0).lower().replace("-", ":"),
                "hostname": hostname,
                "expires": expires,
            })
        _LOGGER.debug("Parsed %d DHCP leases", len(leases))
        return leases

    @staticmethod
    def _parse_dhcpv6_leases_output(output: str) -> list[dict]:
        all_leases: list[dict] = []
        segments = re.split(r"===(\S+)===", output)
        it = iter(segments[1:])
        for iface, content in zip(it, it):
            all_leases.extend(_parse_dhcpv6_segment(content, iface))
        return all_leases

    @staticmethod
    def _parse_dhcpd_conf_output(output: str) -> list[dict[str, str | None]]:
        results = []
        block_pat = re.compile(r'host\s+(\S+)\s*\{([^}]+)\}', re.DOTALL)
        ip_pat = re.compile(r'fixed-address\s+(\d{1,3}(?:\.\d{1,3}){3})')
        mac_pat = re.compile(r'hardware\s+ethernet\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})')
        for block in block_pat.finditer(output):
            body = block.group(2)
            ip_m = ip_pat.search(body)
            mac_m = mac_pat.search(body)
            if ip_m and mac_m:
                results.append({
                    "ip": ip_m.group(1),
                    "mac": mac_m.group(1).lower().replace("-", ":"),
                    "hostname": block.group(1),
                })
        _LOGGER.debug("Found %d host entries in dhcpd.conf", len(results))
        return results

    @staticmethod
    def _parse_dnsmasq_output(output: str) -> list[dict[str, str | None]]:
        leases = []
        for line in output.strip().split("\n"):
            parts = line.split()
            if len(parts) < 4:
                continue
            leases.append({
                "mac": parts[1].lower(),
                "ip": parts[2],
                "hostname": parts[3] if parts[3] != "*" else None,
            })
        _LOGGER.debug("Parsed %d dnsmasq leases", len(leases))
        return leases

    def get_arp_table(self) -> list[dict[str, str]]:
        """Get the ARP table from the EdgeRouter."""
        return self._parse_arp_output(self._exec_command("show arp"))

    def get_ndp_table(self) -> list[dict[str, str]]:
        """Get the IPv6 NDP neighbor table from the EdgeRouter."""
        return self._parse_ndp_output(self._exec_command("show ipv6 neighbors"))

    def get_dhcp_leases(self) -> list[dict[str, str]]:
        """Get DHCP leases from the EdgeRouter."""
        return self._parse_dhcp_leases_output(self._exec_command("show dhcp leases"))

    def get_dhcpv6_leases(self) -> list[dict]:
        """Get DHCPv6 leases by reading the ISC dhcpd leases files directly.

        Discovers lease files dynamically via glob so no interface names are hardcoded.
        Each file is prefixed with ===<iface>=== so segments can be attributed to
        the correct interface for lease-matching in get_all_clients().
        """
        output = self._exec_raw_command(_DHCPV6_LEASES_CMD)
        leases = self._parse_dhcpv6_leases_output(output)
        _LOGGER.debug("Found %d DHCPv6 lease entries", len(leases))
        return leases

    def get_dhcpv6_static_mappings(self) -> dict[str, str]:
        """Read static DHCPv6 DUID→address mappings from dhcpd conf files.

        Discovers conf files dynamically via glob — no hardcoded interface names.
        """
        output = self._exec_raw_command(_DHCPV6_CONF_CMD)
        mappings = _parse_dhcpv6_conf(output)
        _LOGGER.debug("Found %d static DHCPv6 mappings", len(mappings))
        return mappings

    def get_dhcp_static_reservations(self) -> list[dict[str, str | None]]:
        """Read static DHCP reservations from the generated ISC dhcpd config.

        /opt/vyatta/etc/dhcpd.conf is regenerated from EdgeOS config on every
        commit, covers all VLANs, and uses a clean standard ISC dhcpd format.
        The same MAC may appear in multiple subnets (per-VLAN reservations);
        each is returned as a separate entry so get_all_clients can create
        distinct (mac, interface) keys for them.
        """
        return self._parse_dhcpd_conf_output(self._exec_raw_command("cat /opt/vyatta/etc/dhcpd.conf"))

    def get_dnsmasq_leases(self) -> list[dict[str, str | None]]:
        """Get all leases from dnsmasq lease file (dynamic and static reservations)."""
        return self._parse_dnsmasq_output(
            self._exec_raw_command("cat /var/run/dnsmasq-dhcp.leases 2>/dev/null")
        )

    def get_all_clients(self) -> dict[tuple[str, str], ClientInfo]:
        """Get all connected clients combining ARP, NDP, and DHCP data.

        Returns a dict keyed by (mac, interface). The same MAC may appear under
        multiple interface keys when it has reservations on more than one VLAN.
        Interface is an empty string when it cannot be determined.

        Runs all 7 data sources over the persistent SSH connection, reconnecting
        only if it has dropped since the previous poll.
        """
        clients: dict[tuple[str, str], ClientInfo] = {}
        now = datetime.now()

        # --- Phase 1: Fetch all raw data over a single SSH connection ---
        raw: dict[str, str] = {}
        with self._connection() as ssh:
            _LOGGER.debug("Poll cycle: fetching all data from %s", self.host)
            for label, raw_key, fetcher in [
                ("ARP",           "arp",          lambda c: self._run_command(c, "show arp")),
                ("NDP",           "ndp",          lambda c: self._run_command(c, "show ipv6 neighbors")),
                ("DHCP leases",   "dhcp",         lambda c: self._run_command(c, "show dhcp leases")),
                ("dnsmasq",       "dnsmasq",      lambda c: self._run_raw(c, "cat /var/run/dnsmasq-dhcp.leases 2>/dev/null")),
                ("dhcpd.conf",    "dhcpd",        lambda c: self._run_raw(c, "cat /opt/vyatta/etc/dhcpd.conf")),
                ("DHCPv6 leases", "dhcpv6",       lambda c: self._run_raw(c, _DHCPV6_LEASES_CMD)),
                ("DHCPv6 conf",   "dhcpv6_conf",  lambda c: self._run_raw(c, _DHCPV6_CONF_CMD)),
            ]:
                try:
                    raw[raw_key] = fetcher(ssh)
                except Exception as err:
                    _LOGGER.error("Error fetching %s: %s", label, err)
                    raw[raw_key] = ""

        # --- Phase 2: Parse ---
        arp_entries: list[dict] = []
        try:
            arp_entries = self._parse_arp_output(raw["arp"])
        except Exception as err:
            _LOGGER.error("Error parsing ARP table: %s", err)

        ndp_entries: list[dict] = []
        try:
            ndp_entries = self._parse_ndp_output(raw["ndp"])
        except Exception as err:
            _LOGGER.error("Error parsing NDP table: %s", err)

        dhcp_leases: list[dict] = []
        try:
            dhcp_leases = self._parse_dhcp_leases_output(raw["dhcp"])
        except Exception as err:
            _LOGGER.error("Error parsing DHCP leases: %s", err)

        dnsmasq_leases: list[dict] = []
        try:
            dnsmasq_leases = self._parse_dnsmasq_output(raw["dnsmasq"])
        except Exception as err:
            _LOGGER.error("Error parsing dnsmasq leases: %s", err)

        static_reservations: list[dict] = []
        try:
            static_reservations = self._parse_dhcpd_conf_output(raw["dhcpd"])
        except Exception as err:
            _LOGGER.error("Error parsing dhcpd.conf: %s", err)

        dhcpv6_leases: list[dict] = []
        try:
            dhcpv6_leases = self._parse_dhcpv6_leases_output(raw["dhcpv6"])
            _LOGGER.debug("Found %d DHCPv6 lease entries", len(dhcpv6_leases))
        except Exception as err:
            _LOGGER.error("Error parsing DHCPv6 leases: %s", err)

        static_mappings: dict[str, str] = {}
        static_hostnames: dict[str, str] = {}
        try:
            static_mappings = _parse_dhcpv6_conf(raw["dhcpv6_conf"])
            static_hostnames = _parse_dhcpv6_conf_hostnames(raw["dhcpv6_conf"])
            _LOGGER.debug("Found %d static DHCPv6 mappings", len(static_mappings))
        except Exception as err:
            _LOGGER.error("Error parsing DHCPv6 conf: %s", err)

        # --- Phase 3: Merge ---

        # ARP (IPv4 connectivity)
        for entry in arp_entries:
            mac = entry["mac"]
            iface = entry.get("interface") or ""
            key = (mac, iface)
            if key not in clients:
                clients[key] = ClientInfo(mac=mac)
            clients[key].ip = entry["ip"]
            clients[key].interface = iface or None
            clients[key].in_arp = True
            clients[key].last_seen = now

        # Build helper maps from ARP — used by later sources that don't report interface.
        # prefix_to_iface: "192.168.50" → "eth1.50" (assumes /24, works for home networks)
        # mac_to_arp_iface: first known interface for each MAC
        prefix_to_iface: dict[str, str] = {}
        mac_to_arp_iface: dict[str, str] = {}
        for entry in arp_entries:
            iface = entry.get("interface", "")
            if not iface:
                continue
            parts = entry["ip"].split(".")
            if len(parts) == 4:
                prefix_to_iface[f"{parts[0]}.{parts[1]}.{parts[2]}"] = iface
            if entry["mac"] not in mac_to_arp_iface:
                mac_to_arp_iface[entry["mac"]] = iface

        # NDP (IPv6 connectivity) — group by MAC to deduplicate trunk-port devices
        ndp_by_mac: dict[str, list[dict]] = {}
        for entry in ndp_entries:
            ndp_by_mac.setdefault(entry["mac"], []).append(entry)
        for mac, entries in ndp_by_mac.items():
            # Prefer the ARP interface as canonical key; otherwise use the first
            # NDP-reported interface so we attach to an existing client if possible.
            arp_iface = mac_to_arp_iface.get(mac)
            key = (mac, arp_iface) if arp_iface else (mac, entries[0]["interface"])
            if key not in clients:
                clients[key] = ClientInfo(mac=mac)
            clients[key].in_ndp = True
            clients[key].last_seen = now
            if not clients[key].interface:
                # For NDP-only devices on multiple VLANs show all interfaces.
                ifaces = list(dict.fromkeys(e["interface"] for e in entries))
                clients[key].interface = ", ".join(ifaces)
            # Collect addresses across all NDP interfaces. Global addresses come first
            # (DHCPv6 will insert its lease addr at front later). Link-local addresses
            # are appended with %interface zone ID so they can be used directly in
            # ping/ssh without ambiguity.
            global_addrs = list(dict.fromkeys(
                e["ipv6"] for e in entries if not e["ipv6"].startswith("fe80:")
            ))
            link_local_addrs = list(dict.fromkeys(
                f"{e['ipv6']}%{e['interface']}"
                for e in entries if e["ipv6"].startswith("fe80:")
            ))
            all_addrs = global_addrs + link_local_addrs
            if all_addrs:
                clients[key].ipv6_addrs = all_addrs
                if not clients[key].ipv6_addr:
                    clients[key].ipv6_addr = global_addrs[0] if global_addrs else link_local_addrs[0]

        # DHCP leases — show dhcp leases doesn't report interface; infer from ARP map
        for lease in dhcp_leases:
            mac = lease["mac"]
            iface = mac_to_arp_iface.get(mac, "")
            key = (mac, iface)
            if key not in clients:
                clients[key] = ClientInfo(mac=mac)
                clients[key].ip = lease["ip"]
                clients[key].interface = iface or None
            clients[key].hostname = lease.get("hostname")
            clients[key].lease_expires = lease.get("expires")
            clients[key].has_dhcp_lease = True
            if clients[key].in_arp:
                clients[key].last_seen = now

        # dnsmasq leases — seeds offline devices with static reservations not in ARP
        dynamic_macs = {mac for (mac, _), c in clients.items() if c.has_dhcp_lease}
        for lease in dnsmasq_leases:
            mac = lease["mac"]
            ip = lease.get("ip") or ""
            parts = ip.split(".")
            prefix = f"{parts[0]}.{parts[1]}.{parts[2]}" if len(parts) == 4 else ""
            iface = prefix_to_iface.get(prefix) or mac_to_arp_iface.get(mac, "")
            key = (mac, iface)
            if key not in clients:
                clients[key] = ClientInfo(
                    mac=mac,
                    ip=ip,
                    interface=iface or None,
                    last_seen=datetime.fromtimestamp(0),
                )
            if not clients[key].hostname and lease.get("hostname"):
                clients[key].hostname = lease["hostname"]
            if mac not in dynamic_macs:
                clients[key].has_static_reservation = True

        # Static DHCP reservations (dhcpd.conf) — authoritative source
        # Each (mac, interface) pair gets its own entry; same MAC on two VLANs → two entries.
        for reservation in static_reservations:
            mac = reservation["mac"]
            ip = reservation.get("ip") or ""
            parts = ip.split(".")
            prefix = f"{parts[0]}.{parts[1]}.{parts[2]}" if len(parts) == 4 else ""
            iface = prefix_to_iface.get(prefix) or mac_to_arp_iface.get(mac, "")
            key = (mac, iface)
            if key not in clients:
                clients[key] = ClientInfo(
                    mac=mac,
                    ip=ip,
                    interface=iface or None,
                    last_seen=datetime.fromtimestamp(0),
                )
            clients[key].has_static_reservation = True
            if not clients[key].ip:
                clients[key].ip = ip
            if not clients[key].hostname and reservation.get("hostname"):
                clients[key].hostname = reservation["hostname"]

        # DHCPv6 leases — group by MAC; non-MAC DUIDs (EN, UUID) collected separately
        ipv6_by_mac: dict[str, list[dict]] = {}
        non_mac_duid_leases: list[dict] = []
        for lease in dhcpv6_leases:
            mac = lease.get("mac")
            if mac:
                ipv6_by_mac.setdefault(mac.lower(), []).append(lease)
            elif lease.get("addr"):
                non_mac_duid_leases.append(lease)
            else:
                _LOGGER.debug(
                    "DHCPv6 lease with DUID type %s has no MAC and no address, skipping",
                    lease.get("duid_type"),
                )

        for (mac, iface), client in clients.items():
            if mac not in ipv6_by_mac:
                continue
            leases = ipv6_by_mac[mac]
            preferred = [e for e in leases if e.get("vlan") == iface and e.get("addr")]
            fallback = [e for e in leases if e.get("addr")]
            chosen = (preferred or fallback or leases)[-1]
            lease_addr = chosen.get("addr")
            client.ipv6_addr = lease_addr
            client.ipv6_duid = chosen.get("duid_raw")
            client.ipv6_lease_state = chosen.get("state")
            client.ipv6_lease_ends = chosen.get("ends")
            client.has_dhcpv6_lease = True
            if lease_addr:
                if lease_addr in client.ipv6_addrs:
                    client.ipv6_addrs.remove(lease_addr)
                client.ipv6_addrs.insert(0, lease_addr)

        # For non-MAC DUIDs (EN, UUID): match to clients via IPv6 address.
        # Two sources for the address:
        #   1. Active lease file (iaaddr block) — covers dynamic non-MAC DUID clients
        #   2. Static conf file (fixed-address6) — covers static non-MAC DUID clients whose
        #      lease file has only a cltt entry with no iaaddr block
        non_mac_static_duids: dict[str, str] = {}
        for duid, addr in static_mappings.items():
            try:
                if not _decode_duid(bytes.fromhex(duid)).get("mac"):
                    non_mac_static_duids[duid] = addr
            except (ValueError, Exception) as err:
                _LOGGER.warning("Skipping malformed DUID %r in conf file: %s", duid, err)
        needs_addr_matching = non_mac_duid_leases or non_mac_static_duids
        if needs_addr_matching:
            ipv6_addr_to_key: dict[str, tuple[str, str]] = {}
            for key, client in clients.items():
                for a in client.ipv6_addrs:
                    ipv6_addr_to_key.setdefault(a.split("%")[0], key)

            # Match active non-MAC DUID leases (have an iaaddr)
            for lease in non_mac_duid_leases:
                key = ipv6_addr_to_key.get(lease["addr"])
                if key:
                    client = clients[key]
                    client.ipv6_duid = lease.get("duid_raw")
                    client.ipv6_lease_state = lease.get("state")
                    client.ipv6_lease_ends = lease.get("ends")
                    client.has_dhcpv6_lease = True
                    if lease["addr"] not in client.ipv6_addrs:
                        client.ipv6_addrs.insert(0, lease["addr"])
                    if not client.ipv6_addr:
                        client.ipv6_addr = lease["addr"]
                else:
                    _LOGGER.debug(
                        "DHCPv6 lease DUID type %s addr %s: no matching NDP client",
                        lease.get("duid_type"), lease["addr"],
                    )

            # Match static non-MAC DUIDs via their fixed-address6 from the conf file.
            # Static clients typically have no iaaddr in the lease file — the conf is the
            # only source of their assigned address.
            already_matched = {c.ipv6_duid for c in clients.values() if c.ipv6_duid}
            for duid_raw, conf_addr in non_mac_static_duids.items():
                if duid_raw in already_matched:
                    continue
                key = ipv6_addr_to_key.get(conf_addr)
                if key:
                    client = clients[key]
                    client.ipv6_duid = duid_raw
                    if conf_addr in client.ipv6_addrs:
                        client.ipv6_addrs.remove(conf_addr)
                    client.ipv6_addrs.insert(0, conf_addr)
                    client.ipv6_addr = conf_addr
                else:
                    _LOGGER.debug(
                        "Static DHCPv6 DUID (non-MAC type) conf addr %s: no matching NDP client",
                        conf_addr,
                    )

        # DHCPv6 static mappings — determine connection type
        mac_to_static_ipv6: dict[str, str] = {}
        for duid_raw, addr in static_mappings.items():
            try:
                decoded = _decode_duid(bytes.fromhex(duid_raw))
                if decoded.get("mac"):
                    mac_to_static_ipv6[decoded["mac"]] = addr
            except (ValueError, Exception) as err:
                _LOGGER.warning("Skipping malformed DUID %r in static mappings: %s", duid_raw, err)

        for client in clients.values():
            if client.has_dhcpv6_lease:
                if client.ipv6_duid and client.ipv6_duid in static_mappings:
                    client.ipv6_connection_type = "static"
                    conf_addr = static_mappings[client.ipv6_duid]
                    if not client.ipv6_addr:
                        client.ipv6_addr = conf_addr
                    if conf_addr in client.ipv6_addrs:
                        client.ipv6_addrs.remove(conf_addr)
                    client.ipv6_addrs.insert(0, conf_addr)
                else:
                    client.ipv6_connection_type = "dhcpv6"
            elif client.ipv6_duid and client.ipv6_duid in static_mappings:
                # Non-MAC DUID (EN/UUID) matched via NDP address — has_dhcpv6_lease is False
                # because the lease file has no iaaddr block for static clients.
                client.ipv6_connection_type = "static"
                if not client.ipv6_addr:
                    client.ipv6_addr = static_mappings[client.ipv6_duid]
            elif client.mac in mac_to_static_ipv6:
                addr = mac_to_static_ipv6[client.mac]
                # Always move the static address to front so it survives any list cap.
                if addr in client.ipv6_addrs:
                    client.ipv6_addrs.remove(addr)
                client.ipv6_addrs.insert(0, addr)
                client.ipv6_addr = addr
                client.ipv6_connection_type = "static"

        # Synthetic entries for non-MAC static DUIDs that couldn't be matched via NDP.
        # These ensure every static DHCPv6 reservation appears in the Static v6 tab even
        # when the device's IPv6 address isn't currently in the NDP table.
        #
        # Before creating a synthetic, try hostname-based matching: if the conf file's
        # host block name (e.g. "mac-mini") matches a real client's DHCP hostname, apply
        # the static IPv6 info to the real client so it shows as online.
        matched_duids = {c.ipv6_duid for c in clients.values() if c.ipv6_duid}
        for duid_raw, conf_addr in non_mac_static_duids.items():
            if duid_raw in matched_duids:
                continue
            hostname = static_hostnames.get(duid_raw)

            # Attempt hostname match
            if hostname:
                hostname_lc = hostname.lower()
                real_key = next(
                    (k for k, c in clients.items()
                     if not c.synthetic and (c.hostname or "").lower() == hostname_lc),
                    None,
                )
                if real_key:
                    real_client = clients[real_key]
                    real_client.ipv6_duid = duid_raw
                    real_client.ipv6_connection_type = "static"
                    if conf_addr not in real_client.ipv6_addrs:
                        real_client.ipv6_addrs.insert(0, conf_addr)
                    real_client.ipv6_addr = real_client.ipv6_addr or conf_addr
                    _LOGGER.debug(
                        "Matched non-MAC DUID %s (%s) to real client %s via hostname",
                        duid_raw[:8], hostname, real_key[0],
                    )
                    continue

            syn_key = (f"duid:{duid_raw}", "")
            clients[syn_key] = ClientInfo(
                mac=f"duid:{duid_raw}",
                ipv6_addr=conf_addr,
                ipv6_addrs=[conf_addr],
                ipv6_duid=duid_raw,
                hostname=hostname,
                ipv6_connection_type="static",
                last_seen=datetime.fromtimestamp(0),
                synthetic=True,
            )
            _LOGGER.debug(
                "Created synthetic static-IPv6 entry for DUID %s (%s) addr %s",
                duid_raw[:8], hostname or "?", conf_addr,
            )

        _LOGGER.info("Found %d client entries (MAC+interface pairs)", len(clients))
        return clients
