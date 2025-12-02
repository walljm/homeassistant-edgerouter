"""EdgeRouter API client."""
from __future__ import annotations

import logging
import re
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
    has_dhcp_lease: bool = False
    last_seen: datetime = field(default_factory=datetime.now)

    @property
    def name(self) -> str:
        """Return the best name for this client."""
        if self.hostname and self.hostname != "?":
            return self.hostname
        if self.ip:
            return self.ip
        return self.mac


class EdgeRouterAPI:
    """API client for EdgeRouter devices via SSH."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        timeout: int = 10,
    ) -> None:
        """Initialize the EdgeRouter API client."""
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.timeout = timeout

    def _exec_command(self, command: str) -> str:
        """Execute a command on the EdgeRouter via SSH."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
            )
            _LOGGER.debug("Connected to EdgeRouter at %s", self.host)

            # EdgeOS requires commands to be run through the CLI wrapper
            # Use /opt/vyatta/bin/vyatta-op-cmd-wrapper for operational commands
            wrapped_command = f"/opt/vyatta/bin/vyatta-op-cmd-wrapper {command}"
            stdin, stdout, stderr = client.exec_command(wrapped_command, timeout=self.timeout)
            output = stdout.read().decode("utf-8")
            error = stderr.read().decode("utf-8")

            if error:
                _LOGGER.warning("Command '%s' produced error: %s", command, error)

            return output

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
        finally:
            client.close()

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

    def get_arp_table(self) -> list[dict[str, str]]:
        """Get the ARP table from the EdgeRouter."""
        output = self._exec_command("show arp")
        entries = []

        _LOGGER.debug("ARP table output:\n%s", output)

        lines = output.strip().split("\n")
        for line in lines:
            # Skip headers and empty lines
            if not line or "Address" in line or "---" in line:
                continue

            # Parse ARP entry - format varies but typically:
            # IP address       HW type     Flags       HW address            Mask     Device
            # Or: IP (incomplete) on interface
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[0]
                # Look for MAC address pattern
                mac_pattern = r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"
                mac_match = re.search(mac_pattern, line)
                if mac_match:
                    mac = mac_match.group(0).lower().replace("-", ":")
                    interface = parts[-1] if len(parts) > 4 else ""
                    entries.append({
                        "ip": ip,
                        "mac": mac,
                        "interface": interface,
                    })

        _LOGGER.debug("Parsed %d ARP entries", len(entries))
        return entries

    def get_dhcp_leases(self) -> list[dict[str, str]]:
        """Get DHCP leases from the EdgeRouter."""
        output = self._exec_command("show dhcp leases")
        leases = []

        _LOGGER.debug("DHCP leases output:\n%s", output)

        lines = output.strip().split("\n")
        in_data = False
        
        for line in lines:
            # Skip headers and empty lines
            if not line.strip():
                continue
            if "IP address" in line or "---" in line:
                in_data = True
                continue
            if not in_data:
                continue

            # Parse DHCP lease - format typically:
            # IP address      Hardware Address   Lease expiration     Pool       Client Name
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[0]
                mac_pattern = r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"
                mac_match = re.search(mac_pattern, line)
                
                if mac_match:
                    mac = mac_match.group(0).lower().replace("-", ":")
                    
                    # Try to extract hostname (usually last field or before pool name)
                    hostname = None
                    # Look for hostname after lease expiration
                    remaining = line[mac_match.end():].strip()
                    remaining_parts = remaining.split()
                    if len(remaining_parts) >= 3:
                        # Skip date/time and pool name, hostname is often last
                        hostname = remaining_parts[-1] if remaining_parts[-1] != "?" else None
                    
                    # Extract expiration info
                    expires = None
                    date_pattern = r"\d{4}/\d{2}/\d{2}"
                    date_match = re.search(date_pattern, remaining)
                    if date_match:
                        expires = remaining[date_match.start():date_match.start() + 19]

                    leases.append({
                        "ip": ip,
                        "mac": mac,
                        "hostname": hostname,
                        "expires": expires,
                    })

        _LOGGER.debug("Parsed %d DHCP leases", len(leases))
        return leases

    def get_all_clients(self) -> dict[str, ClientInfo]:
        """Get all connected clients by combining ARP and DHCP data."""
        clients: dict[str, ClientInfo] = {}
        now = datetime.now()

        # Get ARP entries
        try:
            arp_entries = self.get_arp_table()
            for entry in arp_entries:
                mac = entry["mac"]
                if mac not in clients:
                    clients[mac] = ClientInfo(mac=mac)
                clients[mac].ip = entry["ip"]
                clients[mac].interface = entry.get("interface")
                clients[mac].in_arp = True
                clients[mac].last_seen = now
        except Exception as err:
            _LOGGER.error("Error getting ARP table: %s", err)

        # Get DHCP leases
        try:
            dhcp_leases = self.get_dhcp_leases()
            for lease in dhcp_leases:
                mac = lease["mac"]
                if mac not in clients:
                    clients[mac] = ClientInfo(mac=mac)
                    clients[mac].ip = lease["ip"]
                clients[mac].hostname = lease.get("hostname")
                clients[mac].lease_expires = lease.get("expires")
                clients[mac].has_dhcp_lease = True
                if clients[mac].in_arp:
                    clients[mac].last_seen = now
        except Exception as err:
            _LOGGER.error("Error getting DHCP leases: %s", err)

        _LOGGER.info("Found %d unique clients", len(clients))
        return clients
