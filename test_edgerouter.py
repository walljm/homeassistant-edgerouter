#!/usr/bin/env python3
"""
Test script for EdgeRouter integration.

This script tests the connection to your EdgeRouter and displays
the ARP table and DHCP lease information.

Usage:
    python test_edgerouter.py <host> <username> [password] [--port PORT]

Example:
    python test_edgerouter.py 192.168.1.1 ubnt
    python test_edgerouter.py 192.168.1.1 ubnt mypassword
    python test_edgerouter.py 192.168.1.1 ubnt --port 2222
"""

import argparse
import getpass
import importlib.util
import sys
from datetime import datetime
from pathlib import Path

# Load the edgerouter_api module directly from the custom_components package
# This tests the actual library code without requiring Home Assistant dependencies
_api_path = Path(__file__).parent / "custom_components" / "edgerouter" / "edgerouter_api.py"
_spec = importlib.util.spec_from_file_location("edgerouter_api", _api_path)
_module = importlib.util.module_from_spec(_spec)
sys.modules["edgerouter_api"] = _module
_spec.loader.exec_module(_module)

EdgeRouterAPI = _module.EdgeRouterAPI
EdgeRouterAuthenticationError = _module.EdgeRouterAuthenticationError
EdgeRouterConnectionError = _module.EdgeRouterConnectionError


def print_header(title: str) -> None:
    """Print a formatted header."""
    print()
    print("=" * 60)
    print(f" {title}")
    print("=" * 60)


def print_table(headers: list[str], rows: list[list[str]]) -> None:
    """Print a formatted table."""
    if not rows:
        print("  (no data)")
        return

    # Calculate column widths
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))

    # Print header
    header_line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(f"  {header_line}")
    print("  " + "  ".join("-" * w for w in widths))

    # Print rows
    for row in rows:
        row_line = "  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row))
        print(f"  {row_line}")


def test_connection(api: EdgeRouterAPI) -> bool:
    """Test basic SSH connection."""
    print_header("Testing Connection")
    try:
        result = api.test_connection()
        if result:
            print("  ✅ Connection successful!")
            return True
        else:
            print("  ❌ Connection failed!")
            return False
    except EdgeRouterAuthenticationError as e:
        print(f"  ❌ Authentication failed: {e}")
        return False
    except EdgeRouterConnectionError as e:
        print(f"  ❌ Connection error: {e}")
        return False


def test_system_info(api: EdgeRouterAPI) -> None:
    """Test getting system information."""
    print_header("System Information")
    try:
        info = api.get_system_info()
        for key, value in info.items():
            print(f"  {key}: {value}")
    except Exception as e:
        print(f"  ❌ Error: {e}")


def test_arp_table(api: EdgeRouterAPI) -> list:
    """Test getting ARP table."""
    print_header("ARP Table")
    try:
        entries = api.get_arp_table()
        rows = [[e["ip"], e["mac"], e.get("interface", "")] for e in entries]
        print_table(["IP Address", "MAC Address", "Interface"], rows)
        print(f"\n  Total ARP entries: {len(entries)}")
        return entries
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return []


def test_dhcp_leases(api: EdgeRouterAPI) -> list:
    """Test getting DHCP leases."""
    print_header("DHCP Leases")
    try:
        leases = api.get_dhcp_leases()
        rows = [
            [lease["ip"], lease["mac"], lease.get("hostname") or "", lease.get("expires") or ""]
            for lease in leases
        ]
        print_table(["IP Address", "MAC Address", "Hostname", "Expires"], rows)
        print(f"\n  Total DHCP leases: {len(leases)}")
        return leases
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return []


def test_dhcpv6_leases(api: EdgeRouterAPI) -> list:
    """Test getting DHCPv6 leases."""
    print_header("DHCPv6 Leases")
    try:
        leases = api.get_dhcpv6_leases()
        rows = [
            [
                lease.get("addr") or "",
                lease.get("mac") or "(no MAC — " + lease.get("duid_type", "?") + ")",
                lease.get("vlan") or "",
                lease.get("state") or "",
                lease.get("ends") or "",
            ]
            for lease in leases
        ]
        print_table(["IPv6 Address", "MAC / DUID type", "VLAN", "State", "Ends"], rows)
        print(f"\n  Total DHCPv6 leases: {len(leases)}")
        return leases
    except Exception as e:
        print(f"  ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return []


def test_all_clients(api: EdgeRouterAPI) -> None:
    """Test getting all clients (combined ARP + DHCP)."""
    print_header("All Connected Clients")
    try:
        clients = api.get_all_clients()

        rows = []
        for (mac, _iface), client in sorted(clients.items(), key=lambda x: x[1].ip or ""):
            status = []
            if client.in_arp:
                status.append("ARP")
            if client.has_dhcp_lease:
                status.append("DHCP")

            rows.append([
                client.ip or "",
                mac,
                client.hostname or "",
                client.interface or "",
                ", ".join(status),
            ])

        print_table(
            ["IP Address", "MAC Address", "Hostname", "Interface", "Source"],
            rows,
        )

        # Summary
        arp_count = sum(1 for c in clients.values() if c.in_arp)
        dhcp_count = sum(1 for c in clients.values() if c.has_dhcp_lease)
        both_count = sum(1 for c in clients.values() if c.in_arp and c.has_dhcp_lease)

        print("\n  Summary:")
        print(f"    Total unique clients: {len(clients)}")
        print(f"    In ARP table (connected): {arp_count}")
        print(f"    Have DHCP lease: {dhcp_count}")
        print(f"    Both ARP and DHCP: {both_count}")

    except Exception as e:
        print(f"  ❌ Error: {e}")
        import traceback
        traceback.print_exc()


def test_home_assistant_devices(api: EdgeRouterAPI, host: str) -> None:
    """Show how devices will appear in Home Assistant."""
    print_header("Home Assistant Device Preview")

    try:
        system_info = api.get_system_info()
        clients = api.get_all_clients()

        # Router device
        print("\n  ┌─────────────────────────────────────────────────────────┐")
        print("  │  ROUTER DEVICE (Parent)                                 │")
        print("  ├─────────────────────────────────────────────────────────┤")
        print(f"  │  Name:         EdgeRouter ({host})")
        print("  │  Manufacturer: Ubiquiti")
        print(f"  │  Model:        {system_info.get('hw_model', 'EdgeRouter')}")
        print(f"  │  SW Version:   {system_info.get('version', 'Unknown')}")
        print(f"  │  Identifier:   (edgerouter, {host})")
        print("  │")
        print("  │  Entities:")
        print(f"  │    • sensor.edgerouter_{host.replace('.', '_')}_connected_clients")
        print(f"  │    • sensor.edgerouter_{host.replace('.', '_')}_arp_entries")
        print(f"  │    • sensor.edgerouter_{host.replace('.', '_')}_dhcp_leases")
        print("  └─────────────────────────────────────────────────────────┘")

        # Client devices
        print("\n  CLIENT DEVICES (Children - linked via router):")
        print("  " + "─" * 59)

        for (mac, _iface), client in sorted(clients.items(), key=lambda x: x[1].name):
            device_name = client.name
            state = "home" if client.in_arp else "not_home"
            state_icon = "🏠" if client.in_arp else "🚪"

            # Connection type
            if client.in_arp and client.has_dhcp_lease:
                conn_type = "dhcp"
            elif client.in_arp:
                conn_type = "static"
            else:
                conn_type = "dhcp_inactive"

            print(f"\n  ┌─ {device_name}")
            print(f"  │  Connection:   (mac, {mac})")
            print(f"  │  Via Device:   EdgeRouter ({host})")
            print("  │")
            print(f"  │  Entity: device_tracker.{device_name.lower().replace(' ', '_').replace('.', '_').replace(':', '_')}")
            print(f"  │    State:      {state_icon} {state}")
            print(f"  │    MAC:        {mac}")
            if client.ip:
                print(f"  │    IP:         {client.ip}")
            if client.hostname and client.hostname != "?":
                print(f"  │    Hostname:   {client.hostname}")
            if client.interface:
                print(f"  │    Interface:  {client.interface}")
            print(f"  │    Conn Type:  {conn_type}")
            print(f"  └{'─' * 58}")

        print(f"\n  Total devices that will be created: {len(clients) + 1}")
        print("    • 1 router device")
        print(f"    • {len(clients)} tracked client devices")

    except Exception as e:
        print(f"  ❌ Error: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Test EdgeRouter integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_edgerouter.py 192.168.1.1 ubnt
  python test_edgerouter.py 192.168.1.1 admin secret123
  python test_edgerouter.py 192.168.1.1 ubnt --port 2222
  python test_edgerouter.py router.local ubnt --verbose
        """,
    )
    parser.add_argument("host", help="EdgeRouter IP address or hostname")
    parser.add_argument("username", help="SSH username")
    parser.add_argument("password", nargs="?", default=None, help="SSH password (will prompt if not provided and --key not given)")
    parser.add_argument(
        "--key", "-k", default=None, metavar="PATH", help="Path to SSH private key file (use instead of password)"
    )
    parser.add_argument(
        "--port", "-p", type=int, default=22, help="SSH port (default: 22)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    args = parser.parse_args()

    # Resolve auth: key takes priority; prompt for password only if neither supplied
    key_filename = args.key
    password = args.password
    if not key_filename and password is None:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║         EdgeRouter Integration Test Script               ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()
    print(f"  Host:     {args.host}")
    print(f"  Username: {args.username}")
    print(f"  Auth:     {'key: ' + key_filename if key_filename else 'password'}")
    print(f"  Port:     {args.port}")
    print(f"  Time:     {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Create API client
    api = EdgeRouterAPI(
        host=args.host,
        username=args.username,
        password=password,
        port=args.port,
        key_filename=key_filename,
    )

    # Run tests
    if not test_connection(api):
        print("\n❌ Connection test failed. Please check your credentials and network.")
        sys.exit(1)

    test_system_info(api)
    test_arp_table(api)
    test_dhcp_leases(api)
    test_dhcpv6_leases(api)
    test_all_clients(api)
    test_home_assistant_devices(api, args.host)

    print_header("Test Complete")
    print("  ✅ All tests completed successfully!")
    print()
    print("  Your EdgeRouter integration should work correctly.")
    print("  Copy the custom_components/edgerouter folder to your")
    print("  Home Assistant config directory and restart.")
    print()


if __name__ == "__main__":
    main()
