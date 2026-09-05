"""Unit tests for EdgeRouter API parsing logic."""
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from edgerouter_api import (
    EdgeRouterAPI,
    _decode_duid,
    _decode_octal_string,
    _parse_dhcpv6_conf,
    _parse_dhcpv6_segment,
)

# All addresses in this file are from documentation ranges:
#   IPv4: 192.0.2.x (RFC 5737)
#   IPv6: 2001:db8::/32 (RFC 3849)
# MACs and DUIDs are entirely synthetic.


# ---------------------------------------------------------------------------
# _decode_octal_string
# ---------------------------------------------------------------------------

class TestDecodeOctalString:
    def test_plain_ascii(self):
        assert _decode_octal_string("hello") == b"hello"

    def test_single_octal_escape(self):
        # r"\001" is 4 literal chars: \, 0, 0, 1
        assert _decode_octal_string(r"\001") == bytes([1])

    def test_null_byte(self):
        assert _decode_octal_string(r"\000") == bytes([0])

    def test_high_byte(self):
        # \377 = 0xFF = 255
        assert _decode_octal_string(r"\377") == bytes([0xFF])

    def test_multiple_octal_escapes(self):
        assert _decode_octal_string(r"\000\001\002") == bytes([0, 1, 2])

    def test_mixed_ascii_and_octal(self):
        result = _decode_octal_string(r"AB\001CD")
        assert result == b"AB\x01CD"

    def test_duid_type_llt_prefix(self):
        # DUID-LLT type field: \000\001 = bytes [0, 1]
        result = _decode_octal_string(r"\000\001")
        assert result == bytes([0, 1])


# ---------------------------------------------------------------------------
# _decode_duid
# ---------------------------------------------------------------------------
#
# Synthetic DUIDs used throughout:
#   Device A — DUID-LLT: type=0001, hwtype=0001, time=01020304, MAC=aa:bb:cc:dd:ee:ff
#   Device B — DUID-LL:  type=0003, hwtype=0001, MAC=11:22:33:44:55:66
#   Device C — DUID-EN:  type=0002
#   Device D — DUID-UUID: type=0004

_DUID_LLT_BYTES = bytes([0x00, 0x01, 0x00, 0x01,   # type=LLT, hwtype=ethernet
                          0x01, 0x02, 0x03, 0x04,   # timestamp
                          0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])  # MAC

_DUID_LL_BYTES = bytes([0x00, 0x03, 0x00, 0x01,    # type=LL, hwtype=ethernet
                         0x11, 0x22, 0x33, 0x44, 0x55, 0x66])  # MAC

_DUID_EN_BYTES = bytes([0x00, 0x02, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04])

_DUID_UUID_BYTES = bytes([0x00, 0x04]) + bytes(16)


class TestDecodeDuid:
    def test_llt_type_and_mac(self):
        result = _decode_duid(_DUID_LLT_BYTES)
        assert result["type"] == "LLT"
        assert result["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_llt_raw_hex(self):
        result = _decode_duid(_DUID_LLT_BYTES)
        assert result["raw"] == "0001000101020304aabbccddeeff"

    def test_ll_type_and_mac(self):
        result = _decode_duid(_DUID_LL_BYTES)
        assert result["type"] == "LL"
        assert result["mac"] == "11:22:33:44:55:66"

    def test_ll_raw_hex(self):
        result = _decode_duid(_DUID_LL_BYTES)
        assert result["raw"] == "00030001112233445566"

    def test_en_no_mac(self):
        result = _decode_duid(_DUID_EN_BYTES)
        assert result["type"] == "EN"
        assert result["mac"] is None

    def test_uuid_no_mac(self):
        result = _decode_duid(_DUID_UUID_BYTES)
        assert result["type"] == "UUID"
        assert result["mac"] is None

    def test_too_short_returns_unknown(self):
        result = _decode_duid(bytes([0x00]))
        assert result["type"] == "unknown"
        assert result["mac"] is None

    def test_llt_too_short_for_mac_payload(self):
        # 4-byte LLT: has type but no timestamp/MAC — falls through to unknown
        result = _decode_duid(bytes([0x00, 0x01, 0x00, 0x01]))
        assert "unknown" in result["type"]
        assert result["mac"] is None


# ---------------------------------------------------------------------------
# _parse_dhcpv6_segment
# ---------------------------------------------------------------------------
#
# Lease file ident string format: IAID (4 bytes) + DUID bytes, C-style octal escapes.
#
# Device A static lease (no iaaddr — router has a static mapping, daemon omits the block):
#   IAID = \000\000\000\001
#   DUID-LLT = \000\001\000\001\001\002\003\004\252\273\314\335\356\377
#              (type=LLT hwtype=1 time=01020304 MAC=aa:bb:cc:dd:ee:ff)
#
# Device B dynamic lease (has iaaddr block):
#   IAID = \000\000\000\002
#   DUID-LL = \000\003\000\001\021\042\063\104\125\146
#              (type=LL hwtype=1 MAC=11:22:33:44:55:66)
#   octal for 0x11=\021, 0x22=\042, 0x33=\063, 0x44=\104, 0x55=\125, 0x66=\146

_STATIC_LEASE_TEXT = (
    r'ia-na "\000\000\000\001\000\001\000\001\001\002\003\004\252\273\314\335\356\377" {' + "\n"
    r"  cltt 3 2026/06/18 10:00:00;" + "\n"
    r"}" + "\n"
)

_DYNAMIC_LEASE_TEXT = (
    r'ia-na "\000\000\000\002\000\003\000\001\021\042\063\104\125\146" {' + "\n"
    r"  cltt 5 2026/06/18 10:00:00;" + "\n"
    r"  iaaddr 2001:db8::200 {" + "\n"
    r"    binding state active;" + "\n"
    r"    next binding state active;" + "\n"
    r"    ends 5 2026/06/25 10:00:00;" + "\n"
    r"  }" + "\n"
    r"}" + "\n"
)


class TestParseDhcpv6Segment:
    def test_static_lease_no_addr(self):
        results = _parse_dhcpv6_segment(_STATIC_LEASE_TEXT, "eth1")
        assert len(results) == 1
        r = results[0]
        assert r["mac"] == "aa:bb:cc:dd:ee:ff"
        assert r["duid_raw"] == "0001000101020304aabbccddeeff"
        assert r["duid_type"] == "LLT"
        assert r["addr"] is None
        assert r["state"] is None
        assert r["ends"] is None
        assert r["vlan"] == "eth1"

    def test_dynamic_lease_has_addr_and_state(self):
        results = _parse_dhcpv6_segment(_DYNAMIC_LEASE_TEXT, "eth1.40")
        assert len(results) == 1
        r = results[0]
        assert r["mac"] == "11:22:33:44:55:66"
        assert r["duid_type"] == "LL"
        assert r["addr"] == "2001:db8::200"
        assert r["state"] == "active"
        assert r["ends"] == "2026/06/25 10:00:00"
        assert r["vlan"] == "eth1.40"

    def test_multiple_leases_in_one_segment(self):
        combined = _STATIC_LEASE_TEXT + _DYNAMIC_LEASE_TEXT
        results = _parse_dhcpv6_segment(combined, "eth1")
        assert len(results) == 2

    def test_empty_content_returns_empty_list(self):
        assert _parse_dhcpv6_segment("", "eth1") == []

    def test_vlan_label_passed_through(self):
        results = _parse_dhcpv6_segment(_DYNAMIC_LEASE_TEXT, "eth1.30")
        assert results[0]["vlan"] == "eth1.30"


# ---------------------------------------------------------------------------
# _parse_dhcpv6_conf
# ---------------------------------------------------------------------------

# Synthetic conf file using documentation-range addresses and made-up device names
_SAMPLE_CONF = """\
shared-network eth1-pd {
\tsubnet6 2001:db8::/64 {
\t\thost device-a {
\t\t\thost-identifier option dhcp6.client-id 00:01:00:01:01:02:03:04:aa:bb:cc:dd:ee:ff;
\t\t\tfixed-address6 2001:db8::1;
\t\t}
\t\thost device-b {
\t\t\thost-identifier option dhcp6.client-id 00:01:00:01:05:06:07:08:11:22:33:44:55:66;
\t\t\tfixed-address6 2001:db8::2;
\t\t}
\t\thost device-c {
\t\t\thost-identifier option dhcp6.client-id 00:03:00:01:cc:dd:ee:ff:00:11;
\t\t\tfixed-address6 2001:db8::3;
\t\t}
\t\trange6 2001:db8::/64;
\t}
}
"""

# Expected normalized DUID keys (colons stripped, lowercased):
_DUID_A = "0001000101020304aabbccddeeff"
_DUID_B = "000100010506070811223344 5566".replace(" ", "")
_DUID_C = "00030001ccddeeff0011"


class TestParseDhcpv6Conf:
    def test_parses_all_three_hosts(self):
        assert len(_parse_dhcpv6_conf(_SAMPLE_CONF)) == 3

    def test_llt_duid_device_a(self):
        mappings = _parse_dhcpv6_conf(_SAMPLE_CONF)
        assert mappings[_DUID_A] == "2001:db8::1"

    def test_llt_duid_device_b(self):
        mappings = _parse_dhcpv6_conf(_SAMPLE_CONF)
        assert mappings[_DUID_B] == "2001:db8::2"

    def test_ll_duid_device_c(self):
        mappings = _parse_dhcpv6_conf(_SAMPLE_CONF)
        assert mappings[_DUID_C] == "2001:db8::3"

    def test_empty_input(self):
        assert _parse_dhcpv6_conf("") == {}

    def test_host_without_fixed_address_is_skipped(self):
        conf = """\
shared-network x {
    subnet6 2001:db8::/64 {
        host incomplete {
            host-identifier option dhcp6.client-id 00:01:00:01:aa:bb:cc:dd:ee:ff:11:22:33:44;
        }
    }
}
"""
        assert _parse_dhcpv6_conf(conf) == {}

    def test_uppercase_duid_normalized_to_lowercase(self):
        conf = """\
shared-network x {
    subnet6 2001:db8::/64 {
        host mydevice {
            host-identifier option dhcp6.client-id 00:01:00:01:AA:BB:CC:DD:EE:FF:11:22:33:44;
            fixed-address6 2001:db8::ff;
        }
    }
}
"""
        mappings = _parse_dhcpv6_conf(conf)
        assert "00010001aabbccddeeff11223344" in mappings
        assert mappings["00010001aabbccddeeff11223344"] == "2001:db8::ff"


# ---------------------------------------------------------------------------
# EdgeRouterAPI.get_dhcpv6_static_mappings (mocked SSH)
# ---------------------------------------------------------------------------

def _make_api() -> EdgeRouterAPI:
    return EdgeRouterAPI(host="192.0.2.1", username="test")


class TestGetDhcpv6StaticMappings:
    def test_delegates_to_parse_dhcpv6_conf(self):
        api = _make_api()
        with patch.object(api, "_exec_raw_command", return_value=_SAMPLE_CONF):
            mappings = api.get_dhcpv6_static_mappings()
        assert len(mappings) == 3
        assert mappings[_DUID_A] == "2001:db8::1"

    def test_empty_conf_returns_empty_dict(self):
        api = _make_api()
        with patch.object(api, "_exec_raw_command", return_value=""):
            assert api.get_dhcpv6_static_mappings() == {}


# ---------------------------------------------------------------------------
# get_all_clients — IPv6 merge integration
# ---------------------------------------------------------------------------

_ARP_DEVICE_A = [
    {"ip": "192.0.2.10", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth1"},
]

_ARP_DEVICE_B = [
    {"ip": "192.0.2.20", "mac": "11:22:33:44:55:66", "interface": "eth1"},
]

_DHCPV6_LEASE_STATIC_A = [
    {   # Static mapping: lease file has no iaaddr block, so addr=None
        "duid_raw": _DUID_A,
        "duid_type": "LLT",
        "mac": "aa:bb:cc:dd:ee:ff",
        "addr": None,
        "state": None,
        "ends": None,
        "vlan": "eth1",
    }
]

_DHCPV6_LEASE_DYNAMIC_B = [
    {
        "duid_raw": _DUID_B,
        "duid_type": "LLT",
        "mac": "11:22:33:44:55:66",
        "addr": "2001:db8::200",
        "state": "active",
        "ends": "2026/06/25 10:00:00",
        "vlan": "eth1",
    }
]

_STATIC_MAPPINGS_A = {_DUID_A: "2001:db8::1"}


def _all_clients(api, **overrides):
    """Call get_all_clients with SSH and all parse layers patched.

    Accepts either old ``get_*`` names (for backwards-compat) or the new
    ``_parse_*`` names.  ``get_dhcpv6_static_mappings`` maps to the module-level
    ``_parse_dhcpv6_conf`` function.
    """
    _old_to_new = {
        "get_arp_table":              ("method", "_parse_arp_output"),
        "get_ndp_table":              ("method", "_parse_ndp_output"),
        "get_dhcp_leases":            ("method", "_parse_dhcp_leases_output"),
        "get_dnsmasq_leases":         ("method", "_parse_dnsmasq_output"),
        "get_dhcp_static_reservations": ("method", "_parse_dhcpd_conf_output"),
        "get_dhcpv6_leases":          ("method", "_parse_dhcpv6_leases_output"),
        "get_dhcpv6_static_mappings": ("module", "_parse_dhcpv6_conf"),
    }
    method_defaults: dict[str, object] = {
        "_parse_arp_output": [],
        "_parse_ndp_output": [],
        "_parse_dhcp_leases_output": [],
        "_parse_dnsmasq_output": [],
        "_parse_dhcpd_conf_output": [],
        "_parse_dhcpv6_leases_output": [],
    }
    module_defaults: dict[str, object] = {
        "_parse_dhcpv6_conf": {},
    }

    for k, v in overrides.items():
        if k in _old_to_new:
            kind, new_name = _old_to_new[k]
            (method_defaults if kind == "method" else module_defaults)[new_name] = v
        elif k.startswith("_parse_"):
            if k in method_defaults:
                method_defaults[k] = v
            else:
                module_defaults[k] = v

    mock_ssh = MagicMock()

    @contextmanager
    def _mock_connection():
        yield mock_ssh

    with (
        patch.object(api, "_connection", _mock_connection),
        patch.object(api, "_run_command", return_value=""),
        patch.object(api, "_run_raw", return_value=""),
        patch.object(api, "_parse_arp_output", return_value=method_defaults["_parse_arp_output"]),
        patch.object(api, "_parse_ndp_output", return_value=method_defaults["_parse_ndp_output"]),
        patch.object(api, "_parse_dhcp_leases_output", return_value=method_defaults["_parse_dhcp_leases_output"]),
        patch.object(api, "_parse_dnsmasq_output", return_value=method_defaults["_parse_dnsmasq_output"]),
        patch.object(api, "_parse_dhcpd_conf_output", return_value=method_defaults["_parse_dhcpd_conf_output"]),
        patch.object(api, "_parse_dhcpv6_leases_output", return_value=method_defaults["_parse_dhcpv6_leases_output"]),
        patch("edgerouter_api._parse_dhcpv6_conf", return_value=module_defaults["_parse_dhcpv6_conf"]),
    ):
        return api.get_all_clients()


class TestGetAllClientsIpv6:
    def test_static_ipv6_addr_filled_from_conf(self):
        """Static DHCPv6 client: lease file has no iaaddr, address comes from conf file."""
        api = _make_api()
        clients = _all_clients(
            api,
            get_arp_table=_ARP_DEVICE_A,
            get_dhcpv6_leases=_DHCPV6_LEASE_STATIC_A,
            get_dhcpv6_static_mappings=_STATIC_MAPPINGS_A,
        )
        client = clients[("aa:bb:cc:dd:ee:ff", "eth1")]
        assert client.ipv6_addr == "2001:db8::1"
        assert client.ipv6_connection_type == "static"
        assert client.has_dhcpv6_lease is True
        # Static addr must appear in ipv6_addrs (was missing before the fix)
        assert "2001:db8::1" in client.ipv6_addrs

    def test_static_addr_at_front_of_ipv6_addrs_when_lease_has_no_iaaddr(self):
        """MAC-type DUID with static lease (no iaaddr): static addr is index 0 in ipv6_addrs."""
        api = _make_api()
        ndp = [
            {"ipv6": "2001:db8::aaa", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth1", "state": "REACHABLE"},
            {"ipv6": "2001:db8::bbb", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth1", "state": "REACHABLE"},
        ]
        clients = _all_clients(
            api,
            get_arp_table=_ARP_DEVICE_A,
            get_ndp_table=ndp,
            get_dhcpv6_leases=_DHCPV6_LEASE_STATIC_A,
            get_dhcpv6_static_mappings=_STATIC_MAPPINGS_A,
        )
        client = clients[("aa:bb:cc:dd:ee:ff", "eth1")]
        assert client.ipv6_addrs[0] == "2001:db8::1", (
            "Static address must be first in ipv6_addrs even when NDP has other addresses"
        )

    def test_dynamic_ipv6_addr_comes_from_lease(self):
        """Dynamic DHCPv6 client: address is in the iaaddr block of the lease file."""
        api = _make_api()
        clients = _all_clients(
            api,
            get_arp_table=_ARP_DEVICE_B,
            get_dhcpv6_leases=_DHCPV6_LEASE_DYNAMIC_B,
        )
        client = clients[("11:22:33:44:55:66", "eth1")]
        assert client.ipv6_addr == "2001:db8::200"
        assert client.ipv6_connection_type == "dhcpv6"
        assert client.ipv6_lease_state == "active"

    def test_static_addr_not_overwritten_if_lease_already_has_one(self):
        """If the lease file already has an addr, the conf file value is not used."""
        api = _make_api()
        lease_with_addr = [{**_DHCPV6_LEASE_STATIC_A[0], "addr": "2001:db8::1"}]
        clients = _all_clients(
            api,
            get_arp_table=_ARP_DEVICE_A,
            get_dhcpv6_leases=lease_with_addr,
            get_dhcpv6_static_mappings=_STATIC_MAPPINGS_A,
        )
        assert clients[("aa:bb:cc:dd:ee:ff", "eth1")].ipv6_addr == "2001:db8::1"

    def test_static_reservation_and_hostname_from_dnsmasq(self):
        """Device in ARP + dnsmasq but not in show dhcp leases → has_static_reservation."""
        api = _make_api()
        arp = [{"ip": "192.0.2.30", "mac": "cc:dd:ee:ff:00:11", "interface": "eth1"}]
        dnsmasq = [{"mac": "cc:dd:ee:ff:00:11", "ip": "192.0.2.30", "hostname": "mydevice"}]
        clients = _all_clients(api, get_arp_table=arp, get_dnsmasq_leases=dnsmasq)
        client = clients[("cc:dd:ee:ff:00:11", "eth1")]
        assert client.has_static_reservation is True
        assert client.has_dhcp_lease is False
        assert client.hostname == "mydevice"

    def test_offline_device_with_dhcp_lease_still_in_clients(self):
        """Device not in ARP but with a DHCP lease still appears in results."""
        api = _make_api()
        dhcp = [{"ip": "192.0.2.40", "mac": "aa:bb:cc:00:00:01", "hostname": None, "expires": None}]
        clients = _all_clients(api, get_dhcp_leases=dhcp)
        client = clients[("aa:bb:cc:00:00:01", "")]
        assert client.in_arp is False
        assert client.has_dhcp_lease is True

    def test_offline_static_reservation_seeded_from_dnsmasq(self):
        """Device with static DHCP reservation that is offline still gets an entity."""
        api = _make_api()
        dnsmasq = [{"mac": "cc:dd:ee:ff:00:22", "ip": "192.0.2.50", "hostname": "offline-device"}]
        clients = _all_clients(api, get_dnsmasq_leases=dnsmasq)
        assert ("cc:dd:ee:ff:00:22", "") in clients
        client = clients[("cc:dd:ee:ff:00:22", "")]
        assert client.in_arp is False
        assert client.has_static_reservation is True
        assert client.hostname == "offline-device"

    def test_offline_static_device_last_seen_not_recent(self):
        """Offline static devices get epoch last_seen so they don't appear as home."""
        from datetime import datetime, timedelta
        api = _make_api()
        dnsmasq = [{"mac": "cc:dd:ee:ff:00:33", "ip": "192.0.2.51", "hostname": None}]
        clients = _all_clients(api, get_dnsmasq_leases=dnsmasq)
        client = clients[("cc:dd:ee:ff:00:33", "")]
        assert datetime.now() - client.last_seen > timedelta(days=365 * 10)

    def test_static_ipv6_assigned_by_mac_when_no_lease_entry(self):
        """Device with static DHCPv6 mapping but no lease file entry gets IPv6 from conf."""
        api = _make_api()
        clients = _all_clients(
            api,
            get_arp_table=_ARP_DEVICE_A,
            get_dhcpv6_static_mappings=_STATIC_MAPPINGS_A,
        )
        client = clients[("aa:bb:cc:dd:ee:ff", "eth1")]
        assert client.ipv6_addr == "2001:db8::1"
        assert client.ipv6_connection_type == "static"
        assert client.has_dhcpv6_lease is False

    def test_ndp_multiple_addresses_collected(self):
        """Global addrs first, link-local appended with zone ID; globals come before link-local."""
        api = _make_api()
        ndp = [
            {"ipv6": "2001:db8::1", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth1", "state": "REACHABLE"},
            {"ipv6": "2001:db8::2", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth1", "state": "REACHABLE"},
            {"ipv6": "fe80::aabb:ccff:fedd:eeff", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth1", "state": "REACHABLE"},
        ]
        clients = _all_clients(api, get_ndp_table=ndp)
        client = clients[("aa:bb:cc:dd:ee:ff", "eth1")]
        assert "2001:db8::1" in client.ipv6_addrs
        assert "2001:db8::2" in client.ipv6_addrs
        assert "fe80::aabb:ccff:fedd:eeff%eth1" in client.ipv6_addrs
        # Global addresses must appear before link-local
        last_global = max(client.ipv6_addrs.index(a) for a in ["2001:db8::1", "2001:db8::2"])
        first_ll = client.ipv6_addrs.index("fe80::aabb:ccff:fedd:eeff%eth1")
        assert last_global < first_ll

    def test_ndp_multi_interface_deduplicates_to_one_entry(self):
        """Same MAC on 4 NDP interfaces (trunk port) → one client entry, all interfaces listed."""
        api = _make_api()
        ndp = [
            {"ipv6": "fe80::1", "mac": "dd:ee:ff:00:11:22", "interface": "eth1", "state": "STALE"},
            {"ipv6": "fe80::1", "mac": "dd:ee:ff:00:11:22", "interface": "eth1.30", "state": "STALE"},
            {"ipv6": "fe80::1", "mac": "dd:ee:ff:00:11:22", "interface": "eth1.40", "state": "STALE"},
            {"ipv6": "fe80::1", "mac": "dd:ee:ff:00:11:22", "interface": "eth1.50", "state": "STALE"},
        ]
        clients = _all_clients(api, get_ndp_table=ndp)
        mac_entries = [k for k in clients if k[0] == "dd:ee:ff:00:11:22"]
        assert len(mac_entries) == 1
        client = clients[mac_entries[0]]
        assert "eth1" in client.interface
        assert "eth1.30" in client.interface
        assert "eth1.40" in client.interface
        assert "eth1.50" in client.interface

    def test_ndp_multi_interface_merges_into_arp_entry(self):
        """When MAC is already in ARP, NDP entries across multiple interfaces merge into it."""
        api = _make_api()
        arp = [{"ip": "192.0.2.1", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth1"}]
        ndp = [
            {"ipv6": "2001:db8::1", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth1", "state": "REACHABLE"},
            {"ipv6": "2001:db8::2", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth1.30", "state": "STALE"},
        ]
        clients = _all_clients(api, get_arp_table=arp, get_ndp_table=ndp)
        mac_entries = [k for k in clients if k[0] == "aa:bb:cc:dd:ee:ff"]
        assert len(mac_entries) == 1
        assert mac_entries[0] == ("aa:bb:cc:dd:ee:ff", "eth1")
        assert set(clients[mac_entries[0]].ipv6_addrs) == {"2001:db8::1", "2001:db8::2"}

    def test_dhcpv6_lease_addr_first_in_ipv6_addrs(self):
        """DHCPv6 lease address is inserted at front of ipv6_addrs from NDP."""
        api = _make_api()
        ndp = [
            {"ipv6": "2001:db8::slaac", "mac": "11:22:33:44:55:66", "interface": "eth1", "state": "REACHABLE"},
        ]
        clients = _all_clients(
            api,
            get_arp_table=_ARP_DEVICE_B,
            get_ndp_table=ndp,
            get_dhcpv6_leases=_DHCPV6_LEASE_DYNAMIC_B,
        )
        client = clients[("11:22:33:44:55:66", "eth1")]
        assert client.ipv6_addrs[0] == "2001:db8::200"  # DHCPv6 lease addr first

    def test_non_mac_duid_matched_via_ipv6_address(self):
        """DUID-UUID and DUID-EN leases (no extractable MAC) are matched to an existing
        client by finding which client already has the same IPv6 address via NDP."""
        api = _make_api()
        # Synthetic DUID-UUID (type 0004) — no MAC in DUID
        duid_uuid = "0004" + "da3317a0836af0afb964dd74d57f95bb"
        uuid_lease = {
            "duid_raw": duid_uuid,
            "duid_type": "UUID",
            "mac": None,
            "addr": "2001:db8::45",
            "state": "active",
            "ends": None,
            "vlan": "eth1.40",
        }
        ndp = [
            {"ipv6": "2001:db8::45", "mac": "bb:cc:dd:ee:ff:00", "interface": "eth1.40", "state": "REACHABLE"},
        ]
        static = {duid_uuid: "2001:db8::45"}
        clients = _all_clients(
            api,
            get_ndp_table=ndp,
            get_dhcpv6_leases=[uuid_lease],
            get_dhcpv6_static_mappings=static,
        )
        client = clients[("bb:cc:dd:ee:ff:00", "eth1.40")]
        assert client.ipv6_duid == duid_uuid
        assert client.has_dhcpv6_lease is True
        assert client.ipv6_connection_type == "static"

    def test_non_mac_duid_static_matched_via_conf_addr(self):
        """DUID-UUID/EN with a static conf entry but no iaaddr in the lease file are matched
        to an existing NDP client using the fixed-address6 from the conf file."""
        api = _make_api()
        duid_uuid = "0004" + "da3317a0836af0afb964dd74d57f95bb"
        # Lease file has cltt only — no iaaddr block → addr=None
        lease_no_addr = {
            "duid_raw": duid_uuid,
            "duid_type": "UUID",
            "mac": None,
            "addr": None,
            "state": None,
            "ends": None,
            "vlan": "eth1.40",
        }
        ndp = [
            {"ipv6": "2001:db8::45", "mac": "bb:cc:dd:ee:ff:00", "interface": "eth1.40", "state": "REACHABLE"},
        ]
        # Conf file has the full fixed address for this DUID
        static = {duid_uuid: "2001:db8::45"}
        clients = _all_clients(
            api,
            get_ndp_table=ndp,
            get_dhcpv6_leases=[lease_no_addr],
            get_dhcpv6_static_mappings=static,
        )
        client = clients[("bb:cc:dd:ee:ff:00", "eth1.40")]
        assert client.ipv6_duid == duid_uuid
        assert client.ipv6_connection_type == "static"

    def test_non_mac_duid_hostname_match_shows_online(self):
        """When a non-MAC DUID can't be matched via NDP but its conf hostname matches
        a real ARP client's DHCP hostname, the static IPv6 is merged into the real
        client so it appears online in the Static v6 tab."""
        api = _make_api()
        duid_en = "0002" + "0000ab11de9424e1bc75113d"
        static = {duid_en: "2001:db8::150"}
        arp = [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.0.2.50", "interface": "eth1"}]
        ndp = [{"ipv6": "2001:db8::cafe", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth1", "state": "REACHABLE"}]
        dnsmasq = [{"mac": "aa:bb:cc:dd:ee:ff", "ip": "192.0.2.50", "hostname": "my-device", "expires": "0"}]
        conf_hostnames = {duid_en: "my-device"}

        with patch("edgerouter_api._parse_dhcpv6_conf_hostnames", return_value=conf_hostnames):
            clients = _all_clients(
                api,
                get_arp_table=arp,
                get_ndp_table=ndp,
                get_dnsmasq_leases=dnsmasq,
                get_dhcpv6_static_mappings=static,
            )

        real_key = ("aa:bb:cc:dd:ee:ff", "eth1")
        assert real_key in clients
        c = clients[real_key]
        assert c.ipv6_duid == duid_en
        assert c.ipv6_connection_type == "static"
        assert "2001:db8::150" in c.ipv6_addrs
        assert c.in_arp is True
        # No synthetic entry should exist
        assert not any(k[0].startswith("duid:") for k in clients)

    def test_non_mac_duid_synthetic_entry_when_not_in_ndp(self):
        """If a non-MAC DUID static entry can't be matched via NDP, a synthetic placeholder
        entry is created so the device still appears in the Static v6 tab."""
        api = _make_api()
        duid_en = "0002" + "0000ab11de9424e1bc75113d"
        static = {duid_en: "2001:db8::150"}
        # No NDP entry for this device — it's offline or using a different address
        clients = _all_clients(api, get_dhcpv6_static_mappings=static)
        syn_key = (f"duid:{duid_en}", "")
        assert syn_key in clients
        client = clients[syn_key]
        assert client.synthetic is True
        assert client.ipv6_addr == "2001:db8::150"
        assert client.ipv6_duid == duid_en
        assert client.ipv6_connection_type == "static"
        assert client.in_arp is False
        assert client.in_ndp is False
