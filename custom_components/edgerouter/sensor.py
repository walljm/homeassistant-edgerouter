"""Sensor platform for EdgeRouter integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import (
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .const import DOMAIN
from .edgerouter_api import ClientInfo

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up sensors for EdgeRouter."""
    data = hass.data[DOMAIN][config_entry.entry_id]
    coordinator: DataUpdateCoordinator = data["coordinator"]
    device_info: DeviceInfo = data["device_info"]

    async_add_entities([
        EdgeRouterConnectedDevicesSensor(coordinator, config_entry.entry_id, device_info),
        EdgeRouterIPv4ConnectedSensor(coordinator, config_entry.entry_id, device_info),
        EdgeRouterIPv6ConnectedSensor(coordinator, config_entry.entry_id, device_info),
        EdgeRouterTrackedDevicesSensor(coordinator, config_entry.entry_id, device_info),
        EdgeRouterDhcpLeasesSensor(coordinator, config_entry.entry_id, device_info),
        EdgeRouterDhcpv6LeasesSensor(coordinator, config_entry.entry_id, device_info),
        EdgeRouterIPv4StaticDevicesSensor(coordinator, config_entry.entry_id, device_info),
        EdgeRouterIPv6StaticDevicesSensor(coordinator, config_entry.entry_id, device_info),
        EdgeRouterUnknownDevicesSensor(coordinator, config_entry.entry_id, device_info),
    ])


class EdgeRouterBaseSensor(CoordinatorEntity, SensorEntity):
    """Base class for EdgeRouter sensors."""

    _attr_has_entity_name = True
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry_id: str,
        device_info: DeviceInfo,
    ) -> None:
        super().__init__(coordinator)
        self._entry_id = entry_id
        self._attr_device_info = device_info

    def _clients(self) -> dict[tuple[str, str], ClientInfo]:
        return self.coordinator.data or {}


class EdgeRouterConnectedDevicesSensor(EdgeRouterBaseSensor):
    """Devices currently visible in the ARP table."""

    _attr_icon = "mdi:devices"
    _attr_native_unit_of_measurement = "devices"

    def __init__(self, coordinator, entry_id, device_info):
        super().__init__(coordinator, entry_id, device_info)
        self._attr_unique_id = f"{entry_id}_connected_devices"
        self._attr_name = "Connected devices"

    @property
    def native_value(self) -> int:
        seen: set[str] = set()
        for c in self._clients().values():
            if (c.in_arp or c.in_ndp) and c.mac not in seen:
                seen.add(c.mac)
        return len(seen)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        seen: set[str] = set()
        devices = []
        for c in self._clients().values():
            if (c.in_arp or c.in_ndp) and c.mac not in seen:
                seen.add(c.mac)
                devices.append({
                    "mac": c.mac,
                    "ip": c.ip,
                    "ipv6_addr": c.ipv6_addr,
                    "ipv6_addrs": c.ipv6_addrs,
                    "duid": c.ipv6_duid,
                    "hostname": c.hostname,
                    "interface": c.interface,
                    "ipv4_connected": c.in_arp,
                    "ipv6_connected": c.in_ndp,
                    "ipv4_connection_type": (
                        "static" if c.has_static_reservation
                        else "dhcp" if c.has_dhcp_lease
                        else "unknown"
                    ),
                    "ipv6_connection_type": c.ipv6_connection_type,
                })
        return {"devices": devices}


class EdgeRouterIPv4ConnectedSensor(EdgeRouterBaseSensor):
    """Devices currently visible in the IPv4 ARP table."""

    _attr_icon = "mdi:ip"
    _attr_native_unit_of_measurement = "devices"

    def __init__(self, coordinator, entry_id, device_info):
        super().__init__(coordinator, entry_id, device_info)
        self._attr_unique_id = f"{entry_id}_ipv4_connected"
        self._attr_name = "IPv4 connected"

    @property
    def native_value(self) -> int:
        return len({c.mac for c in self._clients().values() if c.in_arp})


class EdgeRouterIPv6ConnectedSensor(EdgeRouterBaseSensor):
    """Devices currently visible in the IPv6 NDP table."""

    _attr_icon = "mdi:ipv6"
    _attr_native_unit_of_measurement = "devices"

    def __init__(self, coordinator, entry_id, device_info):
        super().__init__(coordinator, entry_id, device_info)
        self._attr_unique_id = f"{entry_id}_ipv6_connected"
        self._attr_name = "IPv6 connected"

    @property
    def native_value(self) -> int:
        return len({c.mac for c in self._clients().values() if c.in_ndp})


class EdgeRouterTrackedDevicesSensor(EdgeRouterBaseSensor):
    """All devices ever seen, including offline ones with static reservations."""

    _attr_icon = "mdi:format-list-bulleted"
    _attr_native_unit_of_measurement = "devices"

    def __init__(self, coordinator, entry_id, device_info):
        super().__init__(coordinator, entry_id, device_info)
        self._attr_unique_id = f"{entry_id}_tracked_devices"
        self._attr_name = "Tracked devices"

    @property
    def native_value(self) -> int:
        return len({c.mac for c in self._clients().values()})

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        seen: set[str] = set()
        devices = []
        for c in self._clients().values():
            if c.mac not in seen:
                seen.add(c.mac)
                devices.append({
                    "mac": c.mac,
                    "ip": c.ip,
                    "hostname": c.hostname,
                    "interface": c.interface,
                    "online": c.in_arp,
                })
        return {"devices": devices}


class EdgeRouterDhcpLeasesSensor(EdgeRouterBaseSensor):
    """Active dynamic IPv4 DHCP leases."""

    _attr_icon = "mdi:ip-network"
    _attr_native_unit_of_measurement = "leases"

    def __init__(self, coordinator, entry_id, device_info):
        super().__init__(coordinator, entry_id, device_info)
        self._attr_unique_id = f"{entry_id}_dhcp_leases"
        self._attr_name = "DHCP leases"

    @property
    def native_value(self) -> int:
        return len({c.mac for c in self._clients().values() if c.has_dhcp_lease})

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        seen: set[str] = set()
        leases = []
        for c in self._clients().values():
            if c.has_dhcp_lease and c.mac not in seen:
                seen.add(c.mac)
                leases.append({
                    "mac": c.mac,
                    "ip": c.ip,
                    "hostname": c.hostname,
                    "interface": c.interface,
                    "expires": c.lease_expires,
                })
        return {"leases": leases}


class EdgeRouterDhcpv6LeasesSensor(EdgeRouterBaseSensor):
    """Devices with an active DHCPv6 lease (dynamic or static)."""

    _attr_icon = "mdi:ipv6"
    _attr_native_unit_of_measurement = "leases"

    def __init__(self, coordinator, entry_id, device_info):
        super().__init__(coordinator, entry_id, device_info)
        self._attr_unique_id = f"{entry_id}_dhcpv6_leases"
        self._attr_name = "DHCPv6 leases"

    @property
    def native_value(self) -> int:
        return len({c.mac for c in self._clients().values() if c.has_dhcpv6_lease and c.ipv6_connection_type != "static"})

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        seen: set[str] = set()
        leases = []
        for c in self._clients().values():
            if (c.has_dhcpv6_lease and c.ipv6_connection_type != "static") and c.mac not in seen:
                seen.add(c.mac)
                leases.append({
                    "mac": c.mac,
                    "ipv6_addrs": c.ipv6_addrs,
                    "hostname": c.hostname,
                    "interface": c.interface,
                    "duid": c.ipv6_duid,
                    "expires": c.ipv6_lease_ends,
                })
        return {"leases": leases}


class EdgeRouterIPv4StaticDevicesSensor(EdgeRouterBaseSensor):
    """Devices with a static IPv4 DHCP reservation."""

    _attr_icon = "mdi:bookmark-check"
    _attr_native_unit_of_measurement = "devices"

    def __init__(self, coordinator, entry_id, device_info):
        super().__init__(coordinator, entry_id, device_info)
        self._attr_unique_id = f"{entry_id}_ipv4_static_devices"
        self._attr_name = "IPv4 static devices"

    @property
    def native_value(self) -> int:
        return sum(1 for c in self._clients().values() if c.has_static_reservation)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        devices = [
            {
                "mac": c.mac,
                "ip": c.ip,
                "hostname": c.hostname,
                "interface": c.interface,
                "online": c.in_arp,
            }
            for c in self._clients().values()
            if c.has_static_reservation
        ]
        return {"devices": devices}


class EdgeRouterIPv6StaticDevicesSensor(EdgeRouterBaseSensor):
    """Devices with a static IPv6 DHCPv6 reservation."""

    _attr_icon = "mdi:bookmark-check-outline"
    _attr_native_unit_of_measurement = "devices"

    def __init__(self, coordinator, entry_id, device_info):
        super().__init__(coordinator, entry_id, device_info)
        self._attr_unique_id = f"{entry_id}_ipv6_static_devices"
        self._attr_name = "IPv6 static devices"

    @property
    def native_value(self) -> int:
        return sum(
            1 for c in self._clients().values()
            if c.ipv6_connection_type == "static"
        )

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        devices = [
            {
                "ipv6_addrs": c.ipv6_addrs,
                "duid": c.ipv6_duid,
                "hostname": c.hostname,
                "interface": c.interface,
                "online": c.in_arp or c.in_ndp,
            }
            for c in self._clients().values()
            if c.ipv6_connection_type == "static"
        ]
        return {"devices": devices}


class EdgeRouterUnknownDevicesSensor(EdgeRouterBaseSensor):
    """Devices in the ARP/NDP table with no DHCP lease or static reservation, on LAN interfaces."""

    _attr_icon = "mdi:help-network"
    _attr_native_unit_of_measurement = "devices"

    def __init__(self, coordinator, entry_id, device_info):
        super().__init__(coordinator, entry_id, device_info)
        self._attr_unique_id = f"{entry_id}_unknown_devices"
        self._attr_name = "Unknown devices"

    def _lan_interfaces(self) -> set[str]:
        """Derive LAN interfaces from devices that have DHCP service — excludes WAN side."""
        return {
            c.interface for c in self._clients().values()
            if c.interface and (c.has_dhcp_lease or c.has_static_reservation)
        }

    @staticmethod
    def _in_lan(c: "ClientInfo", lan: set[str]) -> bool:
        """True if any of the client's interfaces (may be comma-separated) is a LAN interface."""
        if not lan:
            return True
        return any(i.strip() in lan for i in (c.interface or "").split(","))

    @property
    def native_value(self) -> int:
        lan = self._lan_interfaces()
        return sum(
            1 for c in self._clients().values()
            if self._in_lan(c, lan) and self._is_unknown(c)
        )

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        lan = self._lan_interfaces()
        is_authorized = lambda c: (
            c.has_dhcp_lease or c.has_static_reservation
            or c.has_dhcpv6_lease or c.ipv6_connection_type == "static"
        )
        devices = [
            {
                "mac": c.mac,
                "ip": c.ip,
                "hostname": c.hostname,
                "interface": c.interface,
                "unknown_ipv4": c.in_arp and not is_authorized(c),
                "unknown_ipv6": c.in_ndp and not is_authorized(c),
                "ipv6_addrs": c.ipv6_addrs,
                "duid": c.ipv6_duid,
            }
            for c in self._clients().values()
            if self._in_lan(c, lan) and self._is_unknown(c)
        ]
        return {"devices": devices}

    @staticmethod
    def _is_unknown(c: "ClientInfo") -> bool:
        authorized = (
            c.has_dhcp_lease or c.has_static_reservation
            or c.has_dhcpv6_lease or c.ipv6_connection_type == "static"
        )
        return (c.in_arp or c.in_ndp) and not authorized
