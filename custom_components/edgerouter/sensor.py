"""Sensor platform for EdgeRouter integration."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import (
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant, callback
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
    host = config_entry.data[CONF_HOST]

    async_add_entities([
        EdgeRouterConnectedClientsSensor(coordinator, config_entry.entry_id, host),
        EdgeRouterArpClientsSensor(coordinator, config_entry.entry_id, host),
        EdgeRouterDhcpLeasesSensor(coordinator, config_entry.entry_id, host),
    ])


class EdgeRouterBaseSensor(CoordinatorEntity, SensorEntity):
    """Base class for EdgeRouter sensors."""

    _attr_has_entity_name = True
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry_id: str,
        host: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._entry_id = entry_id
        self._host = host


class EdgeRouterConnectedClientsSensor(EdgeRouterBaseSensor):
    """Sensor for total connected clients count."""

    _attr_icon = "mdi:devices"
    _attr_native_unit_of_measurement = "clients"

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry_id: str,
        host: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry_id, host)
        self._attr_unique_id = f"{entry_id}_connected_clients"
        self._attr_name = "Connected Clients"

    @property
    def native_value(self) -> int:
        """Return the number of connected clients."""
        if self.coordinator.data:
            clients: dict[str, ClientInfo] = self.coordinator.data
            # Count clients that are in the ARP table (actually connected)
            return sum(1 for c in clients.values() if c.in_arp)
        return 0

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        if not self.coordinator.data:
            return {}

        clients: dict[str, ClientInfo] = self.coordinator.data
        connected = [c for c in clients.values() if c.in_arp]

        return {
            "clients": [
                {
                    "mac": c.mac,
                    "ip": c.ip,
                    "hostname": c.hostname,
                    "interface": c.interface,
                }
                for c in connected
            ]
        }


class EdgeRouterArpClientsSensor(EdgeRouterBaseSensor):
    """Sensor for ARP table entries count."""

    _attr_icon = "mdi:lan"
    _attr_native_unit_of_measurement = "entries"

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry_id: str,
        host: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry_id, host)
        self._attr_unique_id = f"{entry_id}_arp_entries"
        self._attr_name = "ARP Entries"

    @property
    def native_value(self) -> int:
        """Return the number of ARP entries."""
        if self.coordinator.data:
            clients: dict[str, ClientInfo] = self.coordinator.data
            return sum(1 for c in clients.values() if c.in_arp)
        return 0


class EdgeRouterDhcpLeasesSensor(EdgeRouterBaseSensor):
    """Sensor for DHCP leases count."""

    _attr_icon = "mdi:ip-network"
    _attr_native_unit_of_measurement = "leases"

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry_id: str,
        host: str,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry_id, host)
        self._attr_unique_id = f"{entry_id}_dhcp_leases"
        self._attr_name = "DHCP Leases"

    @property
    def native_value(self) -> int:
        """Return the number of DHCP leases."""
        if self.coordinator.data:
            clients: dict[str, ClientInfo] = self.coordinator.data
            return sum(1 for c in clients.values() if c.has_dhcp_lease)
        return 0

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        if not self.coordinator.data:
            return {}

        clients: dict[str, ClientInfo] = self.coordinator.data
        leases = [c for c in clients.values() if c.has_dhcp_lease]

        return {
            "leases": [
                {
                    "mac": c.mac,
                    "ip": c.ip,
                    "hostname": c.hostname,
                    "expires": c.lease_expires,
                }
                for c in leases
            ]
        }
