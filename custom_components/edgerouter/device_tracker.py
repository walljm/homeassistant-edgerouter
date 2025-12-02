"""Device tracker platform for EdgeRouter integration."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from homeassistant.components.device_tracker import SourceType
from homeassistant.components.device_tracker.config_entry import ScannerEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC, DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .const import (
    ATTR_CONNECTION_TYPE,
    ATTR_HOSTNAME,
    ATTR_INTERFACE,
    ATTR_IP_ADDRESS,
    ATTR_LAST_SEEN,
    ATTR_LEASE_EXPIRES,
    ATTR_MAC_ADDRESS,
    DOMAIN,
)
from .edgerouter_api import ClientInfo

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up device tracker for EdgeRouter."""
    data = hass.data[DOMAIN][config_entry.entry_id]
    coordinator: DataUpdateCoordinator = data["coordinator"]
    consider_home: int = data["consider_home"]
    router_device_info: DeviceInfo = data["device_info"]

    # Track known devices
    tracked_macs: set[str] = set()

    @callback
    def async_add_new_entities() -> None:
        """Add new device tracker entities."""
        new_entities = []
        clients: dict[str, ClientInfo] = coordinator.data or {}

        for mac, client in clients.items():
            if mac not in tracked_macs:
                tracked_macs.add(mac)
                new_entities.append(
                    EdgeRouterDeviceTracker(
                        coordinator,
                        config_entry.entry_id,
                        mac,
                        client,
                        consider_home,
                        router_device_info,
                    )
                )

        if new_entities:
            _LOGGER.debug("Adding %d new device trackers", len(new_entities))
            async_add_entities(new_entities)

    # Add entities for current data
    async_add_new_entities()

    # Listen for new data and add new entities
    config_entry.async_on_unload(
        coordinator.async_add_listener(async_add_new_entities)
    )


class EdgeRouterDeviceTracker(CoordinatorEntity, ScannerEntity):
    """Representation of an EdgeRouter tracked device."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry_id: str,
        mac: str,
        client: ClientInfo,
        consider_home: int,
        router_device_info: DeviceInfo,
    ) -> None:
        """Initialize the device tracker."""
        super().__init__(coordinator)
        self._mac = mac
        self._consider_home = timedelta(seconds=consider_home)
        self._entry_id = entry_id
        self._last_seen: datetime | None = client.last_seen
        self._router_device_info = router_device_info
        self._host = router_device_info.get("identifiers", set()).copy().pop()[1] if router_device_info.get("identifiers") else entry_id

        # Create a device for each tracked client using MAC as connection identifier
        # This makes each tracked device appear as its own device in HA
        client_name = client.name if client.name and client.name != "?" else mac
        self._client_name = client_name
        self._attr_device_info = DeviceInfo(
            connections={(CONNECTION_NETWORK_MAC, mac)},
            name=client_name,
            via_device=(DOMAIN, self._host),  # Link to router device
        )

        # Set entity properties
        self._attr_unique_id = f"{entry_id}_{mac.replace(':', '_')}"
        self._attr_name = None  # Use device name only

    @property
    def _client(self) -> ClientInfo | None:
        """Get the current client info."""
        if self.coordinator.data:
            return self.coordinator.data.get(self._mac)
        return None

    @property
    def is_connected(self) -> bool:
        """Return true if the device is connected."""
        client = self._client
        if client and client.in_arp:
            self._last_seen = client.last_seen
            return True

        # Check consider_home window
        if self._last_seen and self._consider_home.total_seconds() > 0:
            return datetime.now() - self._last_seen < self._consider_home

        return False

    @property
    def source_type(self) -> SourceType:
        """Return the source type."""
        return SourceType.ROUTER

    @property
    def mac_address(self) -> str:
        """Return the MAC address of the device."""
        return self._mac

    @property
    def ip_address(self) -> str | None:
        """Return the IP address of the device."""
        client = self._client
        return client.ip if client else None

    @property
    def hostname(self) -> str | None:
        """Return the hostname of the device."""
        client = self._client
        return client.hostname if client else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes."""
        attrs = {
            ATTR_MAC_ADDRESS: self._mac,
        }

        client = self._client
        if client:
            if client.ip:
                attrs[ATTR_IP_ADDRESS] = client.ip
            if client.hostname:
                attrs[ATTR_HOSTNAME] = client.hostname
            if client.interface:
                attrs[ATTR_INTERFACE] = client.interface
            if client.lease_expires:
                attrs[ATTR_LEASE_EXPIRES] = client.lease_expires
            if self._last_seen:
                attrs[ATTR_LAST_SEEN] = self._last_seen.isoformat()

            # Connection type indicator
            if client.in_arp and client.has_dhcp_lease:
                attrs[ATTR_CONNECTION_TYPE] = "dhcp"
            elif client.in_arp:
                attrs[ATTR_CONNECTION_TYPE] = "static"
            elif client.has_dhcp_lease:
                attrs[ATTR_CONNECTION_TYPE] = "dhcp_inactive"

        return attrs

    @callback
    def _handle_coordinator_update(self) -> None:
        """Handle updated data from the coordinator."""
        client = self._client
        if client:
            # Update device name if we got a hostname
            if client.hostname and client.hostname != "?":
                if self._client_name != client.hostname:
                    self._client_name = client.hostname
                    self._attr_device_info = DeviceInfo(
                        connections={(CONNECTION_NETWORK_MAC, self._mac)},
                        name=client.hostname,
                        via_device=(DOMAIN, self._host),
                    )
            # Update last seen if in ARP
            if client.in_arp:
                self._last_seen = client.last_seen

        super()._handle_coordinator_update()
