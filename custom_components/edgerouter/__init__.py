"""Ubiquiti EdgeRouter integration for Home Assistant."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
    Platform,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_CONSIDER_HOME,
    CONF_SSH_KEY_PATH,
    DEFAULT_CONSIDER_HOME,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    EVENT_NEW_DEVICE,
    EVENT_UNKNOWN_DEVICE,
)
from .edgerouter_api import EdgeRouterAPI, EdgeRouterConnectionError

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.DEVICE_TRACKER, Platform.SENSOR]

_CARD_PATH = os.path.join(os.path.dirname(__file__), "www", "edgerouter-card.js")


class EdgeRouterCardView(HomeAssistantView):
    """Serve the EdgeRouter Lovelace card from a pre-loaded in-memory buffer."""

    url = "/edgerouter/edgerouter-card.js"
    name = "api:edgerouter:card"
    requires_auth = False

    def __init__(self, content: str) -> None:
        self._content = content

    async def get(self, request: web.Request) -> web.Response:
        return web.Response(
            text=self._content,
            content_type="application/javascript",
            headers={"Cache-Control": "no-cache"},
        )


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up EdgeRouter from a config entry."""
    hass.data.setdefault(DOMAIN, {})
    if not hass.data[DOMAIN].get("_card_registered"):
        def _read_card() -> str:
            with open(_CARD_PATH, encoding="utf-8") as f:
                return f.read()
        try:
            card_content = await hass.async_add_executor_job(_read_card)
        except FileNotFoundError:
            _LOGGER.error("EdgeRouter card JS not found at %s", _CARD_PATH)
            card_content = "// EdgeRouter card not found"
        hass.http.register_view(EdgeRouterCardView(card_content))
        hass.data[DOMAIN]["_card_registered"] = True

    host = entry.data[CONF_HOST]
    username = entry.data[CONF_USERNAME]
    password = entry.data.get(CONF_PASSWORD) or None
    port = entry.data.get(CONF_PORT, 22)
    key_filename = entry.data.get(CONF_SSH_KEY_PATH) or None
    scan_interval = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    consider_home = entry.options.get(CONF_CONSIDER_HOME, DEFAULT_CONSIDER_HOME)

    api = EdgeRouterAPI(host, username, password, port, key_filename=key_filename)

    # In-memory sets for event deduplication. _seen_macs is bootstrapped from the entity
    # registry on first poll so existing devices don't trigger new-device events after restart.
    _seen_macs: set[str] = set()
    _unknown_macs: set[tuple[str, str]] = set()
    # Grace period before firing unknown-device event — ensures DHCP handshake has time
    # to complete. A normal device connecting gets a lease in <5s; 60s means 2 poll cycles.
    _unknown_since: dict[tuple[str, str], datetime] = {}
    _UNKNOWN_GRACE_SECONDS = 60

    async def async_update_data():
        """Fetch data from EdgeRouter and fire events for new/unknown devices."""
        try:
            data = await hass.async_add_executor_job(api.get_all_clients)
        except EdgeRouterConnectionError as err:
            raise UpdateFailed(f"Error communicating with EdgeRouter: {err}") from err
        except Exception as err:
            raise UpdateFailed(f"Unexpected error from EdgeRouter: {err}") from err

        registry = er.async_get(hass)

        # Derive LAN interfaces from devices with DHCP service — excludes WAN-side ARP entries
        # (e.g. upstream gateway, external IP) which have no lease or reservation.
        lan_interfaces = {
            c.interface for c in data.values()
            if c.interface and (c.has_dhcp_lease or c.has_static_reservation)
        }

        for (mac, iface), client in data.items():
            # --- New device event (deduplicated per MAC, not per MAC+interface) ---
            if mac not in _seen_macs:
                _seen_macs.add(mac)
                unique_id = f"{entry.entry_id}_{mac.replace(':', '_')}"
                already_tracked = registry.async_get_entity_id(
                    Platform.DEVICE_TRACKER, DOMAIN, unique_id
                )
                if not already_tracked:
                    event_data: dict = {
                        "mac": mac,
                        "ip": client.ip,
                        "hostname": client.hostname or mac,
                        "interface": client.interface,
                        "connection_type": (
                            "dhcp" if client.has_dhcp_lease
                            else "static" if client.has_static_reservation
                            else "unknown"
                        ),
                    }
                    if client.ipv6_addrs:
                        event_data["ipv6_addrs"] = client.ipv6_addrs
                    if client.ipv6_connection_type:
                        event_data["ipv6_connection_type"] = client.ipv6_connection_type
                    hass.bus.async_fire(EVENT_NEW_DEVICE, event_data)
                    _LOGGER.info("New device detected: %s (%s) on %s", mac, client.ip, client.interface)

            # --- Unknown device event (per MAC+interface, with grace period) ---
            on_lan = not lan_interfaces or client.interface in lan_interfaces
            is_authorized = (
                client.has_dhcp_lease
                or client.has_static_reservation
                or client.has_dhcpv6_lease
                or client.ipv6_connection_type == "static"
            )
            unknown_ipv4 = client.in_arp and not is_authorized
            unknown_ipv6 = client.in_ndp and not is_authorized
            is_unknown = on_lan and (unknown_ipv4 or unknown_ipv6)
            unknown_key = (mac, iface)
            if is_unknown:
                if unknown_key not in _unknown_since:
                    _unknown_since[unknown_key] = datetime.now()
                elif unknown_key not in _unknown_macs:
                    elapsed = (datetime.now() - _unknown_since[unknown_key]).total_seconds()
                    if elapsed >= _UNKNOWN_GRACE_SECONDS:
                        _unknown_macs.add(unknown_key)
                        event_data = {
                            "mac": mac,
                            "ip": client.ip,
                            "hostname": client.hostname or mac,
                            "interface": client.interface,
                            "unknown_ipv4": unknown_ipv4,
                            "unknown_ipv6": unknown_ipv6,
                        }
                        if client.ipv6_addrs:
                            event_data["ipv6_addrs"] = client.ipv6_addrs
                        hass.bus.async_fire(EVENT_UNKNOWN_DEVICE, event_data)
                        _LOGGER.warning(
                            "Unknown device detected: %s (%s) on %s", mac, client.ip, client.interface
                        )
            else:
                _unknown_since.pop(unknown_key, None)
                _unknown_macs.discard(unknown_key)

        return data

    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name=f"EdgeRouter {host}",
        update_method=async_update_data,
        update_interval=timedelta(seconds=scan_interval),
    )

    # Fetch initial data
    await coordinator.async_config_entry_first_refresh()

    # Get system info for device registry
    try:
        system_info = await hass.async_add_executor_job(api.get_system_info)
    except EdgeRouterConnectionError:
        system_info = {}

    device_info = DeviceInfo(
        identifiers={(DOMAIN, host)},
        name=f"EdgeRouter ({host})",
        manufacturer="Ubiquiti",
        model=system_info.get("hw_model", "EdgeRouter"),
        sw_version=system_info.get("version", "Unknown"),
        configuration_url=f"https://{host}",
    )

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = {
        "coordinator": coordinator,
        "api": api,
        "consider_home": consider_home,
        "device_info": device_info,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Register options update listener
    entry.async_on_unload(entry.add_update_listener(async_update_options))

    return True


async def async_update_options(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        data = hass.data[DOMAIN].pop(entry.entry_id)
        await hass.async_add_executor_job(data["api"].close)

    return unload_ok
