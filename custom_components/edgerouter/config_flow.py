"""Config flow for EdgeRouter integration."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_SCAN_INTERVAL,
    CONF_USERNAME,
)
from homeassistant.core import callback

from .const import (
    CONF_CONSIDER_HOME,
    DEFAULT_CONSIDER_HOME,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SSH_PORT,
    DOMAIN,
)
from .edgerouter_api import (
    EdgeRouterAPI,
    EdgeRouterAuthenticationError,
    EdgeRouterConnectionError,
)

_LOGGER = logging.getLogger(__name__)


def _get_schema(defaults: dict | None = None) -> vol.Schema:
    """Get the data schema with optional defaults."""
    defaults = defaults or {}
    return vol.Schema(
        {
            vol.Required(CONF_HOST, default=defaults.get(CONF_HOST, "")): str,
            vol.Required(CONF_USERNAME, default=defaults.get(CONF_USERNAME, "ubnt")): str,
            vol.Required(CONF_PASSWORD, default=defaults.get(CONF_PASSWORD, "")): str,
            vol.Optional(
                CONF_PORT, default=defaults.get(CONF_PORT, DEFAULT_SSH_PORT)
            ): int,
        }
    )


class EdgeRouterConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for EdgeRouter."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}

        if user_input is not None:
            # Check if already configured
            await self.async_set_unique_id(user_input[CONF_HOST])
            self._abort_if_unique_id_configured()

            # Test the connection
            api = EdgeRouterAPI(
                host=user_input[CONF_HOST],
                username=user_input[CONF_USERNAME],
                password=user_input[CONF_PASSWORD],
                port=user_input.get(CONF_PORT, DEFAULT_SSH_PORT),
            )

            try:
                result = await self.hass.async_add_executor_job(api.test_connection)
                if result:
                    # Get system info for the title
                    info = await self.hass.async_add_executor_job(api.get_system_info)
                    title = info.get("model", f"EdgeRouter {user_input[CONF_HOST]}")

                    return self.async_create_entry(
                        title=title,
                        data=user_input,
                    )
                else:
                    errors["base"] = "cannot_connect"

            except EdgeRouterAuthenticationError:
                errors["base"] = "invalid_auth"
            except EdgeRouterConnectionError:
                errors["base"] = "cannot_connect"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"

        return self.async_show_form(
            step_id="user",
            data_schema=_get_schema(user_input),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Get the options flow for this handler."""
        return EdgeRouterOptionsFlowHandler(config_entry)


class EdgeRouterOptionsFlowHandler(OptionsFlow):
    """Handle EdgeRouter options."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_SCAN_INTERVAL,
                        default=self.config_entry.options.get(
                            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=10, max=300)),
                    vol.Optional(
                        CONF_CONSIDER_HOME,
                        default=self.config_entry.options.get(
                            CONF_CONSIDER_HOME, DEFAULT_CONSIDER_HOME
                        ),
                    ): vol.All(vol.Coerce(int), vol.Range(min=0, max=600)),
                }
            ),
        )
