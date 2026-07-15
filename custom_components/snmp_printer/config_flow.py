"""Config flow for SNMP Printer."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PORT, CONF_USERNAME
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.selector import (
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)
from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo

from .const import (
    CONF_AUTH_KEY,
    CONF_AUTH_PROTOCOL,
    CONF_COMMUNITY,
    CONF_NAME_SOURCE,
    CONF_PRIV_KEY,
    CONF_PRIV_PROTOCOL,
    CONF_SNMP_VERSION,
    CONF_SUBNET,
    CONF_UPDATE_INTERVAL,
    DEFAULT_COMMUNITY,
    DEFAULT_NAME_SOURCE,
    DEFAULT_PORT,
    DEFAULT_SNMP_VERSION,
    DEFAULT_UPDATE_INTERVAL,
    DOMAIN,
    NAME_SOURCE_DNS_FQDN,
    NAME_SOURCE_DNS_HOSTNAME,
    NAME_SOURCE_SNMP,
    SCAN_CONCURRENCY,
    SCAN_MAX_HOSTS,
    SCAN_TIMEOUT,
)
from .snmp_client import SNMPClient

_LOGGER = logging.getLogger(__name__)

# Manufacturer tokens searched for (in order) inside the SNMP system description.
_MANUFACTURERS = (
    "Canon",
    "Epson",
    "Brother",
    "Lexmark",
    "Samsung",
    "Xerox",
    "Konica Minolta",
    "Kyocera",
    "OKI",
    "Panasonic",
    "Ricoh",
    "Sharp",
)

# Selector options for the device-name source (issue #19).
_NAME_SOURCE_OPTIONS = [
    {"value": NAME_SOURCE_SNMP, "label": "SNMP name (default)"},
    {"value": NAME_SOURCE_DNS_HOSTNAME, "label": "DNS hostname"},
    {"value": NAME_SOURCE_DNS_FQDN, "label": "DNS FQDN (full)"},
]


def _extract_model(system_info: dict[str, Any]) -> str:
    """Derive a printer model name from SNMP system information."""
    description = system_info.get("description") or ""
    location = system_info.get("location") or ""
    name = system_info.get("name") or ""

    if description and "PID:" in description:
        parts = description.split("PID:")
        if len(parts) > 1:
            return parts[1].split(",")[0].split(";")[0].strip()
    if location:
        return location
    if name:
        return name
    return "Unknown Printer"


def _extract_manufacturer(description: str) -> str:
    """Derive the manufacturer name from an SNMP system description."""
    if not description:
        return "Unknown"
    if "HP" in description or "Hewlett-Packard" in description:
        return "HP"
    for manufacturer in _MANUFACTURERS:
        if manufacturer in description:
            return manufacturer
    return "Unknown"


class SNMPPrinterConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for SNMP Printer."""

    VERSION = 1
    _discovered_hosts: set[str] = (
        set()
    )  # Class variable for cross-instance deduplication

    def __init__(self):
        """Initialize the config flow."""
        self.discovery_info = {}
        self._scan_results: list[dict[str, Any]] = []
        self._scan_params: dict[str, Any] = {}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step by letting the user pick an entry method."""
        return self.async_show_menu(
            step_id="user",
            menu_options=["manual", "scan"],
        )

    async def async_step_scan(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Scan a network range for SNMP printers (issue #12)."""
        errors: dict[str, str] = {}

        if user_input is not None:
            subnet = user_input[CONF_SUBNET]
            snmp_version = user_input.get(CONF_SNMP_VERSION, DEFAULT_SNMP_VERSION)
            community = user_input.get(CONF_COMMUNITY, DEFAULT_COMMUNITY)
            port = user_input.get(CONF_PORT, DEFAULT_PORT)

            try:
                network = ipaddress.ip_network(subnet, strict=False)
            except ValueError:
                errors["base"] = "invalid_subnet"
            else:
                hosts = list(network.hosts()) or [network.network_address]
                if len(hosts) > SCAN_MAX_HOSTS:
                    errors["base"] = "subnet_too_large"
                else:
                    results = await self._scan_hosts(
                        hosts, snmp_version, community, port
                    )
                    if not results:
                        errors["base"] = "no_printers_found"
                    else:
                        self._scan_results = results
                        self._scan_params = {
                            CONF_SNMP_VERSION: snmp_version,
                            CONF_COMMUNITY: community,
                            CONF_PORT: port,
                        }
                        return await self.async_step_scan_select()

        data_schema = vol.Schema(
            {
                vol.Required(
                    CONF_SUBNET,
                    default=user_input.get(CONF_SUBNET, "") if user_input else "",
                ): str,
                vol.Optional(CONF_SNMP_VERSION, default=DEFAULT_SNMP_VERSION): vol.In(
                    ["1", "2c"]
                ),
                vol.Optional(CONF_COMMUNITY, default=DEFAULT_COMMUNITY): str,
                vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
            }
        )

        return self.async_show_form(
            step_id="scan",
            data_schema=data_schema,
            errors=errors,
        )

    async def _scan_hosts(
        self,
        hosts: list[Any],
        snmp_version: str,
        community: str,
        port: int,
    ) -> list[dict[str, Any]]:
        """Probe each host concurrently and return the printers that respond."""
        semaphore = asyncio.Semaphore(SCAN_CONCURRENCY)
        existing = {
            entry.data.get(CONF_HOST) for entry in self._async_current_entries()
        }

        async def probe(ip_addr: Any) -> dict[str, Any] | None:
            host = str(ip_addr)
            if host in existing:
                return None
            async with semaphore:
                client = SNMPClient(
                    host=host,
                    port=port,
                    snmp_version=snmp_version,
                    community=community,
                    timeout=SCAN_TIMEOUT,
                    retries=0,
                    quiet=True,
                )
                # Probe with a single OID first; unreachable hosts (the common
                # case during a scan) are skipped after one timeout.
                try:
                    description = await client.get_description()
                except Exception:  # pylint: disable=broad-except
                    return None
                if not description:
                    return None
                try:
                    system_info = await client.get_system_info()
                except Exception:  # pylint: disable=broad-except
                    system_info = {"description": description}

            if not system_info.get("description"):
                system_info["description"] = description

            model = _extract_model(system_info)
            manufacturer = _extract_manufacturer(system_info.get("description") or "")
            return {
                CONF_HOST: host,
                "model": model,
                "manufacturer": manufacturer,
            }

        results = await asyncio.gather(*(probe(ip) for ip in hosts))
        return [result for result in results if result]

    async def async_step_scan_select(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Let the user pick a printer found during a network scan."""
        if user_input is not None:
            selected_host = user_input[CONF_HOST]
            return await self.async_step_manual(
                {
                    CONF_HOST: selected_host,
                    CONF_SNMP_VERSION: self._scan_params.get(
                        CONF_SNMP_VERSION, DEFAULT_SNMP_VERSION
                    ),
                    CONF_PORT: self._scan_params.get(CONF_PORT, DEFAULT_PORT),
                    CONF_COMMUNITY: self._scan_params.get(
                        CONF_COMMUNITY, DEFAULT_COMMUNITY
                    ),
                    CONF_UPDATE_INTERVAL: DEFAULT_UPDATE_INTERVAL,
                }
            )

        options = [
            {
                "value": result[CONF_HOST],
                "label": (
                    f"{result['manufacturer']} {result['model']} "
                    f"({result[CONF_HOST]})"
                ),
            }
            for result in self._scan_results
        ]

        data_schema = vol.Schema(
            {
                vol.Required(CONF_HOST): SelectSelector(
                    SelectSelectorConfig(
                        options=options,
                        mode=SelectSelectorMode.DROPDOWN,
                    )
                ),
            }
        )

        return self.async_show_form(
            step_id="scan_select",
            data_schema=data_schema,
            description_placeholders={"count": str(len(self._scan_results))},
        )

    async def async_step_manual(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle manual printer configuration."""
        errors = {}

        if user_input is not None:
            # Create SNMP client and test connection
            client = SNMPClient(
                host=user_input[CONF_HOST],
                port=user_input.get(CONF_PORT, DEFAULT_PORT),
                snmp_version=user_input.get(CONF_SNMP_VERSION, "2c"),
                community=user_input.get(CONF_COMMUNITY, DEFAULT_COMMUNITY),
                username=user_input.get(CONF_USERNAME),
                auth_protocol=user_input.get(CONF_AUTH_PROTOCOL),
                auth_key=user_input.get(CONF_AUTH_KEY),
                priv_protocol=user_input.get(CONF_PRIV_PROTOCOL),
                priv_key=user_input.get(CONF_PRIV_KEY),
            )

            try:
                # Get printer info to verify connection
                system_info = await client.get_system_info()
                device_info = await client.get_device_info()

                # Use serial number as unique ID, fallback to host
                unique_id = device_info.get("serial_number", user_input[CONF_HOST])

                await self.async_set_unique_id(unique_id)
                self._abort_if_unique_id_configured()

                # Extract model name from description for better title
                description = system_info.get("description") or ""
                location = system_info.get("location") or ""
                name = system_info.get("name") or ""

                # Try to get model name from description PID field
                model_name = None
                if description and "PID:" in description:
                    parts = description.split("PID:")
                    if len(parts) > 1:
                        model_name = parts[1].split(",")[0].split(";")[0].strip()
                elif location:
                    model_name = location
                elif name:
                    model_name = name

                # Create entry with printer model as title
                title = model_name or user_input[CONF_HOST]

                return self.async_create_entry(
                    title=title,
                    data={
                        CONF_HOST: user_input[CONF_HOST],
                        CONF_PORT: user_input.get(CONF_PORT, DEFAULT_PORT),
                        CONF_SNMP_VERSION: user_input.get(CONF_SNMP_VERSION, "2c"),
                        CONF_COMMUNITY: user_input.get(
                            CONF_COMMUNITY, DEFAULT_COMMUNITY
                        ),
                        CONF_USERNAME: user_input.get(CONF_USERNAME),
                        CONF_AUTH_PROTOCOL: user_input.get(CONF_AUTH_PROTOCOL),
                        CONF_AUTH_KEY: user_input.get(CONF_AUTH_KEY),
                        CONF_PRIV_PROTOCOL: user_input.get(CONF_PRIV_PROTOCOL),
                        CONF_PRIV_KEY: user_input.get(CONF_PRIV_KEY),
                        CONF_UPDATE_INTERVAL: user_input.get(
                            CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL
                        ),
                    },
                )

            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Error connecting to printer")
                errors["base"] = "cannot_connect"

        # Determine SNMP version (from user_input or default)
        snmp_version = user_input.get(CONF_SNMP_VERSION, "2c") if user_input else "2c"

        # Build schema based on SNMP version
        if snmp_version == "3":
            # SNMPv3 - show username and authentication options
            data_schema = vol.Schema(
                {
                    vol.Required(
                        CONF_HOST,
                        default=user_input.get(CONF_HOST, "") if user_input else "",
                    ): str,
                    vol.Optional(
                        CONF_PORT,
                        default=(
                            user_input.get(CONF_PORT, DEFAULT_PORT)
                            if user_input
                            else DEFAULT_PORT
                        ),
                    ): int,
                    vol.Required(CONF_SNMP_VERSION, default="3"): vol.In(
                        ["1", "2c", "3"]
                    ),
                    vol.Required(
                        CONF_USERNAME,
                        default=user_input.get(CONF_USERNAME, "") if user_input else "",
                    ): str,
                    vol.Optional(
                        CONF_AUTH_PROTOCOL,
                        default=(
                            user_input.get(CONF_AUTH_PROTOCOL) if user_input else None
                        ),
                    ): vol.In(["MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"]),
                    vol.Optional(
                        CONF_AUTH_KEY,
                        default=user_input.get(CONF_AUTH_KEY, "") if user_input else "",
                    ): str,
                    vol.Optional(
                        CONF_PRIV_PROTOCOL,
                        default=(
                            user_input.get(CONF_PRIV_PROTOCOL) if user_input else None
                        ),
                    ): vol.In(["DES", "3DES", "AES", "AES192", "AES256"]),
                    vol.Optional(
                        CONF_PRIV_KEY,
                        default=user_input.get(CONF_PRIV_KEY, "") if user_input else "",
                    ): str,
                    vol.Optional(
                        CONF_UPDATE_INTERVAL,
                        default=(
                            user_input.get(
                                CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL
                            )
                            if user_input
                            else DEFAULT_UPDATE_INTERVAL
                        ),
                    ): int,
                }
            )
        else:
            # SNMPv1/v2c - show community string
            data_schema = vol.Schema(
                {
                    vol.Required(
                        CONF_HOST,
                        default=user_input.get(CONF_HOST, "") if user_input else "",
                    ): str,
                    vol.Optional(
                        CONF_PORT,
                        default=(
                            user_input.get(CONF_PORT, DEFAULT_PORT)
                            if user_input
                            else DEFAULT_PORT
                        ),
                    ): int,
                    vol.Optional(CONF_SNMP_VERSION, default=snmp_version): vol.In(
                        ["1", "2c", "3"]
                    ),
                    vol.Optional(
                        CONF_COMMUNITY,
                        default=(
                            user_input.get(CONF_COMMUNITY, DEFAULT_COMMUNITY)
                            if user_input
                            else DEFAULT_COMMUNITY
                        ),
                    ): str,
                    vol.Optional(
                        CONF_UPDATE_INTERVAL,
                        default=(
                            user_input.get(
                                CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL
                            )
                            if user_input
                            else DEFAULT_UPDATE_INTERVAL
                        ),
                    ): int,
                }
            )

        return self.async_show_form(
            step_id="manual",
            data_schema=data_schema,
            errors=errors,
        )

    async def async_step_zeroconf(
        self, discovery_info: ZeroconfServiceInfo
    ) -> FlowResult:
        """Handle zeroconf discovery."""
        # Extract host from discovery info
        host = discovery_info.host

        if not host:
            return self.async_abort(reason="unknown")

        # Check if we already processed this IP in this session (class variable)
        if host in SNMPPrinterConfigFlow._discovered_hosts:
            _LOGGER.debug(
                "Already processed discovery for %s, skipping duplicate", host
            )
            return self.async_abort(reason="already_in_progress")

        # Mark this IP as being processed (class variable)
        SNMPPrinterConfigFlow._discovered_hosts.add(host)

        # Try to get printer info to set unique ID and get model name
        # Try v2c first, then fall back to v1 if that fails
        system_info = None
        device_info = None
        working_version = None

        for snmp_version in ["2c", "1"]:
            try:
                _LOGGER.info(
                    "Trying to connect to %s using SNMP v%s", host, snmp_version
                )
                client = SNMPClient(
                    host=host,
                    port=DEFAULT_PORT,
                    snmp_version=snmp_version,
                    community=DEFAULT_COMMUNITY,
                    timeout=2.5,  # 2.5 seconds per request
                    retries=1,  # 1 retry = total ~5 seconds max per version
                    quiet=True,
                )
                system_info = await client.get_system_info()
                device_info = await client.get_device_info()

                # Check if we actually got useful data (not all None)
                has_data = (
                    system_info.get("description")
                    or system_info.get("name")
                    or device_info.get("serial_number")
                    or device_info.get("mac_address")
                )

                if has_data:
                    working_version = snmp_version
                    _LOGGER.info(
                        "Successfully connected to %s using SNMP v%s",
                        host,
                        snmp_version,
                    )
                    break  # Success, exit the loop
                else:
                    _LOGGER.warning(
                        "SNMP v%s connected to %s but returned no data, trying next version",
                        snmp_version,
                        host,
                    )
                    system_info = None
                    device_info = None
                    continue

            except Exception as err:  # pylint: disable=broad-except
                _LOGGER.warning(
                    "Could not connect to %s using SNMP v%s: %s",
                    host,
                    snmp_version,
                    err,
                )
                import traceback

                _LOGGER.debug("Traceback: %s", traceback.format_exc())
                continue  # Try next version

        # If we couldn't connect with either version, abort
        if system_info is None or device_info is None:
            _LOGGER.warning(
                "Could not connect to discovered device at %s with any SNMP version",
                host,
            )
            SNMPPrinterConfigFlow._discovered_hosts.discard(
                host
            )  # Remove from set so it can be retried
            return self.async_abort(reason="not_printer")

        try:
            # Log what we got from SNMP
            _LOGGER.debug("System info from %s: %s", host, system_info)
            _LOGGER.debug("Device info from %s: %s", host, device_info)

            # Extract manufacturer and model from the SNMP description
            model = _extract_model(system_info)
            manufacturer = _extract_manufacturer(system_info.get("description") or "")

            # Get serial number for unique ID
            unique_id = device_info.get("serial_number")

            if not unique_id:
                # If no serial number, use MAC address or host as fallback
                unique_id = device_info.get("mac_address", host)

            # Set unique ID based on serial number to prevent duplicate discoveries
            await self.async_set_unique_id(unique_id)
            # Update the host if IP changed, but don't abort - let user see it
            self._abort_if_unique_id_configured(updates={CONF_HOST: host})

            _LOGGER.info(
                "Discovered printer: %s %s at %s (unique_id: %s)",
                manufacturer,
                model,
                host,
                unique_id,
            )

            # Set the title in the context so it appears in the discovery card
            self.context["title_placeholders"] = {
                "name": model,
                "model": model,
                "manufacturer": manufacturer,
            }

            # Store discovery info with actual printer model name
            self.discovery_info = {
                CONF_HOST: host,
                "name": model,
                "model": model,
                "manufacturer": manufacturer,
                "snmp_version": working_version,  # Store the working version
            }

            # If we got here, it's a valid printer
            return await self.async_step_zeroconf_confirm()

        except Exception as err:  # pylint: disable=broad-except
            _LOGGER.error("Error processing discovered device at %s: %s", host, err)
            import traceback

            _LOGGER.debug("Traceback: %s", traceback.format_exc())
            SNMPPrinterConfigFlow._discovered_hosts.discard(
                host
            )  # Remove from set so it can be retried
            return self.async_abort(reason="not_printer")

    async def async_step_zeroconf_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Confirm discovery."""
        if user_input is not None:
            # User confirmed, proceed to manual setup with pre-filled data from discovery
            return await self.async_step_manual(
                {
                    CONF_HOST: self.discovery_info[CONF_HOST],
                    CONF_SNMP_VERSION: self.discovery_info.get("snmp_version", "2c"),
                    CONF_PORT: DEFAULT_PORT,
                    CONF_COMMUNITY: DEFAULT_COMMUNITY,
                    CONF_UPDATE_INTERVAL: DEFAULT_UPDATE_INTERVAL,
                }
            )

        return self.async_show_form(
            step_id="zeroconf_confirm",
            description_placeholders={
                "name": self.discovery_info.get("name", "Unknown Printer"),
                "model": self.discovery_info.get("model", "Unknown"),
                "manufacturer": self.discovery_info.get("manufacturer", "Unknown"),
                "host": self.discovery_info[CONF_HOST],
            },
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> OptionsFlowHandler:
        """Get the options flow for this handler."""
        return OptionsFlowHandler(config_entry)


class OptionsFlowHandler(config_entries.OptionsFlow):
    """Handle options flow for SNMP Printer."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        super().__init__()
        self._data = {}

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options - first step with connection settings."""
        errors = {}

        if user_input is not None:
            # Store the connection settings
            self._data.update(user_input)

            # If SNMP version changed to v3, go to auth step
            if user_input.get(CONF_SNMP_VERSION) == "3":
                return await self.async_step_auth()

            # Otherwise, go to final step to test and save
            return await self.async_step_complete()

        # Build schema for connection settings
        data_schema = vol.Schema(
            {
                vol.Required(
                    CONF_HOST,
                    default=self.config_entry.data.get(CONF_HOST),
                ): str,
                vol.Optional(
                    CONF_PORT,
                    default=self.config_entry.data.get(CONF_PORT, DEFAULT_PORT),
                ): int,
                vol.Required(
                    CONF_SNMP_VERSION,
                    default=self.config_entry.data.get(CONF_SNMP_VERSION, "2c"),
                ): vol.In(["1", "2c", "3"]),
                vol.Optional(
                    CONF_COMMUNITY,
                    default=self.config_entry.data.get(
                        CONF_COMMUNITY, DEFAULT_COMMUNITY
                    ),
                ): str,
                vol.Optional(
                    CONF_UPDATE_INTERVAL,
                    default=self.config_entry.options.get(
                        CONF_UPDATE_INTERVAL,
                        self.config_entry.data.get(
                            CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL
                        ),
                    ),
                ): int,
                vol.Optional(
                    CONF_NAME_SOURCE,
                    default=self.config_entry.options.get(
                        CONF_NAME_SOURCE,
                        self.config_entry.data.get(
                            CONF_NAME_SOURCE, DEFAULT_NAME_SOURCE
                        ),
                    ),
                ): SelectSelector(
                    SelectSelectorConfig(
                        options=_NAME_SOURCE_OPTIONS,
                        mode=SelectSelectorMode.DROPDOWN,
                    )
                ),
            }
        )

        return self.async_show_form(
            step_id="init",
            data_schema=data_schema,
            errors=errors,
        )

    async def async_step_auth(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Configure SNMPv3 authentication."""
        if user_input is not None:
            # Store auth settings
            self._data.update(user_input)
            return await self.async_step_complete()

        # Build schema for SNMPv3 authentication
        data_schema = vol.Schema(
            {
                vol.Required(
                    CONF_USERNAME,
                    default=self.config_entry.data.get(CONF_USERNAME, ""),
                ): str,
                vol.Optional(
                    CONF_AUTH_PROTOCOL,
                    default=self.config_entry.data.get(CONF_AUTH_PROTOCOL),
                ): vol.In(["MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"]),
                vol.Optional(
                    CONF_AUTH_KEY,
                    default=self.config_entry.data.get(CONF_AUTH_KEY, ""),
                ): str,
                vol.Optional(
                    CONF_PRIV_PROTOCOL,
                    default=self.config_entry.data.get(CONF_PRIV_PROTOCOL),
                ): vol.In(["DES", "3DES", "AES", "AES192", "AES256"]),
                vol.Optional(
                    CONF_PRIV_KEY,
                    default=self.config_entry.data.get(CONF_PRIV_KEY, ""),
                ): str,
            }
        )

        return self.async_show_form(
            step_id="auth",
            data_schema=data_schema,
        )

    async def async_step_complete(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Test connection and save settings."""
        errors = {}

        # Build full config from stored data
        snmp_version = self._data.get(CONF_SNMP_VERSION)

        # Create client with new settings
        client = SNMPClient(
            host=self._data.get(CONF_HOST),
            port=self._data.get(CONF_PORT, DEFAULT_PORT),
            snmp_version=snmp_version,
            community=(
                self._data.get(CONF_COMMUNITY, DEFAULT_COMMUNITY)
                if snmp_version != "3"
                else None
            ),
            username=self._data.get(CONF_USERNAME) if snmp_version == "3" else None,
            auth_protocol=(
                self._data.get(CONF_AUTH_PROTOCOL) if snmp_version == "3" else None
            ),
            auth_key=self._data.get(CONF_AUTH_KEY) if snmp_version == "3" else None,
            priv_protocol=(
                self._data.get(CONF_PRIV_PROTOCOL) if snmp_version == "3" else None
            ),
            priv_key=self._data.get(CONF_PRIV_KEY) if snmp_version == "3" else None,
        )

        try:
            await client.get_system_info()

            # Update the config entry data (not just options)
            # This updates the actual configuration
            self.hass.config_entries.async_update_entry(
                self.config_entry,
                data=self._data,
            )

            # Also store in options for consistency
            return self.async_create_entry(title="", data=self._data)

        except Exception:  # pylint: disable=broad-except
            _LOGGER.exception("Error connecting to printer with new settings")
            errors["base"] = "cannot_connect"

            # Go back to init step
            self._data = {}
            return await self.async_step_init(user_input={})
