"""The SNMP Printer integration."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL, DOMAIN
from .snmp_client import SNMPClient

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR]
STORAGE_VERSION = 1
STORAGE_KEY = "snmp_printer_cached_data"


async def check_web_interface(host: str, hass: HomeAssistant) -> bool:
    """Check if the printer has a web interface available."""
    session = async_get_clientsession(hass)

    # Try HTTP first
    try:
        async with asyncio.timeout(3):
            async with session.get(f"http://{host}", allow_redirects=True) as response:
                if (
                    response.status < 500
                ):  # Any response below 500 means web interface exists
                    return True
    except Exception:
        pass

    # Try HTTPS
    try:
        async with asyncio.timeout(3):
            async with session.get(
                f"https://{host}", allow_redirects=True, ssl=False
            ) as response:
                if response.status < 500:
                    return True
    except Exception:
        pass

    return False


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up SNMP Printer from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    # Create SNMP client
    snmp_client = SNMPClient(
        host=entry.data[CONF_HOST],
        port=entry.data.get("port", 161),
        snmp_version=entry.data.get("snmp_version", "2c"),
        community=entry.data.get("community", "public"),
        username=entry.data.get("username"),
        auth_protocol=entry.data.get("auth_protocol"),
        auth_key=entry.data.get("auth_key"),
        priv_protocol=entry.data.get("priv_protocol"),
        priv_key=entry.data.get("priv_key"),
    )

    # Get update interval from config or options
    update_interval = entry.options.get(
        CONF_UPDATE_INTERVAL,
        entry.data.get(CONF_UPDATE_INTERVAL, DEFAULT_UPDATE_INTERVAL),
    )

    # Create storage for cached data
    store = Store(hass, STORAGE_VERSION, f"{STORAGE_KEY}_{entry.entry_id}")

    # Load cached data
    cached_data = await store.async_load() or {}

    # Create coordinator
    async def async_update_data():
        """Fetch data from SNMP printer."""
        try:
            system_info = await snmp_client.get_system_info()
            device_info = await snmp_client.get_device_info()
            data = {
                "info": {**system_info, **device_info},
                "status": device_info,
                "cover_status": {"state": await snmp_client.get_cover_status()},
                "page_count": device_info.get(
                    "page_counts", {"total": device_info.get("page_count")}
                ),
                "supplies": await snmp_client.get_supplies(),
                "input_trays": await snmp_client.get_input_trays(),
                "display_text": await snmp_client.get_display_text(),
                "errors": await snmp_client.get_printer_errors(),
                "web_interface_available": await check_web_interface(
                    entry.data[CONF_HOST], hass
                ),
            }

            # Save successful data to cache with timestamp
            cache_data = {
                "data": data,
                "timestamp": datetime.now().isoformat(),
                "host": entry.data[CONF_HOST],
            }
            await store.async_save(cache_data)

            # Mark as online
            data["is_online"] = True

            return data
        except Exception as err:
            # Check if this is a connection-related error
            error_msg = str(err).lower()
            is_connection_error = any(
                keyword in error_msg
                for keyword in [
                    "timeout",
                    "unreachable",
                    "no route",
                    "connection",
                    "network",
                    "host",
                    "refused",
                    "failed",
                    "no response",
                ]
            )

            # If we have cached data and this is a connection issue, return cached data
            if cached_data.get("data") and is_connection_error:
                _LOGGER.warning(
                    "Printer %s is offline (%s), using cached data from %s",
                    entry.data[CONF_HOST],
                    err,
                    cached_data.get("timestamp", "unknown"),
                )

                cached_printer_data = cached_data["data"].copy()
                cached_printer_data["is_online"] = False
                cached_printer_data["offline_since"] = cached_data.get("timestamp")

                return cached_printer_data

            # For other errors or when we don't have cached data, re-raise the error
            raise UpdateFailed(f"Error fetching printer data: {err}") from err

    coordinator = DataUpdateCoordinator(
        hass,
        _LOGGER,
        name=f"snmp_printer_{entry.data[CONF_HOST]}",
        update_method=async_update_data,
        update_interval=timedelta(seconds=update_interval),
    )

    # Fetch initial data (non-blocking, allows offline printers to complete setup)
    # This prevents blocking Home Assistant boot when printer is unreachable
    await coordinator.async_refresh()

    # Store coordinator, client, and storage
    hass.data[DOMAIN][entry.entry_id] = {
        "coordinator": coordinator,
        "client": snmp_client,
        "store": store,
    }

    # Forward entry setup to platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Register update listener for options
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload config entry."""
    await hass.config_entries.async_reload(entry.entry_id)
