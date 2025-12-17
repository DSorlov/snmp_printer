"""Support for SNMP Printer sensors."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, PERCENTAGE, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo, EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity,
    DataUpdateCoordinator,
)

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up SNMP Printer sensors based on a config entry."""
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]

    entities = []

    # Add main status sensor
    entities.append(PrinterStatusSensor(coordinator, entry))

    # Add cover status sensor
    entities.append(PrinterCoverStatusSensor(coordinator, entry))

    # Add page count sensor
    entities.append(PrinterPageCountSensor(coordinator, entry))

    # Add error sensor
    entities.append(PrinterErrorSensor(coordinator, entry))

    # Add display text sensor
    entities.append(PrinterDisplayTextSensor(coordinator, entry))

    # Add supply sensors (toner, ink, drums, etc.)
    if coordinator.data and "supplies" in coordinator.data:
        for supply in coordinator.data["supplies"]:
            entities.append(PrinterSupplySensor(coordinator, entry, supply))

    # Add tray sensors
    if coordinator.data and "input_trays" in coordinator.data:
        for tray in coordinator.data["input_trays"]:
            entities.append(PrinterTraySensor(coordinator, entry, tray))

    async_add_entities(entities, True)


class PrinterSensorBase(CoordinatorEntity, SensorEntity):
    """Base class for printer sensors."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self._entry = entry
        self._attr_has_entity_name = True

    @property
    def available(self) -> bool:
        """Return if entity is available."""
        # Entity is available if we have data (either live or cached)
        return self.coordinator.data is not None

    @property
    def is_printer_online(self) -> bool:
        """Check if printer is currently online."""
        if not self.coordinator.data:
            return False
        return self.coordinator.data.get("is_online", True)

    @property
    def device_info(self) -> DeviceInfo:
        """Return device information."""
        data = self.coordinator.data
        info = data.get("info", {})
        status = data.get("status", {})

        # Extract manufacturer and model from description
        description = info.get("description", "")
        location = info.get("location", "")

        # Try to get model name from description PID field
        model = "Unknown Printer"
        if "PID:" in description:
            parts = description.split("PID:")
            if len(parts) > 1:
                model = parts[1].split(",")[0].split(";")[0].strip()
        elif location:
            model = location

        # Extract manufacturer
        manufacturer = "Unknown"
        if "HP" in description or "Hewlett-Packard" in description:
            manufacturer = "HP"
        elif "Canon" in description:
            manufacturer = "Canon"
        elif "Epson" in description:
            manufacturer = "Epson"
        elif "Brother" in description:
            manufacturer = "Brother"
        elif "Lexmark" in description:
            manufacturer = "Lexmark"
        elif "Samsung" in description:
            manufacturer = "Samsung"
        elif "Xerox" in description:
            manufacturer = "Xerox"

        # Use serial number or host as unique ID
        unique_id = info.get("serial_number", self._entry.data[CONF_HOST])

        device_info = DeviceInfo(
            identifiers={(DOMAIN, unique_id)},
            name=model if model != "Unknown Printer" else self._entry.data[CONF_HOST],
            manufacturer=manufacturer,
            model=model,
        )

        # Add configuration URL if web interface is available
        if data.get("web_interface_available"):
            device_info["configuration_url"] = f"http://{self._entry.data[CONF_HOST]}"

        if info.get("serial_number"):
            device_info["serial_number"] = info["serial_number"]

        return device_info


class PrinterStatusSensor(PrinterSensorBase):
    """Representation of a printer status sensor."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry)
        self._attr_translation_key = "status"
        unique_id = self.coordinator.data.get("info", {}).get(
            "serial_number", entry.data[CONF_HOST]
        )
        self._attr_unique_id = f"{unique_id}_status"
        self._attr_icon = "mdi:printer"
        self._attr_device_class = SensorDeviceClass.ENUM
        self._attr_options = ["idle", "printing", "warmup", "offline", "unknown"]

    @property
    def native_value(self) -> str:
        """Return the state of the sensor."""
        if not self.coordinator.data:
            return "unknown"

        # If printer is offline, return offline status
        if not self.is_printer_online:
            return "offline"

        status = self.coordinator.data.get("status", {})
        return status.get("state", "unknown")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes."""
        if not self.coordinator.data:
            return {}

        info = self.coordinator.data.get("info", {})
        status = self.coordinator.data.get("status", {})

        attributes = {
            "uptime": info.get("uptime"),
            "contact": info.get("contact"),
            "location": info.get("location"),
            "serial_number": info.get("serial_number"),
            "description": info.get("description"),
        }

        # Add offline information if using cached data
        if not self.is_printer_online:
            attributes["using_cached_data"] = True
            offline_since = self.coordinator.data.get("offline_since")
            if offline_since:
                attributes["offline_since"] = offline_since

        # Remove None values
        return {k: v for k, v in attributes.items() if v is not None}


class PrinterCoverStatusSensor(PrinterSensorBase):
    """Representation of a printer cover status sensor."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry)
        self._attr_translation_key = "cover_status"
        unique_id = self.coordinator.data.get("info", {}).get(
            "serial_number", entry.data[CONF_HOST]
        )
        self._attr_unique_id = f"{unique_id}_cover_status"
        self._attr_icon = "mdi:printer-3d-nozzle-alert"

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return if the entity should be enabled when first added."""
        # Disable by default if no cover data or state is unknown
        if not self.coordinator.data:
            return False
        cover_status = self.coordinator.data.get("cover_status", {})
        state = cover_status.get("state", "unknown")
        # Enable only if we have a valid state (not unknown)
        return state != "unknown" and state != ""

    @property
    def native_value(self) -> str:
        """Return the state of the sensor."""
        if not self.coordinator.data:
            return "unknown"

        cover_status = self.coordinator.data.get("cover_status", {})
        return cover_status.get("state", "unknown")


class PrinterPageCountSensor(PrinterSensorBase):
    """Representation of a printer page count sensor."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry)
        self._attr_translation_key = "page_count"
        unique_id = self.coordinator.data.get("info", {}).get(
            "serial_number", entry.data[CONF_HOST]
        )
        self._attr_unique_id = f"{unique_id}_page_count"
        self._attr_icon = "mdi:counter"
        self._attr_native_unit_of_measurement = "pages"

    @property
    def native_value(self) -> int | None:
        """Return the state of the sensor."""
        if not self.coordinator.data:
            return None

        page_count = self.coordinator.data.get("page_count", {})
        return page_count.get("total")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes."""
        if not self.coordinator.data:
            return {}

        page_count = self.coordinator.data.get("page_count", {})
        attrs = {}

        if page_count.get("color") is not None:
            attrs["color_pages"] = page_count.get("color")

        if page_count.get("black_and_white") is not None:
            attrs["black_and_white_pages"] = page_count.get("black_and_white")

        # Add offline information if using cached data
        if not self.is_printer_online:
            attrs["using_cached_data"] = True
            offline_since = self.coordinator.data.get("offline_since")
            if offline_since:
                attrs["last_updated"] = offline_since

        return attrs


class PrinterSupplySensor(PrinterSensorBase):
    """Representation of a printer supply sensor."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
        supply: dict[str, Any],
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry)
        self._supply = supply

        # Set translation key based on color (lowercase with underscores)
        color = supply.get("color", "")
        if color and color != "Unknown":
            color_key = color.lower().replace(" ", "_")
            self._attr_translation_key = color_key
        else:
            # Fallback to description for non-standard supplies
            self._attr_name = supply.get("description", "Supply")

        unique_id = self.coordinator.data.get("info", {}).get(
            "serial_number", entry.data[CONF_HOST]
        )
        self._attr_unique_id = f"{unique_id}_supply_{supply.get('index')}"
        self._attr_native_unit_of_measurement = PERCENTAGE
        self._attr_state_class = SensorStateClass.MEASUREMENT

        # Set icon based on color - use droplets for all ink/toner
        if color in [
            "Black",
            "Cyan",
            "Magenta",
            "Yellow",
            "Gray",
            "Grey",
            "Light Cyan",
            "Light Magenta",
            "Photo",
        ]:
            self._attr_icon = "mdi:water"
        else:
            # For unknown colors, check supply type
            supply_type = supply.get("type", "").lower()
            if "toner" in supply_type or "ink" in supply_type:
                self._attr_icon = "mdi:water"
            elif "drum" in supply_type or "image" in supply_type:
                self._attr_icon = "mdi:circle-outline"
            else:
                self._attr_icon = "mdi:package-variant"

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return if the entity should be enabled when first added."""
        # Always enable supply sensors, even if percentage is not available
        # This ensures pirated/third-party cartridges that don't report levels are still visible
        return True

    @property
    def native_value(self) -> int | None:
        """Return the state of the sensor."""
        # Update supply data from coordinator
        if not self.coordinator.data or "supplies" not in self.coordinator.data:
            return None

        for supply in self.coordinator.data["supplies"]:
            if supply.get("index") == self._supply.get("index"):
                return supply.get("percentage")

        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes."""
        if not self.coordinator.data or "supplies" not in self.coordinator.data:
            return {}

        for supply in self.coordinator.data["supplies"]:
            if supply.get("index") == self._supply.get("index"):
                attributes = {
                    "type": supply.get("type"),
                    "color": supply.get("color"),
                    "description": supply.get("description"),
                }

                # Add offline information if using cached data
                if not self.is_printer_online:
                    attributes["using_cached_data"] = True
                    offline_since = self.coordinator.data.get("offline_since")
                    if offline_since:
                        attributes["last_updated"] = offline_since

                # Add RGB color code for UI customization
                color = supply.get("color", "")
                if color == "Black":
                    attributes["rgb_color"] = [0, 0, 0]
                elif color == "Cyan":
                    attributes["rgb_color"] = [0, 255, 255]
                elif color == "Magenta":
                    attributes["rgb_color"] = [255, 0, 255]
                elif color == "Yellow":
                    attributes["rgb_color"] = [255, 255, 0]
                elif color == "Gray" or color == "Grey":
                    attributes["rgb_color"] = [128, 128, 128]
                elif color == "Light Cyan":
                    attributes["rgb_color"] = [128, 255, 255]
                elif color == "Light Magenta":
                    attributes["rgb_color"] = [255, 128, 255]
                elif color == "Photo":
                    attributes["rgb_color"] = [128, 128, 255]

                return attributes

        return {}


class PrinterTraySensor(PrinterSensorBase):
    """Representation of a printer tray sensor."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
        tray: dict[str, Any],
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry)
        self._tray = tray

        # Extract tray name from description (e.g., "Tray 1", "MP Tray")
        description = tray.get("description", "")
        tray_name = description if description else f"Tray {tray.get('index', '')}"

        # Set translation key for standard trays (tray_1, tray_2, etc.)
        if "Tray" in tray_name and any(char.isdigit() for char in tray_name):
            # Extract number from tray name
            tray_num = "".join(filter(str.isdigit, tray_name))
            if tray_num:
                self._attr_translation_key = f"tray_{tray_num}"
        else:
            # For non-standard trays (e.g., "MP Tray"), use explicit name
            self._attr_name = tray_name

        unique_id = self.coordinator.data.get("info", {}).get(
            "serial_number", entry.data[CONF_HOST]
        )
        self._attr_unique_id = f"{unique_id}_tray_{tray.get('index')}"
        self._attr_native_unit_of_measurement = PERCENTAGE
        self._attr_icon = "mdi:tray"
        self._attr_state_class = SensorStateClass.MEASUREMENT

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return if the entity should be enabled when first added."""
        # Only enable tray sensors that have valid percentage data
        # Trays without max_capacity or current_level won't have percentage
        return self._tray.get("percentage") is not None

    @property
    def native_value(self) -> int | None:
        """Return the state of the sensor."""
        # Update tray data from coordinator
        if not self.coordinator.data or "input_trays" not in self.coordinator.data:
            return None

        for tray in self.coordinator.data["input_trays"]:
            if tray.get("index") == self._tray.get("index"):
                return tray.get("percentage")

        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes."""
        if not self.coordinator.data or "input_trays" not in self.coordinator.data:
            return {}

        for tray in self.coordinator.data["input_trays"]:
            if tray.get("index") == self._tray.get("index"):
                attributes = {
                    "status": tray.get("status"),
                    "media_name": tray.get("media_name"),
                    "max_capacity": tray.get("max_capacity"),
                    "current_level": tray.get("current_level"),
                }

                # Add offline information if using cached data
                if not self.is_printer_online:
                    attributes["using_cached_data"] = True
                    offline_since = self.coordinator.data.get("offline_since")
                    if offline_since:
                        attributes["last_updated"] = offline_since

                return attributes

        return {}


class PrinterErrorSensor(PrinterSensorBase):
    """Representation of a printer error sensor."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry)
        self._attr_translation_key = "errors"
        unique_id = self.coordinator.data.get("info", {}).get(
            "serial_number", entry.data[CONF_HOST]
        )
        self._attr_unique_id = f"{unique_id}_errors"
        self._attr_icon = "mdi:alert"
        self._attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> str:
        """Return the state of the sensor."""
        if not self.coordinator.data:
            return "none"

        errors = self.coordinator.data.get("errors")
        return errors if errors else "none"

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return if the entity should be enabled when first added."""
        # Always enable error sensor
        return True


class PrinterDisplayTextSensor(PrinterSensorBase):
    """Representation of a printer display text sensor."""

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        entry: ConfigEntry,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator, entry)
        self._attr_translation_key = "display"
        unique_id = self.coordinator.data.get("info", {}).get(
            "serial_number", entry.data[CONF_HOST]
        )
        self._attr_unique_id = f"{unique_id}_display"
        self._attr_icon = "mdi:text-box"
        self._attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> str:
        """Return the state of the sensor."""
        if not self.coordinator.data:
            return "unknown"

        display_text = self.coordinator.data.get("display_text")
        return display_text if display_text else "unknown"

    @property
    def entity_registry_enabled_default(self) -> bool:
        """Return if the entity should be enabled when first added."""
        # Disable by default if no display text
        if not self.coordinator.data:
            return False
        display_text = self.coordinator.data.get("display_text")
        return display_text is not None and display_text != ""
