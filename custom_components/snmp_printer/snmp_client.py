"""SNMP client for printer communication."""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    bulk_walk_cmd,
    get_cmd,
    set_cmd,
    usmAesCfb128Protocol,
    usmDESPrivProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
)
from pysnmp.proto.rfc1902 import OctetString

from .const import (
    DEFAULT_ERROR_LOG_INTERVAL,
    PRINTER_STATUS,
    OID_COVER_DESCRIPTION,
    OID_COVER_STATUS,
    OID_DEVICE_DESCRIPTION,
    OID_DEVICE_ERRORS,
    OID_DEVICE_STATE,
    OID_DISPLAY_BUFFER,
    OID_HARDWARE_ADDRESS,
    OID_INPUT_CURRENT_LEVEL,
    OID_INPUT_DESCRIPTION,
    OID_INPUT_MAX_CAPACITY,
    OID_MARKER_SUPPLIES_CLASS,
    OID_MARKER_SUPPLIES_DESCRIPTION,
    OID_MARKER_SUPPLIES_LEVEL,
    OID_MARKER_SUPPLIES_MAX_CAPACITY,
    OID_MARKER_SUPPLIES_TYPE,
    OID_MEMORY_SIZE,
    OID_PAGE_COUNT,
    OID_PRINTER_ERRORS,
    OID_PRINTER_STATUS,
    OID_SERIAL_NUMBER,
    OID_SYSTEM_CONTACT,
    OID_SYSTEM_DESCRIPTION,
    OID_SYSTEM_LOCATION,
    OID_SYSTEM_NAME,
    OID_SYSTEM_UPTIME,
    SUPPLY_CLASS,
    SUPPLY_TYPE,
)

_LOGGER = logging.getLogger(__name__)


class SNMPClient:
    """SNMP client for printer communication."""

    def __init__(
        self,
        host: str,
        port: int = 161,
        snmp_version: str = "2c",
        community: str = "public",
        username: str | None = None,
        auth_protocol: str | None = None,
        auth_key: str | None = None,
        priv_protocol: str | None = None,
        priv_key: str | None = None,
        timeout: float = 1.0,
        retries: int = 3,
    ):
        """Initialize the SNMP client.

        Args:
            timeout: Timeout in seconds for each SNMP request (default 1.0)
            retries: Number of retries for failed requests (default 3)
        """
        self.host = host
        self.port = port
        self.snmp_version = snmp_version
        self.community = community
        self.username = username
        self.auth_protocol = auth_protocol
        self.auth_key = auth_key
        self.priv_protocol = priv_protocol
        self.priv_key = priv_key
        self.timeout = timeout
        self.retries = retries

        self._engine = None  # Will be created on first use
        self._transport = None  # Will be created async
        self._auth_data = self._get_auth_data()

        # Connection state tracking for better error logging
        self._connection_state = "unknown"  # unknown, online, offline
        self._last_error_log_time = 0
        self._consecutive_failures = 0

    def _create_engine(self):
        """Create SNMP engine (blocking operation)."""
        if self._engine is None:
            self._engine = SnmpEngine()
        return self._engine

    def _handle_snmp_error(self, error_message: str) -> None:
        """Handle SNMP errors with intelligent logging to reduce spam."""
        current_time = time.time()
        self._consecutive_failures += 1

        # Determine if we should log this error
        should_log_error = False
        log_level = logging.ERROR

        if self._connection_state == "unknown" or self._connection_state == "online":
            # First error or was previously online - log as error
            should_log_error = True
            self._connection_state = "offline"
            self._last_error_log_time = current_time
        elif self._connection_state == "offline":
            # Already offline - check if enough time has passed for another log
            time_since_last_log = current_time - self._last_error_log_time
            if time_since_last_log >= DEFAULT_ERROR_LOG_INTERVAL:
                should_log_error = True
                log_level = logging.WARNING  # Reduce severity for ongoing issues
                self._last_error_log_time = current_time

        if should_log_error:
            if self._consecutive_failures == 1:
                _LOGGER.error(
                    "Printer %s: %s (switching to cached data if available)",
                    self.host,
                    error_message,
                )
            else:
                _LOGGER.warning(
                    "Printer %s still offline: %s (attempt %d, using cached data)",
                    self.host,
                    error_message,
                    self._consecutive_failures,
                )
        else:
            # Still log at debug level for troubleshooting
            _LOGGER.debug(
                "Printer %s offline: %s (suppressed, attempt %d)",
                self.host,
                error_message,
                self._consecutive_failures,
            )

    def _mark_connection_success(self) -> None:
        """Mark a successful connection to reset error tracking."""
        if self._connection_state == "offline":
            _LOGGER.info(
                "Printer %s is back online after %d failed attempts",
                self.host,
                self._consecutive_failures,
            )
        self._connection_state = "online"
        self._consecutive_failures = 0

    async def _ensure_transport(self):
        """Ensure transport and engine are created (async operation)."""
        if self._engine is None:
            self._engine = SnmpEngine()
        if self._transport is None:
            self._transport = await UdpTransportTarget.create(
                (self.host, self.port),
                timeout=self.timeout,
                retries=self.retries,
            )

    def _get_auth_data(self):
        """Get authentication data based on SNMP version."""
        if self.snmp_version == "3":
            auth_proto = None
            if self.auth_protocol == "MD5":
                auth_proto = usmHMACMD5AuthProtocol
            elif self.auth_protocol == "SHA":
                auth_proto = usmHMACSHAAuthProtocol

            priv_proto = None
            if self.priv_protocol == "DES":
                priv_proto = usmDESPrivProtocol
            elif self.priv_protocol == "AES":
                priv_proto = usmAesCfb128Protocol

            return UsmUserData(
                self.username,
                authKey=self.auth_key if auth_proto else None,
                authProtocol=auth_proto,
                privKey=self.priv_key if priv_proto else None,
                privProtocol=priv_proto,
            )
        else:
            # SNMP v1 or v2c
            return CommunityData(
                self.community, mpModel=0 if self.snmp_version == "1" else 1
            )

    async def test_connection(self) -> bool:
        """Test the SNMP connection."""
        try:
            await self._ensure_transport()
            result = await self._get_oid(OID_SYSTEM_DESCRIPTION)
            return result is not None
        except Exception as err:
            _LOGGER.error("Connection test failed: %s", err)
            raise

    async def _get_oid(self, oid: str) -> Any:
        """Get a single OID value."""
        await self._ensure_transport()
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            self._engine,
            self._auth_data,
            self._transport,
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )

        if errorIndication:
            self._handle_snmp_error(f"SNMP error: {errorIndication}")
            return None
        elif errorStatus:
            self._handle_snmp_error(
                f"SNMP error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}"
            )
            return None

        for varBind in varBinds:
            self._mark_connection_success()
            return varBind[1].prettyPrint()

        return None

    async def _walk_oid(self, oid: str) -> dict[str, str]:
        """Walk an OID tree (async operation) and return as dict."""
        await self._ensure_transport()

        results = {}
        async for errorIndication, errorStatus, errorIndex, varBinds in bulk_walk_cmd(
            self._engine,
            self._auth_data,
            self._transport,
            ContextData(),
            0,  # Non-repeaters
            25,  # Max-repetitions
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        ):
            if errorIndication:
                self._handle_snmp_error(f"SNMP walk error: {errorIndication}")
                break
            elif errorStatus:
                self._handle_snmp_error(
                    f"SNMP walk error: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}"
                )
                break
            else:
                # Mark success if we get any data
                if not results and varBinds:
                    self._mark_connection_success()

                for varBind in varBinds:
                    # Extract the index from the OID (last part after the base OID)
                    full_oid = str(varBind[0])
                    if full_oid.startswith(oid + "."):
                        index = full_oid[len(oid) + 1 :]
                        results[index] = str(varBind[1])
        return results

    async def _set_oid(self, oid: str, value: str) -> bool:
        """Set an OID value."""
        try:
            await self._ensure_transport()
            errorIndication, errorStatus, errorIndex, varBinds = await set_cmd(
                self._engine,
                self._auth_data,
                self._transport,
                ContextData(),
                ObjectType(ObjectIdentity(oid), OctetString(value)),
            )

            if errorIndication or errorStatus:
                _LOGGER.error("Failed to set OID: %s", errorIndication or errorStatus)
                return False

            return True
        except Exception as err:
            _LOGGER.error("Failed to set OID: %s", err)
            return False

    async def get_system_info(self) -> dict[str, Any]:
        """Get system information."""
        return {
            "description": await self._get_oid(OID_SYSTEM_DESCRIPTION),
            "name": await self._get_oid(OID_SYSTEM_NAME),
            "contact": await self._get_oid(OID_SYSTEM_CONTACT),
            "location": await self._get_oid(OID_SYSTEM_LOCATION),
            "uptime": await self._get_oid(OID_SYSTEM_UPTIME),
        }

    async def get_device_info(self) -> dict[str, Any]:
        """Get device information."""
        device_state = await self._get_oid(OID_PRINTER_STATUS)
        serial = await self._get_oid(OID_SERIAL_NUMBER)
        mac = await self._get_oid(OID_HARDWARE_ADDRESS)

        # Convert MAC address to standard format
        if mac:
            try:
                mac_bytes = bytes.fromhex(mac.replace(" ", "").replace("0x", ""))
                mac = ":".join([f"{b:02x}" for b in mac_bytes])
            except Exception:
                pass

        # Get page counts
        page_counts = await self.get_page_counts()

        return {
            "state": PRINTER_STATUS.get(
                int(device_state) if device_state else 1, "unknown"
            ),
            "errors": await self._get_oid(OID_DEVICE_ERRORS),
            "serial_number": serial,
            "mac_address": mac,
            "memory_size": await self._get_oid(OID_MEMORY_SIZE),
            "page_count": page_counts.get("total"),  # Keep for backward compatibility
            "page_counts": page_counts,  # Detailed page counts
        }

    async def get_supplies(self) -> list[dict[str, Any]]:
        """Get all printer supplies (toner, ink, drums, etc.)."""
        descriptions = await self._walk_oid(OID_MARKER_SUPPLIES_DESCRIPTION)
        types = await self._walk_oid(OID_MARKER_SUPPLIES_TYPE)
        classes = await self._walk_oid(OID_MARKER_SUPPLIES_CLASS)
        max_capacities = await self._walk_oid(OID_MARKER_SUPPLIES_MAX_CAPACITY)
        levels = await self._walk_oid(OID_MARKER_SUPPLIES_LEVEL)

        supplies = []
        for index in descriptions.keys():
            supply_type = int(types.get(index, 1))
            supply_class = int(classes.get(index, 1))
            max_capacity = int(max_capacities.get(index, -2))
            level = int(levels.get(index, -2))

            # Calculate percentage if capacity is known
            percentage = None
            if max_capacity > 0 and level >= 0:
                percentage = int((level / max_capacity) * 100)
            elif level == -2:  # Unknown
                percentage = None
            elif level == -3:  # At least one supply is at some level
                percentage = 50

            # Extract color from description
            description = descriptions[index]
            color = "Unknown"
            description_lower = description.lower()

            # Log the description for debugging color extraction
            _LOGGER.debug(
                "Supply %s: description='%s', extracting color...", index, description
            )

            # Check for common color names in description
            if (
                "black" in description_lower
                or "blk" in description_lower
                or "bk" in description_lower
            ):
                color = "Black"
            elif "cyan" in description_lower:
                color = "Cyan"
            elif "magenta" in description_lower:
                color = "Magenta"
            elif "yellow" in description_lower or "ylw" in description_lower:
                color = "Yellow"
            elif "light cyan" in description_lower or "lightcyan" in description_lower:
                color = "Light Cyan"
            elif (
                "light magenta" in description_lower
                or "lightmagenta" in description_lower
            ):
                color = "Light Magenta"
            elif "photo" in description_lower:
                color = "Photo"
            elif "gray" in description_lower or "grey" in description_lower:
                color = "Gray"

            _LOGGER.debug("Supply %s: extracted color='%s'", index, color)

            supplies.append(
                {
                    "index": index,
                    "description": description,
                    "color": color,
                    "type": SUPPLY_TYPE.get(supply_type, "unknown"),
                    "class": SUPPLY_CLASS.get(supply_class, "unknown"),
                    "max_capacity": max_capacity,
                    "level": level,
                    "percentage": percentage,
                }
            )

        return supplies

    async def get_input_trays(self) -> list[dict[str, Any]]:
        """Get all paper input trays."""
        descriptions = await self._walk_oid(OID_INPUT_DESCRIPTION)
        max_capacities = await self._walk_oid(OID_INPUT_MAX_CAPACITY)
        levels = await self._walk_oid(OID_INPUT_CURRENT_LEVEL)

        trays = []
        for index in descriptions.keys():
            max_capacity = int(max_capacities.get(index, -2))
            level = int(levels.get(index, -2))

            # Calculate percentage
            percentage = None
            if max_capacity > 0 and level >= 0:
                percentage = int((level / max_capacity) * 100)

            trays.append(
                {
                    "index": index,
                    "description": descriptions[index],
                    "max_capacity": max_capacity,
                    "level": level,
                    "percentage": percentage,
                }
            )

        return trays

    async def get_cover_status(self) -> str:
        """Get cover status."""
        status = await self._get_oid(OID_COVER_STATUS)
        if status:
            status_map = {
                "3": "open",
                "4": "closed",
                "5": "interlock_open",
                "6": "interlock_closed",
            }
            return status_map.get(status, "unknown")
        return "unknown"

    async def get_display_text(self) -> str | None:
        """Get text from printer display."""
        try:
            # Try to get display buffer text
            text = await self._get_oid(f"{OID_DISPLAY_BUFFER}.1.1")
            if not text:
                return None

            # Decode hex string if it starts with 0x
            if isinstance(text, str) and text.startswith("0x"):
                try:
                    # Remove 0x prefix and decode hex to bytes, then to UTF-8 string
                    hex_str = text[2:]
                    bytes_data = bytes.fromhex(hex_str)
                    text = bytes_data.decode("utf-8", errors="ignore")
                except Exception:
                    pass  # Return as-is if decoding fails

            return text if text else None
        except Exception:
            return None

    async def get_printer_errors(self) -> str | None:
        """Get printer error messages."""
        errors = await self._get_oid(OID_DEVICE_ERRORS)
        return errors if errors and errors != "0" and errors != "" else None

    async def get_page_counts(self) -> dict[str, int]:
        """Get page counts including total, color, and black/white pages."""
        # Walk the page count OID to get all marker impression counts
        # OID 1.3.6.1.2.1.43.10.2.1.4.1.x where x is the marker index
        page_counts = await self._walk_oid("1.3.6.1.2.1.43.10.2.1.4.1")

        result = {
            "total": None,
            "color": None,
            "black_and_white": None,
        }

        if not page_counts:
            return result

        # Process all page counts
        # Index 1 is usually total pages
        # Subsequent indices may be black/color depending on printer
        counts = [
            int(count) for count in page_counts.values() if count and count.isdigit()
        ]

        if len(counts) > 0:
            # First value is typically total pages
            result["total"] = counts[0]

        if len(counts) == 3:
            # Some printers report: total, color, BW
            result["color"] = counts[1]
            result["black_and_white"] = counts[2]
        elif len(counts) == 2:
            # Some printers report: color, BW (and we calculate total)
            result["color"] = counts[0]
            result["black_and_white"] = counts[1]
            if result["total"] is None:
                result["total"] = result["color"] + result["black_and_white"]

        return result

    async def get_all_data(self) -> dict[str, Any]:
        """Get all printer data."""
        return {
            "system": await self.get_system_info(),
            "device": await self.get_device_info(),
            "supplies": await self.get_supplies(),
            "trays": await self.get_input_trays(),
            "cover_status": await self.get_cover_status(),
        }

    async def set_display_text(self, text: str) -> bool:
        """Set text on printer display."""
        # Try to set display text (may not be supported on all printers)
        return await self._set_oid(f"{OID_DISPLAY_BUFFER}.1.1", text)

    async def get_manufacturer(self) -> str:
        """Extract manufacturer from system description."""
        description = await self._get_oid(OID_SYSTEM_DESCRIPTION)
        if not description:
            return "Unknown"

        # Try to extract manufacturer from description
        from .const import PRINTER_MANUFACTURERS

        description_lower = description.lower()
        for manufacturer in PRINTER_MANUFACTURERS:
            if manufacturer.lower() in description_lower:
                return manufacturer

        return "Unknown"
