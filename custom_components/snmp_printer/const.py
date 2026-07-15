"""Constants for the SNMP Printer integration."""

from typing import Final

DOMAIN: Final = "snmp_printer"

# Configuration
CONF_UPDATE_INTERVAL: Final = "update_interval"
CONF_SNMP_VERSION: Final = "snmp_version"
CONF_COMMUNITY: Final = "community"
CONF_USERNAME: Final = "username"
CONF_AUTH_PROTOCOL: Final = "auth_protocol"
CONF_AUTH_KEY: Final = "auth_key"
CONF_PRIV_PROTOCOL: Final = "priv_protocol"
CONF_PRIV_KEY: Final = "priv_key"
CONF_NAME_SOURCE: Final = "name_source"
CONF_SUBNET: Final = "subnet"

# Defaults
DEFAULT_PORT: Final = 161
DEFAULT_COMMUNITY: Final = "public"
DEFAULT_UPDATE_INTERVAL: Final = 60
DEFAULT_SNMP_VERSION: Final = "2c"

# Device naming sources (issue #19)
NAME_SOURCE_SNMP: Final = "snmp"
NAME_SOURCE_DNS_HOSTNAME: Final = "dns_hostname"
NAME_SOURCE_DNS_FQDN: Final = "dns_fqdn"
DEFAULT_NAME_SOURCE: Final = NAME_SOURCE_SNMP

# Network scan discovery (issue #12)
SCAN_MAX_HOSTS: Final = 1024  # Refuse to scan networks larger than this
SCAN_CONCURRENCY: Final = 40  # Max simultaneous SNMP probes during a scan
SCAN_TIMEOUT: Final = 1.0  # Seconds per probe during a scan

# Error logging configuration
DEFAULT_ERROR_LOG_INTERVAL: Final = (
    300  # Log offline errors at most once every 5 minutes
)

# SNMP error statuses that indicate an OID is simply not supported by the
# printer rather than a connection problem. These must not be treated as
# offline/connection errors or logged repeatedly (issue #14).
UNSUPPORTED_OID_ERRORS: Final = frozenset(
    {"noSuchName", "noSuchObject", "noSuchInstance"}
)

# SNMP OIDs based on RFC 3805 (Printer MIB) and RFC 1213 (MIB-II)
# System information
OID_SYSTEM_DESCRIPTION: Final = "1.3.6.1.2.1.1.1.0"
OID_SYSTEM_UPTIME: Final = "1.3.6.1.2.1.1.3.0"
OID_SYSTEM_CONTACT: Final = "1.3.6.1.2.1.1.4.0"
OID_SYSTEM_NAME: Final = "1.3.6.1.2.1.1.5.0"
OID_SYSTEM_LOCATION: Final = "1.3.6.1.2.1.1.6.0"

# Device information
OID_DEVICE_DESCRIPTION: Final = "1.3.6.1.2.1.25.3.2.1.3.1"
OID_DEVICE_STATE: Final = "1.3.6.1.2.1.25.3.2.1.5.1"
OID_DEVICE_ERRORS: Final = "1.3.6.1.2.1.25.3.2.1.6.1"

# Network information
OID_HARDWARE_ADDRESS: Final = "1.3.6.1.2.1.2.2.1.6.1"

# Printer information
OID_PRINTER_STATUS: Final = "1.3.6.1.2.1.25.3.5.1.1.1"
OID_PRINTER_ERRORS: Final = "1.3.6.1.2.1.25.3.5.1.2.1"

# Printer MIB specific
OID_SERIAL_NUMBER: Final = "1.3.6.1.2.1.43.5.1.1.17.1"
OID_PAGE_COUNT: Final = "1.3.6.1.2.1.43.10.2.1.4.1.1"
OID_MEMORY_SIZE: Final = "1.3.6.1.2.1.25.2.2.0"

# Cover status
OID_COVER_DESCRIPTION: Final = "1.3.6.1.2.1.43.6.1.1.3"
OID_COVER_STATUS: Final = "1.3.6.1.2.1.43.6.1.1.4"

# Marker (toner/ink) information - Base OIDs for walking
OID_MARKER_SUPPLIES_DESCRIPTION: Final = "1.3.6.1.2.1.43.11.1.1.6.1"
OID_MARKER_SUPPLIES_TYPE: Final = "1.3.6.1.2.1.43.11.1.1.4.1"
OID_MARKER_SUPPLIES_CLASS: Final = "1.3.6.1.2.1.43.11.1.1.5.1"
OID_MARKER_SUPPLIES_MAX_CAPACITY: Final = "1.3.6.1.2.1.43.11.1.1.8.1"
OID_MARKER_SUPPLIES_LEVEL: Final = "1.3.6.1.2.1.43.11.1.1.9.1"
OID_MARKER_SUPPLIES_UNIT: Final = "1.3.6.1.2.1.43.11.1.1.7.1"
OID_MARKER_COLOR: Final = "1.3.6.1.2.1.43.12.1.1.4.1"

# Input (paper tray) information - Base OIDs for walking
OID_INPUT_DESCRIPTION: Final = "1.3.6.1.2.1.43.8.2.1.13.1"
OID_INPUT_MAX_CAPACITY: Final = "1.3.6.1.2.1.43.8.2.1.9.1"
OID_INPUT_CURRENT_LEVEL: Final = "1.3.6.1.2.1.43.8.2.1.10.1"
OID_INPUT_STATUS: Final = "1.3.6.1.2.1.43.8.2.1.11.1"
OID_INPUT_TYPE: Final = "1.3.6.1.2.1.43.8.2.1.2.1"

# Console display
OID_DISPLAY_BUFFER: Final = "1.3.6.1.2.1.43.16.5.1.2"

# Device status mapping
DEVICE_STATUS = {
    1: "unknown",
    2: "online",
    3: "warning",
    4: "testing",
    5: "down",
}

# Printer status mapping
PRINTER_STATUS = {
    1: "other",
    2: "unknown",
    3: "idle",
    4: "printing",
    5: "warmup",
}

# Printer detector status mapping
PRINTER_DETECTOR_STATUS = {
    0: "unavailable",
    2: "on",
    3: "off",
    4: "jam",
    5: "no_paper",
}

# Supply type mapping
SUPPLY_TYPE = {
    1: "other",
    2: "unknown",
    3: "toner",
    4: "wasteToner",
    5: "ink",
    6: "inkCartridge",
    7: "inkRibbon",
    8: "wasteInk",
    9: "opc",
    10: "developer",
    11: "fuserOil",
    12: "solidWax",
    13: "ribbonWax",
    14: "wasteWax",
    15: "fuser",
    16: "coronaWire",
    17: "fuserOilWick",
    18: "cleanerUnit",
    19: "fuserCleaningPad",
    20: "transferUnit",
    21: "tonerCartridge",
    22: "fuserOiler",
    23: "water",
    24: "wasteWater",
    25: "glueWaterAdditive",
    26: "wastePaper",
    27: "bindingSupply",
    28: "bandingSupply",
    29: "stitchingWire",
    30: "shrinkWrap",
    31: "paperWrap",
    32: "staples",
    33: "inserts",
    34: "covers",
}

# Supply class mapping
SUPPLY_CLASS = {
    1: "other",
    2: "consumed",
    3: "filled",
}

# Color mapping for markers
MARKER_COLOR_MAP = {
    "black": "Black",
    "cyan": "Cyan",
    "magenta": "Magenta",
    "yellow": "Yellow",
    "lightCyan": "Light Cyan",
    "lightMagenta": "Light Magenta",
    "lightBlack": "Light Black",
    "gray": "Gray",
    "orange": "Orange",
    "violet": "Violet",
    "red": "Red",
    "green": "Green",
    "blue": "Blue",
}

# Printer manufacturers
PRINTER_MANUFACTURERS = [
    "Brother",
    "Canon",
    "HP",
    "Hewlett-Packard",
    "Konica Minolta",
    "Kyocera",
    "Lexmark",
    "OKI",
    "Panasonic",
    "Ricoh",
    "Samsung",
    "Sharp",
    "Xerox",
]
