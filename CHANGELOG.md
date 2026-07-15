# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-07-15

### Fixed
- Blocking `listdir`/`open` calls during setup: the SNMP engine (which loads MIBs
  from disk) is now created in an executor so it no longer blocks the Home
  Assistant event loop (Issue #20)
- Repeated `noSuchName` error spam: OIDs a printer does not expose (e.g. cover
  status) are now treated as "unsupported" and logged at debug level instead of
  being logged as connection errors on every poll (Issue #14)
- SNMPv2c/v3 missing-OID exception values (`NoSuchObject`, `NoSuchInstance`,
  `EndOfMibView`) are now handled the same way as unsupported OIDs

### Changed
- Updated `pysnmp` to 7.1.27 and aligned the pinned version between
  `manifest.json` and `requirements.txt`
- CI: bumped `actions/checkout` to v7 and added Python 3.13 to the test matrix

## [1.1.0] - 2025-10-14

### Added
- Cached values feature: Integration now remembers last known sensor values when printer is offline (Issue #3)
- Offline status indication in sensor attributes with timestamp of last successful data fetch
- Status sensor now shows "offline" state when using cached data

### Fixed
- Reduced excessive SNMP error logging when printer is offline (Issue #6)
- SNMP errors now log once as ERROR, then at WARNING level every 5 minutes to prevent log spam
- Connection recovery is properly logged when printer comes back online

## [1.0.0] - 2025-10-01

### Added
- Initial release
- SNMP v1, v2c, and v3 support
- Automatic printer discovery via Zeroconf/mDNS (a bit slow due to pulling snmp values but works)
- Manual printer configuration
- Support for major printer brands (Brother, Canon, HP, Konica Minolta, Kyocera, Lexmark, OKI, Panasonic, Ricoh, Samsung, Sharp, Xerox)
- Support for MIB and MIBII
- Wide sensor coverage:
  - Printer status sensor with attributes
  - Cover status sensor
  - Total pages sensor with color/BW breakdown
  - Toner/ink level sensors
  - Paper tray sensors
  - Waste container sensor
  - Drum unit sensors
  - Other consumable sensors
- Device information display (manufacturer, serial number, MAC address)
- Automatic web interface link detection (check if web gui reachable)
- Display text service for printer displays (make amazing automations!)
- Localization support