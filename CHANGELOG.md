# Changelog

## [0.1.0] - 2025-12-21

### Added
- Initial release extracted from SAM project
- **Session Tracking**: Cross-instance session management
  - Desktop, laptop, mobile, tablet, Raspberry Pi, server support
  - Session lifecycle (creation, activity counters, end time)
  - User and device association
- **Device Fingerprinting**: Unique device identification
  - User agent string
  - Screen resolution
  - Timezone and language
  - OS and browser detection
  - Hardware identifiers
  - Automatic device type detection
- **Device Registry**: Trusted device management
  - Register devices per user
  - Trust status tracking (Trusted, Suspicious, Revoked)
  - Device fingerprint matching
  - Last seen tracking
  - IP address logging
- **Session Store**: SQLite persistence
  - Store and retrieve sessions
  - Active session queries
  - User session history
  - Device information storage

### Features
- Cross-instance context awareness
- Contextual authentication (skip voice auth on known devices)
- Suspicious device detection
- Device usage pattern tracking
- Automatic device type detection from system info

### Modules
- sessions.rs (305 LOC) - Session types, fingerprinting
- session_store.rs (266 LOC) - SQLite persistence
- device_registry.rs (336 LOC) - Device management

### Dependencies
- rusqlite 0.31 (persistence)
- sam-vector (Database trait)
- num_cpus 1.16 (system info)
- hostname 0.4 (device identification)
- chrono 0.4 (timestamps)
- uuid 1.0 (session IDs)

### Testing
- 18 unit tests passing
- 2 doctests ignored (API examples need updates)

### Notes
- Extracted from [SAM (Societal Advisory Module)](https://github.com/Blackfall-Labs/sam)
- Production-ready for multi-device authentication systems
