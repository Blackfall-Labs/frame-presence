# Frame Presence - Session Tracking and Device Fingerprinting

**Track user sessions across devices and enable contextual authentication for AI systems.**

Extracted from the Frame project.

## Features

- **Device Fingerprinting**: Identify devices by unique characteristics (user agent, screen resolution, timezone, hardware IDs)
- **Cross-Instance Sessions**: Track sessions across desktop, laptop, mobile, Raspberry Pi
- **Contextual Authentication**: Skip voice auth on known devices, detect suspicious new devices
- **Device Registry**: Manage trusted devices per user
- **Session Continuity**: "I see you spoke with me on your desktop"

## Quick Start

```toml
[dependencies]
sam-session = "0.1.0"
```

```rust
use sam_session::{SessionStore, DeviceRegistry, Session, DeviceType};
use frame_catalog::Database;

// Initialize stores
let db = Database::new("sessions.db")?;
let session_store = SessionStore::new(&db)?;
let device_registry = DeviceRegistry::new("devices.db")?;

// Create session
let session = Session::new(
    "user123".to_string(),
    "device-1".to_string(),
    "instance-1".to_string(),
    DeviceType::Desktop
);
session_store.store_session(&session)?;

// Register device
let device_id = device_registry.register_device(
    "user123",
    "Magnus's Desktop",
    "Mozilla/5.0 (X11; Linux x86_64)...",
    Some("192.168.1.100"),
)?;

// Check device trust
if device_registry.is_device_trusted("user123", &device_id)? {
    println!("Known device - expedited auth");
}
```

## Modules

- **sessions** (305 LOC) - Session types, device fingerprinting
- **session_store** (266 LOC) - SQLite persistence for sessions
- **device_registry** (336 LOC) - Device registration and trust tracking

## Device Types

- Desktop
- Laptop
- Mobile
- Tablet
- RaspberryPi
- Server
- Unknown (auto-detected)

## Compatibility

- **Rust Edition**: 2021
- **MSRV**: 1.70+
- **Platforms**: All

## Dependencies

- `rusqlite` (0.31) - Session/device persistence
- `frame-catalog` - Database trait
- `num_cpus` (1.16) - System info
- `hostname` (0.4) - Device identification

## Testing

```bash
cargo test  # 18 tests passing, 2 doctests ignored
```

## License

MIT - See [LICENSE](LICENSE) for details.

## Author

Magnus Trent <magnus@blackfall.dev>

## Links

- **GitHub:** https://github.com/Blackfall-Labs/sam-session
- **SAM Project:** https://github.com/Blackfall-Labs/sam
