//! # SAM Session - Session Tracking and Device Fingerprinting
//!
//! Track user sessions across multiple devices and enable contextual authentication.
//!
//! ## Features
//!
//! ### 📱 Device Fingerprinting
//!
//! Identify devices by unique characteristics:
//!
//! - User agent string
//! - Screen resolution
//! - Timezone and language
//! - Hardware identifiers
//! - Network information
//!
//! ### 🔄 Cross-Instance Sessions
//!
//! Track sessions across multiple SAM instances:
//!
//! - Desktop, laptop, mobile, Raspberry Pi
//! - Session continuity across devices
//! - "I see you spoke with me on your desktop"
//!
//! ### 🔐 Contextual Authentication
//!
//! Make auth decisions based on device trust:
//!
//! - Skip voice auth on known devices
//! - Detect suspicious new devices
//! - Track device usage patterns
//!
//! ## Usage
//!
//! ```rust,ignore
//! use sam_session::{SessionStore, DeviceRegistry, Session, DeviceFingerprint, DeviceType};
//! use sam_vector::Database;
//! use uuid::Uuid;
//!
//! // Initialize stores
//! let db = Database::new("sessions.db").unwrap();
//! let session_store = SessionStore::new(&db).unwrap();
//! let device_registry = DeviceRegistry::new("devices.db").unwrap();
//!
//! // Create session with device fingerprint
//! let fingerprint = DeviceFingerprint {
//!     device_type: DeviceType::Desktop,
//!     os: "Linux".to_string(),
//!     browser: Some("Firefox".to_string()),
//!     screen_resolution: Some("1920x1080".to_string()),
//!     timezone: Some("America/New_York".to_string()),
//!     language: Some("en-US".to_string()),
//!     user_agent: Some("Mozilla/5.0...".to_string()),
//! };
//!
//! let session = Session::new(
//!     "user123".to_string(),
//!     "device-1".to_string(),
//!     "instance-1".to_string(),
//!     DeviceType::Desktop
//! );
//! session_store.store_session(&session).unwrap();
//!
//! // Register device
//! let device_id = device_registry.register_device(
//!     "user123",
//!     "Magnus's Desktop",
//!     "Mozilla/5.0 (X11; Linux x86_64)...",
//!     Some("192.168.1.100"),
//! ).unwrap();
//!
//! // Check device trust
//! if device_registry.is_device_trusted("user123", &device_id).unwrap() {
//!     println!("Known device - expedited auth");
//! }
//! ```

pub mod sessions;
pub mod session_store;
pub mod device_registry;

// Re-export main types
pub use sessions::{Session, DeviceFingerprint, DeviceType};
pub use session_store::{SessionStore, SessionStoreError};
pub use device_registry::{DeviceRegistry, RegisteredDevice, DeviceTrustStatus};
