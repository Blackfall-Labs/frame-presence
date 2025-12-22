//! Device Registry for Contextual Authentication
//!
//! Tracks known devices for each user to enable:
//! - Device fingerprinting (bypass voice auth on known devices)
//! - Contextual authentication decisions
//! - "This is Magnus's phone" recognition
//! - Suspicious device detection
//!
//! ## Device Fingerprint
//!
//! Combination of:
//! - User agent string
//! - Screen resolution
//! - Timezone
//! - Language preferences
//! - Browser/OS version
//! - Hardware identifiers (when available)
//!
//! ## Usage
//!
//! ```ignore
//! use sam_memory::DeviceRegistry;
//! use std::path::Path;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let registry = DeviceRegistry::new(Path::new("sam_memory.db"))?;
//!
//! // Register new device
//! let device_id = registry.register_device(
//!     "user-alice",
//!     "Magnus's iPhone",
//!     "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0...)",
//!     Some("192.168.1.100"),
//! )?;
//!
//! // Check if device is trusted
//! if registry.is_device_trusted("user-alice", &device_id)? {
//!     println!("Known device - skip voice auth");
//! }
//! # Ok(())
//! # }
//! ```

use frame_catalog::database::{Database, DatabaseError};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Device trust status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceTrustStatus {
    /// Pending user approval
    Pending,
    /// Trusted device (skip additional auth)
    Trusted,
    /// Revoked (lost/stolen)
    Revoked,
    /// Suspicious activity detected
    Suspicious,
}

impl DeviceTrustStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Trusted => "trusted",
            Self::Revoked => "revoked",
            Self::Suspicious => "suspicious",
        }
    }

    pub fn from_str(s: &str) -> Result<Self, DatabaseError> {
        match s {
            "pending" => Ok(Self::Pending),
            "trusted" => Ok(Self::Trusted),
            "revoked" => Ok(Self::Revoked),
            "suspicious" => Ok(Self::Suspicious),
            _ => Err(DatabaseError::NotFound),
        }
    }
}

/// Registered device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredDevice {
    pub device_id: String,
    pub user_id: String,
    pub device_name: String,
    pub device_fingerprint: String,
    pub trust_status: DeviceTrustStatus,
    pub last_ip: Option<String>,
    pub registered_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub last_location: Option<String>,
}

/// Device registry for contextual authentication
pub struct DeviceRegistry {
    db: Arc<Mutex<Connection>>,
}

impl DeviceRegistry {
    /// Create a new device registry
    pub fn new(db_path: &Path) -> Result<Self, DatabaseError> {
        let database = Database::new(db_path)?;
        let registry = Self {
            db: database.conn(),
        };

        registry.create_tables()?;
        Ok(registry)
    }

    /// Create device registry tables
    fn create_tables(&self) -> Result<(), DatabaseError> {
        let conn = self.db.lock().unwrap();

        // Devices table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS devices (
                device_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                device_name TEXT NOT NULL,
                device_fingerprint TEXT NOT NULL,
                trust_status TEXT NOT NULL DEFAULT 'pending',
                last_ip TEXT,
                registered_at TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                last_location TEXT,
                UNIQUE(user_id, device_fingerprint)
            )",
            [],
        )?;

        // Index for fast user device lookups
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id)",
            [],
        )?;

        // Index for trust status queries
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_devices_trust_status ON devices(trust_status)",
            [],
        )?;

        tracing::info!("📱 Device registry tables created");
        Ok(())
    }

    /// Register a new device
    pub fn register_device(
        &self,
        user_id: &str,
        device_name: &str,
        device_fingerprint: &str,
        last_ip: Option<&str>,
    ) -> Result<String, DatabaseError> {
        let device_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        let conn = self.db.lock().unwrap();
        conn.execute(
            "INSERT INTO devices (device_id, user_id, device_name, device_fingerprint,
             trust_status, last_ip, registered_at, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                device_id,
                user_id,
                device_name,
                device_fingerprint,
                DeviceTrustStatus::Pending.as_str(),
                last_ip,
                &now,
                &now,
            ],
        )?;

        tracing::info!(
            "📱 Registered device '{}' for user {}",
            device_name,
            user_id
        );

        Ok(device_id)
    }

    /// Trust a device (user approves)
    pub fn trust_device(&self, device_id: &str) -> Result<(), DatabaseError> {
        let conn = self.db.lock().unwrap();
        let rows_affected = conn.execute(
            "UPDATE devices SET trust_status = ?1 WHERE device_id = ?2",
            params![DeviceTrustStatus::Trusted.as_str(), device_id],
        )?;

        if rows_affected == 0 {
            return Err(DatabaseError::NotFound);
        }

        tracing::info!("✅ Device {} marked as trusted", device_id);
        Ok(())
    }

    /// Revoke a device (lost/stolen)
    pub fn revoke_device(&self, device_id: &str) -> Result<(), DatabaseError> {
        let conn = self.db.lock().unwrap();
        let rows_affected = conn.execute(
            "UPDATE devices SET trust_status = ?1 WHERE device_id = ?2",
            params![DeviceTrustStatus::Revoked.as_str(), device_id],
        )?;

        if rows_affected == 0 {
            return Err(DatabaseError::NotFound);
        }

        tracing::warn!("🚫 Device {} revoked", device_id);
        Ok(())
    }

    /// Mark device as suspicious
    pub fn mark_suspicious(&self, device_id: &str) -> Result<(), DatabaseError> {
        let conn = self.db.lock().unwrap();
        let rows_affected = conn.execute(
            "UPDATE devices SET trust_status = ?1 WHERE device_id = ?2",
            params![DeviceTrustStatus::Suspicious.as_str(), device_id],
        )?;

        if rows_affected == 0 {
            return Err(DatabaseError::NotFound);
        }

        tracing::warn!("⚠️ Device {} marked suspicious", device_id);
        Ok(())
    }

    /// Check if device is trusted
    pub fn is_device_trusted(&self, user_id: &str, device_id: &str) -> Result<bool, DatabaseError> {
        let conn = self.db.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT trust_status FROM devices WHERE device_id = ?1 AND user_id = ?2")?;

        let trust_status: String = stmt.query_row(params![device_id, user_id], |row| row.get(0))?;

        Ok(trust_status == DeviceTrustStatus::Trusted.as_str())
    }

    /// Get device by fingerprint
    pub fn get_device_by_fingerprint(
        &self,
        user_id: &str,
        device_fingerprint: &str,
    ) -> Result<RegisteredDevice, DatabaseError> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT device_id, user_id, device_name, device_fingerprint, trust_status,
             last_ip, registered_at, last_seen, last_location
             FROM devices WHERE user_id = ?1 AND device_fingerprint = ?2",
        )?;

        stmt.query_row(params![user_id, device_fingerprint], |row| {
            Ok(RegisteredDevice {
                device_id: row.get(0)?,
                user_id: row.get(1)?,
                device_name: row.get(2)?,
                device_fingerprint: row.get(3)?,
                trust_status: DeviceTrustStatus::from_str(&row.get::<_, String>(4)?).unwrap(),
                last_ip: row.get(5)?,
                registered_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                    .unwrap()
                    .with_timezone(&Utc),
                last_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?)
                    .unwrap()
                    .with_timezone(&Utc),
                last_location: row.get(8)?,
            })
        })
        .map_err(|_| DatabaseError::NotFound)
    }

    /// Get all devices for a user
    pub fn get_user_devices(&self, user_id: &str) -> Result<Vec<RegisteredDevice>, DatabaseError> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT device_id, user_id, device_name, device_fingerprint, trust_status,
             last_ip, registered_at, last_seen, last_location
             FROM devices WHERE user_id = ?1 ORDER BY last_seen DESC",
        )?;

        let devices = stmt
            .query_map(params![user_id], |row| {
                Ok(RegisteredDevice {
                    device_id: row.get(0)?,
                    user_id: row.get(1)?,
                    device_name: row.get(2)?,
                    device_fingerprint: row.get(3)?,
                    trust_status: DeviceTrustStatus::from_str(&row.get::<_, String>(4)?).unwrap(),
                    last_ip: row.get(5)?,
                    registered_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    last_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    last_location: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(devices)
    }

    /// Update device last seen
    pub fn update_last_seen(
        &self,
        device_id: &str,
        last_ip: Option<&str>,
        last_location: Option<&str>,
    ) -> Result<(), DatabaseError> {
        let now = Utc::now().to_rfc3339();

        let conn = self.db.lock().unwrap();
        conn.execute(
            "UPDATE devices SET last_seen = ?1, last_ip = ?2, last_location = ?3
             WHERE device_id = ?4",
            params![&now, last_ip, last_location, device_id],
        )?;

        Ok(())
    }

    /// Get device by ID
    pub fn get_device(&self, device_id: &str) -> Result<RegisteredDevice, DatabaseError> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT device_id, user_id, device_name, device_fingerprint, trust_status,
             last_ip, registered_at, last_seen, last_location
             FROM devices WHERE device_id = ?1",
        )?;

        stmt.query_row(params![device_id], |row| {
            Ok(RegisteredDevice {
                device_id: row.get(0)?,
                user_id: row.get(1)?,
                device_name: row.get(2)?,
                device_fingerprint: row.get(3)?,
                trust_status: DeviceTrustStatus::from_str(&row.get::<_, String>(4)?).unwrap(),
                last_ip: row.get(5)?,
                registered_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                    .unwrap()
                    .with_timezone(&Utc),
                last_seen: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?)
                    .unwrap()
                    .with_timezone(&Utc),
                last_location: row.get(8)?,
            })
        })
        .map_err(|_| DatabaseError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_register_and_trust_device() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let registry = DeviceRegistry::new(&db_path).unwrap();

        // Register device
        let device_id = registry
            .register_device(
                "user-alice",
                "Alice's iPhone",
                "Mozilla/5.0 (iPhone...)",
                Some("192.168.1.100"),
            )
            .unwrap();

        // Should not be trusted initially
        assert!(!registry
            .is_device_trusted("user-alice", &device_id)
            .unwrap());

        // Trust the device
        registry.trust_device(&device_id).unwrap();

        // Now should be trusted
        assert!(registry
            .is_device_trusted("user-alice", &device_id)
            .unwrap());
    }

    #[test]
    fn test_revoke_device() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let registry = DeviceRegistry::new(&db_path).unwrap();

        let device_id = registry
            .register_device("user-bob", "Bob's Phone", "fingerprint-123", None)
            .unwrap();

        registry.trust_device(&device_id).unwrap();
        assert!(registry.is_device_trusted("user-bob", &device_id).unwrap());

        // Revoke device
        registry.revoke_device(&device_id).unwrap();
        assert!(!registry.is_device_trusted("user-bob", &device_id).unwrap());
    }

    #[test]
    fn test_get_device_by_fingerprint() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let registry = DeviceRegistry::new(&db_path).unwrap();

        let fingerprint = "unique-fingerprint-456";
        let device_id = registry
            .register_device(
                "user-charlie",
                "Charlie's Laptop",
                fingerprint,
                Some("10.0.0.5"),
            )
            .unwrap();

        // Get device by fingerprint
        let device = registry
            .get_device_by_fingerprint("user-charlie", fingerprint)
            .unwrap();

        assert_eq!(device.device_id, device_id);
        assert_eq!(device.device_name, "Charlie's Laptop");
        assert_eq!(device.trust_status, DeviceTrustStatus::Pending);
    }

    #[test]
    fn test_get_user_devices() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let registry = DeviceRegistry::new(&db_path).unwrap();

        // Register multiple devices for same user
        registry
            .register_device("user-dave", "Dave's Phone", "fp-1", None)
            .unwrap();
        registry
            .register_device("user-dave", "Dave's Laptop", "fp-2", None)
            .unwrap();
        registry
            .register_device("user-dave", "Dave's Tablet", "fp-3", None)
            .unwrap();

        let devices = registry.get_user_devices("user-dave").unwrap();
        assert_eq!(devices.len(), 3);
    }

    #[test]
    fn test_mark_suspicious() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");

        let registry = DeviceRegistry::new(&db_path).unwrap();

        let device_id = registry
            .register_device("user-eve", "Eve's Device", "fp-suspicious", Some("1.2.3.4"))
            .unwrap();

        registry.mark_suspicious(&device_id).unwrap();

        let device = registry.get_device(&device_id).unwrap();
        assert_eq!(device.trust_status, DeviceTrustStatus::Suspicious);
    }
}
