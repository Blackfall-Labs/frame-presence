//! Session Store - Persistence for sessions and devices
//!
//! Tracks active and historical sessions across all SAM instances.
//! Enables cross-instance context: "I see you spoke with me on your desktop"

use sam_vector::Database;
use crate::sessions::{DeviceFingerprint, DeviceType, Session};
use chrono::{DateTime, Utc};
use rusqlite::params;
use serde_json;
use std::sync::Arc;
use uuid::Uuid;

pub type Result<T> = std::result::Result<T, SessionStoreError>;

#[derive(Debug, thiserror::Error)]
pub enum SessionStoreError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("DateTime parse error: {0}")]
    DateTimeParse(#[from] chrono::ParseError),

    #[error("Session not found: {0}")]
    NotFound(String),

    #[error("Device not found: {0}")]
    DeviceNotFound(String),
}

/// Store for sessions and device fingerprints
pub struct SessionStore {
    db: Arc<std::sync::Mutex<rusqlite::Connection>>,
}

impl SessionStore {
    /// Create session store with database connection
    pub fn new(database: &Database) -> Result<Self> {
        let db = database.conn();

        // Initialize schema
        {
            let conn = db.lock().unwrap();

            // Devices table
            conn.execute(
                "CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    device_type TEXT NOT NULL,
                    hostname TEXT,
                    os TEXT NOT NULL,
                    os_version TEXT NOT NULL,
                    arch TEXT NOT NULL,
                    cpu_cores INTEGER,
                    ram_gb INTEGER,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                )",
                [],
            )?;

            // Sessions table
            conn.execute(
                "CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    instance_id TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    typing_match REAL,
                    voice_match REAL,
                    visual_match REAL,
                    location TEXT,
                    device_type TEXT NOT NULL,
                    conversation_count INTEGER NOT NULL DEFAULT 0,
                    message_count INTEGER NOT NULL DEFAULT 0,
                    metadata TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices(device_id)
                )",
                [],
            )?;

            // Indexes for efficient querying
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)",
                [],
            )?;
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sessions_device ON sessions(device_id)",
                [],
            )?;
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sessions_instance ON sessions(instance_id)",
                [],
            )?;
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(end_time)",
                [],
            )?;
        }

        Ok(Self { db })
    }

    /// Store device fingerprint
    pub fn store_device(&self, device: &DeviceFingerprint) -> Result<()> {
        let conn = self.db.lock().unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO devices
             (device_id, device_type, hostname, os, os_version, arch, cpu_cores, ram_gb, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                device.device_id,
                serde_json::to_string(&device.device_type)?,
                device.hostname,
                device.os,
                device.os_version,
                device.arch,
                device.cpu_cores,
                device.ram_gb,
                device.first_seen.to_rfc3339(),
                device.last_seen.to_rfc3339(),
            ],
        )?;

        Ok(())
    }

    /// Get device fingerprint by ID
    pub fn get_device(&self, device_id: &str) -> Result<DeviceFingerprint> {
        let conn = self.db.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT device_id, device_type, hostname, os, os_version, arch, cpu_cores, ram_gb, first_seen, last_seen
             FROM devices
             WHERE device_id = ?1",
        )?;

        let device = stmt
            .query_row([device_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<u32>>(6)?,
                    row.get::<_, Option<u32>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            })
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    SessionStoreError::DeviceNotFound(device_id.to_string())
                }
                _ => SessionStoreError::Database(e),
            })?;

        let (
            device_id,
            device_type_json,
            hostname,
            os,
            os_version,
            arch,
            cpu_cores,
            ram_gb,
            first_seen,
            last_seen,
        ) = device;

        Ok(DeviceFingerprint {
            device_id,
            device_type: serde_json::from_str(&device_type_json)?,
            hostname,
            os,
            os_version,
            arch,
            cpu_cores,
            ram_gb,
            first_seen: DateTime::parse_from_rfc3339(&first_seen)?.with_timezone(&Utc),
            last_seen: DateTime::parse_from_rfc3339(&last_seen)?.with_timezone(&Utc),
        })
    }

    /// Store session
    pub fn store_session(&self, session: &Session) -> Result<()> {
        let conn = self.db.lock().unwrap();

        let metadata = session
            .metadata
            .as_ref()
            .map(|m| serde_json::to_string(m))
            .transpose()?;

        conn.execute(
            "INSERT OR REPLACE INTO sessions
             (id, user_id, device_id, instance_id, start_time, end_time,
              typing_match, voice_match, visual_match, location, device_type,
              conversation_count, message_count, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                session.id.to_string(),
                session.user_id,
                session.device_id,
                session.instance_id,
                session.start_time.to_rfc3339(),
                session.end_time.map(|t| t.to_rfc3339()),
                session.typing_match,
                session.voice_match,
                session.visual_match,
                session.location,
                serde_json::to_string(&session.device_type)?,
                session.conversation_count,
                session.message_count,
                metadata,
            ],
        )?;

        Ok(())
    }

    /// Get session by ID
    pub fn get_session(&self, session_id: Uuid) -> Result<Session> {
        let conn = self.db.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT id, user_id, device_id, instance_id, start_time, end_time,
                    typing_match, voice_match, visual_match, location, device_type,
                    conversation_count, message_count, metadata
             FROM sessions
             WHERE id = ?1",
        )?;

        let session = stmt
            .query_row([session_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<f32>>(6)?,
                    row.get::<_, Option<f32>>(7)?,
                    row.get::<_, Option<f32>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, u32>(11)?,
                    row.get::<_, u32>(12)?,
                    row.get::<_, Option<String>>(13)?,
                ))
            })
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    SessionStoreError::NotFound(session_id.to_string())
                }
                _ => SessionStoreError::Database(e),
            })?;

        let (
            id,
            user_id,
            device_id,
            instance_id,
            start_time,
            end_time,
            typing_match,
            voice_match,
            visual_match,
            location,
            device_type_json,
            conversation_count,
            message_count,
            metadata_json,
        ) = session;

        let metadata = metadata_json
            .map(|m| serde_json::from_str(&m))
            .transpose()?;

        Ok(Session {
            id: Uuid::parse_str(&id).unwrap(),
            user_id,
            device_id,
            instance_id,
            start_time: DateTime::parse_from_rfc3339(&start_time)?.with_timezone(&Utc),
            end_time: end_time
                .map(|t| DateTime::parse_from_rfc3339(&t).ok())
                .flatten()
                .map(|dt| dt.with_timezone(&Utc)),
            typing_match,
            voice_match,
            visual_match,
            location,
            device_type: serde_json::from_str(&device_type_json)?,
            conversation_count,
            message_count,
            metadata,
        })
    }

    /// Get all sessions for a user
    pub fn get_user_sessions(&self, user_id: &str, limit: Option<usize>) -> Result<Vec<Session>> {
        let conn = self.db.lock().unwrap();

        let query = if let Some(limit) = limit {
            format!(
                "SELECT id, user_id, device_id, instance_id, start_time, end_time,
                        typing_match, voice_match, visual_match, location, device_type,
                        conversation_count, message_count, metadata
                 FROM sessions
                 WHERE user_id = ?1
                 ORDER BY start_time DESC
                 LIMIT {}",
                limit
            )
        } else {
            "SELECT id, user_id, device_id, instance_id, start_time, end_time,
                    typing_match, voice_match, visual_match, location, device_type,
                    conversation_count, message_count, metadata
             FROM sessions
             WHERE user_id = ?1
             ORDER BY start_time DESC"
                .to_string()
        };

        let mut stmt = conn.prepare(&query)?;

        let rows = stmt.query_map([user_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<f32>>(6)?,
                row.get::<_, Option<f32>>(7)?,
                row.get::<_, Option<f32>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, u32>(11)?,
                row.get::<_, u32>(12)?,
                row.get::<_, Option<String>>(13)?,
            ))
        })?;

        let mut sessions = Vec::new();
        for row in rows {
            let (
                id,
                user_id,
                device_id,
                instance_id,
                start_time,
                end_time,
                typing_match,
                voice_match,
                visual_match,
                location,
                device_type_json,
                conversation_count,
                message_count,
                metadata_json,
            ) = row?;

            let metadata = metadata_json
                .map(|m| serde_json::from_str(&m))
                .transpose()?;

            sessions.push(Session {
                id: Uuid::parse_str(&id).unwrap(),
                user_id,
                device_id,
                instance_id,
                start_time: DateTime::parse_from_rfc3339(&start_time)
                    .unwrap()
                    .with_timezone(&Utc),
                end_time: end_time
                    .map(|t| DateTime::parse_from_rfc3339(&t).ok())
                    .flatten()
                    .map(|dt| dt.with_timezone(&Utc)),
                typing_match,
                voice_match,
                visual_match,
                location,
                device_type: serde_json::from_str(&device_type_json)?,
                conversation_count,
                message_count,
                metadata,
            });
        }

        Ok(sessions)
    }

    /// Get active sessions (end_time is NULL)
    pub fn get_active_sessions(&self) -> Result<Vec<Session>> {
        let conn = self.db.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT id, user_id, device_id, instance_id, start_time, end_time,
                    typing_match, voice_match, visual_match, location, device_type,
                    conversation_count, message_count, metadata
             FROM sessions
             WHERE end_time IS NULL
             ORDER BY start_time DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<f32>>(6)?,
                row.get::<_, Option<f32>>(7)?,
                row.get::<_, Option<f32>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, u32>(11)?,
                row.get::<_, u32>(12)?,
                row.get::<_, Option<String>>(13)?,
            ))
        })?;

        let mut sessions = Vec::new();
        for row in rows {
            let (
                id,
                user_id,
                device_id,
                instance_id,
                start_time,
                end_time,
                typing_match,
                voice_match,
                visual_match,
                location,
                device_type_json,
                conversation_count,
                message_count,
                metadata_json,
            ) = row?;

            let metadata = metadata_json
                .map(|m| serde_json::from_str(&m))
                .transpose()?;

            sessions.push(Session {
                id: Uuid::parse_str(&id).unwrap(),
                user_id,
                device_id,
                instance_id,
                start_time: DateTime::parse_from_rfc3339(&start_time)
                    .unwrap()
                    .with_timezone(&Utc),
                end_time: end_time
                    .map(|t| DateTime::parse_from_rfc3339(&t).ok())
                    .flatten()
                    .map(|dt| dt.with_timezone(&Utc)),
                typing_match,
                voice_match,
                visual_match,
                location,
                device_type: serde_json::from_str(&device_type_json)?,
                conversation_count,
                message_count,
                metadata,
            });
        }

        Ok(sessions)
    }

    /// Get active sessions for a specific user
    pub fn get_user_active_sessions(&self, user_id: &str) -> Result<Vec<Session>> {
        let conn = self.db.lock().unwrap();

        let mut stmt = conn.prepare(
            "SELECT id, user_id, device_id, instance_id, start_time, end_time,
                    typing_match, voice_match, visual_match, location, device_type,
                    conversation_count, message_count, metadata
             FROM sessions
             WHERE user_id = ?1 AND end_time IS NULL
             ORDER BY start_time DESC",
        )?;

        let rows = stmt.query_map([user_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<f32>>(6)?,
                row.get::<_, Option<f32>>(7)?,
                row.get::<_, Option<f32>>(8)?,
                row.get::<_, Option<String>>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, u32>(11)?,
                row.get::<_, u32>(12)?,
                row.get::<_, Option<String>>(13)?,
            ))
        })?;

        let mut sessions = Vec::new();
        for row in rows {
            let (
                id,
                user_id,
                device_id,
                instance_id,
                start_time,
                end_time,
                typing_match,
                voice_match,
                visual_match,
                location,
                device_type_json,
                conversation_count,
                message_count,
                metadata_json,
            ) = row?;

            let metadata = metadata_json
                .map(|m| serde_json::from_str(&m))
                .transpose()?;

            sessions.push(Session {
                id: Uuid::parse_str(&id).unwrap(),
                user_id,
                device_id,
                instance_id,
                start_time: DateTime::parse_from_rfc3339(&start_time)
                    .unwrap()
                    .with_timezone(&Utc),
                end_time: end_time
                    .map(|t| DateTime::parse_from_rfc3339(&t).ok())
                    .flatten()
                    .map(|dt| dt.with_timezone(&Utc)),
                typing_match,
                voice_match,
                visual_match,
                location,
                device_type: serde_json::from_str(&device_type_json)?,
                conversation_count,
                message_count,
                metadata,
            });
        }

        Ok(sessions)
    }

    /// Count total sessions
    pub fn count_sessions(&self) -> Result<usize> {
        let conn = self.db.lock().unwrap();
        let count: usize = conn.query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Count devices
    pub fn count_devices(&self) -> Result<usize> {
        let conn = self.db.lock().unwrap();
        let count: usize = conn.query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sessions::DeviceType;

    fn create_test_db() -> Database {
        Database::new(":memory:").unwrap()
    }

    #[test]
    fn test_session_store_creation() {
        let db = create_test_db();
        let store = SessionStore::new(&db).unwrap();
        assert_eq!(store.count_sessions().unwrap(), 0);
        assert_eq!(store.count_devices().unwrap(), 0);
    }

    #[test]
    fn test_store_and_retrieve_device() {
        let db = create_test_db();
        let store = SessionStore::new(&db).unwrap();

        let device = DeviceFingerprint::generate();
        let device_id = device.device_id.clone();

        store.store_device(&device).unwrap();

        let retrieved = store.get_device(&device_id).unwrap();
        assert_eq!(retrieved.device_id, device_id);
        assert_eq!(retrieved.os, device.os);
    }

    #[test]
    fn test_store_and_retrieve_session() {
        let db = create_test_db();
        let store = SessionStore::new(&db).unwrap();

        // Store device first
        let device = DeviceFingerprint::generate();
        store.store_device(&device).unwrap();

        // Create and store session
        let session = Session::new(
            "magnus".to_string(),
            device.device_id.clone(),
            "instance-1".to_string(),
            DeviceType::Desktop,
        );
        let session_id = session.id;

        store.store_session(&session).unwrap();

        let retrieved = store.get_session(session_id).unwrap();
        assert_eq!(retrieved.id, session_id);
        assert_eq!(retrieved.user_id, "magnus");
    }

    #[test]
    fn test_get_user_sessions() {
        let db = create_test_db();
        let store = SessionStore::new(&db).unwrap();

        let device = DeviceFingerprint::generate();
        store.store_device(&device).unwrap();

        // Create 3 sessions for magnus
        for _i in 0..3 {
            let session = Session::new(
                "magnus".to_string(),
                device.device_id.clone(),
                "instance-1".to_string(),
                DeviceType::Desktop,
            );
            store.store_session(&session).unwrap();
        }

        let sessions = store.get_user_sessions("magnus", None).unwrap();
        assert_eq!(sessions.len(), 3);
    }

    #[test]
    fn test_get_active_sessions() {
        let db = create_test_db();
        let store = SessionStore::new(&db).unwrap();

        let device = DeviceFingerprint::generate();
        store.store_device(&device).unwrap();

        // Create 2 active sessions
        let session1 = Session::new(
            "magnus".to_string(),
            device.device_id.clone(),
            "instance-1".to_string(),
            DeviceType::Desktop,
        );
        store.store_session(&session1).unwrap();

        let session2 = Session::new(
            "alex".to_string(),
            device.device_id.clone(),
            "instance-1".to_string(),
            DeviceType::Desktop,
        );
        store.store_session(&session2).unwrap();

        // Create 1 ended session
        let mut session3 = Session::new(
            "magnus".to_string(),
            device.device_id.clone(),
            "instance-2".to_string(),
            DeviceType::Laptop,
        );
        session3.end();
        store.store_session(&session3).unwrap();

        // Should get 2 active sessions
        let active = store.get_active_sessions().unwrap();
        assert_eq!(active.len(), 2);

        // Should get 1 active session for magnus
        let magnus_active = store.get_user_active_sessions("magnus").unwrap();
        assert_eq!(magnus_active.len(), 1);
    }
}
