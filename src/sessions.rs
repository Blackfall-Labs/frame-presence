//! Session Tracking and Device Fingerprinting
//!
//! Tracks user sessions across multiple SAM instances and devices.
//! Enables cross-instance awareness: "I see you spoke with me on your desktop"

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Device type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceType {
    Desktop,
    Laptop,
    Mobile,
    Tablet,
    RaspberryPi,
    Server,
    Unknown,
}

impl DeviceType {
    /// Detect device type from system information
    pub fn detect() -> Self {
        // Check if running on Raspberry Pi
        if let Ok(model) = std::fs::read_to_string("/proc/device-tree/model") {
            if model.contains("Raspberry Pi") {
                return DeviceType::RaspberryPi;
            }
        }

        // Check system architecture and characteristics
        #[cfg(target_os = "linux")]
        {
            // Check for ARM architecture (common on mobile/embedded)
            if cfg!(target_arch = "arm") || cfg!(target_arch = "aarch64") {
                return DeviceType::RaspberryPi; // Default ARM Linux to Pi
            }
        }

        #[cfg(target_os = "android")]
        {
            return DeviceType::Mobile;
        }

        #[cfg(target_os = "ios")]
        {
            return DeviceType::Mobile;
        }

        // Desktop/Laptop detection (harder to distinguish)
        #[cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]
        {
            // Could check battery presence for laptop detection
            // For now, default to desktop
            return DeviceType::Desktop;
        }

        DeviceType::Unknown
    }

    /// Human-readable description
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceType::Desktop => "desktop",
            DeviceType::Laptop => "laptop",
            DeviceType::Mobile => "mobile",
            DeviceType::Tablet => "tablet",
            DeviceType::RaspberryPi => "Raspberry Pi",
            DeviceType::Server => "server",
            DeviceType::Unknown => "unknown device",
        }
    }
}

/// Device fingerprint for identifying specific hardware
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceFingerprint {
    /// Unique device identifier (persistent across sessions)
    pub device_id: String,

    /// Device type classification
    pub device_type: DeviceType,

    /// Hostname
    pub hostname: Option<String>,

    /// Operating system
    pub os: String,

    /// OS version
    pub os_version: String,

    /// CPU architecture
    pub arch: String,

    /// Number of CPU cores
    pub cpu_cores: Option<u32>,

    /// Total RAM in GB
    pub ram_gb: Option<u32>,

    /// First seen timestamp
    pub first_seen: DateTime<Utc>,

    /// Last seen timestamp
    pub last_seen: DateTime<Utc>,
}

impl DeviceFingerprint {
    /// Generate device fingerprint from system information
    pub fn generate() -> Self {
        let device_id = Self::generate_device_id();
        let hostname = Self::get_hostname();
        let (os, os_version) = Self::get_os_info();
        let arch = std::env::consts::ARCH.to_string();
        let cpu_cores = Self::get_cpu_cores();
        let ram_gb = Self::get_ram_gb();
        let device_type = DeviceType::detect();
        let now = Utc::now();

        Self {
            device_id,
            device_type,
            hostname,
            os,
            os_version,
            arch,
            cpu_cores,
            ram_gb,
            first_seen: now,
            last_seen: now,
        }
    }

    /// Generate stable device ID (based on hardware characteristics)
    fn generate_device_id() -> String {
        // Use hostname + MAC address hash for stable ID
        let hostname = Self::get_hostname().unwrap_or_else(|| "unknown".to_string());

        // Try to get MAC address or other stable identifier
        #[cfg(target_os = "linux")]
        {
            if let Ok(machine_id) = std::fs::read_to_string("/etc/machine-id") {
                return format!("{}_{}", hostname, machine_id.trim());
            }
        }

        #[cfg(target_os = "windows")]
        {
            // Windows machine GUID is in registry
            // For now, use hostname + user
            if let Ok(username) = std::env::var("USERNAME") {
                return format!("{}_{}", hostname, username);
            }
        }

        #[cfg(target_os = "macos")]
        {
            // macOS hardware UUID
            if let Ok(output) = std::process::Command::new("system_profiler")
                .args(&["SPHardwareDataType"])
                .output()
            {
                if let Ok(stdout) = String::from_utf8(output.stdout) {
                    if let Some(line) = stdout.lines().find(|l| l.contains("UUID")) {
                        let uuid = line.split(':').nth(1).unwrap_or("").trim();
                        return format!("{}_{}", hostname, uuid);
                    }
                }
            }
        }

        // Fallback: use hostname + timestamp hash
        format!("{}_{}", hostname, Uuid::new_v4())
    }

    /// Get system hostname
    fn get_hostname() -> Option<String> {
        hostname::get().ok().and_then(|h| h.into_string().ok())
    }

    /// Get OS name and version
    fn get_os_info() -> (String, String) {
        let os = std::env::consts::OS.to_string();

        #[cfg(target_os = "linux")]
        {
            if let Ok(release) = std::fs::read_to_string("/etc/os-release") {
                for line in release.lines() {
                    if line.starts_with("PRETTY_NAME=") {
                        let version = line
                            .strip_prefix("PRETTY_NAME=")
                            .unwrap_or("")
                            .trim_matches('"')
                            .to_string();
                        return (os, version);
                    }
                }
            }
            return (os, "Unknown".to_string());
        }

        #[cfg(target_os = "windows")]
        {
            // Windows version detection
            return (os, "Windows".to_string());
        }

        #[cfg(target_os = "macos")]
        {
            // macOS version detection
            if let Ok(output) = std::process::Command::new("sw_vers")
                .arg("-productVersion")
                .output()
            {
                if let Ok(version) = String::from_utf8(output.stdout) {
                    return (os, version.trim().to_string());
                }
            }
            return (os, "Unknown".to_string());
        }

        (os, "Unknown".to_string())
    }

    /// Get number of CPU cores
    fn get_cpu_cores() -> Option<u32> {
        num_cpus::get().try_into().ok()
    }

    /// Get total RAM in GB
    fn get_ram_gb() -> Option<u32> {
        #[cfg(target_os = "linux")]
        {
            if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
                for line in meminfo.lines() {
                    if line.starts_with("MemTotal:") {
                        let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
                        return Some((kb / 1024 / 1024) as u32);
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            // Would need Windows API for accurate RAM detection
            return None;
        }

        #[cfg(target_os = "macos")]
        {
            if let Ok(output) = std::process::Command::new("sysctl")
                .arg("hw.memsize")
                .output()
            {
                if let Ok(stdout) = String::from_utf8(output.stdout) {
                    let bytes: u64 = stdout.split(':').nth(1)?.trim().parse().ok()?;
                    return Some((bytes / 1024 / 1024 / 1024) as u32);
                }
            }
        }

        None
    }

    /// Update last_seen timestamp
    pub fn touch(&mut self) {
        self.last_seen = Utc::now();
    }
}

/// User session on a specific device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session ID
    pub id: Uuid,

    /// User ID (from identity system)
    pub user_id: String,

    /// Device this session is on
    pub device_id: String,

    /// SAM instance ID
    pub instance_id: String,

    /// When session started
    pub start_time: DateTime<Utc>,

    /// When session ended (None if active)
    pub end_time: Option<DateTime<Utc>>,

    /// Multi-modal verification scores
    pub typing_match: Option<f32>,
    pub voice_match: Option<f32>,
    pub visual_match: Option<f32>,

    /// Geographic location (optional, privacy-respecting)
    pub location: Option<String>,

    /// Device type
    pub device_type: DeviceType,

    /// Conversation count in this session
    pub conversation_count: u32,

    /// Message count in this session
    pub message_count: u32,

    /// Session metadata (JSON)
    pub metadata: Option<HashMap<String, String>>,
}

impl Session {
    /// Create a new session
    pub fn new(
        user_id: String,
        device_id: String,
        instance_id: String,
        device_type: DeviceType,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id,
            device_id,
            instance_id,
            start_time: Utc::now(),
            end_time: None,
            typing_match: None,
            voice_match: None,
            visual_match: None,
            location: None,
            device_type,
            conversation_count: 0,
            message_count: 0,
            metadata: None,
        }
    }

    /// Check if session is active
    pub fn is_active(&self) -> bool {
        self.end_time.is_none()
    }

    /// End the session
    pub fn end(&mut self) {
        if self.end_time.is_none() {
            self.end_time = Some(Utc::now());
        }
    }

    /// Get session duration
    pub fn duration(&self) -> chrono::Duration {
        let end = self.end_time.unwrap_or_else(Utc::now);
        end - self.start_time
    }

    /// Update typing pattern match confidence
    pub fn set_typing_match(&mut self, confidence: f32) {
        self.typing_match = Some(confidence);
    }

    /// Update voice pattern match confidence
    pub fn set_voice_match(&mut self, confidence: f32) {
        self.voice_match = Some(confidence);
    }

    /// Update visual pattern match confidence
    pub fn set_visual_match(&mut self, confidence: f32) {
        self.visual_match = Some(confidence);
    }

    /// Get combined identity confidence from all modalities
    pub fn combined_confidence(&self) -> f32 {
        let mut total_weight = 0.0;
        let mut weighted_sum = 0.0;

        // Modality weights (typing, voice, visual)
        let weights = [0.6, 0.8, 0.9];
        let scores = [self.typing_match, self.voice_match, self.visual_match];

        for (score, weight) in scores.iter().zip(weights.iter()) {
            if let Some(s) = score {
                weighted_sum += s * weight;
                total_weight += weight;
            }
        }

        if total_weight > 0.0 {
            weighted_sum / total_weight
        } else {
            0.0
        }
    }

    /// Increment conversation counter
    pub fn increment_conversations(&mut self) {
        self.conversation_count += 1;
    }

    /// Increment message counter
    pub fn increment_messages(&mut self) {
        self.message_count += 1;
    }

    /// Human-readable session description
    pub fn description(&self) -> String {
        let duration = self.duration();
        let hours = duration.num_hours();
        let minutes = duration.num_minutes() % 60;

        if self.is_active() {
            format!(
                "Active session on {} ({}h {}m, {} messages)",
                self.device_type.as_str(),
                hours,
                minutes,
                self.message_count
            )
        } else {
            format!(
                "Session on {} ({}h {}m, {} messages)",
                self.device_type.as_str(),
                hours,
                minutes,
                self.message_count
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_type_detection() {
        let device_type = DeviceType::detect();
        assert_ne!(device_type, DeviceType::Unknown);
    }

    #[test]
    fn test_device_fingerprint_generation() {
        let fingerprint = DeviceFingerprint::generate();
        assert!(!fingerprint.device_id.is_empty());
        assert!(!fingerprint.os.is_empty());
        assert!(!fingerprint.arch.is_empty());
    }

    #[test]
    fn test_device_fingerprint_stable() {
        let fp1 = DeviceFingerprint::generate();
        let fp2 = DeviceFingerprint::generate();

        // Device ID should be stable (same device)
        assert_eq!(fp1.device_id, fp2.device_id);
    }

    #[test]
    fn test_session_creation() {
        let session = Session::new(
            "magnus".to_string(),
            "device-1".to_string(),
            "instance-1".to_string(),
            DeviceType::Desktop,
        );

        assert_eq!(session.user_id, "magnus");
        assert!(session.is_active());
        assert_eq!(session.conversation_count, 0);
        assert_eq!(session.message_count, 0);
    }

    #[test]
    fn test_session_end() {
        let mut session = Session::new(
            "magnus".to_string(),
            "device-1".to_string(),
            "instance-1".to_string(),
            DeviceType::Desktop,
        );

        assert!(session.is_active());

        session.end();

        assert!(!session.is_active());
        assert!(session.end_time.is_some());
    }

    #[test]
    fn test_combined_confidence() {
        let mut session = Session::new(
            "magnus".to_string(),
            "device-1".to_string(),
            "instance-1".to_string(),
            DeviceType::Desktop,
        );

        // No modalities yet
        assert_eq!(session.combined_confidence(), 0.0);

        // Add typing match
        session.set_typing_match(0.85);
        assert!(session.combined_confidence() > 0.0);

        // Add voice match (higher weight)
        session.set_voice_match(0.90);
        let conf_with_voice = session.combined_confidence();
        assert!(conf_with_voice > 0.85);

        // Add visual match (highest weight)
        session.set_visual_match(0.95);
        let conf_with_all = session.combined_confidence();
        assert!(conf_with_all > conf_with_voice);
    }

    #[test]
    fn test_session_counters() {
        let mut session = Session::new(
            "magnus".to_string(),
            "device-1".to_string(),
            "instance-1".to_string(),
            DeviceType::Desktop,
        );

        session.increment_conversations();
        assert_eq!(session.conversation_count, 1);

        session.increment_messages();
        session.increment_messages();
        assert_eq!(session.message_count, 2);
    }

    #[test]
    fn test_session_description() {
        let session = Session::new(
            "magnus".to_string(),
            "device-1".to_string(),
            "instance-1".to_string(),
            DeviceType::Desktop,
        );

        let desc = session.description();
        assert!(desc.contains("desktop"));
        assert!(desc.contains("Active"));
    }
}
