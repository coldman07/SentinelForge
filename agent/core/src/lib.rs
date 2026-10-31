#![forbid(unsafe_code)]

//! Platform-neutral process event data collected by endpoint sensors.
//!
//! The field names and types follow `proto/events/v1/event.proto`. The Linux
//! Aya sensor will construct these values and the transport layer will encode
//! them using the shared Protobuf contract.

use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const SCHEMA_VERSION: &str = "1.0";

pub fn format_ip_address(family: u16, address: [u8; 16]) -> Option<String> {
    match family {
        2 => Some(Ipv4Addr::new(address[0], address[1], address[2], address[3]).to_string()),
        10 => Some(Ipv6Addr::from(address).to_string()),
        _ => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Host {
    pub host_id: String,
    pub os: String,
    pub os_version: String,
    pub agent_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct User {
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sid: String,
    pub privilege: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RawSource {
    pub source: String,
    pub provider: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessReference {
    pub pid: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Hash {
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessDetails {
    pub pid: u64,
    pub name: String,
    pub path: String,
    pub command_line: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<ProcessReference>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProcessStart {
    pub event_id: String,
    pub timestamp: String,
    pub host: Host,
    pub category: &'static str,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,
    pub process: ProcessDetails,
    pub raw: RawSource,
    pub schema_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileDetails {
    pub path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub file_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    pub flags: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_written: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FileEvent {
    pub event_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub timestamp: String,
    pub host: Host,
    pub category: &'static str,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,
    pub file: FileDetails,
    pub raw: RawSource,
    pub schema_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NetworkDetails {
    pub protocol: String,
    pub direction: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub local_address: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub local_port: u32,
    pub remote_address: String,
    pub remote_port: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NetworkConnect {
    pub event_id: String,
    pub timestamp: String,
    pub host: Host,
    pub category: &'static str,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<User>,
    pub network: NetworkDetails,
    pub raw: RawSource,
    pub schema_version: String,
}

impl ProcessStart {
    /// Build a shared process-start envelope from a platform sensor observation.
    #[allow(clippy::too_many_arguments)]
    pub fn from_observation(
        event_id: String,
        timestamp: String,
        host: Host,
        pid: u32,
        user: Option<User>,
        filename: &str,
        command_line: &str,
        parent: Option<ProcessReference>,
        source: &str,
        provider: &str,
    ) -> Self {
        let name = filename
            .rsplit(|ch| ch == '/' || ch == '\\')
            .next()
            .unwrap_or(filename);
        Self {
            event_id,
            timestamp,
            host,
            category: "process",
            action: "create".into(),
            user,
            process: ProcessDetails {
                pid: u64::from(pid),
                name: name.into(),
                path: filename.into(),
                command_line: command_line.into(),
                hash: None,
                parent,
            },
            raw: RawSource {
                source: source.into(),
                provider: provider.into(),
            },
            schema_version: SCHEMA_VERSION.into(),
        }
    }

    /// Build the shared process-start envelope from a successful eBPF exec
    /// observation. Linux does not currently collect the full argv list.
    pub fn from_exec_observation(
        event_id: String,
        timestamp: String,
        host: Host,
        pid: u32,
        user: Option<User>,
        filename: &str,
    ) -> Self {
        Self::from_observation(
            event_id,
            timestamp,
            host,
            pid,
            user,
            filename,
            filename,
            None,
            "eBPF",
            "sys_enter/exit_execve",
        )
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

impl FileEvent {
    /// Build a file event from a successful Linux file syscall.
    pub fn from_observation(
        event_id: String,
        timestamp: String,
        host: Host,
        user: Option<User>,
        path: &str,
        syscall: u8,
        flags: u32,
        bytes_written: u64,
        correlation_id: Option<String>,
    ) -> Self {
        let (action, provider) = match syscall {
            1 => (file_open_action(flags), "sys_enter/exit_openat"),
            2 => (file_open_action(flags), "sys_enter/exit_openat2"),
            3 if flags & 0x200 != 0 => ("delete_directory", "sys_enter/exit_unlinkat"),
            3 => ("delete", "sys_enter/exit_unlinkat"),
            4 | 5 => (
                if syscall == 4 {
                    "rename_from"
                } else {
                    "rename_to"
                },
                "sys_enter/exit_renameat",
            ),
            6 | 7 => (
                if syscall == 6 {
                    "rename_from"
                } else {
                    "rename_to"
                },
                "sys_enter/exit_renameat2",
            ),
            8 => ("write", "sys_enter/exit_write"),
            _ => ("unknown", "unknown"),
        };
        Self {
            event_id,
            correlation_id,
            timestamp,
            host,
            category: "file",
            action: action.into(),
            user,
            file: FileDetails {
                path: path.into(),
                file_type: String::new(),
                hash: None,
                size_bytes: None,
                flags,
                bytes_written: (bytes_written > 0).then_some(bytes_written),
            },
            raw: RawSource {
                source: "eBPF".into(),
                provider: provider.into(),
            },
            schema_version: SCHEMA_VERSION.into(),
        }
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if !is_uuid(&self.event_id) {
            return Err(ValidationError::InvalidEventId);
        }
        if self.timestamp.trim().is_empty() {
            return Err(ValidationError::MissingTimestamp);
        }
        if self.host.host_id.trim().is_empty()
            || self.host.os.trim().is_empty()
            || self.host.agent_version.trim().is_empty()
        {
            return Err(ValidationError::MissingHostIdentity);
        }
        if self.file.path.trim().is_empty() {
            return Err(ValidationError::InvalidFile);
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err(ValidationError::UnsupportedSchemaVersion);
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

impl NetworkConnect {
    pub fn from_connect_observation(
        event_id: String,
        timestamp: String,
        host: Host,
        user: Option<User>,
        remote_address: &str,
        remote_port: u16,
    ) -> Self {
        Self {
            event_id,
            timestamp,
            host,
            category: "network",
            action: "connect".into(),
            user,
            network: NetworkDetails {
                protocol: "unknown".into(),
                direction: "outbound".into(),
                local_address: String::new(),
                local_port: 0,
                remote_address: remote_address.into(),
                remote_port: u32::from(remote_port),
            },
            raw: RawSource {
                source: "eBPF".into(),
                provider: "sys_enter/exit_connect".into(),
            },
            schema_version: SCHEMA_VERSION.into(),
        }
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if !is_uuid(&self.event_id) {
            return Err(ValidationError::InvalidEventId);
        }
        if self.timestamp.trim().is_empty() {
            return Err(ValidationError::MissingTimestamp);
        }
        if self.host.host_id.trim().is_empty()
            || self.host.os.trim().is_empty()
            || self.host.agent_version.trim().is_empty()
        {
            return Err(ValidationError::MissingHostIdentity);
        }
        if self.network.remote_address.trim().is_empty() {
            return Err(ValidationError::InvalidNetwork);
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err(ValidationError::UnsupportedSchemaVersion);
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

fn file_open_action(open_flags: u32) -> &'static str {
    const O_WRONLY: u32 = 0o1;
    const O_RDWR: u32 = 0o2;
    const O_CREAT: u32 = 0o100;
    const O_TRUNC: u32 = 0o1000;

    if open_flags & O_TRUNC != 0 {
        "truncate"
    } else if open_flags & O_CREAT != 0 {
        "open_create_intent"
    } else if open_flags & (O_WRONLY | O_RDWR) != 0 {
        "open_write_intent"
    } else {
        "open"
    }
}

/// Format Unix time as an RFC 3339 UTC timestamp without a platform-specific
/// time library. Returns `None` for nanoseconds outside the valid range.
pub fn format_timestamp(unix_seconds: u64, nanoseconds: u32) -> Option<String> {
    if nanoseconds >= 1_000_000_000 {
        return None;
    }
    let days = i64::try_from(unix_seconds / 86_400).ok()?;
    let seconds_of_day = unix_seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    if !(0..=9999).contains(&year) {
        return None;
    }
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanoseconds:09}Z"
    ))
}

/// Create a canonical UUID v4 string from 16 bytes supplied by an OS RNG.
pub fn uuid_v4_from_random(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month as u32, day as u32)
}

impl ProcessStart {
    /// Check the invariants needed before encoding a process-start event.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if !is_uuid(&self.event_id) {
            return Err(ValidationError::InvalidEventId);
        }
        if self.timestamp.trim().is_empty() {
            return Err(ValidationError::MissingTimestamp);
        }
        if self.host.host_id.trim().is_empty()
            || self.host.os.trim().is_empty()
            || self.host.agent_version.trim().is_empty()
        {
            return Err(ValidationError::MissingHostIdentity);
        }
        if self.action.trim().is_empty() {
            return Err(ValidationError::MissingAction);
        }
        if self.process.pid == 0
            || self.process.name.trim().is_empty()
            || self.process.path.trim().is_empty()
        {
            return Err(ValidationError::InvalidProcess);
        }
        if self.schema_version != SCHEMA_VERSION {
            return Err(ValidationError::UnsupportedSchemaVersion);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    InvalidEventId,
    MissingTimestamp,
    MissingHostIdentity,
    MissingAction,
    InvalidProcess,
    UnsupportedSchemaVersion,
    InvalidFile,
    InvalidNetwork,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidEventId => "event_id must be a UUID",
            Self::MissingTimestamp => "timestamp is required",
            Self::MissingHostIdentity => "host identity fields are required",
            Self::MissingAction => "action is required",
            Self::InvalidProcess => "process pid, name, and path are required",
            Self::UnsupportedSchemaVersion => "unsupported schema version",
            Self::InvalidFile => "file path is required",
            Self::InvalidNetwork => "remote network address is required",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ValidationError {}

fn is_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 || ![8, 13, 18, 23].iter().all(|&i| bytes[i] == b'-') {
        return false;
    }
    bytes
        .iter()
        .enumerate()
        .all(|(i, byte)| [8, 13, 18, 23].contains(&i) || byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ProcessStart {
        ProcessStart {
            event_id: "b6f1c9e2-3a4d-4c1e-9f0a-7e5d2c1b8a90".into(),
            timestamp: "2026-01-15T10:42:07.318Z".into(),
            host: Host {
                host_id: "linux-lab-01".into(),
                os: "linux".into(),
                os_version: "6.8.0".into(),
                agent_version: "0.1.0".into(),
            },
            category: "process",
            action: "create".into(),
            user: None,
            process: ProcessDetails {
                pid: 4312,
                name: "sh".into(),
                path: "/usr/bin/sh".into(),
                command_line: "sh -c id".into(),
                hash: None,
                parent: Some(ProcessReference {
                    pid: 2210,
                    name: "terminal".into(),
                }),
            },
            raw: RawSource {
                source: "eBPF".into(),
                provider: "sys_enter/exit_execve".into(),
            },
            schema_version: SCHEMA_VERSION.into(),
        }
    }

    #[test]
    fn accepts_a_valid_process_start() {
        assert_eq!(sample().validate(), Ok(()));
    }

    #[test]
    fn exec_observation_serializes_to_the_gateway_event_shape() {
        let event = ProcessStart::from_exec_observation(
            "b6f1c9e2-3a4d-4c1e-9f0a-7e5d2c1b8a90".into(),
            "2026-01-15T10:42:07.318Z".into(),
            sample().host,
            4312,
            None,
            "/usr/bin/sh",
        );
        let json = serde_json::to_value(event).expect("serialize process event");
        assert_eq!(json["category"], "process");
        assert_eq!(json["process"]["pid"], 4312);
        assert_eq!(json["process"]["name"], "sh");
        assert_eq!(json["process"]["path"], "/usr/bin/sh");
        assert_eq!(json["raw"]["source"], "eBPF");
        assert_eq!(json["raw"]["provider"], "sys_enter/exit_execve");
        assert!(json.get("user").is_none());
        assert!(json["process"].get("hash").is_none());
    }

    #[test]
    fn formats_timestamp_at_epoch_and_leap_day() {
        assert_eq!(
            format_timestamp(0, 0).as_deref(),
            Some("1970-01-01T00:00:00.000000000Z")
        );
        assert_eq!(
            format_timestamp(951_782_400, 123_000_000).as_deref(),
            Some("2000-02-29T00:00:00.123000000Z")
        );
        assert_eq!(format_timestamp(0, 1_000_000_000), None);
    }

    #[test]
    fn formats_a_version_four_uuid() {
        let id = uuid_v4_from_random([0; 16]);
        assert_eq!(id, "00000000-0000-4000-8000-000000000000");
        assert!(is_uuid(&id));
    }

    #[test]
    fn file_observation_serializes_to_the_gateway_event_shape() {
        let event = FileEvent::from_observation(
            "b6f1c9e2-3a4d-4c1e-9f0a-7e5d2c1b8a90".into(),
            "2026-01-15T10:42:07.318Z".into(),
            sample().host,
            None,
            "/tmp/new-file.txt",
            1,
            0o101,
            0,
            None,
        );
        let json: serde_json::Value =
            serde_json::from_str(&event.to_json().expect("serialize file event"))
                .expect("parse file event JSON");
        assert_eq!(json["category"], "file");
        assert_eq!(json["action"], "open_create_intent");
        assert_eq!(json["file"]["path"], "/tmp/new-file.txt");
        assert_eq!(json["file"]["flags"], 0o101);
        assert_eq!(json["raw"]["provider"], "sys_enter/exit_openat");
        assert!(json.get("user").is_none());
    }

    #[test]
    fn classifies_file_operations_without_claiming_creation() {
        assert_eq!(file_open_action(0), "open");
        assert_eq!(file_open_action(0o1), "open_write_intent");
        assert_eq!(file_open_action(0o101), "open_create_intent");
        assert_eq!(file_open_action(0o1101), "truncate");
        let event = FileEvent::from_observation(
            "b6f1c9e2-3a4d-4c1e-9f0a-7e5d2c1b8a90".into(),
            "2026-01-15T10:42:07.318Z".into(),
            sample().host,
            None,
            "/tmp/removed-directory",
            3,
            0x200,
            0,
            None,
        );
        let json: serde_json::Value =
            serde_json::from_str(&event.to_json().expect("serialize delete event"))
                .expect("parse delete event JSON");
        assert_eq!(json["category"], "file");
        assert_eq!(json["action"], "delete_directory");
        assert_eq!(json["file"]["flags"], 0x200);
        assert_eq!(json["raw"]["provider"], "sys_enter/exit_unlinkat");
    }

    #[test]
    fn rename_sides_share_a_correlation_id() {
        let correlation_id = "a1b2c3d4e5f60718".to_owned();
        let from = FileEvent::from_observation(
            "b6f1c9e2-3a4d-4c1e-9f0a-7e5d2c1b8a90".into(),
            "2026-01-15T10:42:07.318Z".into(),
            sample().host.clone(),
            None,
            "/tmp/old-name",
            4,
            0,
            0,
            Some(correlation_id.clone()),
        );
        let to = FileEvent::from_observation(
            "a6f1c9e2-3a4d-4c1e-9f0a-7e5d2c1b8a91".into(),
            "2026-01-15T10:42:07.318Z".into(),
            sample().host,
            None,
            "/tmp/new-name",
            5,
            0,
            0,
            Some(correlation_id.clone()),
        );
        let from_json: serde_json::Value =
            serde_json::from_str(&from.to_json().expect("serialize rename source"))
                .expect("parse rename source");
        let to_json: serde_json::Value =
            serde_json::from_str(&to.to_json().expect("serialize rename target"))
                .expect("parse rename target");
        assert_eq!(from_json["action"], "rename_from");
        assert_eq!(to_json["action"], "rename_to");
        assert_eq!(from_json["correlation_id"], correlation_id);
        assert_eq!(from_json["correlation_id"], to_json["correlation_id"]);
    }

    #[test]
    fn write_observation_reports_bytes_written() {
        let event = FileEvent::from_observation(
            "b6f1c9e2-3a4d-4c1e-9f0a-7e5d2c1b8a90".into(),
            "2026-01-15T10:42:07.318Z".into(),
            sample().host,
            None,
            "/tmp/output.txt",
            8,
            0,
            128,
            None,
        );
        let json: serde_json::Value =
            serde_json::from_str(&event.to_json().expect("serialize write event"))
                .expect("parse write event JSON");
        assert_eq!(json["action"], "write");
        assert_eq!(json["file"]["bytes_written"], 128);
        assert_eq!(json["raw"]["provider"], "sys_enter/exit_write");
    }

    #[test]
    fn network_connect_serializes_to_the_gateway_event_shape() {
        let event = NetworkConnect::from_connect_observation(
            "b6f1c9e2-3a4d-4c1e-9f0a-7e5d2c1b8a90".into(),
            "2026-01-15T10:42:07.318Z".into(),
            sample().host,
            None,
            "203.0.113.7",
            443,
        );
        let json: serde_json::Value =
            serde_json::from_str(&event.to_json().expect("serialize network event"))
                .expect("parse network event JSON");
        assert_eq!(json["category"], "network");
        assert_eq!(json["action"], "connect");
        assert_eq!(json["network"]["direction"], "outbound");
        assert_eq!(json["network"]["remote_address"], "203.0.113.7");
        assert_eq!(json["network"]["remote_port"], 443);
        assert!(json["network"].get("local_address").is_none());
        assert!(json.get("user").is_none());
    }

    #[test]
    fn formats_ipv4_and_ipv6_sockaddr_values() {
        assert_eq!(
            format_ip_address(2, [203, 0, 113, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(format_ip_address(10, [0; 16]).as_deref(), Some("::"));
        assert_eq!(format_ip_address(1, [0; 16]), None);
    }

    #[test]
    fn rejects_an_invalid_event_id() {
        let mut event = sample();
        event.event_id = "not-a-uuid".into();
        assert_eq!(event.validate(), Err(ValidationError::InvalidEventId));
    }

    #[test]
    fn rejects_missing_process_identity() {
        let mut event = sample();
        event.process.path.clear();
        assert_eq!(event.validate(), Err(ValidationError::InvalidProcess));
    }

    #[test]
    fn rejects_a_schema_version_that_does_not_match_the_proto_contract() {
        let mut event = sample();
        event.schema_version = "2.0".into();
        assert_eq!(
            event.validate(),
            Err(ValidationError::UnsupportedSchemaVersion)
        );
    }
}
