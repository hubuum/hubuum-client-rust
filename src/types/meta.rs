use serde::{Deserialize, Serialize};

use crate::types::HubuumDateTime;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObjectsByClass {
    pub hubuum_class_id: i32,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CountsResponse {
    pub total_objects: i64,
    pub total_classes: i64,
    #[serde(default)]
    pub total_namespaces: i64,
    #[serde(default)]
    pub objects_per_class: Vec<ObjectsByClass>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DbStateResponse {
    pub available_connections: i32,
    pub idle_connections: i32,
    pub active_connections: i64,
    pub db_size: i64,
    pub last_vacuum_time: Option<HubuumDateTime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginRateLimitConfig {
    pub enabled: bool,
    pub max_attempts: u64,
    pub max_attempts_per_ip: u64,
    pub max_attempts_per_subnet: u64,
    pub window_seconds: u64,
    pub backoff_base_seconds: u64,
    pub backoff_max_seconds: u64,
    pub subnet_prefix_v4: u8,
    pub subnet_prefix_v6: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginRateLimitEntry {
    pub id: String,
    pub scope: String,
    pub identifier: String,
    pub attempts: u64,
    pub locked: bool,
    pub locked_for_seconds: Option<u64>,
    pub lockout_level: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginRateLimitState {
    pub config: LoginRateLimitConfig,
    pub tracked_entries: u64,
    pub locked_entries: u64,
    pub returned_entries: u64,
    pub entries: Vec<LoginRateLimitEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseRateLimitResponse {
    pub released: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClearRateLimitResponse {
    pub cleared: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_rate_limit_state_deserializes() {
        let state: LoginRateLimitState = serde_json::from_value(serde_json::json!({
            "config": {
                "enabled": true, "max_attempts": 5, "max_attempts_per_ip": 20,
                "max_attempts_per_subnet": 100, "window_seconds": 300,
                "backoff_base_seconds": 300, "backoff_max_seconds": 86400,
                "subnet_prefix_v4": 24, "subnet_prefix_v6": 64
            },
            "tracked_entries": 2, "locked_entries": 1, "returned_entries": 1,
            "entries": [{
                "id": "dTp0ZXN0", "scope": "user_ip", "identifier": "alice@1.2.3.4",
                "attempts": 6, "locked": true, "locked_for_seconds": 120, "lockout_level": 1
            }]
        }))
        .unwrap();
        assert_eq!(state.config.max_attempts_per_ip, 20);
        assert_eq!(state.config.subnet_prefix_v4, 24);
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.entries[0].locked_for_seconds, Some(120));
    }
}
