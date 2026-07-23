use serde::{Deserialize, Serialize};

use crate::{ClassId, types::HubuumDateTime};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObjectsByClass {
    pub hubuum_class_id: ClassId,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CountsResponse {
    pub total_objects: i64,
    pub total_classes: i64,
    #[serde(default)]
    pub total_collections: i64,
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

/// Complete database and connection-pool state returned by Hubuum.
///
/// This additive type preserves the process-local pool counters that the
/// original [`DbStateResponse`] model predates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct FullDbStateResponse {
    pub max_connections: u32,
    pub total_connections: u32,
    pub available_connections: u32,
    pub idle_connections: u32,
    pub in_use_connections: u32,
    pub pending_acquisitions: u64,
    pub acquisitions_started: u64,
    pub acquisitions_direct: u64,
    pub acquisitions_waited: u64,
    pub acquisitions_timed_out: u64,
    pub acquisition_wait_time_ms: u64,
    pub connections_created: u64,
    pub connections_closed_broken: u64,
    pub connections_closed_invalid: u64,
    pub connections_closed_max_lifetime: u64,
    pub connections_closed_idle_timeout: u64,
    pub active_connections: i64,
    pub db_size: i64,
    pub last_vacuum_time: Option<HubuumDateTime>,
}

impl From<FullDbStateResponse> for DbStateResponse {
    fn from(value: FullDbStateResponse) -> Self {
        Self {
            available_connections: i32::try_from(value.available_connections).unwrap_or(i32::MAX),
            idle_connections: i32::try_from(value.idle_connections).unwrap_or(i32::MAX),
            active_connections: value.active_connections,
            db_size: value.db_size,
            last_vacuum_time: value.last_vacuum_time,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginRateLimitConfig {
    pub enabled: bool,
    pub backend: String,
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

/// Response from the `/healthz` and `/readyz` liveness/readiness probes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeResponse {
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_db_state_preserves_pool_metrics() {
        let state: FullDbStateResponse = serde_json::from_value(serde_json::json!({
            "max_connections": 20,
            "total_connections": 7,
            "available_connections": 18,
            "idle_connections": 5,
            "in_use_connections": 2,
            "pending_acquisitions": 1,
            "acquisitions_started": 101,
            "acquisitions_direct": 80,
            "acquisitions_waited": 21,
            "acquisitions_timed_out": 3,
            "acquisition_wait_time_ms": 250,
            "connections_created": 9,
            "connections_closed_broken": 1,
            "connections_closed_invalid": 2,
            "connections_closed_max_lifetime": 3,
            "connections_closed_idle_timeout": 4,
            "active_connections": 6,
            "db_size": 1024,
            "last_vacuum_time": "2024-01-01T00:00:00Z"
        }))
        .unwrap();

        assert_eq!(state.max_connections, 20);
        assert_eq!(state.in_use_connections, 2);
        assert_eq!(state.acquisitions_timed_out, 3);
        assert_eq!(state.connections_closed_idle_timeout, 4);

        let legacy = DbStateResponse::from(state);
        assert_eq!(legacy.available_connections, 18);
        assert_eq!(legacy.active_connections, 6);
    }

    #[test]
    fn full_db_state_accepts_unsigned_counter_limits() {
        let state: FullDbStateResponse = serde_json::from_value(serde_json::json!({
            "max_connections": u32::MAX,
            "total_connections": u32::MAX,
            "available_connections": u32::MAX,
            "idle_connections": u32::MAX,
            "in_use_connections": u32::MAX,
            "pending_acquisitions": u64::MAX,
            "acquisitions_started": u64::MAX,
            "acquisitions_direct": u64::MAX,
            "acquisitions_waited": u64::MAX,
            "acquisitions_timed_out": u64::MAX,
            "acquisition_wait_time_ms": u64::MAX,
            "connections_created": u64::MAX,
            "connections_closed_broken": u64::MAX,
            "connections_closed_invalid": u64::MAX,
            "connections_closed_max_lifetime": u64::MAX,
            "connections_closed_idle_timeout": u64::MAX,
            "active_connections": i64::MAX,
            "db_size": i64::MAX,
            "last_vacuum_time": null
        }))
        .unwrap();

        assert_eq!(state.pending_acquisitions, u64::MAX);

        let legacy = DbStateResponse::from(state);
        assert_eq!(legacy.available_connections, i32::MAX);
        assert_eq!(legacy.idle_connections, i32::MAX);
    }

    #[test]
    fn login_rate_limit_state_deserializes() {
        let state: LoginRateLimitState = serde_json::from_value(serde_json::json!({
            "config": {
                "enabled": true, "backend": "memory", "max_attempts": 5, "max_attempts_per_ip": 20,
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
