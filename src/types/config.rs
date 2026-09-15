use serde::{Deserialize, Deserializer, Serialize, de};

use crate::ApiError;

/// Default path of the Hubuum Prometheus scrape endpoint.
pub const DEFAULT_METRICS_PATH: &str = "/metrics";

/// Unauthenticated capability information needed by API consumers.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientConfig {
    pub pagination: ClientPaginationConfig,
    pub authentication: ClientAuthenticationConfig,
}

/// Effective pagination defaults and limits advertised by the server.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientPaginationConfig {
    pub default_page_limit: u64,
    pub max_page_limit: u64,
}

/// Effective authentication defaults advertised to unauthenticated clients.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientAuthenticationConfig {
    /// Lifetime applied when login or token minting omits an explicit expiry.
    pub default_token_lifetime_hours: i64,
    /// Largest lifetime accepted for an explicitly requested token expiry.
    pub max_token_lifetime_hours: i64,
}

/// Redacted effective process configuration returned by the administrative
/// configuration endpoint.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunningConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub tasks: TaskConfig,
    pub events: EventConfig,
    pub exports: ExportConfig,
    pub backups: BackupConfig,
    pub restores: RestoreConfig,
    pub remote_calls: RemoteCallConfig,
    pub authentication: AuthenticationConfig,
    pub permissions: PermissionConfig,
    pub pagination: PaginationConfig,
    pub network: NetworkConfig,
    pub secrets: SecretSourceConfig,
    pub tracing: TracingConfig,
    pub schema_validation: SchemaValidationConfig,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerConfig {
    pub runtime_role: String,
    pub bind_ip: String,
    pub bind_port: u32,
    pub log_level: String,
    pub actix_workers: u64,
    pub metrics_enabled: bool,
    pub metrics_path: String,
    pub tls: TlsConfig,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsConfig {
    pub enabled: bool,
    pub certificate_path_configured: bool,
    pub private_key_path: SecretStatus,
    pub private_key_passphrase: SecretStatus,
    pub backend: Option<String>,
}

/// Indicates whether a secret is present without exposing its value.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretStatus {
    pub configured: bool,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatabaseConfig {
    pub backend: String,
    pub role_mode: String,
    pub privilege_mode: String,
    pub owner_role: String,
    pub migrator_role: String,
    pub runtime_role: String,
    pub url: SecretStatus,
    pub pool_size: u32,
    pub pool_acquire_timeout_ms: u64,
    pub statement_timeout_ms: u64,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TaskConfig {
    pub workers: u64,
    pub poll_interval_ms: u64,
    pub lease_seconds: u64,
    pub heartbeat_seconds: u64,
    pub recovery_interval_seconds: u64,
    pub computed_reindex_batch_size: u64,
    pub import_max_active_per_user: u64,
    pub export_max_active_per_user: u64,
    pub remote_call_max_active_per_user: u64,
    pub import_execution_timeout_seconds: u64,
    pub export_execution_timeout_seconds: u64,
    pub backup_execution_timeout_seconds: u64,
    pub reindex_execution_timeout_seconds: u64,
    pub remote_call_execution_timeout_seconds: u64,
    pub schema_validation_execution_timeout_seconds: u64,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventConfig {
    pub fanout_workers: u64,
    pub fanout_batch_size: u64,
    pub fanout_poll_interval_ms: u64,
    pub fanout_lock_timeout_ms: u64,
    pub delivery_workers: u64,
    pub delivery_batch_size: u64,
    pub delivery_poll_interval_ms: u64,
    pub delivery_lock_timeout_ms: u64,
    pub delivery_transport_timeout_ms: u64,
    pub delivery_retry_backoff_base_ms: u64,
    pub delivery_retry_backoff_max_ms: u64,
    pub delivery_max_attempts: i32,
    pub retention_purge_enabled: bool,
    pub retention_days: i64,
    pub delivery_retention_days: i64,
    pub retention_purge_interval_seconds: u64,
    pub retention_purge_batch_size: u64,
    pub retention_file_archive_enabled: bool,
    pub retention_archive_path_configured: bool,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportConfig {
    pub output_retention_hours: i64,
    pub output_cleanup_interval_seconds: u64,
    pub template_recursion_limit: u64,
    pub template_fuel: u64,
    pub template_max_objects: u64,
    pub max_output_bytes: u64,
    pub stage_timeout_ms: u64,
    pub database_statement_timeout_ms: u64,
    pub storage_query_budget_ms: u64,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupConfig {
    pub output_retention_hours: i64,
    pub max_active_tasks_per_user: u64,
    pub max_output_bytes: u64,
    pub max_capture_rows: u64,
}

/// Effective JSON Schema admission and validation work budgets.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaValidationConfig {
    pub max_schema_bytes: u64,
    pub max_expanded_work: u64,
    pub max_instance_bytes: u64,
    pub max_instance_work: u64,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestoreConfig {
    pub stage_retention_minutes: i64,
    pub max_upload_bytes: u64,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteCallConfig {
    pub timeout_ms: u64,
    pub max_response_bytes: u64,
    pub allow_private_targets: bool,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthenticationConfig {
    pub token_lifetime_hours: i64,
    pub max_token_lifetime_hours: i64,
    pub token_retention_purge_enabled: bool,
    pub token_retention_days: i64,
    pub token_retention_purge_interval_seconds: u64,
    pub token_retention_purge_batch_size: u64,
    pub stable_token_hash_key_configured: bool,
    pub require_stable_token_hash_key: bool,
    pub token_hash_key_mode: String,
    pub active_token_hash_key_id: String,
    pub previous_token_hash_key_ids: Vec<String>,
    pub token_hash_key_ring_identity: String,
    pub admin_groupname: String,
    pub admin_identity_scope: Option<String>,
    pub provider_config_path: SecretStatus,
    pub login_rate_limit: RunningLoginRateLimitConfig,
}

/// Redacted login rate-limit configuration in the administrative process view.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunningLoginRateLimitConfig {
    pub enabled: bool,
    pub max_attempts: u64,
    pub max_attempts_per_ip: u64,
    pub max_attempts_per_subnet: u64,
    pub window_seconds: u64,
    pub backoff_base_seconds: u64,
    pub backoff_max_seconds: u64,
    pub subnet_prefix_v4: u8,
    pub subnet_prefix_v6: u8,
    pub backend: String,
    pub valkey_url: SecretStatus,
    pub valkey_prefix: String,
    pub valkey_io_timeout_ms: u64,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PermissionConfig {
    pub backend: String,
    pub treetop_url: SecretStatus,
    pub treetop_connect_timeout_ms: u64,
    pub treetop_request_timeout_ms: u64,
    pub treetop_ca_certificate_configured: bool,
    pub treetop_accept_invalid_certificates: bool,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaginationConfig {
    pub default_page_limit: u64,
    pub max_page_limit: u64,
    pub max_transitive_depth: i32,
    pub max_traversal_work_rows: i32,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkConfig {
    pub trust_ip_headers: bool,
    pub trusted_proxy_hops: u64,
    pub trusted_proxy_networks: u64,
    pub client_allowlist: ClientAllowlistStatus,
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientAllowlistStatus {
    pub allows_any: bool,
    pub network_count: u64,
}

/// Effective secret-provider policy; secret values and paths are not exposed.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretSourceConfig {
    pub provider: String,
    pub file_root_configured: bool,
    pub cache_ttl_seconds: u64,
    pub cache_capacity_per_consumer: u64,
    pub cache_total_bytes_per_consumer: u64,
    pub stale_values_allowed: bool,
    pub projected_symlinks_confined_to_root: bool,
}

/// A finite tracing sampling probability between zero and one, inclusive.
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
#[serde(transparent)]
pub struct SamplingRatio(f64);

impl SamplingRatio {
    pub fn new(value: f64) -> Result<Self, ApiError> {
        if value.is_finite() && (0.0..=1.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ApiError::InvalidSamplingRatio)
        }
    }

    pub const fn get(self) -> f64 {
        self.0
    }
}

// Construction and deserialization exclude NaN, so equality is reflexive.
impl Eq for SamplingRatio {}

impl<'de> Deserialize<'de> for SamplingRatio {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(f64::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// Redacted OpenTelemetry configuration advertised by the server.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TracingConfig {
    pub enabled: bool,
    pub protocol: String,
    pub endpoint: SecretStatus,
    pub static_headers: SecretStatus,
    pub ca_certificate_configured: bool,
    pub client_certificate_configured: bool,
    pub client_private_key: SecretStatus,
    pub service_name: String,
    pub service_namespace: String,
    pub deployment_environment: String,
    pub sampling_mode: String,
    pub sampling_ratio: SamplingRatio,
    pub trust_incoming_sampling: bool,
    pub propagate_outbound: bool,
    pub queue_capacity: u64,
    pub batch_size: u64,
    pub connect_timeout_ms: u64,
    pub export_timeout_ms: u64,
    pub flush_timeout_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::SamplingRatio;

    #[rstest::rstest]
    #[case(0.0)]
    #[case(0.125)]
    #[case(1.0)]
    fn sampling_ratio_roundtrips(#[case] value: f64) {
        let ratio = SamplingRatio::new(value).unwrap();
        let encoded = serde_json::to_string(&ratio).unwrap();
        assert_eq!(ratio.get(), value);
        assert_eq!(
            serde_json::from_str::<SamplingRatio>(&encoded).unwrap(),
            ratio
        );
    }

    #[rstest::rstest]
    #[case(-0.1)]
    #[case(1.1)]
    #[case(f64::NAN)]
    #[case(f64::INFINITY)]
    #[case(f64::NEG_INFINITY)]
    fn sampling_ratio_rejects_invalid_values(#[case] value: f64) {
        assert!(SamplingRatio::new(value).is_err());
        assert!(serde_json::from_str::<SamplingRatio>(&value.to_string()).is_err());
    }
}
