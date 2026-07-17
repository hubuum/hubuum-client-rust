use serde::{Deserialize, Serialize};

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
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupConfig {
    pub output_retention_hours: i64,
    pub max_active_tasks_per_user: u64,
    pub max_output_bytes: u64,
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
    pub stable_token_hash_key_configured: bool,
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
