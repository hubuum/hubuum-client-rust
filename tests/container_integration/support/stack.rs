use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::support::naming::unique_suffix;

const DB_USER: &str = "hubuum";
const DB_PASSWORD: &str = "hubuum_password";
const DB_NAME: &str = "hubuum";
const DB_IMAGE_DEFAULT: &str = "postgres:18";
const SERVER_IMAGE_DEFAULT: &str = "ghcr.io/hubuum/hubuum-server:main";
const LDAP_IMAGE_DEFAULT: &str = "ghcr.io/rroemhild/docker-test-openldap@sha256:08a769cd1a8c8a17cba7fba28bc3443722203dd101b4f3628929a4ee30b50ec4";
const AUTH_CONFIG_DEFAULT: &str = "tests/container_integration/fixtures/auth-providers.toml";
const LDAP_CERTIFICATE_SCRIPT: &str =
    "tests/container_integration/fixtures/generate-ldap-certificates.sh";
const LDAP_HOST_ALIAS: &str = "planetexpress.com";
const CLIENT_ALLOWLIST_DEFAULT: &str = "*";
const STACK_TIMEOUT_DEFAULT_SECS: u64 = 300;
const EXTERNAL_BASE_URL_ENV: &str = "HUBUUM_INTEGRATION_BASE_URL";
const EXTERNAL_ADMIN_PASSWORD_ENV: &str = "HUBUUM_INTEGRATION_ADMIN_PASSWORD";
const CONTAINER_RUNTIME_ENV: &str = "HUBUUM_INTEGRATION_CONTAINER_RUNTIME";

fn shared_stack_slot() -> &'static Mutex<Weak<StackInner>> {
    static SHARED_STACK: OnceLock<Mutex<Weak<StackInner>>> = OnceLock::new();
    SHARED_STACK.get_or_init(|| Mutex::new(Weak::new()))
}

fn container_runtime() -> Result<String, String> {
    if let Ok(runtime) = std::env::var(CONTAINER_RUNTIME_ENV) {
        let runtime = runtime.trim();
        if !runtime.is_empty() {
            return Ok(runtime.to_string());
        }
    }

    for runtime in ["docker", "podman"] {
        if Command::new(runtime)
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
        {
            return Ok(runtime.to_string());
        }
    }

    Err(format!(
        "neither docker nor podman was found; set {CONTAINER_RUNTIME_ENV}"
    ))
}

fn container(args: &[String]) -> Result<String, String> {
    let runtime = container_runtime()?;
    let output = Command::new(&runtime)
        .args(args)
        .output()
        .map_err(|err| format!("failed to run `{runtime} {}`: {err}", args.join(" ")))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "`{runtime} {}` failed with status {}: {}",
            args.join(" "),
            output
                .status
                .code()
                .map_or_else(|| "unknown".to_string(), |code| code.to_string()),
            stderr.trim()
        ))
    }
}

fn wait_until<F>(timeout: Duration, mut predicate: F) -> Result<(), String>
where
    F: FnMut() -> Result<bool, String>,
{
    let started = Instant::now();
    while started.elapsed() < timeout {
        if predicate()? {
            return Ok(());
        }
        sleep(Duration::from_millis(500));
    }
    Err(format!("timed out after {}s", timeout.as_secs()))
}

fn server_image() -> String {
    std::env::var("HUBUUM_INTEGRATION_SERVER_IMAGE").unwrap_or_else(|_| SERVER_IMAGE_DEFAULT.into())
}

fn db_image() -> String {
    std::env::var("HUBUUM_INTEGRATION_DB_IMAGE").unwrap_or_else(|_| DB_IMAGE_DEFAULT.into())
}

fn ldap_image() -> String {
    std::env::var("HUBUUM_INTEGRATION_LDAP_IMAGE").unwrap_or_else(|_| LDAP_IMAGE_DEFAULT.into())
}

fn resolve_repo_path(configured: impl Into<std::path::PathBuf>) -> Result<String, String> {
    let path = configured.into();
    let path = if path.is_absolute() {
        path
    } else {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
    };

    path.canonicalize()
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(|err| format!("failed to resolve integration fixture: {err}"))
}

fn auth_config_path() -> Result<String, String> {
    let configured = std::env::var("HUBUUM_INTEGRATION_AUTH_CONFIG")
        .unwrap_or_else(|_| AUTH_CONFIG_DEFAULT.into());
    resolve_repo_path(configured)
}

fn initialize_ldap_certificates(volume_name: &str) -> Result<(), String> {
    let certificate_script = resolve_repo_path(LDAP_CERTIFICATE_SCRIPT)?;
    container(&[
        "run".to_string(),
        "--rm".to_string(),
        "--entrypoint".to_string(),
        "sh".to_string(),
        "--mount".to_string(),
        format!("type=volume,source={volume_name},target=/certs"),
        "--mount".to_string(),
        format!(
            "type=bind,source={certificate_script},target=/generate-ldap-certificates.sh,readonly"
        ),
        ldap_image(),
        "/generate-ldap-certificates.sh".to_string(),
    ])
    .map(|_| ())
}

fn keep_containers() -> bool {
    std::env::var("HUBUUM_INTEGRATION_KEEP_CONTAINERS")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn stack_timeout() -> Duration {
    let secs = std::env::var("HUBUUM_INTEGRATION_STACK_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(STACK_TIMEOUT_DEFAULT_SECS);
    Duration::from_secs(secs)
}

fn client_allowlist() -> String {
    std::env::var("HUBUUM_CLIENT_ALLOWLIST").unwrap_or_else(|_| CLIENT_ALLOWLIST_DEFAULT.into())
}

fn extract_admin_password(logs: &str) -> Option<String> {
    for line in logs.lines() {
        let Ok(json) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if json.get("message").and_then(Value::as_str) != Some("Created admin user") {
            continue;
        }
        if let Some(password) = json.get("password").and_then(Value::as_str) {
            return Some(password.to_string());
        }
    }
    None
}

fn extract_admin_password_from_text(text: &str) -> Option<String> {
    for line in text.lines().rev() {
        if let Ok(json) = serde_json::from_str::<Value>(line)
            && let Some(password) = json.get("password").and_then(Value::as_str)
        {
            return Some(password.to_string());
        }

        let lower = line.to_ascii_lowercase();
        if !lower.contains("password") {
            continue;
        }

        if let Some(candidate) = line
            .split_whitespace()
            .last()
            .map(|raw| raw.trim_matches(|c| c == '"' || c == '\'' || c == ',' || c == '.'))
            .filter(|candidate| !candidate.is_empty())
        {
            return Some(candidate.to_string());
        }
    }

    None
}

fn reset_admin_password(server_container_name: &str) -> Result<Option<String>, String> {
    let output = container(&[
        "exec".to_string(),
        server_container_name.to_string(),
        "hubuum-admin".to_string(),
        "--reset-password".to_string(),
        "admin".to_string(),
    ])?;

    Ok(extract_admin_password_from_text(&output))
}

fn resolve_admin_password(
    server_container_name: &str,
    timeout: Duration,
) -> Result<String, String> {
    let logs = container(&["logs".to_string(), server_container_name.to_string()])?;
    if let Some(password) = extract_admin_password(&logs) {
        return Ok(password);
    }

    let started = Instant::now();
    while started.elapsed() < timeout {
        match reset_admin_password(server_container_name) {
            Ok(Some(password)) => return Ok(password),
            Ok(None) => {}
            Err(_) => {}
        }
        sleep(Duration::from_millis(500));
    }

    Err("failed to reset admin password via hubuum-admin before timeout".to_string())
}

fn cleanup_stack_resources(
    network_name: &str,
    db_container_name: &str,
    server_container_name: &str,
    ldap_container_name: &str,
    ldap_cert_volume_name: &str,
) {
    let _ = container(&[
        "rm".to_string(),
        "-f".to_string(),
        server_container_name.to_string(),
        db_container_name.to_string(),
        ldap_container_name.to_string(),
    ]);
    let _ = container(&[
        "volume".to_string(),
        "rm".to_string(),
        ldap_cert_volume_name.to_string(),
    ]);
    let _ = container(&[
        "network".to_string(),
        "rm".to_string(),
        network_name.to_string(),
    ]);
}

fn collect_stack_diagnostics(
    server_container_name: &str,
    db_container_name: &str,
    ldap_container_name: &str,
    base_url: &str,
) -> String {
    let server_status = container(&[
        "inspect".to_string(),
        "-f".to_string(),
        "{{.State.Status}}".to_string(),
        server_container_name.to_string(),
    ])
    .unwrap_or_else(|err| format!("inspect-error: {err}"));

    let db_status = container(&[
        "inspect".to_string(),
        "-f".to_string(),
        "{{.State.Status}}".to_string(),
        db_container_name.to_string(),
    ])
    .unwrap_or_else(|err| format!("inspect-error: {err}"));

    let server_logs = container(&[
        "logs".to_string(),
        "--tail".to_string(),
        "100".to_string(),
        server_container_name.to_string(),
    ])
    .unwrap_or_else(|err| format!("logs-error: {err}"));

    let db_logs = container(&[
        "logs".to_string(),
        "--tail".to_string(),
        "50".to_string(),
        db_container_name.to_string(),
    ])
    .unwrap_or_else(|err| format!("logs-error: {err}"));

    let ldap_status = container(&[
        "inspect".to_string(),
        "-f".to_string(),
        "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}"
            .to_string(),
        ldap_container_name.to_string(),
    ])
    .unwrap_or_else(|err| format!("inspect-error: {err}"));

    let ldap_logs = container(&[
        "logs".to_string(),
        "--tail".to_string(),
        "100".to_string(),
        ldap_container_name.to_string(),
    ])
    .unwrap_or_else(|err| format!("logs-error: {err}"));

    let probe = match reqwest::blocking::Client::new()
        .post(format!("{base_url}/api/v0/auth/login"))
        .json(&json!({ "name": "__readiness__", "password": "__readiness__" }))
        .send()
    {
        Ok(response) => format!(
            "probe-status={} (POST /api/v0/auth/login)",
            response.status()
        ),
        Err(err) => format!("probe-error={err}"),
    };

    format!(
        "server_status={server_status}\ndb_status={db_status}\nldap_status={ldap_status}\n{probe}\nserver_logs_tail:\n{server_logs}\ndb_logs_tail:\n{db_logs}\nldap_logs_tail:\n{ldap_logs}"
    )
}

fn collect_db_startup_diagnostics(db_container_name: &str) -> String {
    let db_status = container(&[
        "inspect".to_string(),
        "-f".to_string(),
        "{{.State.Status}}".to_string(),
        db_container_name.to_string(),
    ])
    .unwrap_or_else(|err| format!("inspect-error: {err}"));

    let db_health = container(&[
        "inspect".to_string(),
        "-f".to_string(),
        "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}".to_string(),
        db_container_name.to_string(),
    ])
    .unwrap_or_else(|err| format!("inspect-error: {err}"));

    let db_logs = container(&[
        "logs".to_string(),
        "--tail".to_string(),
        "80".to_string(),
        db_container_name.to_string(),
    ])
    .unwrap_or_else(|err| format!("logs-error: {err}"));

    format!("db_status={db_status}\ndb_health={db_health}\ndb_logs_tail:\n{db_logs}")
}

struct StackInner {
    network_name: String,
    db_container_name: String,
    server_container_name: String,
    ldap_container_name: String,
    ldap_cert_volume_name: String,
    base_url: String,
    admin_password: String,
}

impl StackInner {
    fn start_new() -> Result<Self, String> {
        let suffix = unique_suffix();
        let timeout = stack_timeout();
        let auth_config_path = auth_config_path()?;
        let network_name = format!("hubuum-it-net-{suffix}");
        let db_container_name = format!("hubuum-it-db-{suffix}");
        let server_container_name = format!("hubuum-it-server-{suffix}");
        let ldap_container_name = format!("hubuum-it-ldap-{suffix}");
        let ldap_cert_volume_name = format!("hubuum-it-ldap-certs-{suffix}");

        container(&[
            "network".to_string(),
            "create".to_string(),
            network_name.clone(),
        ])
        .map_err(|err| format!("failed to create docker network `{network_name}`: {err}"))?;

        if let Err(err) = container(&[
            "volume".to_string(),
            "create".to_string(),
            ldap_cert_volume_name.clone(),
        ]) {
            cleanup_stack_resources(
                &network_name,
                &db_container_name,
                &server_container_name,
                &ldap_container_name,
                &ldap_cert_volume_name,
            );
            return Err(format!(
                "failed to create LDAP certificate volume `{ldap_cert_volume_name}`: {err}"
            ));
        }

        if let Err(err) = initialize_ldap_certificates(&ldap_cert_volume_name) {
            cleanup_stack_resources(
                &network_name,
                &db_container_name,
                &server_container_name,
                &ldap_container_name,
                &ldap_cert_volume_name,
            );
            return Err(format!(
                "failed to initialize LDAP certificates in `{ldap_cert_volume_name}`: {err}"
            ));
        }

        if let Err(err) = container(&[
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            ldap_container_name.clone(),
            "--network".to_string(),
            network_name.clone(),
            "--network-alias".to_string(),
            LDAP_HOST_ALIAS.to_string(),
            "--mount".to_string(),
            format!("type=volume,source={ldap_cert_volume_name},target=/etc/ldap/ssl"),
            ldap_image(),
        ]) {
            cleanup_stack_resources(
                &network_name,
                &db_container_name,
                &server_container_name,
                &ldap_container_name,
                &ldap_cert_volume_name,
            );
            return Err(format!(
                "failed to start LDAP container `{ldap_container_name}`: {err}"
            ));
        }

        if let Err(err) = wait_until(timeout, || {
            Ok(container(&[
                "exec".to_string(),
                ldap_container_name.clone(),
                "ldapsearch".to_string(),
                "-x".to_string(),
                "-H".to_string(),
                "ldap://127.0.0.1:10389".to_string(),
                "-D".to_string(),
                "cn=admin,dc=planetexpress,dc=com".to_string(),
                "-w".to_string(),
                "GoodNewsEveryone".to_string(),
                "-b".to_string(),
                "ou=people,dc=planetexpress,dc=com".to_string(),
                "-s".to_string(),
                "base".to_string(),
                "(objectClass=organizationalUnit)".to_string(),
                "dn".to_string(),
            ])
            .is_ok())
        })
        .map_err(|err| format!("LDAP container did not become healthy: {err}"))
        {
            let ldap_logs = container(&[
                "logs".to_string(),
                "--tail".to_string(),
                "120".to_string(),
                ldap_container_name.clone(),
            ])
            .unwrap_or_else(|logs_err| format!("logs-error: {logs_err}"));
            cleanup_stack_resources(
                &network_name,
                &db_container_name,
                &server_container_name,
                &ldap_container_name,
                &ldap_cert_volume_name,
            );
            return Err(format!("{err}\nldap_logs_tail:\n{ldap_logs}"));
        }

        let database_url =
            format!("postgres://{DB_USER}:{DB_PASSWORD}@{db_container_name}/{DB_NAME}");

        if let Err(err) = container(&[
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            db_container_name.clone(),
            "--network".to_string(),
            network_name.clone(),
            "--health-cmd".to_string(),
            "pg_isready -U hubuum -d hubuum".to_string(),
            "--health-interval".to_string(),
            "1s".to_string(),
            "--health-timeout".to_string(),
            "5s".to_string(),
            "--health-retries".to_string(),
            "30".to_string(),
            "-e".to_string(),
            format!("POSTGRES_USER={DB_USER}"),
            "-e".to_string(),
            format!("POSTGRES_PASSWORD={DB_PASSWORD}"),
            "-e".to_string(),
            format!("POSTGRES_DB={DB_NAME}"),
            db_image(),
        ]) {
            cleanup_stack_resources(
                &network_name,
                &db_container_name,
                &server_container_name,
                &ldap_container_name,
                &ldap_cert_volume_name,
            );
            return Err(format!(
                "failed to start postgres container `{db_container_name}`: {err}"
            ));
        }

        if let Err(err) = wait_until(timeout, || {
            let health = container(&[
                "inspect".to_string(),
                "-f".to_string(),
                "{{.State.Health.Status}}".to_string(),
                db_container_name.clone(),
            ])?;
            Ok(health == "healthy")
        })
        .map_err(|err| format!("database container did not become healthy: {err}"))
        {
            let diagnostics = collect_db_startup_diagnostics(&db_container_name);
            cleanup_stack_resources(
                &network_name,
                &db_container_name,
                &server_container_name,
                &ldap_container_name,
                &ldap_cert_volume_name,
            );
            return Err(format!("{err}\n{diagnostics}"));
        }

        if let Err(err) = container(&[
            "run".to_string(),
            "-d".to_string(),
            "--name".to_string(),
            server_container_name.clone(),
            "--network".to_string(),
            network_name.clone(),
            "-p".to_string(),
            "127.0.0.1::8080".to_string(),
            "-e".to_string(),
            "HUBUUM_BIND_IP=0.0.0.0".to_string(),
            "-e".to_string(),
            "HUBUUM_BIND_PORT=8080".to_string(),
            "-e".to_string(),
            format!("HUBUUM_CLIENT_ALLOWLIST={}", client_allowlist()),
            "-e".to_string(),
            "HUBUUM_LOG_LEVEL=debug".to_string(),
            "-e".to_string(),
            "HUBUUM_AUTH_CONFIG_PATH=/etc/hubuum/auth-providers.toml".to_string(),
            "-e".to_string(),
            format!("HUBUUM_DATABASE_URL={database_url}"),
            "-e".to_string(),
            format!("DATABASE_URL={database_url}"),
            "-e".to_string(),
            "SSL_CERT_FILE=/etc/hubuum/ldap-certs/ca.crt".to_string(),
            "--mount".to_string(),
            format!(
                "type=bind,source={auth_config_path},target=/etc/hubuum/auth-providers.toml,readonly"
            ),
            "--mount".to_string(),
            format!(
                "type=volume,source={ldap_cert_volume_name},target=/etc/hubuum/ldap-certs,readonly"
            ),
            server_image(),
        ]) {
            cleanup_stack_resources(
                &network_name,
                &db_container_name,
                &server_container_name,
                &ldap_container_name,
                &ldap_cert_volume_name,
            );
            return Err(format!(
                "failed to start hubuum server container `{server_container_name}`: {err}"
            ));
        }

        let mapped = match container(&[
            "port".to_string(),
            server_container_name.clone(),
            "8080/tcp".to_string(),
        ]) {
            Ok(value) => value,
            Err(err) => {
                cleanup_stack_resources(
                    &network_name,
                    &db_container_name,
                    &server_container_name,
                    &ldap_container_name,
                    &ldap_cert_volume_name,
                );
                return Err(format!("failed to resolve mapped server port: {err}"));
            }
        };
        let mapped_port = mapped
            .rsplit(':')
            .next()
            .ok_or_else(|| format!("failed to parse mapped server port from `{mapped}`"))?
            .parse::<u16>()
            .map_err(|err| format!("failed to parse mapped server port as integer: {err}"))?;
        let base_url = format!("http://127.0.0.1:{mapped_port}");

        if let Err(err) = wait_until(timeout, || {
            match reqwest::blocking::Client::new()
                .post(format!("{base_url}/api/v0/auth/login"))
                .json(&json!({ "name": "__readiness__", "password": "__readiness__" }))
                .send()
            {
                Ok(response) => {
                    Ok(response.status().is_success() || response.status().is_client_error())
                }
                Err(_) => Ok(false),
            }
        })
        .map_err(|err| format!("hubuum-server did not become ready: {err}"))
        {
            let diagnostics = collect_stack_diagnostics(
                &server_container_name,
                &db_container_name,
                &ldap_container_name,
                &base_url,
            );
            cleanup_stack_resources(
                &network_name,
                &db_container_name,
                &server_container_name,
                &ldap_container_name,
                &ldap_cert_volume_name,
            );
            return Err(format!("{err}\n{diagnostics}"));
        }

        let admin_password = match resolve_admin_password(&server_container_name, timeout) {
            Ok(password) => password,
            Err(err) => {
                let diagnostics = collect_stack_diagnostics(
                    &server_container_name,
                    &db_container_name,
                    &ldap_container_name,
                    &base_url,
                );
                cleanup_stack_resources(
                    &network_name,
                    &db_container_name,
                    &server_container_name,
                    &ldap_container_name,
                    &ldap_cert_volume_name,
                );
                return Err(format!("{err}\n{diagnostics}"));
            }
        };

        Ok(Self {
            network_name,
            db_container_name,
            server_container_name,
            ldap_container_name,
            ldap_cert_volume_name,
            base_url,
            admin_password,
        })
    }
}

impl Drop for StackInner {
    fn drop(&mut self) {
        if keep_containers() {
            eprintln!(
                "Keeping integration containers per HUBUUM_INTEGRATION_KEEP_CONTAINERS=1: server={}, db={}, ldap={}, ldap_certs={}, network={}",
                self.server_container_name,
                self.db_container_name,
                self.ldap_container_name,
                self.ldap_cert_volume_name,
                self.network_name
            );
            return;
        }

        cleanup_stack_resources(
            &self.network_name,
            &self.db_container_name,
            &self.server_container_name,
            &self.ldap_container_name,
            &self.ldap_cert_volume_name,
        );
    }
}

pub(crate) struct IntegrationStack {
    _inner: Option<Arc<StackInner>>,
    pub(crate) base_url: String,
    pub(crate) admin_password: String,
}

impl IntegrationStack {
    fn from_external_env() -> Result<Option<Self>, String> {
        let base_url = std::env::var(EXTERNAL_BASE_URL_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let admin_password = std::env::var(EXTERNAL_ADMIN_PASSWORD_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        match (base_url, admin_password) {
            (Some(base_url), Some(admin_password)) => Ok(Some(Self {
                _inner: None,
                base_url,
                admin_password,
            })),
            (None, None) => Ok(None),
            _ => Err(format!(
                "set both {EXTERNAL_BASE_URL_ENV} and {EXTERNAL_ADMIN_PASSWORD_ENV} to use an external integration stack"
            )),
        }
    }

    pub(crate) fn start() -> Result<Self, String> {
        if let Some(external) = Self::from_external_env()? {
            return Ok(external);
        }

        let slot = shared_stack_slot();
        let mut weak = slot
            .lock()
            .map_err(|_| "shared integration stack mutex poisoned".to_string())?;

        if let Some(inner) = weak.upgrade() {
            return Ok(Self {
                base_url: inner.base_url.clone(),
                admin_password: inner.admin_password.clone(),
                _inner: Some(inner),
            });
        }

        let inner = Arc::new(StackInner::start_new()?);
        *weak = Arc::downgrade(&inner);

        Ok(Self {
            base_url: inner.base_url.clone(),
            admin_password: inner.admin_password.clone(),
            _inner: Some(inner),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_admin_password_from_bootstrap_json_logs() {
        let logs = r#"
{"message":"other"}
{"message":"Created admin user","password":"boot-pass"}
"#;

        assert_eq!(extract_admin_password(logs).as_deref(), Some("boot-pass"));
    }

    #[test]
    fn extracts_admin_password_from_reset_json_output() {
        let output = r#"{"username":"admin","password":"reset-pass"}"#;

        assert_eq!(
            extract_admin_password_from_text(output).as_deref(),
            Some("reset-pass")
        );
    }

    #[test]
    fn extracts_admin_password_from_reset_text_output() {
        let output = "Reset admin password: text-pass";

        assert_eq!(
            extract_admin_password_from_text(output).as_deref(),
            Some("text-pass")
        );
    }
}
