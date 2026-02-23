use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::support::naming::unique_suffix;

const DB_USER: &str = "hubuum";
const DB_PASSWORD: &str = "hubuum_password";
const DB_NAME: &str = "hubuum";
const DB_IMAGE_DEFAULT: &str = "postgres:15";
const SERVER_IMAGE_DEFAULT: &str = "ghcr.io/hubuum/hubuum-server:no-tls-main";
const STACK_TIMEOUT_DEFAULT_SECS: u64 = 300;

fn docker(args: &[String]) -> Result<String, String> {
    let output = Command::new("docker")
        .args(args)
        .output()
        .map_err(|err| format!("failed to run `docker {}`: {err}", args.join(" ")))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "`docker {}` failed with status {}: {}",
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

fn cleanup_stack_resources(
    network_name: &str,
    db_container_name: &str,
    server_container_name: &str,
) {
    let _ = docker(&[
        "rm".to_string(),
        "-f".to_string(),
        server_container_name.to_string(),
        db_container_name.to_string(),
    ]);
    let _ = docker(&[
        "network".to_string(),
        "rm".to_string(),
        network_name.to_string(),
    ]);
}

fn collect_stack_diagnostics(
    server_container_name: &str,
    db_container_name: &str,
    base_url: &str,
) -> String {
    let server_status = docker(&[
        "inspect".to_string(),
        "-f".to_string(),
        "{{.State.Status}}".to_string(),
        server_container_name.to_string(),
    ])
    .unwrap_or_else(|err| format!("inspect-error: {err}"));

    let db_status = docker(&[
        "inspect".to_string(),
        "-f".to_string(),
        "{{.State.Status}}".to_string(),
        db_container_name.to_string(),
    ])
    .unwrap_or_else(|err| format!("inspect-error: {err}"));

    let server_logs = docker(&[
        "logs".to_string(),
        "--tail".to_string(),
        "100".to_string(),
        server_container_name.to_string(),
    ])
    .unwrap_or_else(|err| format!("logs-error: {err}"));

    let db_logs = docker(&[
        "logs".to_string(),
        "--tail".to_string(),
        "50".to_string(),
        db_container_name.to_string(),
    ])
    .unwrap_or_else(|err| format!("logs-error: {err}"));

    let probe = match reqwest::blocking::Client::new()
        .post(format!("{base_url}/api/v0/auth/login"))
        .json(&json!({ "username": "__readiness__", "password": "__readiness__" }))
        .send()
    {
        Ok(response) => format!(
            "probe-status={} (POST /api/v0/auth/login)",
            response.status()
        ),
        Err(err) => format!("probe-error={err}"),
    };

    format!(
        "server_status={server_status}\ndb_status={db_status}\n{probe}\nserver_logs_tail:\n{server_logs}\ndb_logs_tail:\n{db_logs}"
    )
}

pub(crate) struct IntegrationStack {
    network_name: String,
    db_container_name: String,
    server_container_name: String,
    pub(crate) base_url: String,
    pub(crate) admin_password: String,
}

impl IntegrationStack {
    pub(crate) fn start() -> Result<Self, String> {
        let suffix = unique_suffix();
        let timeout = stack_timeout();
        let network_name = format!("hubuum-it-net-{suffix}");
        let db_container_name = format!("hubuum-it-db-{suffix}");
        let server_container_name = format!("hubuum-it-server-{suffix}");

        docker(&[
            "network".to_string(),
            "create".to_string(),
            network_name.clone(),
        ])
        .map_err(|err| format!("failed to create docker network `{network_name}`: {err}"))?;

        let database_url =
            format!("postgres://{DB_USER}:{DB_PASSWORD}@{db_container_name}/{DB_NAME}");

        if let Err(err) = docker(&[
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
            cleanup_stack_resources(&network_name, &db_container_name, &server_container_name);
            return Err(format!(
                "failed to start postgres container `{db_container_name}`: {err}"
            ));
        }

        if let Err(err) = wait_until(timeout, || {
            let health = docker(&[
                "inspect".to_string(),
                "-f".to_string(),
                "{{.State.Health.Status}}".to_string(),
                db_container_name.clone(),
            ])?;
            Ok(health == "healthy")
        })
        .map_err(|err| format!("database container did not become healthy: {err}"))
        {
            cleanup_stack_resources(&network_name, &db_container_name, &server_container_name);
            return Err(err);
        }

        if let Err(err) = docker(&[
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
            "HUBUUM_LOG_LEVEL=debug".to_string(),
            "-e".to_string(),
            format!("HUBUUM_DATABASE_URL={database_url}"),
            "-e".to_string(),
            format!("DATABASE_URL={database_url}"),
            server_image(),
        ]) {
            cleanup_stack_resources(&network_name, &db_container_name, &server_container_name);
            return Err(format!(
                "failed to start hubuum server container `{server_container_name}`: {err}"
            ));
        }

        let mapped = match docker(&[
            "port".to_string(),
            server_container_name.clone(),
            "8080/tcp".to_string(),
        ]) {
            Ok(value) => value,
            Err(err) => {
                cleanup_stack_resources(&network_name, &db_container_name, &server_container_name);
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
            let logs = docker(&["logs".to_string(), server_container_name.clone()])?;
            Ok(extract_admin_password(&logs).is_some())
        })
        .map_err(|err| {
            format!("failed to detect bootstrapped admin password in server logs: {err}")
        }) {
            let diagnostics =
                collect_stack_diagnostics(&server_container_name, &db_container_name, &base_url);
            cleanup_stack_resources(&network_name, &db_container_name, &server_container_name);
            return Err(format!("{err}\n{diagnostics}"));
        }

        if let Err(err) = wait_until(timeout, || {
            match reqwest::blocking::Client::new()
                .post(format!("{base_url}/api/v0/auth/login"))
                .json(&json!({ "username": "__readiness__", "password": "__readiness__" }))
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
            let diagnostics =
                collect_stack_diagnostics(&server_container_name, &db_container_name, &base_url);
            cleanup_stack_resources(&network_name, &db_container_name, &server_container_name);
            return Err(format!("{err}\n{diagnostics}"));
        }

        let logs = match docker(&["logs".to_string(), server_container_name.clone()]) {
            Ok(value) => value,
            Err(err) => {
                cleanup_stack_resources(&network_name, &db_container_name, &server_container_name);
                return Err(format!("failed to read server logs: {err}"));
            }
        };
        let admin_password = extract_admin_password(&logs).ok_or_else(|| {
            "admin password was not present in server logs after successful startup".to_string()
        })?;

        Ok(Self {
            network_name,
            db_container_name,
            server_container_name,
            base_url,
            admin_password,
        })
    }
}

impl Drop for IntegrationStack {
    fn drop(&mut self) {
        if keep_containers() {
            eprintln!(
                "Keeping integration containers per HUBUUM_INTEGRATION_KEEP_CONTAINERS=1: server={}, db={}, network={}",
                self.server_container_name, self.db_container_name, self.network_name
            );
            return;
        }

        cleanup_stack_resources(
            &self.network_name,
            &self.db_container_name,
            &self.server_container_name,
        );
    }
}
