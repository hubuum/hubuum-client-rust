use std::str::FromStr;

use httpmock::prelude::*;
use serde_json::json;
use yare::parameterized;

use super::{ClientCore, UrlParams, r#async as async_client, sync as sync_client};
use crate::ApiError;
use crate::client::{Authenticated, Unauthenticated};
use crate::endpoints::Endpoint;
use crate::types::{BaseUrl, Credentials};

const USERNAME: &str = "tester";
const PASSWORD: &str = "secret";
const TOKEN: &str = "integration-token";

fn mock_login(server: &MockServer) {
    server.mock(|when, then| {
        when.method(POST)
            .path("/api/v0/auth/login")
            .json_body(json!({ "name": USERNAME, "password": PASSWORD }));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "token": TOKEN }));
    });
}

fn build_sync_client(server: &MockServer) -> Result<sync_client::Client<Authenticated>, ApiError> {
    let base_url = BaseUrl::from_str(&server.base_url()).expect("base URL should be valid");
    sync_client::Client::new_with_certificate_validation(base_url, true)
        .login(Credentials::new(USERNAME.to_string(), PASSWORD.to_string()))
}

async fn build_async_client(
    server: &MockServer,
) -> Result<async_client::Client<Authenticated>, ApiError> {
    let base_url = BaseUrl::from_str(&server.base_url()).expect("base URL should be valid");
    async_client::Client::new_with_certificate_validation(base_url, true)
        .login(Credentials::new(USERNAME.to_string(), PASSWORD.to_string()))
        .await
}

#[parameterized(
    login_foo = { "https://foo.bar.com", Endpoint::Login },
    users_foo = { "https://foo.bar.com", Endpoint::Users },
    classes_foo = { "https://foo.bar.com", Endpoint::Classes },
    login_bar = { "https://bar.baz.com", Endpoint::Login },
    users_bar = { "https://bar.baz.com", Endpoint::Users },
    classes_bar = { "https://bar.baz.com", Endpoint::Classes }
)]
fn sync_build_url_matches_endpoint(server: &str, endpoint: Endpoint) {
    let base_url = BaseUrl::from_str(server).unwrap();
    let client = sync_client::Client::<Unauthenticated>::new_without_certificate_validation(
        base_url.clone(),
    );

    assert_eq!(
        client.build_url(&endpoint, UrlParams::default()),
        format!(
            "{}{}",
            base_url.with_trailing_slash(),
            endpoint.trim_start_matches('/')
        )
    );
}

#[parameterized(
    login_foo = { "https://foo.bar.com", Endpoint::Login },
    users_foo = { "https://foo.bar.com", Endpoint::Users },
    classes_foo = { "https://foo.bar.com", Endpoint::Classes },
    login_bar = { "https://bar.baz.com", Endpoint::Login },
    users_bar = { "https://bar.baz.com", Endpoint::Users },
    classes_bar = { "https://bar.baz.com", Endpoint::Classes }
)]
fn async_build_url_matches_endpoint(server: &str, endpoint: Endpoint) {
    let base_url = BaseUrl::from_str(server).unwrap();
    let client = async_client::Client::<Unauthenticated>::new_without_certificate_validation(
        base_url.clone(),
    );

    assert_eq!(
        client.build_url(&endpoint, UrlParams::default()),
        format!(
            "{}{}",
            base_url.with_trailing_slash(),
            endpoint.trim_start_matches('/')
        )
    );
}

#[test]
fn sync_request_patch_requires_patch_id() {
    let server = MockServer::start();
    mock_login(&server);
    let client = build_sync_client(&server).expect("login should succeed");

    let err = client
        .request_with_endpoint::<sync_client::EmptyPostParams, serde_json::Value>(
            reqwest::Method::PATCH,
            &Endpoint::Classes,
            vec![],
            vec![],
            sync_client::EmptyPostParams {},
        )
        .expect_err("PATCH without patch_id should fail");

    assert!(matches!(err, ApiError::MissingUrlIdentifier));
}

#[tokio::test]
async fn async_request_patch_requires_patch_id() {
    let server = MockServer::start();
    mock_login(&server);
    let client = build_async_client(&server)
        .await
        .expect("login should succeed");

    let err = client
        .request_with_endpoint::<async_client::EmptyPostParams, serde_json::Value>(
            reqwest::Method::PATCH,
            &Endpoint::Classes,
            vec![],
            vec![],
            async_client::EmptyPostParams {},
        )
        .await
        .expect_err("PATCH without patch_id should fail");

    assert!(matches!(err, ApiError::MissingUrlIdentifier));
}

#[test]
fn sync_task_wait_polls_until_terminal() {
    let server = MockServer::start();
    mock_login(&server);
    let task = server.mock(|when, then| {
        when.method(GET).path("/api/v1/tasks/9");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "id": 9, "kind": "report", "status": "succeeded",
                "created_at": "2026-03-06T12:00:00Z",
                "progress": {"total_items":1,"processed_items":1,"success_items":1,"failed_items":0},
                "links": {"task":"/api/v1/tasks/9","events":"/api/v1/tasks/9/events"}
            }));
    });
    let client = build_sync_client(&server).unwrap();
    let result = client
        .tasks()
        .wait(9)
        .poll_interval(std::time::Duration::from_millis(1))
        .send()
        .unwrap();
    assert_eq!(result.status, crate::types::TaskStatus::Succeeded);
    task.assert_calls(1);
}

#[test]
fn sync_task_wait_times_out() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/tasks/9");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "id": 9, "kind": "report", "status": "running",
                "created_at": "2026-03-06T12:00:00Z",
                "progress": {"total_items":1,"processed_items":0,"success_items":0,"failed_items":0},
                "links": {"task":"/api/v1/tasks/9","events":"/api/v1/tasks/9/events"}
            }));
    });
    let client = build_sync_client(&server).unwrap();
    // Large poll interval vs. small timeout: a remaining-time-aware sleep must not
    // overshoot the deadline by a full interval.
    let started = std::time::Instant::now();
    let err = client
        .tasks()
        .wait(9)
        .poll_interval(std::time::Duration::from_secs(10))
        .timeout(Some(std::time::Duration::from_millis(20)))
        .send()
        .unwrap_err();
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    assert!(matches!(err, ApiError::Api(m) if m.contains("Timed out")));
}

#[tokio::test]
async fn async_task_wait_polls_until_terminal() {
    let server = MockServer::start();
    mock_login(&server);
    let task = server.mock(|when, then| {
        when.method(GET).path("/api/v1/tasks/9");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "id": 9, "kind": "report", "status": "succeeded",
                "created_at": "2026-03-06T12:00:00Z",
                "progress": {"total_items":1,"processed_items":1,"success_items":1,"failed_items":0},
                "links": {"task":"/api/v1/tasks/9","events":"/api/v1/tasks/9/events"}
            }));
    });
    let client = build_async_client(&server).await.unwrap();
    let result = client
        .tasks()
        .wait(9)
        .poll_interval(std::time::Duration::from_millis(1))
        .send()
        .await
        .unwrap();
    assert_eq!(result.status, crate::types::TaskStatus::Succeeded);
    task.assert_calls(1);
}

#[tokio::test]
async fn async_task_wait_times_out() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/tasks/9");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "id": 9, "kind": "report", "status": "running",
                "created_at": "2026-03-06T12:00:00Z",
                "progress": {"total_items":1,"processed_items":0,"success_items":0,"failed_items":0},
                "links": {"task":"/api/v1/tasks/9","events":"/api/v1/tasks/9/events"}
            }));
    });
    let client = build_async_client(&server).await.unwrap();
    let started = std::time::Instant::now();
    let err = client
        .tasks()
        .wait(9)
        .poll_interval(std::time::Duration::from_secs(10))
        .timeout(Some(std::time::Duration::from_millis(20)))
        .send()
        .await
        .unwrap_err();
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    assert!(matches!(err, ApiError::Api(m) if m.contains("Timed out")));
}

#[test]
fn sync_tasks_query_uses_raw_params() {
    let server = MockServer::start();
    mock_login(&server);
    let listing = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/tasks")
            .query_param("kind", "report")
            .query_param("status", "succeeded")
            .query_param("submitted_by", "3");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([]));
    });
    let client = build_sync_client(&server).unwrap();
    let _ = client
        .tasks()
        .query()
        .kind(crate::types::TaskKind::Report)
        .status(crate::types::TaskStatus::Succeeded)
        .submitted_by(3)
        .list()
        .unwrap();
    listing.assert_calls(1);
}

#[tokio::test]
async fn async_tasks_query_uses_raw_params() {
    let server = MockServer::start();
    mock_login(&server);
    let listing = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/tasks")
            .query_param("kind", "report")
            .query_param("status", "succeeded")
            .query_param("submitted_by", "3");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([]));
    });
    let client = build_async_client(&server).await.unwrap();
    let _ = client
        .tasks()
        .query()
        .kind(crate::types::TaskKind::Report)
        .status(crate::types::TaskStatus::Succeeded)
        .submitted_by(3)
        .list()
        .await
        .unwrap();
    listing.assert_calls(1);
}

fn report_task_json(status: &str) -> serde_json::Value {
    json!({
        "id": 11, "kind": "report", "status": status,
        "created_at": "2026-03-06T12:00:00Z",
        "progress": {"total_items":1,"processed_items":1,"success_items":1,"failed_items":0},
        "links": {"task":"/api/v1/tasks/11","events":"/api/v1/tasks/11/events",
                  "report":"/api/v1/reports/11","report_output":"/api/v1/reports/11/output"}
    })
}

fn report_request_value() -> crate::types::ReportRequest {
    crate::types::ReportRequest {
        limits: None,
        missing_data_policy: None,
        output: None,
        query: None,
        scope: crate::types::ReportScope {
            class_id: Some(42),
            kind: crate::types::ReportScopeKind::ObjectsInClass,
            object_id: None,
        },
        include: None,
        relation_context: None,
    }
}

#[test]
fn sync_report_run_json_output() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(POST).path("/api/v1/reports");
        then.status(202)
            .header("content-type", "application/json")
            .json_body(report_task_json("queued"));
    });
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/tasks/11");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(report_task_json("succeeded"));
    });
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/reports/11/output");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({"items": [{"id":1}], "meta": {
                "content_type":"application/json","count":1,
                "scope":{"class_id":42,"kind":"objects_in_class","object_id":null},
                "truncated":false}, "warnings": []}));
    });
    let client = build_sync_client(&server).unwrap();
    let result = client
        .reports()
        .run(report_request_value())
        .poll_interval(std::time::Duration::from_millis(1))
        .send()
        .unwrap();
    match result {
        crate::types::ReportResult::Json(body) => assert_eq!(body.meta.count, 1),
        other => panic!("expected Json, got {other:?}"),
    }
}

#[test]
fn sync_report_output_rendered_csv() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/reports/11/output");
        then.status(200)
            .header("content-type", "text/csv")
            .body("id,name\n1,srv-01\n");
    });
    let client = build_sync_client(&server).unwrap();
    match client.reports().output(11).unwrap() {
        crate::types::ReportResult::Rendered { content_type, body } => {
            assert_eq!(content_type, crate::types::ReportContentType::TextCsv);
            assert!(body.contains("srv-01"));
        }
        other => panic!("expected Rendered, got {other:?}"),
    }
}

#[test]
fn sync_report_run_failed_errors() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(POST).path("/api/v1/reports");
        then.status(202)
            .header("content-type", "application/json")
            .json_body(report_task_json("queued"));
    });
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/tasks/11");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "id": 11, "kind":"report", "status":"failed", "summary":"boom",
                "created_at":"2026-03-06T12:00:00Z",
                "progress":{"total_items":1,"processed_items":1,"success_items":0,"failed_items":1},
                "links":{"task":"/api/v1/tasks/11","events":"/api/v1/tasks/11/events"}
            }));
    });
    let client = build_sync_client(&server).unwrap();
    let err = client
        .reports()
        .run(report_request_value())
        .poll_interval(std::time::Duration::from_millis(1))
        .send()
        .unwrap_err();
    assert!(matches!(err, ApiError::Api(m) if m.contains("boom")));
}

#[tokio::test]
async fn async_report_run_json_output() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(POST).path("/api/v1/reports");
        then.status(202)
            .header("content-type", "application/json")
            .json_body(report_task_json("queued"));
    });
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/tasks/11");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(report_task_json("succeeded"));
    });
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/reports/11/output");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({"items": [{"id":1}], "meta": {
                "content_type":"application/json","count":1,
                "scope":{"class_id":42,"kind":"objects_in_class","object_id":null},
                "truncated":false}, "warnings": []}));
    });
    let client = build_async_client(&server).await.unwrap();
    let result = client
        .reports()
        .run(report_request_value())
        .poll_interval(std::time::Duration::from_millis(1))
        .send()
        .await
        .unwrap();
    match result {
        crate::types::ReportResult::Json(body) => assert_eq!(body.meta.count, 1),
        other => panic!("expected Json, got {other:?}"),
    }
}

#[tokio::test]
async fn async_report_output_rendered_html() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/reports/11/output");
        then.status(200)
            .header("content-type", "text/html")
            .body("<p>html report</p>");
    });
    let client = build_async_client(&server).await.unwrap();
    match client.reports().output(11).await.unwrap() {
        crate::types::ReportResult::Rendered { content_type, body } => {
            assert_eq!(content_type, crate::types::ReportContentType::TextHtml);
            assert_eq!(body, "<p>html report</p>");
        }
        other => panic!("expected Rendered, got {other:?}"),
    }
}

#[tokio::test]
async fn async_report_run_failed_errors() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(POST).path("/api/v1/reports");
        then.status(202)
            .header("content-type", "application/json")
            .json_body(report_task_json("queued"));
    });
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/tasks/11");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "id": 11, "kind":"report", "status":"cancelled", "summary":"stopped",
                "created_at":"2026-03-06T12:00:00Z",
                "progress":{"total_items":1,"processed_items":0,"success_items":0,"failed_items":0},
                "links":{"task":"/api/v1/tasks/11","events":"/api/v1/tasks/11/events"}
            }));
    });
    let client = build_async_client(&server).await.unwrap();
    let err = client
        .reports()
        .run(report_request_value())
        .poll_interval(std::time::Duration::from_millis(1))
        .send()
        .await
        .unwrap_err();
    assert!(matches!(err, ApiError::Api(m) if m.contains("stopped")));
}

#[test]
fn sync_meta_login_rate_limit_state() {
    let server = MockServer::start();
    mock_login(&server);
    let m = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/meta/login-rate-limit")
            .query_param("include", "all")
            .query_param("scope", "ip");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "config": {"enabled":true,"max_attempts":5,"max_attempts_per_ip":20,
                    "max_attempts_per_subnet":100,"window_seconds":300,"backoff_base_seconds":300,
                    "backoff_max_seconds":86400,"subnet_prefix_v4":24,"subnet_prefix_v6":64},
                "tracked_entries":0,"locked_entries":0,"returned_entries":0,"entries":[]
            }));
    });
    let client = build_sync_client(&server).unwrap();
    let state = client
        .meta_login_rate_limit()
        .include_all(true)
        .scope("ip")
        .send()
        .unwrap();
    assert_eq!(state.config.max_attempts_per_ip, 20);
    m.assert_calls(1);
}

#[test]
fn sync_meta_login_rate_limit_release_decodes_delete_body() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v0/meta/login-rate-limit/abc123");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({"released": true}));
    });
    let client = build_sync_client(&server).unwrap();
    let resp = client.meta_login_rate_limit_release("abc123").unwrap();
    assert!(resp.released);
}

#[test]
fn sync_meta_login_rate_limit_clear_decodes_delete_body() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(DELETE).path("/api/v0/meta/login-rate-limit");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({"cleared": 4}));
    });
    let client = build_sync_client(&server).unwrap();
    assert_eq!(client.meta_login_rate_limit_clear().unwrap().cleared, 4);
}

#[tokio::test]
async fn async_meta_login_rate_limit_state() {
    let server = MockServer::start();
    mock_login(&server);
    let m = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/meta/login-rate-limit")
            .query_param("q", "alice");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({
                "config": {"enabled":true,"max_attempts":5,"max_attempts_per_ip":20,
                    "max_attempts_per_subnet":100,"window_seconds":300,"backoff_base_seconds":300,
                    "backoff_max_seconds":86400,"subnet_prefix_v4":24,"subnet_prefix_v6":64},
                "tracked_entries":1,"locked_entries":1,"returned_entries":1,
                "entries":[{"id":"x","scope":"user_ip","identifier":"alice@1.2.3.4",
                    "attempts":6,"locked":true,"locked_for_seconds":120,"lockout_level":1}]
            }));
    });
    let client = build_async_client(&server).await.unwrap();
    let state = client
        .meta_login_rate_limit()
        .q("alice")
        .send()
        .await
        .unwrap();
    assert_eq!(state.entries.len(), 1);
    assert_eq!(state.entries[0].lockout_level, 1);
    m.assert_calls(1);
}

#[tokio::test]
async fn async_meta_login_rate_limit_release_and_clear() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v0/meta/login-rate-limit/zzz");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({"released": false}));
    });
    server.mock(|when, then| {
        when.method(DELETE).path("/api/v0/meta/login-rate-limit");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({"cleared": 0}));
    });
    let client = build_async_client(&server).await.unwrap();
    assert!(
        !client
            .meta_login_rate_limit_release("zzz")
            .await
            .unwrap()
            .released
    );
    assert_eq!(
        client.meta_login_rate_limit_clear().await.unwrap().cleared,
        0
    );
}
