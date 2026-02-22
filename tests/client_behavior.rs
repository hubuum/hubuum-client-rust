use std::str::FromStr;

use httpmock::prelude::*;
use hubuum_client::{ApiError, AsyncClient, BaseUrl, Credentials, SyncClient};
use serde_json::json;

const USERNAME: &str = "tester";
const PASSWORD: &str = "secret";
const TOKEN: &str = "integration-token";

fn ts() -> &'static str {
    "2024-01-01T00:00:00"
}

fn class_json(name: &str) -> serde_json::Value {
    json!({
        "id": 42,
        "name": name,
        "description": "Class",
        "namespace": {
            "id": 7,
            "name": "namespace-1",
            "description": "Namespace",
            "created_at": ts(),
            "updated_at": ts()
        },
        "json_schema": null,
        "validate_schema": null,
        "created_at": ts(),
        "updated_at": ts()
    })
}

fn mock_login(server: &MockServer) {
    server.mock(|when, then| {
        when.method(POST)
            .path("/api/v0/auth/login")
            .json_body(json!({ "username": USERNAME, "password": PASSWORD }));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "token": TOKEN }));
    });
}

fn sync_client(server: &MockServer) -> SyncClient<hubuum_client::Authenticated> {
    let base_url = BaseUrl::from_str(&server.base_url()).expect("mock base URL should be valid");
    SyncClient::new_with_certificate_validation(base_url, true)
        .login(Credentials::new(USERNAME.to_string(), PASSWORD.to_string()))
        .expect("sync login should succeed")
}

async fn async_client(server: &MockServer) -> AsyncClient<hubuum_client::Authenticated> {
    let base_url = BaseUrl::from_str(&server.base_url()).expect("mock base URL should be valid");
    AsyncClient::new_with_certificate_validation(base_url, true)
        .login(Credentials::new(USERNAME.to_string(), PASSWORD.to_string()))
        .await
        .expect("async login should succeed")
}

#[test]
fn sync_returns_http_error_with_message_from_json_body() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/classes/");
        then.status(400)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "bad request from server" }));
    });
    let client = sync_client(&server);

    let err = client
        .classes()
        .filter(())
        .expect_err("request should fail");
    match err {
        ApiError::HttpWithBody { status, message } => {
            assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
            assert_eq!(message, "bad request from server");
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[tokio::test]
async fn async_returns_http_error_with_message_from_json_body() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/classes/");
        then.status(400)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "bad request from server" }));
    });
    let client = async_client(&server).await;

    let err = client
        .classes()
        .filter(())
        .await
        .expect_err("request should fail");
    match err {
        ApiError::HttpWithBody { status, message } => {
            assert_eq!(status, reqwest::StatusCode::BAD_REQUEST);
            assert_eq!(message, "bad request from server");
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn sync_delete_rejects_non_empty_response_body() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/classes/1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .body("{\"ok\":true}");
    });
    let client = sync_client(&server);

    let err = client
        .classes()
        .delete(1)
        .expect_err("delete should reject non-empty response");
    match err {
        ApiError::DeserializationError(body) => assert_eq!(body, "{\"ok\":true}"),
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[tokio::test]
async fn async_delete_rejects_non_empty_response_body() {
    let server = MockServer::start();
    mock_login(&server);
    server.mock(|when, then| {
        when.method(DELETE)
            .path("/api/v1/classes/1")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .body("{\"ok\":true}");
    });
    let client = async_client(&server).await;

    let err = client
        .classes()
        .delete(1)
        .await
        .expect_err("delete should reject non-empty response");
    match err {
        ApiError::DeserializationError(body) => assert_eq!(body, "{\"ok\":true}"),
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn sync_select_by_name_applies_name_filter() {
    let server = MockServer::start();
    mock_login(&server);
    let class_name = "class-name-1";
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/")
            .query_param("name__equals", class_name)
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json(class_name)]));
    });
    let client = sync_client(&server);

    let class = client
        .classes()
        .select_by_name(class_name)
        .expect("class lookup should succeed");
    assert_eq!(class.resource().name, class_name);
}

#[tokio::test]
async fn async_select_by_name_applies_name_filter() {
    let server = MockServer::start();
    mock_login(&server);
    let class_name = "class-name-1";
    server.mock(|when, then| {
        when.method(GET)
            .path("/api/v1/classes/")
            .query_param("name__equals", class_name)
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!([class_json(class_name)]));
    });
    let client = async_client(&server).await;

    let class = client
        .classes()
        .select_by_name(class_name)
        .await
        .expect("class lookup should succeed");
    assert_eq!(class.resource().name, class_name);
}

#[test]
fn sync_supports_all_auth_logout_endpoints() {
    let server = MockServer::start();
    mock_login(&server);

    let logout = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/auth/logout")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "logged out" }));
    });

    let logout_token = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/auth/logout/token/revoked-token")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "token revoked" }));
    });

    let logout_user = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/auth/logout/uid/99")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "user tokens revoked" }));
    });

    let logout_all = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/auth/logout_all")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "all revoked" }));
    });

    let client = sync_client(&server);
    client.logout().expect("logout should succeed");
    client
        .logout_token("revoked-token")
        .expect("logout_token should succeed");
    client.logout_user(99).expect("logout_user should succeed");
    client.logout_all().expect("logout_all should succeed");

    logout.assert_calls(1);
    logout_token.assert_calls(1);
    logout_user.assert_calls(1);
    logout_all.assert_calls(1);
}

#[tokio::test]
async fn async_supports_all_auth_logout_endpoints() {
    let server = MockServer::start();
    mock_login(&server);

    let logout = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/auth/logout")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "logged out" }));
    });

    let logout_token = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/auth/logout/token/revoked-token")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "token revoked" }));
    });

    let logout_user = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/auth/logout/uid/99")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "user tokens revoked" }));
    });

    let logout_all = server.mock(|when, then| {
        when.method(GET)
            .path("/api/v0/auth/logout_all")
            .header("authorization", format!("Bearer {}", TOKEN));
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({ "message": "all revoked" }));
    });

    let client = async_client(&server).await;
    client.logout().await.expect("logout should succeed");
    client
        .logout_token("revoked-token")
        .await
        .expect("logout_token should succeed");
    client
        .logout_user(99)
        .await
        .expect("logout_user should succeed");
    client
        .logout_all()
        .await
        .expect("logout_all should succeed");

    logout.assert_calls(1);
    logout_token.assert_calls(1);
    logout_user.assert_calls(1);
    logout_all.assert_calls(1);
}
