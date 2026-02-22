use std::str::FromStr;

use httpmock::prelude::*;
use serde_json::json;
use yare::parameterized;

use super::{r#async as async_client, sync as sync_client, ClientCore, UrlParams};
use crate::client::{Authenticated, Unauthenticated};
use crate::endpoints::Endpoint;
use crate::types::{BaseUrl, Credentials};
use crate::ApiError;

const USERNAME: &str = "tester";
const PASSWORD: &str = "secret";
const TOKEN: &str = "integration-token";

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
