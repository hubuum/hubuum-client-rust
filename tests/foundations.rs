#![cfg(all(feature = "async", feature = "blocking", feature = "typed-schemas"))]

use std::sync::Arc;
use std::time::Duration;

use hubuum_client::{
    ApiError, BaseUrl, ExportContentType, ExportTemplateKind, MockTransport, RetryPolicy,
    TaskStatus, Token, TransportResponse, TypedObject, blocking,
};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;

fn blocking_mock_client(
    transport: MockTransport,
    max_body_bytes: usize,
) -> blocking::Client<hubuum_client::Authenticated> {
    blocking::Client::builder(BaseUrl::new("https://example.invalid").unwrap())
        .with_transport(Arc::new(transport))
        .max_response_body_bytes(max_body_bytes)
        .retry_policy(RetryPolicy {
            max_attempts: 2,
            initial_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        })
        .build()
        .unwrap()
        .authenticate(Token::new("consumer-secret"))
}

#[test]
fn mock_transport_retries_safe_requests_and_redacts_diagnostics() {
    let transport = MockTransport::default();
    transport.push_response(TransportResponse::empty(StatusCode::TOO_MANY_REQUESTS));
    transport
        .push_response(TransportResponse::json(StatusCode::OK, &json!({ "ok": true })).unwrap());
    let client = blocking_mock_client(transport.clone(), 1024);

    let response: serde_json::Value = client
        .raw(Method::GET, "api/v1/extensions/check")
        .query_param("cursor", "consumer-secret")
        .send()
        .unwrap();

    assert_eq!(response, json!({ "ok": true }));
    let requests = transport.requests();
    assert_eq!(requests.len(), 2);
    let diagnostic = format!("{:?}", requests[0]);
    assert!(!diagnostic.contains("consumer-secret"));
    assert!(diagnostic.contains("%5BREDACTED%5D"));
}

#[test]
fn mock_transport_enforces_body_limits_and_raw_path_boundaries() {
    let transport = MockTransport::default();
    transport.push_response(TransportResponse {
        status: StatusCode::OK,
        headers: Default::default(),
        body: b"12345".to_vec(),
    });
    let client = blocking_mock_client(transport, 4);

    assert!(matches!(
        client.raw(Method::GET, "api/v1/large").send_text(),
        Err(ApiError::ResponseTooLarge {
            limit: 4,
            content_length: Some(5)
        })
    ));
    assert!(matches!(
        client
            .raw(Method::GET, "https://attacker.invalid/path")
            .send_text(),
        Err(ApiError::InvalidBaseUrl(_))
    ));
}

#[test]
fn raw_requests_cannot_escape_the_base_origin_or_path_prefix() {
    let transport = MockTransport::default();
    let client =
        blocking::Client::builder(BaseUrl::new("https://example.invalid/tenant/hubuum/").unwrap())
            .with_transport(Arc::new(transport.clone()))
            .build()
            .unwrap()
            .authenticate(Token::new("consumer-secret"));

    for path in [
        "//attacker.invalid/path",
        r"\\attacker.invalid/path",
        "%2e%2e/admin",
        "api/%2E%2E/%2e%2e/admin",
        "api/v1/classes?redirect=https://attacker.invalid",
    ] {
        assert!(
            matches!(
                client.raw(Method::GET, path).send_text(),
                Err(ApiError::InvalidBaseUrl(_))
            ),
            "raw path should be rejected: {path}"
        );
    }

    assert!(transport.requests().is_empty());
}

#[test]
fn response_and_error_debug_output_redacts_sensitive_values() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("x-private-token", "header-secret".parse().unwrap());
    let response = TransportResponse {
        status: StatusCode::OK,
        headers,
        body: b"body-secret".to_vec(),
    };

    let response_debug = format!("{response:?}");
    assert!(response_debug.contains("x-private-token"));
    assert!(response_debug.contains("body_len: 11"));
    assert!(!response_debug.contains("header-secret"));
    assert!(!response_debug.contains("body-secret"));

    let error = ApiError::HttpWithBody {
        method: Method::GET,
        url: "https://example.invalid/search?q=query-secret&cursor=cursor-secret".into(),
        status: StatusCode::BAD_REQUEST,
        message: "invalid query".into(),
        body: "body-secret".into(),
    };
    let error_debug = format!("{error:?}");
    assert!(error_debug.contains("%5BREDACTED%5D"));
    assert!(!error_debug.contains("query-secret"));
    assert!(!error_debug.contains("cursor-secret"));
    assert!(!error_debug.contains("body-secret"));
    assert!(!error.to_string().contains("query-secret"));
}

#[test]
fn principal_settings_support_get_replace_patch_and_reset() {
    let transport = MockTransport::default();
    for response in [
        json!({ "theme": "light" }),
        json!({ "theme": "dark" }),
        json!({ "theme": "dark", "dashboard": { "columns": 3 } }),
        json!({ "locale": "nb-NO" }),
    ] {
        transport.push_response(TransportResponse::json(StatusCode::OK, &response).unwrap());
    }
    transport.push_response(TransportResponse::empty(StatusCode::NO_CONTENT));
    let client = blocking_mock_client(transport.clone(), 4096);

    assert_eq!(
        client.settings().get().unwrap().get("theme"),
        Some(&json!("light"))
    );
    client
        .settings()
        .replace(&json!({ "theme": "dark" }))
        .unwrap();
    client
        .settings()
        .patch(&json!({ "dashboard": { "columns": 3 } }))
        .unwrap();
    assert_eq!(
        client.principal_settings(42).get().unwrap().get("locale"),
        Some(&json!("nb-NO"))
    );
    client.settings().reset().unwrap();

    let requests = transport.requests();
    assert_eq!(requests.len(), 5);
    assert_eq!(requests[0].method, Method::GET);
    assert_eq!(requests[0].url.path(), "/api/v1/iam/me/settings");
    assert_eq!(requests[1].method, Method::PUT);
    assert_eq!(requests[1].body(), br#"{"theme":"dark"}"#);
    assert_eq!(requests[2].method, Method::PATCH);
    assert_eq!(requests[2].body(), br#"{"dashboard":{"columns":3}}"#);
    assert_eq!(requests[3].url.path(), "/api/v1/iam/principals/42/settings");
    assert_eq!(requests[4].method, Method::DELETE);
}

#[test]
fn principal_settings_reject_non_object_documents_before_transport() {
    let transport = MockTransport::default();
    let client = blocking_mock_client(transport.clone(), 1024);

    assert!(matches!(
        client.settings().replace(&json!(["invalid"])),
        Err(ApiError::InvalidPrincipalSettings)
    ));
    assert!(matches!(
        client.settings().patch(&json!(null)),
        Err(ApiError::InvalidPrincipalSettings)
    ));
    assert!(transport.requests().is_empty());
}

#[tokio::test]
async fn async_principal_settings_use_the_same_typed_surface() {
    let transport = MockTransport::default();
    transport.push_response(
        TransportResponse::json(StatusCode::OK, &json!({ "locale": "nb-NO" })).unwrap(),
    );
    let client = hubuum_client::Client::builder(BaseUrl::new("https://example.invalid").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("consumer-secret"));

    let settings = client
        .principal_settings(42)
        .patch(&json!({ "locale": "nb-NO" }))
        .await
        .unwrap();

    assert_eq!(settings.get("locale"), Some(&json!("nb-NO")));
    let requests = transport.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, Method::PATCH);
    assert_eq!(requests[0].url.path(), "/api/v1/iam/principals/42/settings");
}

#[test]
fn raw_json_requests_set_content_type_for_custom_transports() {
    let transport = MockTransport::default();
    transport.push_response(
        TransportResponse::json(StatusCode::OK, &json!({ "accepted": true })).unwrap(),
    );
    let client = blocking_mock_client(transport.clone(), 1024);

    let _: serde_json::Value = client
        .raw(Method::POST, "api/v1/extensions/action")
        .json(&json!({ "password": "consumer-secret" }))
        .unwrap()
        .send()
        .unwrap();

    let request = transport.requests().pop().unwrap();
    assert_eq!(
        request.headers.get(reqwest::header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
    assert_eq!(request.body(), br#"{"password":"consumer-secret"}"#);
    assert!(!format!("{request:?}").contains("consumer-secret"));
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
struct ServerData {
    hostname: String,
    cores: u16,
}

#[test]
fn typed_objects_round_trip_and_generate_schema() {
    let raw: hubuum_client::Object = serde_json::from_value(json!({
        "id": 3,
        "name": "server-3",
        "collection_id": 7,
        "hubuum_class_id": 9,
        "description": "server",
        "data": { "hostname": "node-3", "cores": 8 },
        "created_at": "2026-07-10T10:00:00Z",
        "updated_at": "2026-07-10T10:00:00Z"
    }))
    .unwrap();

    let typed = TypedObject::<ServerData>::try_from(raw).unwrap();
    assert_eq!(typed.data.hostname, "node-3");
    assert_eq!(typed.clone().try_into_untyped().unwrap().id, typed.id);

    let schema = hubuum_client::types::schema_for::<ServerData>().unwrap();
    assert_eq!(schema["properties"]["cores"]["type"], "integer");
}

#[test]
fn unknown_server_enum_values_remain_decodable() {
    assert_eq!(
        serde_json::from_str::<TaskStatus>(r#""paused_by_policy""#).unwrap(),
        TaskStatus::Unknown
    );
    assert_eq!(
        serde_json::from_str::<ExportTemplateKind>(r#""future_template""#).unwrap(),
        ExportTemplateKind::Unknown
    );
    assert_eq!(
        ExportContentType::from_header("application/vnd.hubuum.future+json"),
        Some(ExportContentType::Unknown)
    );
}
