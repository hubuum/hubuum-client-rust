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
