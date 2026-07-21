#![cfg(all(feature = "async", feature = "blocking", feature = "typed-schemas"))]

use std::sync::Arc;
use std::time::Duration;

use hubuum_client::{
    ApiError, BaseUrl, ClassPatch, ExportContentType, ExportTemplateKind, MockTransport,
    ObjectDataPatchDocument, ObjectDataPatchOperation, ObjectPatch, RetryPolicy, TaskStatus, Token,
    TransportResponse, TypedObject, blocking,
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

fn exact_name_class_json(name: &str) -> serde_json::Value {
    json!({
        "id": 42,
        "name": name,
        "description": "Class",
        "collection": {
            "id": 7,
            "name": "collection-1",
            "description": "Collection",
            "created_at": "2026-07-21T10:00:00Z",
            "updated_at": "2026-07-21T10:00:00Z"
        },
        "json_schema": null,
        "validate_schema": null,
        "created_at": "2026-07-21T10:00:00Z",
        "updated_at": "2026-07-21T10:00:00Z"
    })
}

fn exact_name_object_json(name: &str) -> serde_json::Value {
    json!({
        "id": 9,
        "name": name,
        "collection_id": 7,
        "hubuum_class_id": 42,
        "description": "Object",
        "data": {"owner": "network"},
        "created_at": "2026-07-21T10:00:00Z",
        "updated_at": "2026-07-21T10:00:00Z"
    })
}

fn enqueue_exact_name_responses(transport: &MockTransport, class_name: &str, object_name: &str) {
    for body in [
        exact_name_class_json(class_name),
        exact_name_class_json(class_name),
        exact_name_object_json(object_name),
        exact_name_object_json(object_name),
        exact_name_object_json(object_name),
    ] {
        transport.push_response(TransportResponse::json(StatusCode::OK, &body).unwrap());
    }
    transport.push_response(TransportResponse::empty(StatusCode::NO_CONTENT));
    transport.push_response(TransportResponse::empty(StatusCode::NO_CONTENT));
}

fn assert_exact_name_requests(
    transport: &MockTransport,
    expected_class_path: &str,
    expected_object_path: &str,
) {
    let requests = transport.requests();
    assert_eq!(requests.len(), 7);
    assert_eq!(requests[0].method, Method::GET);
    assert_eq!(requests[0].url.path(), expected_class_path);
    assert_eq!(requests[1].method, Method::PATCH);
    assert_eq!(requests[1].url.path(), expected_class_path);
    assert_eq!(requests[2].method, Method::GET);
    assert_eq!(requests[2].url.path(), expected_object_path);
    assert_eq!(requests[3].method, Method::PATCH);
    assert_eq!(requests[3].url.path(), expected_object_path);
    assert_eq!(requests[4].method, Method::PATCH);
    assert_eq!(
        requests[4].url.path(),
        format!("{expected_object_path}/data")
    );
    assert_eq!(
        requests[4]
            .headers
            .get(reqwest::header::CONTENT_TYPE)
            .unwrap(),
        "application/json-patch+json"
    );
    assert_eq!(requests[5].method, Method::DELETE);
    assert_eq!(requests[5].url.path(), expected_object_path);
    assert_eq!(requests[6].method, Method::DELETE);
    assert_eq!(requests[6].url.path(), expected_class_path);
}

fn class_patch() -> ClassPatch {
    ClassPatch {
        name: None,
        description: Some("updated".into()),
        collection_id: 7.into(),
        json_schema: None,
        validate_schema: None,
    }
}

fn object_patch() -> ObjectPatch {
    ObjectPatch {
        name: None,
        collection_id: None,
        hubuum_class_id: None,
        description: Some("updated".into()),
        data: None,
    }
}

fn object_data_patch() -> ObjectDataPatchDocument {
    ObjectDataPatchDocument::new([ObjectDataPatchOperation::Replace {
        path: "/owner".into(),
        value: json!("network"),
    }])
}

#[test]
fn blocking_exact_name_routes_preserve_opaque_path_segments() {
    let class_name = r"a/../b\class";
    let object_name = r"x/./y\object";
    let transport = MockTransport::default();
    enqueue_exact_name_responses(&transport, class_name, object_name);
    let client = blocking_mock_client(transport.clone(), 4096);

    let class = client.class_by_name(class_name);
    class.get().unwrap();
    class.update(class_patch()).unwrap();
    let object = class.objects().by_name(object_name);
    object.get().unwrap();
    object.update(object_patch()).unwrap();
    object.patch_data(&object_data_patch()).unwrap();
    object.delete().unwrap();
    class.delete().unwrap();

    let class_path = "/api/v1/classes/by-name/a%2F..%2Fb%5Cclass";
    let object_path = format!("{class_path}/objects/by-name/x%2F.%2Fy%5Cobject");
    assert_exact_name_requests(&transport, class_path, &object_path);
}

#[tokio::test]
async fn async_exact_name_routes_preserve_opaque_path_segments() {
    let class_name = r"a/../b\class";
    let object_name = r"x/./y\object";
    let transport = MockTransport::default();
    enqueue_exact_name_responses(&transport, class_name, object_name);
    let client = hubuum_client::Client::builder(BaseUrl::new("https://example.invalid").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("consumer-secret"));

    let class = client.class_by_name(class_name);
    class.get().await.unwrap();
    class.update(class_patch()).await.unwrap();
    let object = class.objects().by_name(object_name);
    object.get().await.unwrap();
    object.update(object_patch()).await.unwrap();
    object.patch_data(&object_data_patch()).await.unwrap();
    object.delete().await.unwrap();
    class.delete().await.unwrap();

    let class_path = "/api/v1/classes/by-name/a%2F..%2Fb%5Cclass";
    let object_path = format!("{class_path}/objects/by-name/x%2F.%2Fy%5Cobject");
    assert_exact_name_requests(&transport, class_path, &object_path);
}

fn enqueue_dot_name_responses(transport: &MockTransport, class_name: &str, object_name: &str) {
    for body in [
        json!([exact_name_class_json(class_name)]),
        exact_name_class_json(class_name),
        json!([exact_name_object_json(object_name)]),
        exact_name_object_json(object_name),
        exact_name_object_json(object_name),
        json!([]),
        json!({"classes": [], "relations": []}),
        json!([]),
        json!({"objects": [], "relations": []}),
    ] {
        transport.push_response(TransportResponse::json(StatusCode::OK, &body).unwrap());
    }
    transport.push_response(TransportResponse::empty(StatusCode::NO_CONTENT));
    transport.push_response(TransportResponse::empty(StatusCode::NO_CONTENT));
}

fn assert_dot_name_requests(transport: &MockTransport, class_name: &str, object_name: &str) {
    let requests = transport.requests();
    let class_query = format!("name__equals={class_name}");
    let object_query = format!("name__equals={object_name}");
    assert_eq!(requests.len(), 11);
    assert_eq!(requests[0].method, Method::GET);
    assert_eq!(requests[0].url.path(), "/api/v1/classes");
    assert_eq!(requests[0].url.query(), Some(class_query.as_str()));
    assert_eq!(requests[1].method, Method::PATCH);
    assert_eq!(requests[1].url.path(), "/api/v1/classes/42");
    assert_eq!(requests[2].method, Method::GET);
    assert_eq!(requests[2].url.path(), "/api/v1/classes/42/");
    assert_eq!(requests[2].url.query(), Some(object_query.as_str()));
    assert_eq!(requests[3].method, Method::PATCH);
    assert_eq!(requests[3].url.path(), "/api/v1/classes/42/9");
    assert_eq!(requests[4].method, Method::PATCH);
    assert_eq!(requests[4].url.path(), "/api/v1/classes/42/9/data");
    assert_eq!(
        requests[4]
            .headers
            .get(reqwest::header::CONTENT_TYPE)
            .unwrap(),
        "application/json-patch+json"
    );
    assert_eq!(requests[5].method, Method::GET);
    assert_eq!(requests[5].url.path(), "/api/v1/classes/42/permissions");
    assert_eq!(requests[6].method, Method::GET);
    assert_eq!(requests[6].url.path(), "/api/v1/classes/42/related/graph");
    assert_eq!(requests[7].method, Method::GET);
    assert_eq!(
        requests[7].url.path(),
        "/api/v1/classes/42/objects/9/related/objects"
    );
    assert_eq!(requests[8].method, Method::GET);
    assert_eq!(
        requests[8].url.path(),
        "/api/v1/classes/42/objects/9/related/graph"
    );
    assert_eq!(requests[9].method, Method::DELETE);
    assert_eq!(requests[9].url.path(), "/api/v1/classes/42/9");
    assert_eq!(requests[10].method, Method::DELETE);
    assert_eq!(requests[10].url.path(), "/api/v1/classes/42");
}

#[test]
fn blocking_exact_name_routes_resolve_dot_segments_to_id_routes() {
    for (class_name, object_name) in [(".", ".."), ("..", ".")] {
        let transport = MockTransport::default();
        enqueue_dot_name_responses(&transport, class_name, object_name);
        let client = blocking_mock_client(transport.clone(), 4096);

        let class = client.class_by_name(class_name);
        class.get().unwrap();
        class.update(class_patch()).unwrap();
        let object = class.objects().by_name(object_name);
        object.get().unwrap();
        object.update(object_patch()).unwrap();
        object.patch_data(&object_data_patch()).unwrap();
        class.permissions().list().unwrap();
        class.related_graph().send().unwrap();
        object.related_objects().list().unwrap();
        object.related_graph().send().unwrap();
        object.delete().unwrap();
        class.delete().unwrap();

        assert_dot_name_requests(&transport, class_name, object_name);
    }
}

#[tokio::test]
async fn async_exact_name_routes_resolve_dot_segments_to_id_routes() {
    for (class_name, object_name) in [(".", ".."), ("..", ".")] {
        let transport = MockTransport::default();
        enqueue_dot_name_responses(&transport, class_name, object_name);
        let client =
            hubuum_client::Client::builder(BaseUrl::new("https://example.invalid").unwrap())
                .with_transport(Arc::new(transport.clone()))
                .build()
                .unwrap()
                .authenticate(Token::new("consumer-secret"));

        let class = client.class_by_name(class_name);
        class.get().await.unwrap();
        class.update(class_patch()).await.unwrap();
        let object = class.objects().by_name(object_name);
        object.get().await.unwrap();
        object.update(object_patch()).await.unwrap();
        object.patch_data(&object_data_patch()).await.unwrap();
        class.permissions().list().await.unwrap();
        class.related_graph().send().await.unwrap();
        object.related_objects().list().await.unwrap();
        object.related_graph().send().await.unwrap();
        object.delete().await.unwrap();
        class.delete().await.unwrap();

        assert_dot_name_requests(&transport, class_name, object_name);
    }
}

fn enqueue_dot_scope_builder_responses(transport: &MockTransport) {
    transport.push_response(
        TransportResponse::json(StatusCode::OK, &json!([exact_name_class_json(".")])).unwrap(),
    );
    for _ in 0..5 {
        transport.push_response(TransportResponse::json(StatusCode::OK, &json!([])).unwrap());
    }
    transport.push_response(
        TransportResponse::json(StatusCode::OK, &json!({"classes": [], "relations": []})).unwrap(),
    );
    transport.push_response(
        TransportResponse::json(StatusCode::OK, &json!([exact_name_object_json("..")])).unwrap(),
    );
    for _ in 0..2 {
        transport.push_response(TransportResponse::json(StatusCode::OK, &json!([])).unwrap());
    }
    transport.push_response(
        TransportResponse::json(StatusCode::OK, &json!({"objects": [], "relations": []})).unwrap(),
    );
}

fn assert_dot_scope_builder_requests(transport: &MockTransport) {
    let requests = transport.requests();
    let expected_paths = [
        "/api/v1/classes",
        "/api/v1/classes/42/",
        "/api/v1/classes/42/object-aggregates",
        "/api/v1/classes/42/permissions",
        "/api/v1/classes/42/related/classes",
        "/api/v1/classes/42/related/relations",
        "/api/v1/classes/42/related/graph",
        "/api/v1/classes/42/",
        "/api/v1/classes/42/objects/9/related/objects",
        "/api/v1/classes/42/objects/9/related/relations",
        "/api/v1/classes/42/objects/9/related/graph",
    ];
    assert_eq!(requests.len(), expected_paths.len());
    for (request, expected_path) in requests.iter().zip(expected_paths) {
        assert_eq!(request.method, Method::GET);
        assert_eq!(request.url.path(), expected_path);
    }
    assert_eq!(requests[0].url.query(), Some("name__equals=."));
    assert_eq!(requests[7].url.query(), Some("name__equals=.."));
}

#[test]
fn blocking_dot_name_scope_builders_use_id_routes() {
    let transport = MockTransport::default();
    enqueue_dot_scope_builder_responses(&transport);
    let client = blocking_mock_client(transport.clone(), 4096);
    let class = client.class_by_name(".");
    let object = class.objects().by_name("..");

    class.objects().query().list().unwrap();
    class.object_aggregates().list().unwrap();
    class.permissions().list().unwrap();
    class.related_classes().list().unwrap();
    class.related_relations().list().unwrap();
    class.related_graph().send().unwrap();
    object.related_objects().list().unwrap();
    object.related_relations().list().unwrap();
    object.related_graph().send().unwrap();

    assert_dot_scope_builder_requests(&transport);
}

#[tokio::test]
async fn async_dot_name_scope_builders_use_id_routes() {
    let transport = MockTransport::default();
    enqueue_dot_scope_builder_responses(&transport);
    let client = hubuum_client::Client::builder(BaseUrl::new("https://example.invalid").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("consumer-secret"));
    let class = client.class_by_name(".");
    let object = class.objects().by_name("..");

    class.objects().query().list().await.unwrap();
    class.object_aggregates().list().await.unwrap();
    class.permissions().list().await.unwrap();
    class.related_classes().list().await.unwrap();
    class.related_relations().list().await.unwrap();
    class.related_graph().send().await.unwrap();
    object.related_objects().list().await.unwrap();
    object.related_relations().list().await.unwrap();
    object.related_graph().send().await.unwrap();

    assert_dot_scope_builder_requests(&transport);
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

#[test]
fn object_data_patch_preserves_its_media_type_for_custom_transports() {
    let transport = MockTransport::default();
    transport.push_response(
        TransportResponse::json(
            StatusCode::OK,
            &json!({
                "id": 9,
                "name": "router",
                "collection_id": 7,
                "hubuum_class_id": 42,
                "description": "Router",
                "data": {"owner": "network"},
                "created_at": "2026-07-21T10:00:00Z",
                "updated_at": "2026-07-21T10:00:00Z"
            }),
        )
        .unwrap(),
    );
    let client = blocking_mock_client(transport.clone(), 1024);
    let patch = ObjectDataPatchDocument::new([ObjectDataPatchOperation::Replace {
        path: "/owner".into(),
        value: json!("network"),
    }]);

    client.patch_object_data(42, 9, &patch).unwrap();

    let request = transport.requests().pop().unwrap();
    assert_eq!(
        request.headers.get(reqwest::header::CONTENT_TYPE).unwrap(),
        "application/json-patch+json"
    );
    assert_eq!(
        request.body(),
        br#"[{"op":"replace","path":"/owner","value":"network"}]"#
    );
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

#[test]
fn scoped_identity_resource_models_preserve_provider_metadata() {
    let user: hubuum_client::User = serde_json::from_value(json!({
        "id": 7,
        "identity_scope": "corp-directory",
        "provider_kind": "ldap",
        "provider_managed": true,
        "name": "alice",
        "proper_name": "Alice Example",
        "email": "alice@example.com",
        "last_sync_attempted_at": "2026-07-10T10:00:00Z",
        "last_sync_success_at": "2026-07-10T10:00:00Z",
        "created_at": "2026-07-10T10:00:00Z",
        "updated_at": "2026-07-10T10:00:00Z"
    }))
    .unwrap();
    let group: hubuum_client::Group = serde_json::from_value(json!({
        "id": 8,
        "identity_scope": "corp-directory",
        "groupname": "operators",
        "description": "Directory operators",
        "managed_by": "ldap",
        "external_key": "cn=operators,dc=example,dc=com",
        "last_sync_attempted_at": "2026-07-10T10:00:00Z",
        "last_sync_success_at": "2026-07-10T10:00:00Z",
        "created_at": "2026-07-10T10:00:00Z",
        "updated_at": "2026-07-10T10:00:00Z"
    }))
    .unwrap();
    let service_account: hubuum_client::ServiceAccount = serde_json::from_value(json!({
        "id": 9,
        "identity_scope": "local",
        "name": "automation",
        "description": "Automation",
        "owner_group_id": 8,
        "created_by": 7,
        "disabled_at": null,
        "created_at": "2026-07-10T10:00:00Z",
        "updated_at": "2026-07-10T10:00:00Z"
    }))
    .unwrap();

    assert!(user.is_provider_managed());
    assert_eq!(user.provider_kind, hubuum_client::LDAP_PROVIDER_KIND);
    assert!(group.is_provider_managed());
    assert_eq!(
        group.external_key.as_deref(),
        Some("cn=operators,dc=example,dc=com")
    );
    assert!(service_account.is_local());
}

#[test]
fn identity_metadata_defaults_to_local_for_older_server_responses() {
    let user: hubuum_client::User = serde_json::from_value(json!({
        "id": 7,
        "name": "alice",
        "proper_name": null,
        "email": null,
        "created_at": "2026-07-10T10:00:00Z",
        "updated_at": "2026-07-10T10:00:00Z"
    }))
    .unwrap();
    let group: hubuum_client::Group = serde_json::from_value(json!({
        "id": 8,
        "groupname": "operators",
        "description": "Operators",
        "created_at": "2026-07-10T10:00:00Z",
        "updated_at": "2026-07-10T10:00:00Z"
    }))
    .unwrap();

    assert_eq!(user.identity_scope, hubuum_client::LOCAL_IDENTITY_SCOPE);
    assert_eq!(user.provider_kind, hubuum_client::LOCAL_PROVIDER_KIND);
    assert!(!user.is_provider_managed());
    assert_eq!(group.identity_scope, hubuum_client::LOCAL_IDENTITY_SCOPE);
    assert_eq!(group.managed_by, hubuum_client::LOCAL_PROVIDER_KIND);
    assert!(!group.is_provider_managed());
}

#[test]
fn scoped_create_requests_serialize_identity_scope() {
    let user = hubuum_client::UserPost {
        identity_scope: Some("local".into()),
        name: "alice".into(),
        password: "secret".into(),
        proper_name: None,
        email: None,
    };
    let group = hubuum_client::GroupPost {
        identity_scope: Some("local".into()),
        groupname: "operators".into(),
        description: None,
    };
    let service_account = hubuum_client::ServiceAccountPost {
        identity_scope: Some("local".into()),
        name: "automation".into(),
        description: None,
        owner_group_id: 8.into(),
    };

    assert_eq!(
        serde_json::to_value(user).unwrap()["identity_scope"],
        "local"
    );
    assert_eq!(
        serde_json::to_value(group).unwrap()["identity_scope"],
        "local"
    );
    assert_eq!(
        serde_json::to_value(service_account).unwrap()["identity_scope"],
        "local"
    );
}
