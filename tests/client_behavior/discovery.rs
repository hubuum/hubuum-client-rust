use crate::{class_json, task_response_json};
use std::{sync::Arc, time::Duration};

use hubuum_client::{
    ApiError, ClassId, Client, FieldDiscoveryOptions, FieldPathSegment, FieldSampleLimit,
    MockTransport, ProfileSuggestionStatus, SchemaProfilePreset, SchemaProfileReport,
    SchemaProfileRequest, TaskId, TaskKind, TaskOutputDiscoveryState, Token, TransportResponse,
    blocking,
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

fn push(transport: &MockTransport, status: StatusCode, body: Value) {
    transport.push_response(TransportResponse::json(status, &body).unwrap());
}

fn inventory() -> Value {
    let mut fields = Vec::new();
    for path in [
        json!([{"kind":"property","name":"private_a.b"}]),
        json!([
            {"kind":"property","name":"private_a"}, {"kind":"property","name":"b"}
        ]),
    ] {
        fields.push(
            json!({"field":"data.private_a.b","source":"data","path":path,
            "observation_count":2,"object_count":1,"types":{"number":1,"null":1},
            "example":"private_preview","example_truncated":true,"error_count":0}),
        );
    }
    json!({"sampled":true,"sampled_objects":2,"effective_sample_limit":2,
        "max_depth":3,"include_containers":true,"truncation":["sample_limit"],"fields":fields})
}

fn report(preset: SchemaProfilePreset) -> Value {
    json!({"class_id":42,"sampled":true,"sampled_objects":2,"effective_sample_limit":2,
        "truncation":"sample_limit","options":{"preset":preset,"sample_limit":2},
        "status":"candidate","schema":{"type":"object","properties":{"private_key":{"type":"string"}}},
        "profile":{"private_statistics":1},"findings":[{"private_reason":true}],
        "replay":{"private_evidence":true},"sample_valid":true})
}

fn task(status: &str) -> Value {
    let mut value = task_response_json(71, status);
    value["kind"] = json!("schema_profiling");
    value["details"] = json!({"schema_profiling":{"class_id":42,
        "output_url":"/api/v1/classes/42/schema/profiles/71"}});
    value
}

macro_rules! client {
    ($mode:ident, $transport:ident) => {
        $mode::Client::builder_from_url("https://example.test")
            .unwrap()
            .with_transport(Arc::new($transport.clone()))
            .build()
            .unwrap()
            .authenticate(Token::new("private_token"))
    };
}

// Both transport modes run the same assertions, including URL fallback behavior.
macro_rules! discover {
    ($client:ident, $transport:ident, $send:ident, $address:expr) => {{
        let address = $address;
        if address == "handle" {
            push(&$transport, StatusCode::OK, class_json("Hosts"));
        }
        if matches!(address, "." | "..") {
            push(&$transport, StatusCode::OK, json!([class_json(address)]));
        }
        push(&$transport, StatusCode::OK, inventory());
        let options = FieldDiscoveryOptions::default()
            .with_sample_limit(FieldSampleLimit::new(2).unwrap())
            .with_depth(3)
            .unwrap()
            .with_containers(true);
        let result = match address {
            "id" => $send!($client.class_fields(ClassId::new(42).unwrap(), &options)).unwrap(),
            "handle" => {
                let handle = $send!($client.classes().get(ClassId::new(42).unwrap())).unwrap();
                $send!(handle.fields(&options)).unwrap()
            }
            _ => $send!($client.class_by_name(address).fields(&options)).unwrap(),
        };
        assert_eq!(result.fields.len(), 2);
        assert_ne!(result.fields[0].path, result.fields[1].path);
        assert_eq!(
            result.fields[0].path,
            vec![FieldPathSegment::Property("private_a.b".into())]
        );
        assert_eq!(result.fields[0].observation_count, 2);
        assert_eq!(result.fields[0].object_count, 1);
        assert!(!format!("{result:?}").contains("private_"));
        let requests = $transport.requests();
        assert_eq!(
            requests.len(),
            if matches!(address, "handle" | "." | "..") {
                2
            } else {
                1
            }
        );
        let request = requests.last().unwrap();
        assert_eq!(request.method, Method::GET);
        if matches!(address, "id" | "handle" | "." | "..") {
            assert_eq!(request.url.path(), "/api/v1/classes/42/fields");
        } else {
            assert!(request.url.path().starts_with("/api/v1/classes/by-name/"));
            let encoded = request.url.path_segments().unwrap().nth(4).unwrap();
            assert_eq!(
                percent_encoding::percent_decode_str(encoded)
                    .decode_utf8()
                    .unwrap(),
                address
            );
        }
        assert_eq!(request.url.query(), Some("limit=2&depth=3&containers=true"));
        if matches!(address, "." | "..") {
            assert!(
                requests[0]
                    .url
                    .query_pairs()
                    .any(|(key, value)| key == "name__equals" && value == address)
            );
        }
    }};
}

#[rstest::rstest]
#[case("id")]
#[case("handle")]
#[case("Hosts")]
#[case("123")]
#[case(".")]
#[case("..")]
#[case("a/b ?#")]
fn blocking_field_discovery(#[case] address: &str) {
    let transport = MockTransport::default();
    let client = client!(blocking, transport);
    macro_rules! send {
        ($v:expr) => {
            $v
        };
    }
    discover!(client, transport, send, address);
}

#[rstest::rstest]
#[case("id")]
#[case("handle")]
#[case("Hosts")]
#[case("123")]
#[case(".")]
#[case("..")]
#[case("a/b ?#")]
#[tokio::test]
async fn async_field_discovery(#[case] address: &str) {
    let transport = MockTransport::default();
    let client = Client::builder_from_url("https://example.test")
        .unwrap()
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("private_token"));
    macro_rules! send {
        ($v:expr) => {
            $v.await
        };
    }
    discover!(client, transport, send, address);
}

macro_rules! suggestion {
    ($client:ident, $transport:ident, $send:ident, $preset:expr) => {{
        let preset = $preset;
        push(&$transport, StatusCode::ACCEPTED, task("queued"));
        push(&$transport, StatusCode::OK, task("running"));
        push(&$transport, StatusCode::OK, task("succeeded"));
        push(&$transport, StatusCode::OK, report(preset));
        let schema = $client.class_schema(ClassId::new(42).unwrap());
        let report = $send!(schema.suggest(SchemaProfileRequest::new(preset, FieldSampleLimit::new(2).unwrap()))
            .idempotency_key("profile-replay").poll_interval(Duration::from_millis(1))
            .timeout(Some(Duration::from_secs(1))).send()).unwrap();
        assert_eq!(report.status, ProfileSuggestionStatus::Candidate);
        assert!(!format!("{report:?}").contains("private_"));
        let stage = report.stage_request(true).unwrap();
        assert_eq!(stage.json_schema, report.schema);
        assert!(stage.validate_schema);
        let requests = $transport.requests();
        assert_eq!(requests.len(), 4, "suggestion must not stage or activate a schema");
        assert_eq!(requests[0].method, Method::POST);
        assert_eq!(requests[0].url.path(), "/api/v1/classes/42/schema/profiles");
        assert_eq!(requests[0].headers["idempotency-key"], "profile-replay");
        assert_eq!(serde_json::from_slice::<Value>(requests[0].body()).unwrap(), json!({"preset":preset,"sample_limit":2}));
        assert_eq!(requests[3].url.path(), "/api/v1/classes/42/schema/profiles/71");
    }};
}

#[rstest::rstest]
fn blocking_suggestion_workflow(
    #[values(
        SchemaProfilePreset::Strict,
        SchemaProfilePreset::Balanced,
        SchemaProfilePreset::Expansive
    )]
    preset: SchemaProfilePreset,
) {
    let transport = MockTransport::default();
    let client = client!(blocking, transport);
    macro_rules! send {
        ($v:expr) => {
            $v
        };
    }
    suggestion!(client, transport, send, preset);
}

#[rstest::rstest]
#[tokio::test]
async fn async_suggestion_workflow(
    #[values(
        SchemaProfilePreset::Strict,
        SchemaProfilePreset::Balanced,
        SchemaProfilePreset::Expansive
    )]
    preset: SchemaProfilePreset,
) {
    let transport = MockTransport::default();
    let client = Client::builder_from_url("https://example.test")
        .unwrap()
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("private_token"));
    macro_rules! send {
        ($v:expr) => {
            $v.await
        };
    }
    suggestion!(client, transport, send, preset);
}

macro_rules! failure {
    ($client:ident, $transport:ident, $send:ident, $status:expr) => {{
        push(&$transport, StatusCode::ACCEPTED, task("queued"));
        push(&$transport, StatusCode::OK, task($status));
        let error = $send!($client.class_schema(ClassId::new(42).unwrap())
            .suggest(SchemaProfileRequest::default()).send()).unwrap_err();
        assert!(matches!(error, ApiError::TaskUnsuccessful { task_id, .. } if task_id == 71));
        assert_eq!($transport.requests().len(), 2, "failed tasks have no report to fetch");
    }};
}

#[rstest::rstest]
fn blocking_failed_suggestion(
    #[values("failed", "cancelled", "partially_succeeded")] status: &str,
) {
    let transport = MockTransport::default();
    let client = client!(blocking, transport);
    macro_rules! send {
        ($v:expr) => {
            $v
        };
    }
    failure!(client, transport, send, status);
}

#[rstest::rstest]
#[tokio::test]
async fn async_failed_suggestion(
    #[values("failed", "cancelled", "partially_succeeded")] status: &str,
) {
    let transport = MockTransport::default();
    let client = Client::builder_from_url("https://example.test")
        .unwrap()
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("private_token"));
    macro_rules! send {
        ($v:expr) => {
            $v.await
        };
    }
    failure!(client, transport, send, status);
}

#[rstest::rstest]
#[case("blocked", Some(true))]
#[case("insufficient", None)]
#[case("candidate", Some(false))]
fn unusable_report_cannot_become_a_staging_request(
    #[case] status: &str,
    #[case] valid: Option<bool>,
) {
    let mut value = report(SchemaProfilePreset::Balanced);
    value["status"] = json!(status);
    value["sample_valid"] = json!(valid);
    let report: SchemaProfileReport = serde_json::from_value(value).unwrap();
    assert!(report.stage_request(true).is_err());
}

#[rstest::rstest]
#[case(0, false)]
#[case(1, true)]
#[case(250, true)]
#[case(251, false)]
fn sample_limit_is_validated_on_construction_and_decode(#[case] value: usize, #[case] valid: bool) {
    assert_eq!(FieldSampleLimit::new(value).is_ok(), valid);
    assert_eq!(
        serde_json::from_value::<SchemaProfileRequest>(json!({"sample_limit":value})).is_ok(),
        valid
    );
}

#[rstest::rstest]
#[case(0, true)]
#[case(32, true)]
#[case(33, false)]
fn discovery_depth_is_validated(#[case] value: usize, #[case] valid: bool) {
    assert_eq!(
        FieldDiscoveryOptions::default().with_depth(value).is_ok(),
        valid
    );
}

#[rstest::rstest]
fn blocking_report_preserves_http_errors(#[values(403, 404, 410)] code: u16) {
    let transport = MockTransport::default();
    push(
        &transport,
        StatusCode::from_u16(code).unwrap(),
        json!({"error":"Unavailable","message":"report unavailable"}),
    );
    let client = client!(blocking, transport);
    let error = client
        .class_schema(ClassId::new(42).unwrap())
        .profile_report(TaskId::new(71).unwrap())
        .unwrap_err();
    assert_eq!(error.status().unwrap().as_u16(), code);
}

#[rstest::rstest]
#[tokio::test]
async fn async_report_preserves_http_errors(#[values(403, 404, 410)] code: u16) {
    let transport = MockTransport::default();
    push(
        &transport,
        StatusCode::from_u16(code).unwrap(),
        json!({"error":"Unavailable","message":"report unavailable"}),
    );
    let client = Client::builder_from_url("https://example.test")
        .unwrap()
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("private_token"));
    let error = client
        .class_schema(ClassId::new(42).unwrap())
        .profile_report(TaskId::new(71).unwrap())
        .await
        .unwrap_err();
    assert_eq!(error.status().unwrap().as_u16(), code);
}

#[test]
fn profiling_discovery_accepts_class_and_output_filters() {
    let transport = MockTransport::default();
    push(&transport, StatusCode::OK, json!([task("succeeded")]));
    let client = client!(blocking, transport);
    let tasks = client
        .tasks()
        .query()
        .kind(TaskKind::SchemaProfiling)
        .class_id(ClassId::new(42).unwrap())
        .output_state(TaskOutputDiscoveryState::Available)
        .all()
        .unwrap();
    let details = tasks[0]
        .details
        .as_ref()
        .unwrap()
        .schema_profiling
        .as_ref()
        .unwrap();
    assert_eq!(details.class_id, Some(ClassId::new(42).unwrap()));
    assert_eq!(
        details.output_url.as_deref(),
        Some("/api/v1/classes/42/schema/profiles/71")
    );
}
