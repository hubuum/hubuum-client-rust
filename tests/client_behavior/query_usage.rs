use std::sync::Arc;

use hubuum_client::{
    BaseUrl, Client, JsonPath, MockTransport, QueryUsageAnalysisRequest, QueryUsageAnalysisStatus,
    QueryUsageCreateRequest, QueryUsageDeclarationId, QueryUsageOperation, QueryUsagePattern,
    QueryUsageReplaceRequest, QueryUsageResourceOwnership, QueryUsageValueType, ResourceRevision,
    Token, TransportResponse, blocking,
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

fn pattern() -> QueryUsagePattern {
    QueryUsagePattern::new(
        JsonPath::new(["private_path"]).unwrap(),
        QueryUsageValueType::String,
        [QueryUsageOperation::Equals],
    )
    .unwrap()
}

fn declaration() -> Value {
    json!({"id":17,"class_id":42,"pattern":pattern(),"revision":3,
        "created_at":"2026-10-13T10:00:00Z","updated_at":"2026-10-13T10:00:01Z",
        "created_by":1,"updated_by":2,"schema_compatibility":"compatible"})
}

fn analysis(status: &str) -> Value {
    json!({"status":status,"assessed_at":"2026-10-13T10:00:01Z",
        "observations":{"source":"process_local","settings":{"enabled":true,"sample_every":1,
            "max_patterns":2048,"max_patterns_per_class":64,"retention_seconds":86400,"max_predicates_per_query":16},
            "process_started_at":"2026-10-13T10:00:00Z","captured_at":"2026-10-13T10:00:01Z",
            "patterns":[{"pattern":pattern(),"sampled_queries":5,"first_observed_at":"2026-10-13T10:00:00Z",
                "last_observed_at":"2026-10-13T10:00:01Z","whole_query_duration_micros":1337}],"capacity_drops":2},
        "assessments":[{"declaration_id":17,"pattern":pattern(),"schema_compatibility":"compatible","can_prepare":true,
            "resources":[{"reference":"private_reference","ownership":"declaration_managed","bytes":8192,
                "native_scan_count":7,"declaration_owners":2,"cleanup_eligible_if_removed":false}],
            "adapter_progress":{"reference":"private_reference","state":"pending","declaration_owners":2,
                "last_error":"private_diagnostic","updated_at":"2026-10-13T10:00:01Z"},"rationale":"private_rationale"}],
        "suggestions":[{"proposed":pattern(),"observations":[],"rationale":"private_rationale"}],
        "limitations":["private_limitation"]})
}

fn transport(status: &str) -> MockTransport {
    let transport = MockTransport::default();
    for (status, body) in [
        (StatusCode::OK, json!([declaration()])),
        (StatusCode::CREATED, declaration()),
        (StatusCode::OK, declaration()),
        (StatusCode::OK, analysis(status)),
        (StatusCode::NO_CONTENT, Value::Null),
        (StatusCode::CONFLICT, json!({"message":"stale revision"})),
        (
            StatusCode::FORBIDDEN,
            json!({"message":"administrator required"}),
        ),
    ] {
        transport.push_response(TransportResponse::json(status, &body).unwrap());
    }
    transport
}

macro_rules! exercise {
    ($client:ident, $send:ident, $expected:expr) => {{
        let usage = $client.class_query_usage(42);
        assert_eq!(usage.class_id().get(), 42);
        let records = $send!(usage.list()).unwrap();
        assert_eq!(records[0].created_by.unwrap().get(), 1);
        let created = $send!(usage.create(QueryUsageCreateRequest { pattern: pattern() })).unwrap();
        assert_eq!(created.id.get(), 17);
        let replaced = $send!(usage.replace(
            created.id,
            QueryUsageReplaceRequest {
                pattern: pattern(),
                expected_revision: created.revision,
            }
        ))
        .unwrap();
        let analysis =
            $send!(usage.analyze(QueryUsageAnalysisRequest::new([pattern()]).unwrap())).unwrap();
        assert_eq!(analysis.status, $expected);
        assert_eq!(analysis.observations.patterns[0].sampled_queries, 5);
        assert_eq!(analysis.observations.capacity_drops, 2);
        let assessment = &analysis.assessments[0];
        assert_eq!(
            assessment.resources[0].ownership,
            QueryUsageResourceOwnership::DeclarationManaged
        );
        assert_eq!(assessment.resources[0].native_scan_count, Some(7));
        assert_eq!(
            assessment.adapter_progress.as_ref().unwrap().state,
            "pending"
        );
        assert_eq!(analysis.suggestions[0].proposed.path(), "private_path");
        assert!(!format!("{analysis:?}").contains("private_"));
        $send!(usage.delete(replaced.id, replaced.revision)).unwrap();
        let stale = $send!(usage.delete(
            QueryUsageDeclarationId::new(17).unwrap(),
            ResourceRevision::INITIAL
        ))
        .unwrap_err();
        assert_eq!(stale.status(), Some(StatusCode::CONFLICT));
        let denied = $send!(usage.analyze(QueryUsageAnalysisRequest::default())).unwrap_err();
        assert_eq!(denied.status(), Some(StatusCode::FORBIDDEN));
    }};
}

fn assert_requests(transport: &MockTransport) {
    let requests = transport.requests();
    assert_eq!(requests.len(), 7);
    for (request, (method, suffix)) in requests.iter().zip([
        (Method::GET, ""),
        (Method::POST, ""),
        (Method::PUT, "/17"),
        (Method::POST, "/analysis"),
        (Method::DELETE, "/17"),
        (Method::DELETE, "/17"),
        (Method::POST, "/analysis"),
    ]) {
        assert_eq!(request.method, method);
        assert_eq!(
            request.url.path(),
            format!("/api/v1/classes/42/query-usage{suffix}")
        );
        assert_eq!(request.headers["authorization"], "Bearer private_token");
        assert!(!format!("{request:?}").contains("private_"));
    }
    assert_eq!(
        serde_json::from_slice::<Value>(requests[1].body()).unwrap(),
        json!({"pattern":pattern()})
    );
    assert_eq!(
        serde_json::from_slice::<Value>(requests[2].body()).unwrap(),
        json!({"pattern":pattern(),"expected_revision":3})
    );
    assert_eq!(
        serde_json::from_slice::<Value>(requests[3].body()).unwrap(),
        json!({"proposed":[pattern()]})
    );
    assert_eq!(requests[4].url.query(), Some("expected_revision=3"));
    assert_eq!(requests[5].url.query(), Some("expected_revision=1"));
    assert_eq!(
        serde_json::from_slice::<Value>(requests[6].body()).unwrap(),
        json!({})
    );
}

#[rstest::rstest]
#[case("complete", QueryUsageAnalysisStatus::Complete)]
#[case(
    "insufficient_evidence",
    QueryUsageAnalysisStatus::InsufficientEvidence
)]
#[case("unavailable", QueryUsageAnalysisStatus::Unavailable)]
fn blocking_query_usage(#[case] status: &str, #[case] expected: QueryUsageAnalysisStatus) {
    let transport = transport(status);
    let client = blocking::Client::builder(BaseUrl::new("https://example.test").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("private_token"));
    macro_rules! send {
        ($value:expr) => {
            $value
        };
    }
    exercise!(client, send, expected);
    assert_requests(&transport);
}

#[rstest::rstest]
#[case("complete", QueryUsageAnalysisStatus::Complete)]
#[case(
    "insufficient_evidence",
    QueryUsageAnalysisStatus::InsufficientEvidence
)]
#[case("unavailable", QueryUsageAnalysisStatus::Unavailable)]
#[tokio::test]
async fn async_query_usage(#[case] status: &str, #[case] expected: QueryUsageAnalysisStatus) {
    let transport = transport(status);
    let client = Client::builder(BaseUrl::new("https://example.test").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("private_token"));
    macro_rules! send {
        ($value:expr) => {
            $value.await
        };
    }
    exercise!(client, send, expected);
    assert_requests(&transport);
}

#[test]
fn blocking_object_json_filter_uses_server_query_key() {
    let transport = MockTransport::default();
    transport.push_response(TransportResponse::json(StatusCode::OK, &json!([])).unwrap());
    let client = blocking::Client::builder(BaseUrl::new("https://example.test").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("token"));
    client
        .objects(42)
        .data()
        .path(["hardware", "serial"])
        .eq("abc")
        .list()
        .unwrap();
    assert_eq!(
        transport.requests()[0]
            .url
            .query_pairs()
            .collect::<Vec<_>>(),
        [("json_data__equals".into(), "hardware,serial=abc".into())]
    );
}
#[tokio::test]
async fn async_object_json_filter_uses_server_query_key() {
    let transport = MockTransport::default();
    transport.push_response(TransportResponse::json(StatusCode::OK, &json!([])).unwrap());
    let client = Client::builder(BaseUrl::new("https://example.test").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("token"));
    client
        .objects(42)
        .data()
        .path(["hardware", "serial"])
        .eq("abc")
        .list()
        .await
        .unwrap();
    assert_eq!(
        transport.requests()[0]
            .url
            .query_pairs()
            .collect::<Vec<_>>(),
        [("json_data__equals".into(), "hardware,serial=abc".into())]
    );
}
