use std::sync::Arc;

use hubuum_client::{
    BaseUrl, Client, EventNotificationRequest, EventSubscriptionFilter, MockTransport,
    NewEventSubscription, PrincipalKind, Token, TransportResponse, UpdateEventSubscription,
    blocking,
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

fn subscription() -> Value {
    json!({"id":7,"sink_id":9,"name":"login alerts","description":"description",
        "entity_types":["authentication"],"actions":["succeeded"],"routing":{"token":"private_routing"},
        "enabled":false,"filter":{"subject_principal_ids":[3],"subject_identity_scopes":["local"],"subject_is_admin":true},
        "created_at":"2026-10-13T00:00:00Z","updated_at":"2026-10-13T00:00:00Z","revision":1})
}

fn transport() -> MockTransport {
    let transport = MockTransport::default();
    for body in [
        json!([subscription()]),
        subscription(),
        subscription(),
        subscription(),
        json!({"sink_kind":"webhook","payload":{"text":"private_payload"}}),
        json!({"id":1,"event_id":2,"subscription_id":7,"status":"pending","purpose":"test",
            "attempts":0,"next_attempt_at":"2026-10-13T00:00:00Z","created_at":"2026-10-13T00:00:00Z",
            "updated_at":"2026-10-13T00:00:00Z"}),
        json!([]),
    ] {
        transport.push_response(TransportResponse::json(StatusCode::OK, &body).unwrap());
    }
    transport.push_response(TransportResponse::json(StatusCode::NO_CONTENT, &Value::Null).unwrap());
    transport
}

macro_rules! workflow {
    ($client:ident, $send:ident) => {{
        let subscriptions = $client.system_event_subscriptions();
        let listed = $send!(subscriptions.list()).unwrap();
        assert!(!format!("{:?}", listed[0]).contains("private_routing"));
        let fetched = $send!(subscriptions.get(7)).unwrap();
        assert_eq!(
            fetched.filter.as_ref().unwrap().subject_is_admin,
            Some(true)
        );
        let filter = EventSubscriptionFilter {
            subject_principal_ids: Some(vec![3.into()]),
            subject_identity_scopes: Some(vec!["local".into()]),
            subject_is_admin: Some(true),
            ..Default::default()
        };
        let created = $send!(subscriptions.create(NewEventSubscription {
            sink_id: 9.into(),
            name: "login alerts".into(),
            entity_types: vec!["authentication".into()],
            actions: vec!["succeeded".into()],
            filter: Some(filter.clone()),
            ..Default::default()
        }))
        .unwrap();
        $send!(subscriptions.update(
            created.id,
            UpdateEventSubscription {
                filter: Some(filter),
                ..Default::default()
            }
        ))
        .unwrap();
        let input = EventNotificationRequest {
            subscription_id: 7.into(),
            event_id: "11111111-1111-4111-8111-111111111111".into(),
        };
        let preview = $send!($client.preview_event_notification(9, input.clone())).unwrap();
        assert_eq!(preview.payload["text"], "private_payload");
        assert!(!format!("{preview:?}").contains("private_payload"));
        $send!($client.test_event_notification(9, input)).unwrap();
        $send!(
            $client
                .class_events(42)
                .include_relations(false)
                .include_relations(true)
                .all()
        )
        .unwrap();
        $send!(subscriptions.delete(7)).unwrap();
    }};
}

fn assert_requests(transport: &MockTransport) {
    let requests = transport.requests();
    for (request, (method, path)) in requests.iter().zip([
        (Method::GET, "/api/v1/system-event-subscriptions"),
        (Method::GET, "/api/v1/system-event-subscriptions/7"),
        (Method::POST, "/api/v1/system-event-subscriptions"),
        (Method::PATCH, "/api/v1/system-event-subscriptions/7"),
        (Method::POST, "/api/v1/event-sinks/9/preview"),
        (Method::POST, "/api/v1/event-sinks/9/test"),
        (Method::GET, "/api/v1/classes/42/events"),
        (Method::DELETE, "/api/v1/system-event-subscriptions/7"),
    ]) {
        assert_eq!(request.method, method);
        assert_eq!(request.url.path(), path);
    }
    assert_eq!(requests.len(), 8);
    let body: Value = serde_json::from_slice(requests[2].body()).unwrap();
    assert_eq!(body["filter"], subscription()["filter"]);
    assert_eq!(requests[6].url.query(), Some("include_relations=true"));
    let body: Value = serde_json::from_slice(requests[4].body()).unwrap();
    assert_eq!(body["subscription_id"], 7);
    assert_eq!(body["event_id"], "11111111-1111-4111-8111-111111111111");
}

#[test]
fn blocking_typed_notifications() {
    let transport = transport();
    let client = blocking::Client::builder(BaseUrl::new("https://example.test").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("token"));
    macro_rules! send {
        ($value:expr) => {
            $value
        };
    }
    workflow!(client, send);
    assert_requests(&transport);
}

#[tokio::test]
async fn async_typed_notifications() {
    let transport = transport();
    let client = Client::builder(BaseUrl::new("https://example.test").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("token"));
    macro_rules! send {
        ($value:expr) => {
            $value.await
        };
    }
    workflow!(client, send);
    assert_requests(&transport);
}

#[rstest::rstest]
#[case(json!({}), true)]
#[case(json!({"subject":null}), true)]
#[case(json!({"subject":{"principal_id":3,"name":"alice","kind":"human","identity_scope":"local","authentication_provider_kind":"local","is_admin":true}}), true)]
#[case(json!({"subject":{"principal_id":"broken"}}), false)]
fn event_subject_decoding(#[case] metadata: Value, #[case] valid: bool) {
    let event: hubuum_client::EventResponse = serde_json::from_value(json!({
        "id":1,"event_id":"11111111-1111-4111-8111-111111111111","occurred_at":"2026-10-13T00:00:00Z",
        "entity_type":"authentication","action":"succeeded","actor_kind":"user","summary":"login","schema_version":1,
        "metadata":metadata,
    })).unwrap();
    let subject = event.subject();
    assert_eq!(subject.is_ok(), valid);
    if let Ok(Some(subject)) = subject {
        assert_eq!(subject.kind, PrincipalKind::Human);
    }
}
