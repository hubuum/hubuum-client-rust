use std::sync::Arc;

use hubuum_client::{
    BaseUrl, Client, CredentialActivityPageOptions, CredentialActivityResponse, MockTransport,
    Token, TransportResponse, blocking,
};
use reqwest::{Method, StatusCode};
use rstest::rstest;
use serde_json::{Value, json};

fn activity(offset: usize, next: Option<usize>) -> Value {
    json!({
        "session_id": "86f53d97-1135-45c9-a940-f2d36eac2df7",
        "creation": {"issuer_id": 7, "issuance_method": "login",
            "issued_at": "2026-10-22T08:00:00Z", "address": "192.0.2.1",
            "address_method": "connection_peer"},
        "sources": [{"address": "2001:db8::1", "address_method": "trusted_forwarded",
            "first_seen": "2026-10-22T08:00:00Z", "last_seen": "2026-10-22T09:00:00Z"}],
        "total": 2, "offset": offset, "limit": 1, "next_offset": next,
        "collection_enabled": true, "best_effort": true, "retention_days": 30,
        "source_cap": 32, "overflow_since": "2026-10-22T09:00:00Z"
    })
}

fn push(transport: &MockTransport, value: &Value) {
    transport.push_response(TransportResponse::json(StatusCode::OK, value).unwrap());
}

macro_rules! sync_finish {
    ($e:expr) => {
        $e
    };
}
macro_rules! async_finish {
    ($e:expr) => {
        $e.await
    };
}

macro_rules! read_activity {
    ($client:ident, $finish:ident, $surface:expr, $options:expr) => {
        match $surface {
            "user" => $finish!(
                $finish!($client.users().get(42))
                    .unwrap()
                    .token_activity(9, $options)
            ),
            "service" => $finish!(
                $finish!($client.service_accounts().get(42))
                    .unwrap()
                    .token_activity(9, $options)
            ),
            _ => $finish!($client.token_activity(42, 9, $options)),
        }
    };
}

fn push_handle(transport: &MockTransport, surface: &str) {
    match surface {
        "user" => push(transport, &crate::user_json(42, "owner")),
        "service" => push(transport, &crate::service_account_json(42, "owner", 3)),
        _ => (),
    }
}

macro_rules! pagination_scenario {
    ($client:ident, $transport:ident, $surface:ident, $finish:ident) => {{
        push_handle(&$transport, $surface);
        push(&$transport, &activity(0, Some(1)));
        let page = read_activity!(
            $client,
            $finish,
            $surface,
            CredentialActivityPageOptions::default().limit(1).unwrap()
        )
        .unwrap();
        assert_eq!(page.creation.as_ref().unwrap().issuer_id.unwrap().get(), 7);
        assert_eq!(page.sources[0].address.unwrap().to_string(), "2001:db8::1");
        assert!(page.best_effort && page.collection_enabled);
        assert_eq!(page.source_cap, 32);
        assert!(page.overflow_since.is_some());
        let debug = format!("{page:?}");
        assert!(!debug.contains("192.0.2.1") && !debug.contains("2001:db8::1"));
        assert!(!debug.contains(page.session_id.as_ref().unwrap()));
        let next = page.next_page_options().unwrap().unwrap();
        push_handle(&$transport, $surface);
        push(&$transport, &activity(1, None));
        let last = read_activity!($client, $finish, $surface, next).unwrap();
        assert!(last.next_page_options().unwrap().is_none());
        let requests = $transport.requests();
        let requests: Vec<_> = requests
            .iter()
            .filter(|r| r.url.path().ends_with("/activity"))
            .collect();
        assert_eq!(requests.len(), 2);
        for (offset, request) in requests.iter().enumerate() {
            assert_eq!(request.method, Method::GET);
            assert_eq!(
                request.url.path(),
                "/prefix/api/v1/iam/principals/42/tokens/9/activity"
            );
            assert_eq!(
                request.url.query().unwrap(),
                format!("offset={offset}&limit=1")
            );
            assert_eq!(request.headers["authorization"], "Bearer private-token");
            assert!(!request.headers.contains_key("if-match"));
            assert!(request.body().is_empty());
        }
    }};
}

#[rstest]
#[case("principal")]
#[case("user")]
#[case("service")]
fn blocking_activity_pagination(#[case] surface: &str) {
    let transport = MockTransport::default();
    let client =
        blocking::Client::builder("https://example.test/prefix/".parse::<BaseUrl>().unwrap())
            .with_transport(Arc::new(transport.clone()))
            .build()
            .unwrap()
            .authenticate(Token::new("private-token"));
    pagination_scenario!(client, transport, surface, sync_finish);
}

#[rstest]
#[case("principal")]
#[case("user")]
#[case("service")]
#[tokio::test]
async fn async_activity_pagination(#[case] surface: &str) {
    let transport = MockTransport::default();
    let client = Client::builder("https://example.test/prefix/".parse::<BaseUrl>().unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("private-token"));
    pagination_scenario!(client, transport, surface, async_finish);
}

#[rstest]
#[case(StatusCode::FORBIDDEN)]
#[case(StatusCode::NOT_FOUND)]
#[tokio::test]
async fn activity_preserves_management_errors_in_both_modes(#[case] status: StatusCode) {
    let transport = MockTransport::default();
    let body = json!({"error":"NotFound", "message":"not visible", "reason":"not_visible"});
    transport.push_response(TransportResponse::json(status, &body).unwrap());
    transport.push_response(TransportResponse::json(status, &body).unwrap());
    let client = Client::builder("https://example.test".parse().unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("token"));
    let error = client
        .token_activity(42, 9, Default::default())
        .await
        .unwrap_err();
    assert!(error.is_status(status));
    let blocking_transport = transport.clone();
    std::thread::spawn(move || {
        let client = blocking::Client::builder("https://example.test".parse().unwrap())
            .with_transport(Arc::new(blocking_transport))
            .build()
            .unwrap()
            .authenticate(Token::new("token"));
        assert!(
            client
                .token_activity(42, 9, Default::default())
                .unwrap_err()
                .is_status(status)
        );
    })
    .join()
    .unwrap();
    assert_eq!(transport.requests().len(), 2);
}

#[test]
fn activity_preserves_unknown_provenance_and_incomplete_coverage() {
    let mut body = activity(0, None);
    body["creation"] = Value::Null;
    body["session_id"] = Value::Null;
    body["collection_enabled"] = json!(false);
    body["sources"][0]["address"] = Value::Null;
    body["sources"][0]["address_method"] = json!("future_method");
    let page: CredentialActivityResponse = serde_json::from_value(body).unwrap();
    assert!(page.creation.is_none() && page.session_id.is_none());
    assert!(page.sources[0].address.is_none());
    assert_eq!(page.sources[0].address_method, "future_method");
    assert!(!page.collection_enabled && page.best_effort && page.overflow_since.is_some());
}

#[rstest]
#[case(0, Some(0), 1)]
#[case(2, Some(1), 1)]
#[case(0, Some(257), 1)]
#[case(0, Some(1), 0)]
#[case(0, Some(1), 101)]
fn activity_rejects_invalid_continuations(
    #[case] offset: usize,
    #[case] next: Option<usize>,
    #[case] limit: usize,
) {
    let mut body = activity(offset, next);
    body["limit"] = json!(limit);
    let page: CredentialActivityResponse = serde_json::from_value(body).unwrap();
    assert!(page.next_page_options().is_err());
}

#[rstest]
#[case(0, 1, true)]
#[case(256, 100, true)]
#[case(257, 50, false)]
#[case(0, 0, false)]
#[case(0, 101, false)]
fn activity_validates_page_options(
    #[case] offset: usize,
    #[case] limit: usize,
    #[case] valid: bool,
) {
    let result = CredentialActivityPageOptions::default()
        .offset(offset)
        .and_then(|p| p.limit(limit));
    assert_eq!(result.is_ok(), valid);
}

fn authentication_settings() -> Value {
    json!({"session_access_seconds": 900, "session_idle_seconds": 604800,
        "session_absolute_seconds": 2592000, "session_retention_seconds": 3456000})
}

macro_rules! config_scenario {
    ($client:ident, $transport:ident, $finish:ident, $modern:ident) => {{
        let mut public = json!({"pagination":{"default_page_limit":50,"max_page_limit":100},
            "authentication":{"default_token_lifetime_hours":24,"max_token_lifetime_hours":8760}});
        let mut admin = crate::running_config_json();
        if $modern {
            public["authentication"].as_object_mut().unwrap().extend(authentication_settings().as_object().unwrap().clone());
            admin["authentication"].as_object_mut().unwrap().extend(authentication_settings().as_object().unwrap().clone());
            admin["authentication"]["credential_activity_enabled"] = json!(false);
            admin["authentication"]["credential_activity_retention_days"] = json!(14);
            admin["authentication"]["credential_activity_source_cap"] = json!(64);
        }
        push(&$transport, &public);
        push(&$transport, &admin);
        let public = $finish!($client.config()).unwrap().authentication;
        let admin = $finish!($client.authenticate(Token::new("token")).admin_config()).unwrap().authentication;
        for actual in [public.session_access_seconds, admin.session_access_seconds] { assert_eq!(actual, $modern.then_some(900)); }
        for actual in [public.session_idle_seconds, admin.session_idle_seconds] { assert_eq!(actual, $modern.then_some(604800)); }
        for actual in [public.session_absolute_seconds, admin.session_absolute_seconds] { assert_eq!(actual, $modern.then_some(2592000)); }
        for actual in [public.session_retention_seconds, admin.session_retention_seconds] { assert_eq!(actual, $modern.then_some(3456000)); }
        assert_eq!(admin.credential_activity_enabled, $modern.then_some(false));
        assert_eq!(admin.credential_activity_retention_days, $modern.then_some(14));
        assert_eq!(admin.credential_activity_source_cap, $modern.then_some(64));
    }};
}

#[rstest]
#[case(true)]
#[case(false)]
fn blocking_activity_and_session_config(#[case] modern: bool) {
    let transport = MockTransport::default();
    let client = blocking::Client::builder("https://example.test".parse().unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap();
    config_scenario!(client, transport, sync_finish, modern);
}

#[rstest]
#[case(true)]
#[case(false)]
#[tokio::test]
async fn async_activity_and_session_config(#[case] modern: bool) {
    let transport = MockTransport::default();
    let client = Client::builder("https://example.test".parse().unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap();
    config_scenario!(client, transport, async_finish, modern);
}
