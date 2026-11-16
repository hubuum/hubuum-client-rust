use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use hubuum_client::{
    ApiError, AuthenticationInteractionRequest, AuthenticationProviderId, BaseUrl, Client,
    MockTransport, RetryPolicy, SessionClientId, SessionStore, SessionStoreGuard, StoredSession,
    TransportResponse, blocking,
};
use reqwest::{StatusCode, header::HeaderValue};
use serde_json::{Value, json};

const ID: &str = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa";

#[derive(Debug)]
struct FailingStore;
impl SessionStore for FailingStore {
    fn lock(&self) -> Result<Box<dyn SessionStoreGuard>, ApiError> {
        Ok(Box::new(FailingStore))
    }
}
impl SessionStoreGuard for FailingStore {
    fn load(&self) -> Result<Option<StoredSession>, ApiError> {
        Ok(None)
    }
    fn save(&mut self, session: Option<&StoredSession>) -> Result<(), ApiError> {
        if session.is_some() {
            Err(std::io::Error::other("fixture store could not persist the session").into())
        } else {
            Ok(())
        }
    }
}

fn secret() -> String {
    format!("hai1.{}", "a".repeat(64))
}

fn begun() -> Value {
    json!({"id": ID, "interaction_version": 1, "redemption_secret": secret(),
        "expires_at": Utc::now() + chrono::Duration::minutes(5), "interval_seconds": 1,
        "next": {"kind": "credentials"}})
}

fn push(transport: &MockTransport, status: StatusCode, body: Value) {
    transport.push_response(TransportResponse::json(status, &body).unwrap());
}

macro_rules! scenario {
    ($client:ident, $transport:ident, $finish:ident, $pause:ident, $case:expr) => {{
        if $case.starts_with("discovery") {
            let status = match $case { "discovery_404" => StatusCode::NOT_FOUND, "discovery_503" => StatusCode::SERVICE_UNAVAILABLE, _ => StatusCode::OK };
            push(&$transport, status, json!({"interaction_version":1,"methods":[{"provider_id":"local","name":"Local","kind":"local","interaction":"credentials","fresh_authentication":true,"browser_available":true}]}));
            let result = $finish!($client.authentication_methods());
            if status.is_success() {
                assert_eq!(result.unwrap().methods[0].provider_id, AuthenticationProviderId::local());
            } else {
                assert!(result.is_err());
            }
            let requests = $transport.requests();
            assert_eq!(requests.len(),1);
            assert_eq!(requests[0].url.path(),"/api/v1/auth/methods");
            assert!(!requests[0].headers.contains_key("Authorization"));
            return;
        }
        let mut begin = begun();
        match $case {
            "browser_password" => begin["next"] = json!({"kind":"browser", "verification_uri":"https://example.invalid/verify", "user_code":"public-code"}),
            "expired" => begin["expires_at"] = json!(Utc::now() - chrono::Duration::seconds(1)),
            "foreign_browser" => begin["next"] = json!({"kind":"browser", "verification_uri":"https://foreign.invalid/verify", "user_code":"public-code"}),
            "invalid_proof" => begin["redemption_secret"] = json!("not-a-capability"),
            "unsupported_version" => begin["interaction_version"] = json!(2),
            _ => (),
        }
        push(&$transport, StatusCode::OK, begin.clone());
        let result = $finish!($client.begin_login_interaction(AuthenticationInteractionRequest::new(
            SessionClientId::new("sdk-fixture").unwrap(), AuthenticationProviderId::local(),
        )));
        if ["expired", "foreign_browser", "invalid_proof", "unsupported_version"].contains(&$case) {
            assert!(result.is_err());
            assert_eq!($transport.requests().len(), 1);
        } else {
            let mut flow = result.unwrap();
            assert!(!format!("{flow:?}").contains(&secret()));
            assert_eq!(flow.id().as_str(), ID);
            match $case {
                "browser_password" => {
                    assert!(matches!($finish!(flow.submit_credentials("user", "not-sent")), Err(ApiError::InvalidAuthenticationInteraction)));
                    assert_eq!($transport.requests().len(),1);
                }
                "denied_poll" => {
                    $pause!();
                    push(&$transport,StatusCode::FORBIDDEN,json!({"error":"Forbidden","message":"Denied","reason":"access_denied"}));
                    assert_eq!($finish!(flow.poll()).unwrap_err().api_response().unwrap().reason.as_deref(),Some("access_denied"));
                    assert!(matches!($finish!(flow.poll()),Err(ApiError::AuthenticationInteractionTerminated)));
                    assert_eq!($transport.requests().len(),2);
                }
                "early_poll" => {
                    assert!(matches!($finish!(flow.poll()), Err(ApiError::AuthenticationPollingTooEarly)));
                    assert_eq!($transport.requests().len(), 1);
                }
                "slow_down" => {
                    $pause!();
                    let mut response = TransportResponse::json(StatusCode::TOO_MANY_REQUESTS,
                        &json!({"error":"TooManyRequests", "message":"Wait", "reason":"slow_down"})).unwrap();
                    response.headers.insert("retry-after", HeaderValue::from_static("17"));
                    $transport.push_response(response);
                    let error = $finish!(flow.poll()).unwrap_err();
                    assert_eq!(error.api_response().unwrap().reason.as_deref(), Some("slow_down"));
                    assert!(flow.poll_after() > Duration::from_secs(16));
                    assert_eq!($transport.requests().len(), 2);
                }
                "password_no_retry" => {
                    let password = format!("fixture-{:032x}", fastrand::u128(..));
                    push(&$transport, StatusCode::SERVICE_UNAVAILABLE, json!({"error":"Unavailable", "message":"Unavailable"}));
                    assert!($finish!(flow.submit_credentials("user", password.clone())).is_err());
                    let requests = $transport.requests();
                    assert_eq!(requests.len(), 2);
                    assert_eq!(serde_json::from_slice::<Value>(requests[1].body()).unwrap()["password"], password);
                    assert!(!format!("{:?}", requests[1]).contains(&password));
                }
                "completion_no_retry" => {
                    let cleanup = flow.issued_session_cleanup();
                    push(&$transport, StatusCode::SERVICE_UNAVAILABLE, json!({"error":"Unavailable", "message":"Unknown completion outcome"}));
                    assert!($finish!(flow.complete()).is_err());
                    assert_eq!($transport.requests().iter().filter(|request|request.url.path().ends_with("/complete")).count(),1);
                    assert!($transport.requests().last().unwrap().url.path().ends_with("/issued-session/revoke"));
                    $transport.push_response(TransportResponse::empty(StatusCode::NO_CONTENT));
                    $transport.push_response(TransportResponse::empty(StatusCode::NO_CONTENT));
                    $finish!(cleanup.revoke()).unwrap();
                    assert!($transport.requests().last().unwrap().url.path().ends_with("/issued-session/revoke"));
                }
                "cleanup_pending" | "cleanup_uncertain" => {
                    let cleanup=flow.issued_session_cleanup();
                    if $case=="cleanup_pending" {
                        $transport.push_response(TransportResponse::empty(StatusCode::NO_CONTENT));
                    } else {
                        push(&$transport,StatusCode::SERVICE_UNAVAILABLE,json!({"error":"Unavailable","message":"Cancellation outcome unknown"}));
                    }
                    push(&$transport,StatusCode::CONFLICT,json!({"error":"Conflict","message":"No issued session","reason":"interaction_pending"}));
                    let result=$finish!(cleanup.revoke());
                    assert_eq!(result.is_ok(),$case=="cleanup_pending");
                    let requests=$transport.requests();
                    assert!(requests[1].url.path().ends_with("/cancel"));
                    assert!(requests[2].url.path().ends_with("/issued-session/revoke"));
                }
                "invalid_session" => {
                    push(&$transport, StatusCode::OK, json!({"access_token":"incomplete-session"}));
                    assert!(matches!($finish!(flow.complete()), Err(ApiError::InvalidSessionResponse)));
                }
                "session" | "storage_failure" => {
                    push(&$transport, StatusCode::OK, json!({"id":ID,"state":"ready","expires_at":begin["expires_at"]}));
                    $finish!(flow.submit_credentials("user", format!("fixture-{:032x}", fastrand::u128(..)))).unwrap();
                    let now = Utc::now();
                    push(&$transport, StatusCode::OK, json!({"session_id": ID, "token_type":"Bearer",
                        "access_token":"access-value", "refresh_token":"refresh-value",
                        "access_expires_at":now+chrono::Duration::minutes(15),
                        "refresh_expires_at":now+chrono::Duration::days(7),
                        "absolute_expires_at":now+chrono::Duration::days(30)}));
                    if $case=="storage_failure" {
                        $transport.push_response(TransportResponse::empty(StatusCode::NO_CONTENT));
                        $transport.push_response(TransportResponse::empty(StatusCode::NO_CONTENT));
                        assert!(matches!($finish!(flow.complete_with_store(Arc::new(FailingStore))),Err(ApiError::Io(_))));
                        assert!($transport.requests().last().unwrap().url.path().ends_with("/issued-session/revoke"));
                    } else {
                        let client = $finish!(flow.complete()).unwrap();
                        assert_eq!(client.session_info().unwrap().id(), ID);
                        assert_eq!(client.token().unwrap().as_str(), "access-value");
                        assert!(!format!("{client:?}").contains("refresh-value"));
                    }
                }
                "cancel" => {
                    $transport.push_response(TransportResponse::empty(StatusCode::NO_CONTENT));
                    $finish!(flow.cancel()).unwrap();
                    assert!($transport.requests().last().unwrap().url.path().ends_with("/cancel"));
                }
                _ => panic!("unknown scenario"),
            }
            for request in $transport.requests().iter().skip(1) {
                assert_eq!(request.url.origin().ascii_serialization(), "https://example.invalid");
                assert!(request.url.query().is_none());
                assert_eq!(request.headers["Authorization"], format!("Hubuum-Interaction {}", secret()));
                assert!(request.headers["Authorization"].is_sensitive());
                assert_eq!(serde_json::from_slice::<Value>(request.body()).unwrap()["client_id"], "sdk-fixture");
                assert!(!format!("{request:?}").contains(&secret()));
            }
        }
        let requests = $transport.requests();
        assert_eq!(requests[0].url.path(), "/api/v1/auth/interactions");
        assert!(!requests[0].headers.contains_key("Authorization"));
        assert_eq!(serde_json::from_slice::<Value>(requests[0].body()).unwrap()["purpose"], "login");
    }};
}

#[rstest::rstest]
#[case("discovery")]
#[case("discovery_404")]
#[case("discovery_503")]
#[case("expired")]
#[case("foreign_browser")]
#[case("invalid_proof")]
#[case("unsupported_version")]
#[case("early_poll")]
#[case("slow_down")]
#[case("password_no_retry")]
#[case("completion_no_retry")]
#[case("invalid_session")]
#[case("session")]
#[case("cancel")]
#[case("browser_password")]
#[case("denied_poll")]
#[case("storage_failure")]
#[case("cleanup_pending")]
#[case("cleanup_uncertain")]
fn blocking_interaction_protocol(#[case] case: &str) {
    macro_rules! finish {
        ($request:expr) => {
            $request
        };
    }
    macro_rules! pause {
        () => {
            std::thread::sleep(Duration::from_millis(1100))
        };
    }
    let transport = MockTransport::default();
    let client = blocking::Client::builder(BaseUrl::new("https://example.invalid").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .retry_policy(RetryPolicy::default())
        .build()
        .unwrap();
    scenario!(client, transport, finish, pause, case);
}

#[rstest::rstest]
#[case("discovery")]
#[case("discovery_404")]
#[case("discovery_503")]
#[case("expired")]
#[case("foreign_browser")]
#[case("invalid_proof")]
#[case("unsupported_version")]
#[case("early_poll")]
#[case("slow_down")]
#[case("password_no_retry")]
#[case("completion_no_retry")]
#[case("invalid_session")]
#[case("session")]
#[case("cancel")]
#[case("browser_password")]
#[case("denied_poll")]
#[case("storage_failure")]
#[case("cleanup_pending")]
#[case("cleanup_uncertain")]
#[tokio::test]
async fn async_interaction_protocol(#[case] case: &str) {
    macro_rules! finish {
        ($request:expr) => {
            $request.await
        };
    }
    macro_rules! pause {
        () => {
            tokio::time::sleep(Duration::from_millis(1100)).await
        };
    }
    let transport = MockTransport::default();
    let client = Client::builder(BaseUrl::new("https://example.invalid").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .retry_policy(RetryPolicy::default())
        .build()
        .unwrap();
    scenario!(client, transport, finish, pause, case);
}

macro_rules! http_boundary {
    ($module:ident, $finish:ident, $timeout:expr) => {{
        use httpmock::prelude::*;
        let server=MockServer::start();
        let outside=MockServer::start();
        let escaped=outside.mock(|when,then| {when.any_request();then.status(200);});
        server.mock(|when,then| {when.method(POST).path("/api/v1/auth/interactions");then.status(201).json_body(begun());});
        let attempt=server.mock(|when,then| {
            when.method(POST).path(format!("/api/v1/auth/interactions/{ID}/credentials"))
                .header("authorization",format!("Hubuum-Interaction {}",secret()));
            if $timeout {then.status(200).delay(Duration::from_millis(750));}
            else {then.status(307).header("location",outside.url("/escape"));}
        });
        let client=$module::Client::builder(BaseUrl::new(server.base_url()).unwrap())
            .timeout(Duration::from_millis(100)).build().unwrap();
        let mut flow=$finish!(client.begin_login_interaction(AuthenticationInteractionRequest::new(
            SessionClientId::default(),AuthenticationProviderId::local()))).unwrap();
        let error=$finish!(flow.submit_credentials("user",format!("fixture-{:032x}",fastrand::u128(..)))).unwrap_err();
        if $timeout {assert!(matches!(error,ApiError::Http(ref error) if error.is_timeout()));}
        else {assert_eq!(error.status(),Some(StatusCode::TEMPORARY_REDIRECT));}
        attempt.assert_calls(1);
        escaped.assert_calls(0);
    }};
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn blocking_interaction_http_boundary(#[case] timeout: bool) {
    macro_rules! finish {
        ($request:expr) => {
            $request
        };
    }
    http_boundary!(blocking, finish, timeout);
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
#[tokio::test]
async fn async_interaction_http_boundary(#[case] timeout: bool) {
    macro_rules! finish {
        ($request:expr) => {
            $request.await
        };
    }
    http_boundary!(hubuum_client, finish, timeout);
}
