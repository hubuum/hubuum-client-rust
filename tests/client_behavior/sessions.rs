use std::{sync::Arc, time::Duration};

use chrono::Utc;
use hubuum_client::{
    ApiError, BaseUrl, Client, Credentials, MockTransport, SessionClientId, TransportResponse,
    blocking,
};
use reqwest::{Method, StatusCode};
use rstest::rstest;
use serde_json::{Value, json};

fn pair() -> Value {
    let now = Utc::now();
    json!({
        "session_id": "86f53d97-1135-45c9-a940-f2d36eac2df7", "token_type": "Bearer",
        "access_token": "first-access", "refresh_token": "first-refresh",
        "access_expires_at": now + chrono::Duration::seconds(1),
        "refresh_expires_at": now + chrono::Duration::days(7),
        "absolute_expires_at": now + chrono::Duration::days(30),
    })
}

fn successor(initial: &Value) -> Value {
    let mut pair = initial.clone();
    pair["access_token"] = json!("next-access");
    pair["refresh_token"] = json!("next-refresh");
    pair["access_expires_at"] = json!(Utc::now() + chrono::Duration::minutes(15));
    pair
}

fn push(transport: &MockTransport, status: StatusCode, body: Value) {
    transport.push_response(TransportResponse::json(status, &body).unwrap());
}

macro_rules! scenario {
    ($client:ident, $transport:ident, $finish:ident, $pause:ident, $case:expr) => {{
        let mut initial = pair();
        if $case == "expired" { initial["refresh_expires_at"] = initial["access_expires_at"].clone(); }
        push(&$transport, StatusCode::OK, initial.clone());
        let client = $finish!($client.login_session(Credentials::new("admin", "password-secret"), SessionClientId::default())).unwrap();
        let clone = client.clone();
        assert!(!format!("{client:?}").contains("first-refresh"));
        assert_eq!(client.session_info().unwrap().id(), initial["session_id"]);
        $pause!();
        let mut next = successor(&initial);
        match $case {
            "rejected" => push(&$transport, StatusCode::UNAUTHORIZED, json!({"message":"first-refresh"})),
            "invalid" => push(&$transport, StatusCode::OK, json!({"access_token":"secret"})),
            "family" => { next["session_id"] = json!("another-family"); push(&$transport, StatusCode::OK, next); }
            "absolute" => { next["absolute_expires_at"] = json!(Utc::now() + chrono::Duration::days(31)); push(&$transport, StatusCode::OK, next); }
            "reused" => { next["refresh_token"] = initial["refresh_token"].clone(); push(&$transport, StatusCode::OK, next); }
            "transport" | "expired" => (),
            _ => { push(&$transport, StatusCode::OK, next); push(&$transport, StatusCode::OK, json!({"ok":true})); }
        }
        let result = $finish!(client.raw(Method::GET, "/api/v1/iam/me").send::<Value>());
        if $case == "rotate" || $case == "logout" {
            assert_eq!(result.unwrap(), json!({"ok":true}));
            assert_eq!(clone.token().unwrap().as_str(), "next-access");
            let requests = $transport.requests();
            assert_eq!(requests[1].url.path(), "/api/v1/auth/refresh");
            assert!(!requests[1].headers.contains_key("Authorization"));
            assert_eq!(serde_json::from_slice::<Value>(requests[1].body()).unwrap(), json!({"client_id":"hubuum-rust", "refresh_token":"first-refresh"}));
            assert_eq!(requests[2].headers["Authorization"], "Bearer next-access");
            if $case == "logout" {
                $transport.push_response(TransportResponse::empty(StatusCode::NO_CONTENT));
                $finish!(client.logout()).unwrap();
                assert!(matches!(clone.token(), Err(ApiError::SessionExpired)));
                assert_eq!($transport.requests().last().unwrap().url.path(), "/api/v1/auth/logout");
            }
        } else {
            let error = result.unwrap_err();
            assert!(matches!(error, ApiError::SessionExpired));
            assert!(!format!("{error:?} {error}").contains("first-refresh"));
            assert!(clone.token().is_err());
            let count = $transport.requests().len();
            assert!(matches!($finish!(clone.raw(Method::GET, "/api/v1/iam/me").send::<Value>()), Err(ApiError::SessionExpired)));
            assert_eq!($transport.requests().len(), count);
            assert_eq!(count, if $case == "expired" { 1 } else { 2 });
        }
        let requests = $transport.requests();
        assert_eq!(requests[0].url.path(), "/api/v1/auth/login");
        for request in requests {
            let debug = format!("{request:?}");
            assert!(!debug.contains("first-refresh"));
            assert!(!debug.contains("password-secret"));
        }
    }};
}

#[rstest]
#[case("rotate")]
#[case("logout")]
#[case("rejected")]
#[case("invalid")]
#[case("family")]
#[case("absolute")]
#[case("reused")]
#[case("transport")]
#[case("expired")]
#[tokio::test]
async fn async_sessions(#[case] case: &str) {
    let transport = Arc::new(MockTransport::default());
    let client = Client::builder(BaseUrl::new("https://hubuum.test").unwrap())
        .with_transport(transport.clone())
        .build()
        .unwrap();
    macro_rules! finish {
        ($e:expr) => {
            $e.await
        };
    }
    macro_rules! pause {
        () => {
            tokio::time::sleep(Duration::from_millis(1100)).await
        };
    }
    scenario!(client, transport, finish, pause, case);
}

#[rstest]
#[case("rotate")]
#[case("logout")]
#[case("rejected")]
#[case("invalid")]
#[case("family")]
#[case("absolute")]
#[case("reused")]
#[case("transport")]
#[case("expired")]
fn blocking_sessions(#[case] case: &str) {
    let transport = Arc::new(MockTransport::default());
    let client = blocking::Client::builder(BaseUrl::new("https://hubuum.test").unwrap())
        .with_transport(transport.clone())
        .build()
        .unwrap();
    macro_rules! finish {
        ($e:expr) => {
            $e
        };
    }
    macro_rules! pause {
        () => {
            std::thread::sleep(Duration::from_millis(1100))
        };
    }
    scenario!(client, transport, finish, pause, case);
}

fn queue_concurrent(transport: &MockTransport, initial: &Value) {
    push(transport, StatusCode::OK, successor(initial));
    for _ in 0..20 {
        push(transport, StatusCode::OK, json!({"ok":true}));
    }
}
fn assert_single_rotation(transport: &MockTransport) {
    let requests = transport.requests();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.url.path() == "/api/v1/auth/refresh")
            .count(),
        1
    );
    assert!(
        requests
            .iter()
            .filter(|r| r.method == Method::GET)
            .all(|r| r.headers["Authorization"] == "Bearer next-access")
    );
}

#[tokio::test]
async fn concurrent_async_clones_rotate_once() {
    let transport = Arc::new(MockTransport::default());
    let initial = pair();
    push(&transport, StatusCode::OK, initial.clone());
    let client = Client::builder(BaseUrl::new("https://hubuum.test").unwrap())
        .with_transport(transport.clone())
        .build()
        .unwrap()
        .login_session(
            Credentials::new("admin", "password"),
            SessionClientId::default(),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    queue_concurrent(&transport, &initial);
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let client = client.clone();
        tasks.spawn(async move {
            client
                .raw(Method::GET, "/api/v1/iam/me")
                .send::<Value>()
                .await
                .unwrap()
        });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap(), json!({"ok":true}));
    }
    assert_single_rotation(&transport);
}

#[test]
fn concurrent_blocking_clones_rotate_once() {
    let transport = Arc::new(MockTransport::default());
    let initial = pair();
    push(&transport, StatusCode::OK, initial.clone());
    let client = blocking::Client::builder(BaseUrl::new("https://hubuum.test").unwrap())
        .with_transport(transport.clone())
        .build()
        .unwrap()
        .login_session(
            Credentials::new("admin", "password"),
            SessionClientId::default(),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    queue_concurrent(&transport, &initial);
    std::thread::scope(|scope| {
        for _ in 0..20 {
            let client = client.clone();
            scope.spawn(move || {
                assert_eq!(
                    client
                        .raw(Method::GET, "/api/v1/iam/me")
                        .send::<Value>()
                        .unwrap(),
                    json!({"ok":true})
                );
            });
        }
    });
    assert_single_rotation(&transport);
}

#[derive(Debug)]
struct InterruptedRefresh {
    transport: MockTransport,
    started: tokio::sync::Notify,
    attempts: std::sync::atomic::AtomicUsize,
}

impl hubuum_client::AsyncTransport for InterruptedRefresh {
    fn execute<'a>(
        &'a self,
        request: hubuum_client::RequestPlan,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TransportResponse, ApiError>> + Send + 'a>,
    > {
        Box::pin(async move {
            if request.url.path() == "/api/v1/auth/refresh" {
                self.attempts
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                self.started.notify_one();
                std::future::pending().await
            } else {
                self.transport.execute(request).await
            }
        })
    }
}

#[tokio::test]
async fn cancellation_never_reuses_the_refresh_credential() {
    let transport = Arc::new(InterruptedRefresh {
        transport: MockTransport::default(),
        started: tokio::sync::Notify::new(),
        attempts: std::sync::atomic::AtomicUsize::new(0),
    });
    push(&transport.transport, StatusCode::OK, pair());
    let client = Client::builder(BaseUrl::new("https://hubuum.test").unwrap())
        .with_transport(transport.clone())
        .build()
        .unwrap()
        .login_session(
            Credentials::new("admin", "password"),
            SessionClientId::default(),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let clone = client.clone();
    let request = tokio::spawn(async move {
        clone
            .raw(Method::GET, "/api/v1/iam/me")
            .send::<Value>()
            .await
    });
    transport.started.notified().await;
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert!(matches!(
        client
            .raw(Method::GET, "/api/v1/iam/me")
            .send::<Value>()
            .await,
        Err(ApiError::SessionExpired)
    ));
    assert_eq!(
        transport.attempts.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[rstest]
#[case::migrated(StatusCode::NOT_FOUND)]
#[case::rejected(StatusCode::UNAUTHORIZED)]
#[tokio::test]
async fn async_pat_authentication_falls_back_only_when_the_legacy_route_is_absent(
    #[case] legacy: StatusCode,
) {
    let transport = Arc::new(MockTransport::default());
    push(
        &transport,
        legacy,
        json!({"error":"legacy", "message":"legacy"}),
    );
    push(&transport, StatusCode::OK, json!({"message":"valid"}));
    let client = Client::builder(BaseUrl::try_from("https://example.test").unwrap())
        .with_transport(transport.clone())
        .build()
        .unwrap();
    let result = client
        .login_with_token(hubuum_client::Token::new("pat-secret"))
        .await;
    if legacy == StatusCode::UNAUTHORIZED {
        assert!(result.is_err());
        assert_eq!(transport.requests().len(), 1);
        return;
    }
    let client = result.unwrap();
    push(
        &transport,
        StatusCode::NOT_FOUND,
        json!({"error":"legacy", "message":"legacy"}),
    );
    push(&transport, StatusCode::OK, json!({"message":"revoked"}));
    client.logout().await.unwrap();
    let paths: Vec<_> = transport
        .requests()
        .iter()
        .map(|r| r.url.path().to_owned())
        .collect();
    assert_eq!(
        paths,
        [
            "/api/v0/auth/validate",
            "/api/v1/auth/validate",
            "/api/v0/auth/logout",
            "/api/v1/auth/logout"
        ]
    );
}

#[rstest]
#[case::migrated(StatusCode::NOT_FOUND)]
#[case::rejected(StatusCode::UNAUTHORIZED)]
fn blocking_pat_authentication_falls_back_only_when_the_legacy_route_is_absent(
    #[case] legacy: StatusCode,
) {
    let transport = Arc::new(MockTransport::default());
    push(
        &transport,
        legacy,
        json!({"error":"legacy", "message":"legacy"}),
    );
    push(&transport, StatusCode::OK, json!({"message":"valid"}));
    let client = blocking::Client::builder(BaseUrl::try_from("https://example.test").unwrap())
        .with_transport(transport.clone())
        .build()
        .unwrap();
    let result = client.login_with_token(hubuum_client::Token::new("pat-secret"));
    if legacy == StatusCode::UNAUTHORIZED {
        assert!(result.is_err());
        assert_eq!(transport.requests().len(), 1);
        return;
    }
    let client = result.unwrap();
    push(
        &transport,
        StatusCode::NOT_FOUND,
        json!({"error":"legacy", "message":"legacy"}),
    );
    push(&transport, StatusCode::OK, json!({"message":"revoked"}));
    client.logout().unwrap();
    let paths: Vec<_> = transport
        .requests()
        .iter()
        .map(|r| r.url.path().to_owned())
        .collect();
    assert_eq!(
        paths,
        [
            "/api/v0/auth/validate",
            "/api/v1/auth/validate",
            "/api/v0/auth/logout",
            "/api/v1/auth/logout"
        ]
    );
}

#[rstest]
#[case::asynchronous(true)]
#[case::blocking(false)]
#[tokio::test]
async fn session_login_errors_discard_reflected_secrets(#[case] asynchronous: bool) {
    let transport = Arc::new(MockTransport::default());
    push(
        &transport,
        StatusCode::UNAUTHORIZED,
        json!({"message":"password-secret", "refresh_token":"refresh-secret"}),
    );
    let error = if asynchronous {
        Client::builder(BaseUrl::new("https://hubuum.test").unwrap())
            .with_transport(transport)
            .build()
            .unwrap()
            .login_session(
                Credentials::new("admin", "password-secret"),
                SessionClientId::default(),
            )
            .await
            .unwrap_err()
    } else {
        tokio::task::spawn_blocking(move || {
            blocking::Client::builder(BaseUrl::new("https://hubuum.test").unwrap())
                .with_transport(transport)
                .build()
                .unwrap()
                .login_session(
                    Credentials::new("admin", "password-secret"),
                    SessionClientId::default(),
                )
                .unwrap_err()
        })
        .await
        .unwrap()
    };
    assert!(error.is_status(StatusCode::UNAUTHORIZED));
    assert_eq!(error.response_body(), Some(""));
    assert!(!error.api_message().unwrap().contains("password-secret"));
}
