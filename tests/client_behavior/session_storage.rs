use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use chrono::Utc;
use hubuum_client::{
    ApiError, Client, Credentials, MockTransport, SessionClientId, SessionStore, SessionStoreGuard,
    StoredSession, TransportResponse, blocking,
};
use reqwest::{Method, StatusCode};
use rstest::rstest;
use serde_json::{Value, json};
use tokio::sync::{Mutex, OwnedMutexGuard};

#[derive(Default, Debug)]
struct Store {
    state: Arc<Mutex<State>>,
    fail_save: Arc<AtomicBool>,
}

#[derive(Default, Debug)]
struct State {
    value: Option<StoredSession>,
    writes: Vec<bool>,
}

impl Store {
    fn value(&self) -> Option<Value> {
        self.state
            .try_lock()
            .unwrap()
            .value
            .as_ref()
            .map(|s| serde_json::to_value(s).unwrap())
    }
    fn writes(&self) -> Vec<bool> {
        self.state.try_lock().unwrap().writes.clone()
    }
    fn expire_access(&self) {
        let mut state = self.state.try_lock().unwrap();
        let mut value = serde_json::to_value(state.value.as_ref().unwrap()).unwrap();
        value["refresh_at"] = json!(Utc::now() - chrono::Duration::seconds(1));
        value["pair"]["access_expires_at"] = value["refresh_at"].clone();
        state.value = Some(serde_json::from_value(value).unwrap());
    }
}

struct Guard {
    state: OwnedMutexGuard<State>,
    fail_save: Arc<AtomicBool>,
}
impl SessionStore for Store {
    fn lock(&self) -> Result<Box<dyn SessionStoreGuard>, ApiError> {
        Ok(Box::new(Guard {
            state: self.state.clone().blocking_lock_owned(),
            fail_save: self.fail_save.clone(),
        }))
    }
}
impl SessionStoreGuard for Guard {
    fn load(&self) -> Result<Option<StoredSession>, ApiError> {
        // Exercise the public serialization contract on every load.
        Ok(self
            .state
            .value
            .as_ref()
            .map(|s| serde_json::from_slice(&serde_json::to_vec(s).unwrap()).unwrap()))
    }
    fn save(&mut self, session: Option<&StoredSession>) -> Result<(), ApiError> {
        if session.is_some() && self.fail_save.load(Ordering::Acquire) {
            return Err(std::io::Error::other("fixture persistence failure").into());
        }
        self.state.writes.push(session.is_some());
        self.state.value = session.cloned();
        Ok(())
    }
}

fn pair() -> Value {
    let now = Utc::now();
    json!({
        "session_id": "session-family", "token_type": "Bearer",
        "access_token": "first-access", "refresh_token": "first-refresh",
        "access_expires_at": now + chrono::Duration::minutes(15),
        "refresh_expires_at": now + chrono::Duration::days(7),
        "absolute_expires_at": now + chrono::Duration::days(30),
    })
}
fn successor(pair: &Value) -> Value {
    let mut next = pair.clone();
    next["access_token"] = json!("next-access");
    next["refresh_token"] = json!("next-refresh");
    next
}
fn push(transport: &MockTransport, status: StatusCode, value: Value) {
    transport.push_response(TransportResponse::json(status, &value).unwrap());
}
macro_rules! sync_finish {
    ($expr:expr) => {
        $expr
    };
}
macro_rules! async_finish {
    ($expr:expr) => {
        $expr.await
    };
}

macro_rules! scenario {
    ($client:ident, $transport:ident, $finish:ident, $case:expr) => {{
        let store = Arc::new(Store::default());
        let id = SessionClientId::new("persistent-test").unwrap();
        assert!($finish!($client.resume_session(id.clone(), store.clone())).unwrap().is_none());
        let initial = pair();
        push(&$transport, StatusCode::OK, initial.clone());
        let password = format!("fixture-{:032x}", fastrand::u128(..));
        let original = $finish!($client.login_session_with_store(Credentials::new("alice", password.clone()), id.clone(), store.clone())).unwrap();
        let saved = store.value().unwrap();
        assert!(!saved.to_string().contains(&password));
        let debug = format!("{:?}", serde_json::from_value::<StoredSession>(saved.clone()).unwrap());
        assert!(!debug.contains("first-access") && !debug.contains("first-refresh"));
        assert_eq!(saved["base_url"], "https://example.invalid/");
        assert_eq!(saved["client_id"], "persistent-test");
        // Recreate the client from disk, with no password or live original client.
        drop(original);
        if $case == "revoked" {
            push(&$transport, StatusCode::UNAUTHORIZED, json!({}));
            assert!($finish!($client.resume_session(id.clone(), store.clone())).unwrap_err().is_status(StatusCode::UNAUTHORIZED));
            assert!(store.value().is_none());
        } else {
            push(&$transport, StatusCode::OK, json!({}));
            let resumed = $finish!($client.resume_session(id.clone(), store.clone())).unwrap().unwrap();
            assert_eq!(resumed.token().unwrap().as_str(), "first-access");
            if $case == "logout" {
                $transport.push_response(TransportResponse::empty(StatusCode::NO_CONTENT));
                $finish!(resumed.logout()).unwrap();
                assert!(store.value().is_none());
            } else if $case == "binding" {
                let other = SessionClientId::new("different-client").unwrap();
                assert!(matches!($finish!($client.resume_session(other, store.clone())), Err(ApiError::InvalidSessionResponse)));
                assert_eq!($transport.requests().len(), 2);
                assert!(store.value().is_some());
            } else {
                store.expire_access();
                match $case {
                    "rejected" => push(&$transport, StatusCode::UNAUTHORIZED, json!({"message":"first-refresh"})),
                    "invalid" => push(&$transport, StatusCode::OK, json!({"access_token":"secret"})),
                    "transport" => (),
                    "persistence" => {
                        store.fail_save.store(true, Ordering::Release);
                        push(&$transport, StatusCode::OK, successor(&initial));
                    },
                    _ => {
                        push(&$transport, StatusCode::OK, successor(&initial));
                        push(&$transport, StatusCode::OK, json!({"ok":true}));
                    }
                }
                let result = $finish!(resumed.raw(Method::GET, "/api/v1/iam/me").send::<Value>());
                if $case == "rotate" {
                    assert_eq!(result.unwrap(), json!({"ok":true}));
                    assert_eq!(store.value().unwrap()["pair"]["refresh_token"], "next-refresh");
                    assert_eq!(store.writes(), [true, false, true]);
                    // Another restart uses the successor without repeating the refresh.
                    push(&$transport, StatusCode::OK, json!({}));
                    let restarted = $finish!($client.resume_session(id, store.clone())).unwrap().unwrap();
                    assert_eq!(restarted.token().unwrap().as_str(), "next-access");
                } else {
                    let error = result.unwrap_err();
                    assert!(!format!("{error:?} {error}").contains("first-refresh"));
                    assert!(store.value().is_none());
                    let before = $transport.requests().len();
                    assert!($finish!($client.resume_session(id, store.clone())).unwrap().is_none());
                    assert_eq!($transport.requests().len(), before);
                }
            }
        }
        let requests = $transport.requests();
        assert_eq!(requests[0].url.path(), "/api/v1/auth/login");
        assert_eq!(requests[1].url.path(), "/api/v1/auth/validate");
        assert_eq!(requests.iter().filter(|r| r.url.path().ends_with("/refresh")).count(), usize::from(!["revoked", "logout", "binding"].contains(&$case)));
    }};
}

#[rstest]
#[case("rotate")]
#[case("revoked")]
#[case("logout")]
#[case("binding")]
#[case("rejected")]
#[case("invalid")]
#[case("transport")]
#[case("persistence")]
fn blocking_persistent_sessions(#[case] case: &str) {
    let transport = MockTransport::default();
    let client = blocking::Client::builder_from_url("https://example.invalid")
        .unwrap()
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap();
    scenario!(client, transport, sync_finish, case);
}

#[rstest]
#[case("rotate")]
#[case("revoked")]
#[case("logout")]
#[case("binding")]
#[case("rejected")]
#[case("invalid")]
#[case("transport")]
#[case("persistence")]
#[tokio::test]
async fn async_persistent_sessions(#[case] case: &str) {
    let transport = MockTransport::default();
    let client = Client::builder_from_url("https://example.invalid")
        .unwrap()
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap();
    scenario!(client, transport, async_finish, case);
}

#[tokio::test]
async fn independently_resumed_clients_coordinate_refresh_on_one_runtime_thread() {
    let store = Arc::new(Store::default());
    let transport = MockTransport::default();
    let client = Client::builder_from_url("https://example.invalid")
        .unwrap()
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap();
    let initial = pair();
    push(&transport, StatusCode::OK, initial.clone());
    let first = client
        .login_session_with_store(
            Credentials::new("alice", format!("fixture-{:032x}", fastrand::u128(..))),
            SessionClientId::default(),
            store.clone(),
        )
        .await
        .unwrap();
    push(&transport, StatusCode::OK, json!({}));
    let second = client
        .resume_session(SessionClientId::default(), store.clone())
        .await
        .unwrap()
        .unwrap();
    store.expire_access();
    push(&transport, StatusCode::OK, successor(&initial));
    push(&transport, StatusCode::OK, json!({}));
    push(&transport, StatusCode::OK, json!({}));
    let one = first.raw(Method::GET, "/api/v1/iam/me");
    let two = second.raw(Method::GET, "/api/v1/iam/me");
    let (one, two) = tokio::join!(one.send::<Value>(), two.send::<Value>());
    one.unwrap();
    two.unwrap();
    assert_eq!(
        transport
            .requests()
            .iter()
            .filter(|r| r.url.path().ends_with("/refresh"))
            .count(),
        1
    );
    assert_eq!(store.writes(), [true, false, true]);
}
