use std::sync::Arc;

use hubuum_client::{
    ApiError, Authenticated, BaseUrl, Client, CredentialOperation, EntityTag, FullImportGraph,
    FullImportRequest, MockTransport, NewTokenRequest, RenewTokenRequest, RestoreCapability,
    RestoreConfirmRequest, RetryPolicy, Token, TransportResponse, UserPatch, UserPost, blocking,
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};

const EXPIRY: &str = "2026-09-20T12:00:00.123456";

fn approval_secret() -> String {
    format!("hca1.{}", "a".repeat(64))
}

fn approval_response(kind: &str) -> Value {
    json!({
        "approval": approval_secret(),
        "record": {
            "id": 11, "actor_id": 7, "token_id": 18, "operation": kind,
            "target_id": 42, "restore_job_id": null,
            "authenticated_at": "2026-09-19T12:00:00Z",
            "expires_at": "2026-09-19T12:02:00Z",
            "consumed_at": null, "invalidated_at": null
        },
        "token_expires_at": EXPIRY
    })
}

fn push(transport: &MockTransport, status: StatusCode, body: Value) {
    transport.push_response(TransportResponse::json(status, &body).unwrap());
}

fn error_body(reason: Option<&str>) -> Value {
    json!({"error": "Forbidden", "message": "server message", "reason": reason})
}

fn token_request(explicit_expiry: bool) -> NewTokenRequest {
    let request = NewTokenRequest::new()
        .name("new-token")
        .description("approved description");
    if explicit_expiry {
        request.expires_at(serde_json::from_value(json!("2026-09-20T12:00:00.123456789")).unwrap())
    } else {
        request
    }
}

fn assert_wire(transport: &MockTransport, path: &str, operation: Value, body: Value) {
    let requests = transport.requests();
    let approval_index = requests
        .iter()
        .rposition(|request| request.url.path() == "/api/v1/iam/credential-approvals")
        .unwrap();
    let pair = [&requests[approval_index], requests.last().unwrap()];
    assert_eq!(pair[0].method, Method::POST);
    assert_eq!(pair[0].url.path(), "/api/v1/iam/credential-approvals");
    assert_eq!(
        serde_json::from_slice::<Value>(pair[0].body()).unwrap(),
        json!({
            "password": "actor-password", "operation": operation
        })
    );
    assert!(!pair[0].headers.contains_key("X-Hubuum-Credential-Approval"));
    assert_eq!(pair[1].url.path(), path);
    assert_eq!(
        serde_json::from_slice::<Value>(pair[1].body()).unwrap(),
        body
    );
    assert_eq!(
        pair[1].headers["X-Hubuum-Credential-Approval"],
        approval_secret()
    );
    assert!(pair[1].headers["X-Hubuum-Credential-Approval"].is_sensitive());
    for request in pair {
        assert_eq!(request.headers["Authorization"], "Bearer original-bearer");
        let debug = format!("{request:?}");
        for secret in [
            "original-bearer",
            "actor-password",
            "new-password",
            "restore-secret",
            &approval_secret(),
        ] {
            assert!(!debug.contains(secret));
        }
    }
}

// The same public workflows exercise both clients, including real response decoding.
macro_rules! approval_scenarios {
    ($client:ident, $transport:ident, $finish:ident, $scenario:expr) => {{
        match $scenario {
            "create_token" => {
        for explicit in [false, true] {
            let request = token_request(explicit);
            let operation_wire = json!({"kind":"create_token", "principal_id":42, "token":request});
            let mut final_body = serde_json::to_value(&request).unwrap();
            final_body["expires_at"] = json!(EXPIRY);
            push(&$transport, StatusCode::CREATED, approval_response("create_token"));
            push(&$transport, StatusCode::CREATED, json!({"token":"minted-secret", "expires_at":EXPIRY}));
            let operation = CredentialOperation::create_token(42, request);
            let approved = $finish!($client.credential_approvals().approve("actor-password", operation)).unwrap();
            assert_eq!(approved.record().id, 11);
            assert_eq!(approved.token_expires_at().unwrap().0.timestamp_subsec_nanos(), 123456000);
            assert!(!format!("{approved:?}").contains(&approval_secret()));
            let token = $finish!(approved.send()).unwrap();
            assert_eq!(token.as_str(), "minted-secret");
            assert_wire(&$transport, "/api/v1/iam/principals/42/tokens", operation_wire, final_body);
        }
            },
            "renew_token" => {
        for explicit in [false, true] {
            let request = RenewTokenRequest { expires_at: token_request(explicit).expires_at };
            let operation_wire = json!({"kind":"renew_token", "principal_id":42,"token_id":99,"token":request});
            push(&$transport, StatusCode::CREATED, approval_response("renew_token"));
            push(&$transport, StatusCode::CREATED, json!({"token":"renewed-secret", "expires_at":EXPIRY}));
            let approved = $finish!($client.credential_approvals().approve("actor-password",
                CredentialOperation::renew_token(42, 99, request))).unwrap();
            assert_eq!($finish!(approved.send()).unwrap().as_str(), "renewed-secret");
            assert_wire(&$transport, "/api/v1/iam/principals/42/tokens/99/renew", operation_wire, json!({"expires_at":EXPIRY}));
        }

            },
            "create_user" => {
        let user = UserPost { name: "new-user".into(), password: "new-password".into(), ..Default::default() };
        let user_body = serde_json::to_value(&user).unwrap();
        let operation = CredentialOperation::create_user(user);
        assert!(!format!("{operation:?}").contains("new-password"));
        push(&$transport, StatusCode::CREATED, approval_response("create_user"));
        push(&$transport, StatusCode::CONFLICT, error_body(None));
        let approved = $finish!($client.credential_approvals().approve("actor-password", operation)).unwrap();
        assert!($finish!(approved.send()).unwrap_err().is_status(StatusCode::CONFLICT));
        assert_wire(&$transport, "/api/v1/iam/users", json!({"kind":"create_user","user":user_body}), user_body);

            },
            "update_user" => {
        let profile = UserPatch { email: Some("new@example.test".into()), proper_name: None };
        let user_body = json!({"email":"new@example.test", "proper_name":null, "password":"new-password"});
        push(&$transport, StatusCode::CREATED, approval_response("update_user"));
        push(&$transport, StatusCode::PRECONDITION_FAILED, error_body(None));
        let approved = $finish!($client.credential_approvals().approve("actor-password",
            CredentialOperation::update_user(42, profile, "new-password"))).unwrap()
            .if_match(EntityTag::new("\"rev-2\"").unwrap());
        assert!($finish!(approved.send()).unwrap_err().is_status(StatusCode::PRECONDITION_FAILED));
        assert_wire(&$transport, "/api/v1/iam/users/42", json!({"kind":"update_user","user_id":42,"user":user_body}), user_body);
        let last = $transport.requests().pop().unwrap();
        assert_eq!(last.method, Method::PATCH);
        assert_eq!(last.headers["If-Match"], "\"rev-2\"");

            },
            "import_credentials" => {
        let mut graph = FullImportGraph::default();
        for (name, credential) in [("first", json!({"password":"import-password"})), ("second", json!({"password_hash":"import-hash"}))] {
            let mut principal = json!({"name":name, "kind":"human", "provider_managed":false});
            principal.as_object_mut().unwrap().extend(credential.as_object().unwrap().clone());
            graph.principals.push(serde_json::from_value(principal).unwrap());
        }
        let import = FullImportRequest::new(graph).dry_run(true);
        let import_body = serde_json::to_value(&import).unwrap();
        push(&$transport, StatusCode::CREATED, approval_response("import_credentials"));
        push(&$transport, StatusCode::SERVICE_UNAVAILABLE, error_body(None));
        push(&$transport, StatusCode::CONFLICT, error_body(None));
        let approved = $finish!($client.credential_approvals().approve("actor-password",
            CredentialOperation::import_credentials(import))).unwrap().idempotency_key("import-key");
        assert!($finish!(approved.send()).unwrap_err().is_status(StatusCode::CONFLICT));
        assert_wire(&$transport, "/api/v1/imports", json!({"kind":"import_credentials","import":import_body}), import_body);
        assert_eq!($transport.requests().last().unwrap().headers["Idempotency-Key"], "import-key");
        let requests = $transport.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[1].body(), requests[2].body());
        assert_eq!(requests[1].headers, requests[2].headers);

            },
            "confirm_restore" => {
        let confirmation = RestoreConfirmRequest::new(RestoreCapability::new("restore-secret"), "digest");
        let body = serde_json::to_value(&confirmation).unwrap();
        push(&$transport, StatusCode::CREATED, approval_response("confirm_restore"));
        push(&$transport, StatusCode::CONFLICT, error_body(None));
        let approved = $finish!($client.credential_approvals().approve("actor-password",
            CredentialOperation::confirm_restore(73, confirmation))).unwrap();
        assert!($finish!(approved.send()).unwrap_err().is_status(StatusCode::CONFLICT));
        assert_wire(&$transport, "/api/v1/restores/73/confirm", json!({"kind":"confirm_restore","restore_id":73,"confirmation":body}), body);

            },
            "retained_evidence" => {
        let mut record = approval_response("create_token")["record"].clone();
        record["consumed_at"] = json!("2026-09-19T12:00:01Z");
        push(&$transport, StatusCode::OK, record);
        let record = $finish!($client.credential_approvals().get(11)).unwrap();
        assert!(record.consumed_at.is_some());
        let last = $transport.requests().pop().unwrap();
        assert_eq!(last.method, Method::GET);
        assert_eq!(last.url.path(), "/api/v1/iam/credential-approvals/11");
        assert!(!last.headers.contains_key("X-Hubuum-Credential-Approval"));

            },
            "legacy_server" => {
        // Old servers receive exactly the legacy mutation, with no discovery probe.
        push(&$transport, StatusCode::OK, json!({"id":42,"name":"existing-user","created_at":"2026-01-01T00:00:00","updated_at":"2026-01-01T00:00:00","revision":1}));
        let user = $finish!($client.users().get(42)).unwrap();
        let before = $transport.requests().len();
        push(&$transport, StatusCode::CREATED, json!({"token":"legacy-secret"}));
        let token = $finish!(user.tokens_create_token(NewTokenRequest::new())).unwrap();
        assert_eq!(token.as_str(), "legacy-secret");
        assert_eq!($transport.requests().len(), before + 1);
        assert!(!$transport.requests().last().unwrap().headers.contains_key("X-Hubuum-Credential-Approval"));

            },
            "approval_failures" => {
        // Approval failures never fall back to an unapproved mutation or retry the password.
        for status in [StatusCode::NOT_FOUND, StatusCode::UNAUTHORIZED, StatusCode::FORBIDDEN, StatusCode::TOO_MANY_REQUESTS, StatusCode::SERVICE_UNAVAILABLE] {
            let before = $transport.requests().len();
            push(&$transport, status, error_body(None));
            let error = $finish!($client.credential_approvals().approve("actor-password",
                CredentialOperation::create_token(42, NewTokenRequest::new()))).unwrap_err();
            assert!(error.is_status(status));
            assert_eq!($transport.requests().len(), before + 1);
        }
            },
            "mutation_rejection" => {
        // An approved mutation rejection also never retries or drops its approval.
        push(&$transport, StatusCode::CREATED, approval_response("create_token"));
        push(&$transport, StatusCode::FORBIDDEN, error_body(Some("reauthentication_required")));
        let approved = $finish!($client.credential_approvals().approve("actor-password",
            CredentialOperation::create_token(42, NewTokenRequest::new()))).unwrap();
        let before = $transport.requests().len();
        let error = $finish!(approved.send()).unwrap_err();
        assert!(error.is_reauthentication_required());
        assert_eq!($transport.requests().len(), before + 1);

            },
            "malformed_response" => {
        for (secret, expiry) in [(approval_secret(), Value::Null), ("bad\r\nsecret".into(), json!(EXPIRY))] {
            let before = $transport.requests().len();
            let mut response = approval_response("create_token");
            response["approval"] = json!(secret);
            response["token_expires_at"] = expiry;
            push(&$transport, StatusCode::CREATED, response);
            let error = $finish!($client.credential_approvals().approve("actor-password",
                CredentialOperation::create_token(42, NewTokenRequest::new()))).unwrap_err();
            assert!(!format!("{error:?}").contains(&secret));
            assert_eq!($transport.requests().len(), before + 1);
        }
            },
            "invalid_operation" => {
                let operation = CredentialOperation::create_token(42, NewTokenRequest::new().scopes(vec![]));
                let error = $finish!($client.credential_approvals().approve("actor-password", operation)).unwrap_err();
                assert!(matches!(error, ApiError::InvalidTokenScopes));
                assert!($transport.requests().is_empty());
            },
            _ => panic!("unknown approval scenario"),
        }
    }};
}

fn retry_policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: 3,
        initial_delay: std::time::Duration::ZERO,
        max_delay: std::time::Duration::ZERO,
    }
}

#[rstest::rstest]
#[case::create_token("create_token")]
#[case::renew_token("renew_token")]
#[case::create_user("create_user")]
#[case::update_user("update_user")]
#[case::import_credentials("import_credentials")]
#[case::confirm_restore("confirm_restore")]
#[case::retained_evidence("retained_evidence")]
#[case::legacy_server("legacy_server")]
#[case::approval_failures("approval_failures")]
#[case::mutation_rejection("mutation_rejection")]
#[case::malformed_response("malformed_response")]
#[case::invalid_operation("invalid_operation")]
fn blocking_approval_protocol(#[case] scenario: &str) {
    macro_rules! finish {
        ($request:expr) => {
            $request
        };
    }
    let transport = MockTransport::default();
    let client: blocking::Client<Authenticated> =
        blocking::Client::builder(BaseUrl::new("https://example.invalid").unwrap())
            .with_transport(Arc::new(transport.clone()))
            .retry_policy(retry_policy())
            .build()
            .unwrap()
            .authenticate(Token::new("original-bearer"));
    approval_scenarios!(client, transport, finish, scenario);
}

#[rstest::rstest]
#[case::create_token("create_token")]
#[case::renew_token("renew_token")]
#[case::create_user("create_user")]
#[case::update_user("update_user")]
#[case::import_credentials("import_credentials")]
#[case::confirm_restore("confirm_restore")]
#[case::retained_evidence("retained_evidence")]
#[case::legacy_server("legacy_server")]
#[case::approval_failures("approval_failures")]
#[case::mutation_rejection("mutation_rejection")]
#[case::malformed_response("malformed_response")]
#[case::invalid_operation("invalid_operation")]
#[tokio::test]
async fn async_approval_protocol(#[case] scenario: &str) {
    macro_rules! finish {
        ($request:expr) => {
            $request.await
        };
    }
    let transport = MockTransport::default();
    let client = Client::builder(BaseUrl::new("https://example.invalid").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .retry_policy(retry_policy())
        .build()
        .unwrap()
        .authenticate(Token::new("original-bearer"));
    approval_scenarios!(client, transport, finish, scenario);
}

#[rstest::rstest]
#[case(403, Some("reauthentication_required"), true)]
#[case(401, Some("reauthentication_required"), false)]
#[case(403, None, false)]
#[case(403, Some("permission_denied"), false)]
fn detects_only_the_stable_reauthentication_reason(
    #[case] status: u16,
    #[case] reason: Option<&str>,
    #[case] expected: bool,
) {
    let error = ApiError::HttpWithBody {
        method: Method::POST,
        url: "https://example.invalid/api/v1/iam/users".into(),
        status: StatusCode::from_u16(status).unwrap(),
        message: "reauthentication_required".into(),
        body: error_body(reason).to_string(),
    };
    assert_eq!(error.is_reauthentication_required(), expected);
    assert_eq!(error.api_response().unwrap().reason.as_deref(), reason);
}
