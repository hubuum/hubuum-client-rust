//! Consume the pinned server corpus without treating its placeholders as credentials.
//! These are client wire-contract checks; server-owned effects require live tests.
use std::sync::Arc;

use chrono::{DateTime, NaiveDateTime, Utc};
use hubuum_client::{
    ApiErrorResponse, AuthenticationInteractionRequest, AuthenticationInteractionStatus,
    AuthenticationMethods, AuthenticationProviderId, BaseUrl, Client, CredentialApprovalRecord,
    MockTransport, SecurityCandidateActivated, SecurityCandidateReport,
    SecurityCandidateVerification, SessionClientId, TransportResponse, blocking,
};
use reqwest::StatusCode;
use serde_json::Value;

fn materialize(value: &mut Value, offset: chrono::Duration) {
    match value {
        Value::String(text) => {
            *text = match text.as_str() {
                "interaction-fixture" => "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa".into(),
                "bff-interaction-fixture" => "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb".into(),
                "verification-interaction-fixture" => "cccccccc-cccc-4ccc-accc-cccccccccccc".into(),
                "candidate-fixture" => "dddddddd-dddd-4ddd-addd-dddddddddddd".into(),
                "FIXTURE-REDEMPTION-SECRET-NEVER-USE-IN-PRODUCTION" => {
                    format!("hai1.{}", "a".repeat(64))
                }
                "FIXTURE-VERIFICATION-RECEIPT-NEVER-USE-IN-PRODUCTION" => {
                    format!("hcv1.{}", "b".repeat(64))
                }
                _ => {
                    if let Ok(date) = DateTime::parse_from_rfc3339(text) {
                        (date + offset).to_rfc3339()
                    } else if let Ok(date) =
                        NaiveDateTime::parse_from_str(text, "%Y-%m-%dT%H:%M:%S")
                    {
                        (date + offset).format("%Y-%m-%dT%H:%M:%S").to_string()
                    } else {
                        text.clone()
                    }
                }
            };
        }
        Value::Array(values) => values.iter_mut().for_each(|v| materialize(v, offset)),
        Value::Object(fields) => fields.values_mut().for_each(|v| materialize(v, offset)),
        _ => (),
    }
}

fn corpus() -> Value {
    let mut corpus: Value =
        serde_json::from_str(include_str!("../fixtures/authentication/fixtures.json")).unwrap();
    assert_eq!(corpus["cases"].as_array().unwrap().len(), 48);
    let clock = DateTime::parse_from_rfc3339(corpus["clock"].as_str().unwrap()).unwrap();
    materialize(&mut corpus, Utc::now().signed_duration_since(clock));
    corpus
}

fn case<'a>(corpus: &'a Value, id: &str) -> &'a Value {
    corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == id)
        .unwrap()
}

macro_rules! scenario {
    ($client:ident, $transport:ident, $finish:ident, $id:expr) => {{
        let corpus = corpus();
        let fixture = case(&corpus, $id);
        let response = &fixture["response"];
        let status = StatusCode::from_u16(response["status"].as_u64().unwrap() as u16).unwrap();
        let body = response["body"].clone();
        let operation = fixture["operation_id"].as_str().unwrap();
        if status.is_client_error() || status.is_server_error() {
            let expected: ApiErrorResponse = serde_json::from_value(body.clone()).unwrap();
            if operation == "completeInteraction" {
                let begin = case(&corpus, "external_begin");
                $transport.push_response(
                    TransportResponse::json(StatusCode::CREATED, &begin["response"]["body"])
                        .unwrap(),
                );
                let flow = $finish!(
                    $client.begin_login_interaction(AuthenticationInteractionRequest::new(
                        SessionClientId::new("hubuum-cli").unwrap(),
                        AuthenticationProviderId::new(
                            begin["request"]["provider_id"].as_str().unwrap()
                        )
                        .unwrap(),
                    ))
                )
                .unwrap();
                $transport.push_response(TransportResponse::json(status, &body).unwrap());
                let error = $finish!(flow.complete()).unwrap_err();
                assert_eq!(error.status(), Some(status));
                assert_eq!(error.api_response(), Some(expected));
            } else {
                // Callback/admission/activation rejection is a server assertion,
                // not permission to implement those operations in the SDK.
                assert!(!expected.reason.unwrap().is_empty());
            }
        } else {
            match operation {
                "discoverAuthentication" => {
                    $transport.push_response(TransportResponse::json(status, &body).unwrap());
                    let methods: AuthenticationMethods =
                        $finish!($client.authentication_methods()).unwrap();
                    assert_eq!(methods.methods.len(), 3);
                }
                "beginInteraction" if fixture["request"]["purpose"] == "login" => {
                    let request = &fixture["request"];
                    let mut input = AuthenticationInteractionRequest::new(
                        SessionClientId::new(request["client_id"].as_str().unwrap()).unwrap(),
                        AuthenticationProviderId::new(request["provider_id"].as_str().unwrap())
                            .unwrap(),
                    );
                    if request["delivery"] == "bff" {
                        input = input
                            .bff(
                                request["return_target_id"].as_str().unwrap(),
                                request["return_nonce"].as_str().unwrap(),
                            )
                            .unwrap();
                    }
                    $transport.push_response(TransportResponse::json(status, &body).unwrap());
                    let flow = $finish!($client.begin_login_interaction(input)).unwrap();
                    assert_eq!(flow.id().as_str(), body["id"]);
                    let requests = $transport.requests();
                    let sent: Value = serde_json::from_slice(requests[0].body()).unwrap();
                    for (key, value) in request.as_object().unwrap() {
                        assert_eq!(&sent[key], value);
                    }
                    assert!(
                        !format!("{flow:?}").contains(body["redemption_secret"].as_str().unwrap())
                    );
                }
                "interactionStatus" | "continueCredentials" => {
                    let state: AuthenticationInteractionStatus =
                        serde_json::from_value(body.clone()).unwrap();
                    assert_eq!(state.id.as_str(), body["id"]);
                }
                "completeInteraction" if body.get("session_id").is_some() => {
                    let begin_id = if fixture["request"]["client_id"] == "hubuum-frontend" {
                        "bff_begin"
                    } else if $id == "local_success" {
                        "local_begin"
                    } else {
                        "external_begin"
                    };
                    let begin = case(&corpus, begin_id);
                    let mut input = AuthenticationInteractionRequest::new(
                        SessionClientId::new(fixture["request"]["client_id"].as_str().unwrap())
                            .unwrap(),
                        AuthenticationProviderId::new(
                            begin["request"]["provider_id"].as_str().unwrap(),
                        )
                        .unwrap(),
                    );
                    if begin_id == "bff_begin" {
                        input = input.bff("frontend-fixture", "n".repeat(32)).unwrap();
                    }
                    $transport.push_response(
                        TransportResponse::json(StatusCode::CREATED, &begin["response"]["body"])
                            .unwrap(),
                    );
                    let flow = $finish!($client.begin_login_interaction(input)).unwrap();
                    $transport.push_response(TransportResponse::json(status, &body).unwrap());
                    let session = $finish!(flow.complete()).unwrap();
                    assert_eq!(session.session_info().unwrap().id(), body["session_id"]);
                    assert!(
                        !format!("{session:?}").contains(body["refresh_token"].as_str().unwrap())
                    );
                }
                "completeInteraction" if $id == "candidate_browser_verified" => {
                    let verified: SecurityCandidateVerification =
                        serde_json::from_value(body).unwrap();
                    assert!(!verified.verification.issued_session);
                    assert!(!verified.verification.provisioned);
                    verified.candidate.into_activation().unwrap();
                }
                "completeInteraction" if $id == "fresh_approval_success" => {
                    let record: CredentialApprovalRecord =
                        serde_json::from_value(body["record"].clone()).unwrap();
                    assert_eq!(record.operation, "create_token");
                }
                "verifySecurityCandidate" => {
                    let candidate: SecurityCandidateReport = serde_json::from_value(body).unwrap();
                    assert!(candidate.into_activation().is_err());
                }
                "activateSecurityCandidate" => {
                    let activated: SecurityCandidateActivated =
                        serde_json::from_value(body).unwrap();
                    assert!(activated.changed);
                }
                "beginInteraction" if $id == "candidate_verification_begin" => {
                    assert_eq!(body["interaction_version"], 1);
                    assert_eq!(body["next"]["kind"], "browser");
                }
                "cancelInteraction" | "revokeUndeliveredSession" => {
                    assert_eq!(status, StatusCode::NO_CONTENT)
                }
                _ => panic!("unclassified shared vector: {}", $id),
            }
        }
    }};
}

#[rstest::rstest]
#[case("discovery")]
#[case("local_begin")]
#[case("external_begin")]
#[case("bff_begin")]
#[case("status_pending")]
#[case("status_ready")]
#[case("status_consumed")]
#[case("local_credentials")]
#[case("local_success")]
#[case("external_success")]
#[case("remote_browser_cli_success")]
#[case("bff_server_completion")]
#[case("denial")]
#[case("expiry")]
#[case("expiry_reclaimed")]
#[case("replay")]
#[case("cross_client")]
#[case("wrong_secret")]
#[case("cross_provider")]
#[case("wrong_browser")]
#[case("configuration_changed")]
#[case("unsupported_freshness")]
#[case("missing_group_claim")]
#[case("malformed_group_claim")]
#[case("stale_group_data")]
#[case("throttled_poll")]
#[case("subject_mismatch")]
#[case("candidate_revision_conflict")]
#[case("candidate_secret_rotated")]
#[case("candidate_lock_changed")]
#[case("candidate_external_actor")]
#[case("oauth_supplied_profile")]
#[case("cancel")]
#[case("lost_completion_cleanup")]
#[case("candidate_connectivity_only")]
#[case("candidate_verification_begin")]
#[case("candidate_browser_verified")]
#[case("runtime_activation")]
#[case("provider_disabled")]
#[case("complete_empty_groups")]
#[case("missing_optional_groups")]
#[case("local_group_mapping_unsupported")]
#[case("oauth_large_numeric_subject")]
#[case("treetop_runtime_activation")]
#[case("wrong_approval_operation")]
#[case("wrong_originating_credential")]
#[case("recovery_administrator_denied")]
#[case("fresh_approval_success")]
fn blocking_pinned_authentication_corpus(#[case] id: &str) {
    macro_rules! finish {
        ($request:expr) => {
            $request
        };
    }
    let transport = MockTransport::default();
    let client = blocking::Client::builder(BaseUrl::new("https://hubuum.example.invalid").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap();
    scenario!(client, transport, finish, id);
}

#[rstest::rstest]
#[case("discovery")]
#[case("local_begin")]
#[case("external_begin")]
#[case("bff_begin")]
#[case("status_pending")]
#[case("status_ready")]
#[case("status_consumed")]
#[case("local_credentials")]
#[case("local_success")]
#[case("external_success")]
#[case("remote_browser_cli_success")]
#[case("bff_server_completion")]
#[case("denial")]
#[case("expiry")]
#[case("expiry_reclaimed")]
#[case("replay")]
#[case("cross_client")]
#[case("wrong_secret")]
#[case("cross_provider")]
#[case("wrong_browser")]
#[case("configuration_changed")]
#[case("unsupported_freshness")]
#[case("missing_group_claim")]
#[case("malformed_group_claim")]
#[case("stale_group_data")]
#[case("throttled_poll")]
#[case("subject_mismatch")]
#[case("candidate_revision_conflict")]
#[case("candidate_secret_rotated")]
#[case("candidate_lock_changed")]
#[case("candidate_external_actor")]
#[case("oauth_supplied_profile")]
#[case("cancel")]
#[case("lost_completion_cleanup")]
#[case("candidate_connectivity_only")]
#[case("candidate_verification_begin")]
#[case("candidate_browser_verified")]
#[case("runtime_activation")]
#[case("provider_disabled")]
#[case("complete_empty_groups")]
#[case("missing_optional_groups")]
#[case("local_group_mapping_unsupported")]
#[case("oauth_large_numeric_subject")]
#[case("treetop_runtime_activation")]
#[case("wrong_approval_operation")]
#[case("wrong_originating_credential")]
#[case("recovery_administrator_denied")]
#[case("fresh_approval_success")]
#[tokio::test]
async fn async_pinned_authentication_corpus(#[case] id: &str) {
    macro_rules! finish {
        ($request:expr) => {
            $request.await
        };
    }
    let transport = MockTransport::default();
    let client = Client::builder(BaseUrl::new("https://hubuum.example.invalid").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap();
    scenario!(client, transport, finish, id);
}
