use std::sync::Arc;

use chrono::Utc;
use hubuum_client::{
    ApiError, AuthenticationInteractionRequest, AuthenticationProviderId,
    AuthenticationProviderUpdate, BaseUrl, Client, CredentialOperation,
    LdapCandidateVerificationRequest, MockTransport, NewTokenRequest, ProviderConfigurationInput,
    ProviderCredentialInput, ResourceRevision, RuntimeSettingsApplicationStatus,
    SecurityCandidateId, SecurityCandidateReport, SecurityCandidateRequest, SessionClientId, Token,
    TransportResponse, blocking,
};
use reqwest::StatusCode;
use serde_json::{Value, json};

const CANDIDATE: &str = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb";
const PROVIDER: &str = "cccccccc-cccc-4ccc-accc-cccccccccccc";
const INTERACTION: &str = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa";

fn report(state: &str, receipt: bool) -> Value {
    let mut value = json!({"id":CANDIDATE,"group":"authentication","base_revision":7,
        "expires_at":Utc::now()+chrono::Duration::minutes(5), "state":state,"checks":[],
        "providers":[{"provider_id":PROVIDER,"name":"company","kind":"oidc"}]});
    if receipt {
        value["verification_receipt"] = json!(format!("hcv1.{}", "b".repeat(64)));
    }
    value
}

fn preview() -> Value {
    json!({"candidate":report("verified",true),"verification":{
        "candidate_id":CANDIDATE,"provider_id":PROVIDER,"subject":"private-subject",
        "admitted":false,"membership":"complete","groups":[],"issued_session":false,"provisioned":false}})
}

fn begun() -> Value {
    json!({"id":INTERACTION,"interaction_version":1,"redemption_secret":format!("hai1.{}","a".repeat(64)),
        "expires_at":Utc::now()+chrono::Duration::minutes(5),"interval_seconds":5,
        "next":{"kind":"browser","verification_uri":"https://example.invalid/api/v1/auth/interactions/browser","user_code":"public-code"}})
}

fn push(transport: &MockTransport, status: StatusCode, body: Value) {
    transport.push_response(TransportResponse::json(status, &body).unwrap());
}

fn password() -> String {
    format!("fixture-{:032x}", fastrand::u128(..))
}

fn input(kind: &str, secret: &str) -> AuthenticationProviderUpdate {
    let configuration = match kind {
        "ldap" => ProviderConfigurationInput::ldap(json!({"scope":"company","url":"ldaps://directory.example",
            "user_base_dn":"dc=example","user_filter":"(uid={username})","bind_dn":"cn=fixture,dc=example"}), Some(secret.to_owned())).unwrap(),
        "oidc" => ProviderConfigurationInput::oidc(json!({"issuer":"https://identity.example/realm","client_id":"hubuum",
            "client_authentication":"client_secret_basic","scopes":["openid"],"signing_algorithms":["RS256"],
            "membership":{"mode":"local_only","refresh_interval_seconds":300,"max_stale_seconds":900},"admission":{"mode":"existing_only"}}),ProviderCredentialInput::replace(secret).unwrap()).unwrap(),
        "oauth" => ProviderConfigurationInput::oauth(json!({"profile":"github",
            "authorization_endpoint":"https://github.com/login/oauth/authorize","token_endpoint":"https://github.com/login/oauth/access_token",
            "profile_endpoint":"https://api.github.com/user","client_id":"fixture-client","client_authentication":"client_secret_post",
            "scopes":[],"subject_pointer":"/id","subject_type":"integer","name_pointer":"/login",
            "membership":{"mode":"local_only","refresh_interval_seconds":300,"max_stale_seconds":900},"admission":{"mode":"existing_only"}}),ProviderCredentialInput::replace(secret).unwrap()).unwrap(),
        _ => panic!("unknown provider kind"),
    };
    AuthenticationProviderUpdate::runtime("company", configuration).unwrap()
}

macro_rules! scenario {
    ($client:ident,$transport:ident,$finish:ident,$case:expr) => {{
        let candidate_id = SecurityCandidateId::new(CANDIDATE).unwrap();
        let provider_id = AuthenticationProviderId::new(PROVIDER).unwrap();
        match $case {
            "fresh_approval" => {
                push(&$transport,StatusCode::CREATED,begun());
                let operation=CredentialOperation::create_token(hubuum_client::PrincipalId::new(42).unwrap(),NewTokenRequest::new().name("fixture-token"));
                let expected=serde_json::to_value(&operation).unwrap();
                let flow=$finish!($client.begin_credential_approval_interaction(AuthenticationInteractionRequest::new(
                    SessionClientId::new("sdk-fixture").unwrap(),provider_id),operation)).unwrap();
                let expiry=Utc::now().naive_utc()+chrono::Duration::hours(1);
                let approval=format!("hca1.{}","c".repeat(64));
                push(&$transport,StatusCode::OK,json!({"approval":approval,"token_expires_at":expiry,
                    "record":{"id":11,"actor_id":7,"token_id":18,"operation":"create_token","target_id":42,"restore_job_id":null,
                        "authenticated_at":Utc::now(),"expires_at":Utc::now()+chrono::Duration::minutes(2),"consumed_at":null,"invalidated_at":null}}));
                let approved=$finish!(flow.complete()).unwrap();
                push(&$transport,StatusCode::CREATED,json!({"token":"issued-token","expires_at":expiry}));
                assert_eq!($finish!(approved.send()).unwrap().as_str(),"issued-token");
                let requests=$transport.requests();
                assert_eq!(requests.len(),3);
                assert_eq!(serde_json::from_slice::<Value>(requests[0].body()).unwrap()["operation"],expected);
                assert_eq!(requests[0].headers["Authorization"],"Bearer origin-bearer");
                assert!(requests[1].headers["Authorization"].to_str().unwrap().starts_with("Hubuum-Interaction "));
                assert_eq!(requests[2].headers["Authorization"],"Bearer origin-bearer");
                assert_eq!(requests[2].headers["X-Hubuum-Credential-Approval"],approval);
            }
            "ldap" | "oidc" | "oauth" => {
                let secret=password();
                let request=SecurityCandidateRequest::authentication(ResourceRevision::new(7).unwrap(),vec![input($case,&secret)]);
                assert!(!format!("{request:?}").contains(&secret));
                push(&$transport,StatusCode::CREATED,report("unverified",false));
                let report=$finish!($client.create_security_candidate(request)).unwrap();
                assert_eq!(report.id,candidate_id);
                assert!(report.into_activation().is_err());
                let requests=$transport.requests();
                assert_eq!(requests.len(),1);
                assert_eq!(requests[0].url.path(),"/api/v1/admin/runtime-settings/security-candidates");
                let body:Value=serde_json::from_slice(requests[0].body()).unwrap();
                assert_eq!(body["expected_revision"],7);
                assert_eq!(body["providers"][0]["kind"],$case);
                let config=&body["providers"][0]["configuration"];
                assert_eq!(if $case=="ldap" { &config["bind_password"] } else { &config["credential"]["value"] },&secret);
                assert!(!format!("{:?}",requests[0]).contains(&secret));
            }
            "activate" => {
                let report:SecurityCandidateReport=serde_json::from_value(report("verified",true)).unwrap();
                let operation=CredentialOperation::activate_security_candidate(report.into_activation().unwrap());
                let wire=serde_json::to_value(&operation).unwrap();
                assert_eq!(wire,json!({"kind":"activate_security_candidate","candidate_id":CANDIDATE,"group":"authentication","expected_revision":7}));
                let approval=format!("hca1.{}","c".repeat(64));
                push(&$transport,StatusCode::CREATED,json!({"approval":approval,"token_expires_at":null,
                    "record":{"id":11,"actor_id":7,"token_id":18,"operation":"activate_security_candidate","target_id":null,"restore_job_id":null,
                        "authenticated_at":Utc::now(),"expires_at":Utc::now()+chrono::Duration::minutes(2),"consumed_at":null,"invalidated_at":null}}));
                let approved=$finish!($client.credential_approvals().approve(password(),operation)).unwrap();
                assert!(!format!("{approved:?}").contains(&approval));
                push(&$transport,StatusCode::OK,json!({"group":"authentication","revision":8,"changed":true}));
                assert_eq!($finish!(approved.send()).unwrap().revision.get(),8);
                let requests=$transport.requests();
                assert_eq!(requests.len(),2);
                assert_eq!(requests[1].url.path(),format!("/api/v1/admin/runtime-settings/security-candidates/{CANDIDATE}/activate"));
                let body:Value=serde_json::from_slice(requests[1].body()).unwrap();
                assert_eq!(body,json!({"expected_revision":7,"verification_receipt":format!("hcv1.{}","b".repeat(64))}));
                assert_eq!(requests[1].headers["X-Hubuum-Credential-Approval"],approval);
                assert!(requests[1].headers["X-Hubuum-Credential-Approval"].is_sensitive());
                assert_eq!(requests[0].headers["Authorization"],requests[1].headers["Authorization"]);
            }
            "unsupported_approval" => {
                push(&$transport,StatusCode::UNPROCESSABLE_ENTITY,json!({"error":"AuthenticationFailed","message":"Unsupported","reason":"capability_unsupported"}));
                let result=$finish!($client.begin_credential_approval_interaction(
                    AuthenticationInteractionRequest::new(SessionClientId::new("sdk-fixture").unwrap(),provider_id),
                    CredentialOperation::create_token(hubuum_client::PrincipalId::new(42).unwrap(),NewTokenRequest::new().name("fixture-token"))));
                assert!(result.unwrap_err().is_capability_unsupported());
                assert_eq!($transport.requests().len(),1);
            }
            "verification" | "wrong_candidate" | "wrong_provider" | "provisioned" | "issued_session" => {
                push(&$transport,StatusCode::CREATED,begun());
                let flow=$finish!($client.begin_provider_verification_interaction(
                    AuthenticationInteractionRequest::new(SessionClientId::new("sdk-fixture").unwrap(),provider_id),candidate_id)).unwrap();
                let mut response=preview();
                match $case {
                    "wrong_candidate" => response["verification"]["candidate_id"]=json!(INTERACTION),
                    "wrong_provider" => response["verification"]["provider_id"]=json!(INTERACTION),
                    "provisioned" | "issued_session" => response["verification"][$case]=json!(true),
                    _ => (),
                }
                push(&$transport,StatusCode::OK,response);
                let result=$finish!(flow.complete());
                if $case=="verification" {
                    let result=result.unwrap();
                    assert!(!result.verification.provisioned);
                    assert!(!format!("{result:?}").contains("private-subject"));
                    assert!(result.candidate.into_activation().is_ok());
                } else { assert!(matches!(result,Err(ApiError::InvalidAuthenticationInteraction))); }
                let requests=$transport.requests();
                assert_eq!(requests.len(),2);
                assert_eq!(requests[0].headers["Authorization"],"Bearer origin-bearer");
                assert!(requests[1].headers["Authorization"].to_str().unwrap().starts_with("Hubuum-Interaction "));
                let body:Value=serde_json::from_slice(requests[0].body()).unwrap();
                assert_eq!(body["purpose"],"provider_verification");
                assert_eq!(body["candidate_id"],CANDIDATE);
            }
            "ldap_preview" => {
                let secret=password();
                let request=LdapCandidateVerificationRequest::new(provider_id,"directory-user",secret.clone()).unwrap();
                assert!(!format!("{request:?}").contains(&secret));
                let mut response=preview(); response["candidate"]["providers"][0]["kind"]=json!("ldap");
                push(&$transport,StatusCode::OK,response);
                let result=$finish!($client.verify_ldap_security_candidate(&candidate_id,request)).unwrap();
                assert!(!result.verification.issued_session);
                assert!($transport.requests()[0].url.path().ends_with("/verify-ldap"));
            }
            "effective_state" => {
                push(&$transport,StatusCode::OK,json!({"group":"authentication","source":"runtime","revision":7,
                    "changed_at":null,"changed_by":null,"mutable":true,"restart_required":false,"takes_effect":"new_requests",
                    "replica":{"status":"stale","reconcile_interval_seconds":1,"applied_at":null,"last_refresh_attempt_at":null,"last_refresh_failure_at":null},
                    "effective":{"providers":[{"provider_id":PROVIDER,"kind":"oidc","name":"company","source":"runtime",
                        "enabled":true,"definition_mutable":true,"runtime_definition":{"unexpected_sensitive_value":"must-not-log"},"credential_configured":true,"available":false}]},
                    "runtime":null,"deployment":null,"constrained_by_ceiling":false}));
                let settings=$finish!($client.effective_authentication_settings()).unwrap();
                assert_eq!(settings.expected_revision().get(),7);
                assert_eq!(settings.replica().status,RuntimeSettingsApplicationStatus::Stale);
                assert!(settings.providers()[0].credential_configured);
                assert!(!settings.providers()[0].available);
                assert!(!format!("{settings:?}").contains("must-not-log"));
            }
            _=>panic!("unknown scenario"),
        }
        for request in $transport.requests() {
            assert_eq!(request.url.origin().ascii_serialization(),"https://example.invalid");
            assert!(request.url.query().is_none());
            assert!(!format!("{request:?}").contains("origin-bearer"));
        }
    }};
}

#[rstest::rstest]
#[case("ldap")]
#[case("oidc")]
#[case("oauth")]
#[case("activate")]
#[case("unsupported_approval")]
#[case("verification")]
#[case("wrong_candidate")]
#[case("wrong_provider")]
#[case("provisioned")]
#[case("issued_session")]
#[case("ldap_preview")]
#[case("effective_state")]
#[case("fresh_approval")]
fn blocking_runtime_security(#[case] case: &str) {
    macro_rules! finish {
        ($request:expr) => {
            $request
        };
    }
    let transport = MockTransport::default();
    let client = blocking::Client::builder(BaseUrl::new("https://example.invalid").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("origin-bearer"));
    scenario!(client, transport, finish, case);
}

#[rstest::rstest]
#[case("ldap")]
#[case("oidc")]
#[case("oauth")]
#[case("activate")]
#[case("unsupported_approval")]
#[case("verification")]
#[case("wrong_candidate")]
#[case("wrong_provider")]
#[case("provisioned")]
#[case("issued_session")]
#[case("ldap_preview")]
#[case("effective_state")]
#[case("fresh_approval")]
#[tokio::test]
async fn async_runtime_security(#[case] case: &str) {
    macro_rules! finish {
        ($request:expr) => {
            $request.await
        };
    }
    let transport = MockTransport::default();
    let client = Client::builder(BaseUrl::new("https://example.invalid").unwrap())
        .with_transport(Arc::new(transport.clone()))
        .build()
        .unwrap()
        .authenticate(Token::new("origin-bearer"));
    scenario!(client, transport, finish, case);
}

#[test]
fn verification_receipt_cannot_be_obtained_from_an_unverified_report() {
    let report: SecurityCandidateReport =
        serde_json::from_value(report("unverified", false)).unwrap();
    assert!(matches!(
        report.into_activation(),
        Err(ApiError::SecurityCandidateNotVerified)
    ));
}

#[rstest::rstest]
#[case(false)]
#[case(true)]
fn ldap_password_preservation_and_clearing_are_distinct(#[case] clear: bool) {
    let configuration =
        ProviderConfigurationInput::ldap(json!({"url":"ldaps://directory.example"}), None).unwrap();
    let configuration = if clear {
        configuration.clear_ldap_bind_password().unwrap()
    } else {
        configuration
    };
    let value = serde_json::to_value(configuration).unwrap();
    if clear {
        assert!(value.get("bind_password").unwrap().is_null());
    } else {
        assert!(value.get("bind_password").is_none());
    }
}
