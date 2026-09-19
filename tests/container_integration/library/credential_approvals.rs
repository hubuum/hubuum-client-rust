use chrono::{Duration, Utc};
use hubuum_client::{CredentialOperation, HubuumDateTime, NewTokenRequest, RenewTokenRequest};

use crate::support::{
    clients::{login_async, login_sync},
    naming::unique_case_prefix,
    stack::IntegrationStack,
};

macro_rules! token_approval_lifecycle {
    ($client:ident, $password:expr, $send:ident) => {{
        let me = $send!($client.me()).unwrap();
        let principal_id = me.principal.principal_id;
        let user = $send!($client.users().get(principal_id.get())).unwrap();
        let token_name = unique_case_prefix("credential-approval");
        let request = NewTokenRequest::new()
            .name(token_name.clone())
            .expires_at(HubuumDateTime(Utc::now() + Duration::minutes(30)));
        let legacy = $send!(user.tokens_create_token(request.clone()));
        let (created, approvals_required) = match legacy {
            Ok(token) => (token, false),
            Err(error) => {
                assert!(error.is_reauthentication_required(), "{error:?}");
                let approved = $send!($client.credential_approvals().approve(
                    $password,
                    CredentialOperation::create_token(principal_id, request)
                ))
                .unwrap();
                let approval_id = approved.record().id;
                let expiry = approved.token_expires_at().unwrap();
                let created = $send!(approved.send()).unwrap();
                assert_eq!(created.expires_at(), Some(&expiry));
                assert!(
                    $send!($client.credential_approvals().get(approval_id))
                        .unwrap()
                        .consumed_at
                        .is_some()
                );
                (created, true)
            }
        };
        if std::env::var_os("HUBUUM_INTEGRATION_EXPECT_CREDENTIAL_APPROVALS").is_some() {
            assert!(
                approvals_required,
                "the selected server must enforce credential approvals"
            );
        }
        let tokens = $send!(user.tokens()).unwrap();
        let source = tokens
            .iter()
            .find(|token| token.name.as_deref().is_some_and(|name| name == token_name))
            .expect("created token metadata");
        let renewal = RenewTokenRequest::default();
        let renewed = if approvals_required {
            let error = $send!(user.token_renew(source.id, renewal.clone())).unwrap_err();
            assert!(error.is_reauthentication_required());
            let approved = $send!($client.credential_approvals().approve(
                $password,
                CredentialOperation::renew_token(principal_id, source.id, renewal)
            ))
            .unwrap();
            let expiry = approved.token_expires_at().unwrap();
            let token = $send!(approved.send()).unwrap();
            assert_eq!(token.expires_at(), Some(&expiry));
            token
        } else {
            $send!(user.token_renew(source.id, renewal)).unwrap()
        };
        $send!($client.logout_token(created.as_str())).unwrap();
        $send!($client.logout_token(renewed.as_str())).unwrap();
    }};
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn blocking_credential_approvals_token_lifecycle() {
    let stack = IntegrationStack::start().unwrap();
    let client = login_sync(stack.base_url.parse().unwrap(), &stack.admin_password).unwrap();
    macro_rules! send {
        ($value:expr) => {
            $value
        };
    }
    token_approval_lifecycle!(client, stack.admin_password.clone(), send);
}

#[tokio::test]
#[ignore = "requires Docker and hubuum server image"]
async fn async_credential_approvals_token_lifecycle() {
    let stack = IntegrationStack::start().unwrap();
    let client = login_async(stack.base_url.parse().unwrap(), &stack.admin_password)
        .await
        .unwrap();
    macro_rules! send {
        ($value:expr) => {
            $value.await
        };
    }
    token_approval_lifecycle!(client, stack.admin_password.clone(), send);
}
