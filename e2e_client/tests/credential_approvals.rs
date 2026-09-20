use std::time::Duration;

use e2e_client::{harness::E2EHarness, naming::unique_case_prefix};
use hubuum_client::{
    CredentialOperation, Credentials, FullImportGraph, FullImportRequest, ImportPrincipalInput,
    NewTokenRequest, UserPost, blocking,
};
use serde_json::json;

fn test_password() -> String {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).expect("OS randomness must be available for test passwords");
    format!("Approval-{:032x}!", u128::from_ne_bytes(bytes))
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn credential_approvals_user_password_workflow() {
    let harness = E2EHarness::from_env().unwrap();
    let name = unique_case_prefix("approval-user");
    let initial_password = test_password();
    let replacement_password = test_password();
    let user = UserPost {
        name: name.clone(),
        password: initial_password.clone(),
        ..Default::default()
    };
    let (created, approvals_required) = match harness.client.users().create_raw(user.clone()) {
        Ok(user) => (user, false),
        Err(error) => {
            assert!(error.is_reauthentication_required(), "{error:?}");
            let approved = harness
                .client
                .credential_approvals()
                .approve(
                    harness.admin_password.clone(),
                    CredentialOperation::create_user(user),
                )
                .unwrap();
            let id = approved.record().id;
            let user = approved.send().unwrap();
            assert!(
                harness
                    .client
                    .credential_approvals()
                    .get(id)
                    .unwrap()
                    .consumed_at
                    .is_some()
            );
            (user, true)
        }
    };
    if std::env::var_os("HUBUUM_INTEGRATION_EXPECT_CREDENTIAL_APPROVALS").is_some() {
        assert!(approvals_required);
    }
    let user_session = blocking::Client::try_new(harness.base_url.clone())
        .unwrap()
        .login(Credentials::new(&name, initial_password))
        .unwrap();
    let change = harness
        .client
        .users()
        .get(created.id)
        .unwrap()
        .set_password(&replacement_password);
    if approvals_required {
        assert!(change.unwrap_err().is_reauthentication_required());
        let revisioned = harness.client.users().get(created.id).unwrap();
        let approved = harness
            .client
            .credential_approvals()
            .approve(
                harness.admin_password.clone(),
                CredentialOperation::set_password(created.id, &replacement_password),
            )
            .unwrap();
        approved
            .if_match(revisioned.etag().unwrap().clone())
            .send()
            .unwrap();
    } else {
        change.unwrap();
    }
    assert!(
        user_session.me().is_err(),
        "password changes revoke previous tokens"
    );
    let new_session = blocking::Client::try_new(harness.base_url.clone())
        .unwrap()
        .login(Credentials::new(&name, replacement_password))
        .unwrap();
    assert_eq!(
        new_session.me().unwrap().principal.principal_id.get(),
        created.id.get()
    );
    harness.client.users().delete(created.id).unwrap();
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn credential_approvals_import_dry_run() {
    let harness = E2EHarness::from_env().unwrap();
    let name = unique_case_prefix("approval-import");
    let password = test_password();
    let principal: ImportPrincipalInput = serde_json::from_value(json!({
        "name": name, "kind": "human",
        "password": password, "provider_managed": false,
        "identity_scope_key": {"name": "local"}
    }))
    .unwrap();
    let mut graph = FullImportGraph::default();
    graph.principals.push(principal);
    let request = FullImportRequest::new(graph).dry_run(true);
    let key = unique_case_prefix("approval-import-key");
    let submitted = match harness
        .client
        .imports()
        .submit_full(request.clone())
        .idempotency_key(&key)
        .send()
    {
        Ok(task) => {
            assert!(std::env::var_os("HUBUUM_INTEGRATION_EXPECT_CREDENTIAL_APPROVALS").is_none());
            task
        }
        Err(error) => {
            assert!(error.is_reauthentication_required(), "{error:?}");
            let approved = harness
                .client
                .credential_approvals()
                .approve(
                    harness.admin_password.clone(),
                    CredentialOperation::import_credentials(request),
                )
                .unwrap();
            let approval_id = approved.record().id;
            let task = approved.idempotency_key(key).send().unwrap();
            assert!(
                harness
                    .client
                    .credential_approvals()
                    .get(approval_id)
                    .unwrap()
                    .consumed_at
                    .is_some()
            );
            task
        }
    };
    let completed = harness
        .client
        .tasks()
        .wait(submitted.id)
        .poll_interval(Duration::from_millis(100))
        .timeout(Some(Duration::from_secs(60)))
        .send()
        .unwrap();
    assert!(completed.status.is_success(), "{completed:?}");
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn credential_approvals_downstream_token_expiry() {
    let harness = E2EHarness::from_env().unwrap();
    let me = harness.client.me().unwrap();
    let request = NewTokenRequest::new().name(unique_case_prefix("approval-consumer-token"));
    let token = match harness
        .client
        .users()
        .get(me.principal.principal_id.get())
        .unwrap()
        .tokens_create_token(request.clone())
    {
        Ok(token) => {
            assert!(std::env::var_os("HUBUUM_INTEGRATION_EXPECT_CREDENTIAL_APPROVALS").is_none());
            token
        }
        Err(error) => {
            assert!(error.is_reauthentication_required(), "{error:?}");
            let approved = harness
                .client
                .credential_approvals()
                .approve(
                    harness.admin_password.clone(),
                    CredentialOperation::create_token(me.principal.principal_id, request),
                )
                .unwrap();
            let expiry = approved.token_expires_at().unwrap();
            let token = approved.send().unwrap();
            assert_eq!(token.expires_at(), Some(&expiry));
            token
        }
    };
    harness.client.logout_token(token.as_str()).unwrap();
}
