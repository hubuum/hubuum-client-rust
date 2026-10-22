use e2e_client::{
    harness::{E2EHarness, admin_context},
    naming::unique_case_prefix,
};
use hubuum_client::{
    CredentialActivityPageOptions, CredentialOperation, NewTokenRequest, PrincipalId,
    ServiceAccountPost, blocking,
};

#[yare::parameterized(
    human = { false },
    service_account = { true },
)]
#[ignore = "requires the pinned disposable Hubuum server"]
fn durable_credential_activity(service_account: bool) {
    let harness = E2EHarness::from_env().unwrap();
    let issuer = harness.client.me().unwrap().principal.principal_id;
    let owner: PrincipalId = if service_account {
        let (_, group) = admin_context(&harness.client).unwrap();
        harness
            .client
            .service_accounts()
            .create_raw(ServiceAccountPost {
                name: unique_case_prefix("activity-service"),
                description: None,
                identity_scope: None,
                owner_group_id: group,
            })
            .unwrap()
            .id
            .into()
    } else {
        harness.create_user("activity-human").unwrap().id.into()
    };
    let token = harness
        .client
        .credential_approvals()
        .approve(
            harness.admin_password.clone(),
            CredentialOperation::create_token(
                owner,
                NewTokenRequest::new().name(unique_case_prefix("activity-token")),
            ),
        )
        .unwrap()
        .send()
        .unwrap();
    let consumer = blocking::Client::try_new(harness.base_url.clone())
        .unwrap()
        .authenticate(token);
    let me = consumer.me().unwrap();
    assert_eq!(me.principal.principal_id, owner);
    let options = CredentialActivityPageOptions::default().limit(1).unwrap();
    let activity = harness
        .client
        .token_activity(owner, me.token.id, options)
        .unwrap();
    assert!(activity.session_id.is_none());
    let creation = activity
        .creation
        .as_ref()
        .expect("new credentials have issuance evidence");
    assert_eq!(creation.issuer_id, Some(issuer));
    assert_ne!(creation.issuer_id, Some(owner));
    assert_eq!(creation.issuance_method, "creation");
    assert!(creation.address.is_some());
    assert_eq!(creation.address_method, "connection_peer");
    assert!(activity.collection_enabled && activity.best_effort);
    assert_eq!(activity.retention_days, 30);
    assert_eq!(activity.source_cap, 32);
    assert_eq!(activity.sources.len(), 1);
    assert_eq!(activity.sources[0].address, creation.address);
    assert!(activity.overflow_since.is_none());
    let empty = harness
        .client
        .token_activity(owner, me.token.id, options.offset(256).unwrap())
        .unwrap();
    assert!(empty.sources.is_empty() && empty.next_page_options().unwrap().is_none());
    assert_eq!(empty.creation, activity.creation);
    assert_eq!(empty.total, activity.total);

    if service_account {
        assert!(
            consumer
                .token_activity(owner, me.token.id, options)
                .is_err()
        );
        let handle = harness.client.service_accounts().get(owner.get()).unwrap();
        let before = handle.token(me.token.id).unwrap();
        consumer.me().unwrap();
        let after = handle.token(me.token.id).unwrap();
        assert_eq!(
            before.etag(),
            after.etag(),
            "activity must not change token ETags"
        );
        assert_eq!(
            handle
                .token_activity(me.token.id, options)
                .unwrap()
                .creation,
            activity.creation
        );
        handle.token_revoke(me.token.id).unwrap();
        assert_eq!(
            handle
                .token_activity(me.token.id, options)
                .unwrap()
                .creation,
            activity.creation
        );
    } else {
        let handle = harness.client.users().get(owner.get()).unwrap();
        let before = handle.token(me.token.id).unwrap();
        consumer.me().unwrap();
        let after = handle.token(me.token.id).unwrap();
        assert_eq!(
            before.etag(),
            after.etag(),
            "activity must not change token ETags"
        );
        assert_eq!(
            handle
                .token_activity(me.token.id, options)
                .unwrap()
                .creation,
            activity.creation
        );
        handle.token_revoke(me.token.id).unwrap();
        assert_eq!(
            handle
                .token_activity(me.token.id, options)
                .unwrap()
                .creation,
            activity.creation
        );
    }
    assert!(
        harness
            .client
            .token_activity(issuer, me.token.id, options)
            .is_err(),
        "both path IDs constrain activity"
    );
}
