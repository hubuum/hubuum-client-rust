use e2e_client::harness::{E2EHarness, admin_context};
use e2e_client::naming::unique_case_prefix;
use hubuum_client::{
    ApiError, NewTokenRequest, PrincipalSettingsPatchDocument, PrincipalSettingsPatchOperation,
    RenewTokenRequest, TARGET_SERVER_VERSION, TokenListState,
};
use serde_json::json;

fn assert_precondition_failed(error: ApiError) {
    match error {
        ApiError::HttpWithBody { status, .. } if status.as_u16() == 412 => {}
        other => panic!("expected stale If-Match precondition failure, got {other}"),
    }
}

#[test]
#[ignore = "requires Docker and Hubuum server v0.0.9 image"]
fn e2e_v009_revisions_etags_settings_memberships_and_tokens() {
    if TARGET_SERVER_VERSION != "0.0.9" {
        eprintln!("skipping v0.0.9 scenario while the declared target is {TARGET_SERVER_VERSION}");
        return;
    }

    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let (_, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");
    let (_, class_id, _) = harness
        .create_collection_class_object("v009-revisions", admin_group_id)
        .expect("failed to create revision resources");

    let class = harness
        .client
        .classes()
        .get(class_id)
        .expect("class point response should decode");
    let class_etag = class
        .etag()
        .cloned()
        .expect("class point response should include a strong ETag");
    let original_revision = class.revision;
    let updated = harness
        .client
        .classes()
        .update(class_id)
        .description("updated through If-Match")
        .if_match(class_etag.clone())
        .send()
        .expect("matching class ETag should permit update");
    assert!(updated.revision > original_revision);
    assert_precondition_failed(
        harness
            .client
            .classes()
            .update(class_id)
            .description("stale update")
            .if_match(class_etag)
            .send()
            .expect_err("stale class ETag should be rejected"),
    );

    let user = harness
        .create_user("v009-revisions")
        .expect("test user should create");
    let user_handle = harness
        .client
        .users()
        .get(user.id)
        .expect("test user should be selectable");

    let settings = user_handle
        .settings()
        .get_revisioned()
        .expect("settings point response should decode");
    let settings_etag = settings
        .etag()
        .expect("settings response should include a strong ETag");
    let patch = PrincipalSettingsPatchDocument::new([PrincipalSettingsPatchOperation::Add {
        path: "/v009_e2e".to_string(),
        value: json!(true),
    }])
    .expect("settings patch should be valid");
    let patched = user_handle
        .settings()
        .json_patch_if_match(&patch, settings_etag)
        .expect("matching settings ETag should permit JSON Patch");
    assert!(patched.revision > settings.revision);
    assert_eq!(patched.get("v009_e2e"), Some(&json!(true)));

    let (_, group_id) = harness
        .create_group("v009-revisions")
        .expect("test group should create");
    let group = harness
        .client
        .groups()
        .get(group_id)
        .expect("test group should be selectable");
    let membership = group
        .add_member(user.id)
        .expect("membership should create as a revisioned entity");
    assert_eq!(membership.group_id, group_id);
    assert_eq!(membership.principal_id.get(), user.id.get());
    let membership = group
        .member(user.id)
        .expect("membership point response should decode");
    let membership_etag = membership
        .etag()
        .expect("membership point response should include a strong ETag");
    group
        .remove_member_if_match(user.id, membership_etag)
        .expect("matching membership ETag should permit removal");

    let token_name = format!("{}-token", unique_case_prefix("v009-revisions"));
    user_handle
        .tokens_create_token(NewTokenRequest::new().name(token_name.clone()))
        .expect("test token should mint");
    let token_metadata = user_handle
        .tokens_request_state(TokenListState::Active)
        .all()
        .expect("active tokens should list")
        .into_iter()
        .find(|token| token.name.as_deref() == Some(token_name.as_str()))
        .expect("new token should appear in active state filter");
    let replacement = user_handle
        .token_renew(token_metadata.id, RenewTokenRequest::default())
        .expect("token should renew");
    assert_eq!(
        hubuum_client::blocking::Client::try_new(harness.base_url.clone())
            .expect("replacement-token client should build")
            .login_with_token(replacement)
            .expect("replacement token should authenticate")
            .me()
            .expect("replacement token should resolve its identity")
            .principal
            .principal_id
            .get(),
        user.id.get()
    );
    let source = user_handle
        .token(token_metadata.id)
        .expect("renewal source-token point response should decode");
    assert!(
        source.revoked_at.is_none(),
        "renewal should leave its source token unchanged"
    );
    let source_etag = source
        .etag()
        .expect("source token response should include a strong ETag");
    user_handle
        .token_revoke_if_match(token_metadata.id, source_etag)
        .expect("matching token ETag should permit revocation");
    let revoked = user_handle
        .tokens_request_state(TokenListState::Revoked)
        .all()
        .expect("revoked tokens should list");
    assert!(
        revoked.iter().any(|token| token.id == token_metadata.id),
        "conditionally revoked token should appear in the revoked state filter"
    );
}
