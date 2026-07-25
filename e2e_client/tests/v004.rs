use std::time::Duration;

use e2e_client::harness::{E2EHarness, admin_context};
use e2e_client::naming::unique_case_prefix;
use hubuum_client::{
    ApiError, ExportRequest, ExportScope, ExportScopeKind, NewTokenRequest, ObjectAggregateMeasure,
    ObjectAggregateMeasureField, ObjectAggregateMeasureOperation, ObjectPatch, Permissions,
    TARGET_SERVER_VERSION, Token, TokenResourceScope, TokenScopeDetails,
};
use serde_json::json;

fn assert_token_rejected(error: ApiError) {
    match error {
        ApiError::HttpWithBody { status, .. }
            if status.as_u16() == 401 || status.as_u16() == 403 => {}
        other => panic!("expected revoked token authentication failure, got {other}"),
    }
}

fn assert_scope_denied(error: ApiError) {
    match error {
        ApiError::HttpWithBody { status, .. } if status.as_u16() == 403 => {}
        other => panic!("expected token-scope authorization failure, got {other}"),
    }
}

#[test]
#[ignore = "requires Docker and Hubuum server v0.0.4 image"]
fn e2e_v004_token_lifecycle_with_and_without_scopes() {
    if TARGET_SERVER_VERSION != "0.0.4" {
        eprintln!("skipping v0.0.4 scenario while the declared target is {TARGET_SERVER_VERSION}");
        return;
    }

    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let (admin_id, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");
    let (collection_id, class_id, object_id) = harness
        .create_collection_class_object("v004-token-lifecycle", admin_group_id)
        .expect("failed to create token lifecycle resources");
    let prefix = unique_case_prefix("v004-token-lifecycle");
    let admin = harness
        .client
        .users()
        .get(admin_id)
        .expect("admin user should be selectable");
    let scoped_name = format!("{prefix}-scoped");
    let unscoped_name = format!("{prefix}-unscoped");
    let expected_scope = TokenScopeDetails::new(
        Some(vec![Permissions::ReadObject]),
        Some(vec![TokenResourceScope::Collection(collection_id)]),
    )
    .expect("token scope should be valid");

    let scoped_raw = admin
        .tokens_create(
            NewTokenRequest::new()
                .name(scoped_name.clone())
                .scope(expected_scope.clone()),
        )
        .expect("scoped token should mint");
    let unscoped_raw = admin
        .tokens_create(NewTokenRequest::new().name(unscoped_name.clone()))
        .expect("omitting scope should mint an unscoped token");
    assert!(!scoped_raw.is_empty());
    assert!(!unscoped_raw.is_empty());

    let listed_tokens = admin.tokens().expect("admin tokens should list");
    let scoped_metadata = listed_tokens
        .iter()
        .find(|token| token.name.as_deref() == Some(scoped_name.as_str()))
        .expect("scoped token metadata should list");
    assert_eq!(scoped_metadata.scope.as_ref(), Some(&expected_scope));
    let unscoped_metadata = listed_tokens
        .iter()
        .find(|token| token.name.as_deref() == Some(unscoped_name.as_str()))
        .expect("unscoped token metadata should list");
    assert!(
        unscoped_metadata.scope.is_none(),
        "omitting scope must create an unscoped token"
    );

    let scoped_client = hubuum_client::blocking::Client::try_new(harness.base_url.clone())
        .expect("scoped token client should build")
        .login_with_token(Token::new(scoped_raw))
        .expect("scoped token should authenticate");
    let scoped_me = scoped_client
        .me()
        .expect("scoped token should read current identity");
    assert_eq!(scoped_me.token.scope.as_ref(), Some(&expected_scope));
    assert_eq!(
        scoped_client
            .objects(class_id)
            .get(object_id)
            .expect("resource-scoped token should read its object")
            .id,
        object_id
    );
    let scope_error = match scoped_client.collections().get(collection_id) {
        Ok(_) => panic!("ReadObject scope must not grant ReadCollection"),
        Err(error) => error,
    };
    assert_scope_denied(scope_error);

    let unscoped_client = hubuum_client::blocking::Client::try_new(harness.base_url.clone())
        .expect("unscoped token client should build")
        .login_with_token(Token::new(unscoped_raw))
        .expect("unscoped token should authenticate");
    let unscoped_me = unscoped_client
        .me()
        .expect("unscoped token should read current identity");
    assert!(
        unscoped_me.token.scope.is_none(),
        "current-token metadata must preserve an unscoped token"
    );
    assert_eq!(
        unscoped_client
            .collections()
            .get(collection_id)
            .expect("unscoped admin token should retain collection access")
            .id,
        collection_id
    );

    admin
        .token_revoke(scoped_metadata.id)
        .expect("scoped token should revoke");
    admin
        .token_revoke(unscoped_metadata.id)
        .expect("unscoped token should revoke");

    assert_token_rejected(
        scoped_client
            .me()
            .expect_err("revoked scoped token must stop authenticating"),
    );
    assert_token_rejected(
        unscoped_client
            .me()
            .expect_err("revoked unscoped token must stop authenticating"),
    );

    harness
        .client
        .objects(class_id)
        .delete(object_id)
        .expect("object cleanup should succeed");
    harness
        .client
        .classes()
        .delete(class_id)
        .expect("class cleanup should succeed");
    harness
        .client
        .collections()
        .delete(collection_id)
        .expect("collection cleanup should succeed");
}

#[test]
#[ignore = "requires Docker and Hubuum server v0.0.4 image"]
fn e2e_v004_numeric_aggregates_and_provenance() {
    if TARGET_SERVER_VERSION != "0.0.4" {
        eprintln!("skipping v0.0.4 scenario while the declared target is {TARGET_SERVER_VERSION}");
        return;
    }

    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let (admin_id, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");
    let (collection_id, class_id, object_id) = harness
        .create_collection_class_object("v004", admin_group_id)
        .expect("failed to create collection/class/object");
    let prefix = unique_case_prefix("v004-aggregate-provenance");

    harness
        .client
        .objects(class_id)
        .update_raw(
            object_id,
            ObjectPatch {
                name: None,
                collection_id: Some(collection_id),
                hubuum_class_id: Some(class_id),
                description: Some("v0.0.4 numeric aggregate fixture".to_string()),
                data: Some(json!({"metrics": {"cost": 12.5}})),
            },
        )
        .expect("numeric object update should succeed");

    let aggregate_rows = harness
        .client
        .object_aggregates(class_id)
        .aggregate(ObjectAggregateMeasure::new(
            ObjectAggregateMeasureOperation::Sum,
            ObjectAggregateMeasureField::json_data(["metrics", "cost"]),
        ))
        .list()
        .expect("numeric aggregate should succeed");
    assert_eq!(aggregate_rows.len(), 1);
    assert_eq!(aggregate_rows[0].object_count, 1);
    assert_eq!(aggregate_rows[0].measures.len(), 1);
    assert_eq!(aggregate_rows[0].measures[0].value_count, 1);
    assert!(aggregate_rows[0].measures[0].value.is_some());

    let direct_events = harness
        .client
        .object_events(class_id, object_id)
        .action("updated")
        .actor_user_id(admin_id)
        .limit(20)
        .list()
        .expect("object events should filter by direct actor");
    let update_event = direct_events
        .iter()
        .find(|event| event.entity_id == Some(object_id.get()))
        .expect("updated object event should be returned");
    let provenance = update_event
        .provenance
        .as_ref()
        .expect("v0.0.4 events should include provenance");
    assert_eq!(
        provenance
            .actor
            .principal
            .as_ref()
            .map(|actor| actor.principal_id),
        Some(admin_id.into())
    );
    assert!(
        provenance.initiator.is_none(),
        "a direct API mutation has no root-task initiator"
    );

    let export_task = harness
        .client
        .exports()
        .submit(ExportRequest {
            limits: None,
            missing_data_policy: None,
            query: None,
            scope: ExportScope {
                class_id: Some(class_id),
                kind: ExportScopeKind::ObjectsInClass,
                object_id: None,
            },
            include: None,
            relation_context: None,
        })
        .idempotency_key(format!("{prefix}-export"))
        .send()
        .expect("export task should submit");
    harness
        .client
        .tasks()
        .wait(export_task.id)
        .poll_interval(Duration::from_millis(100))
        .timeout(Some(Duration::from_secs(30)))
        .send()
        .expect("export task should complete");

    let task_events = harness
        .client
        .tasks()
        .events(export_task.id)
        .limit(20)
        .list()
        .expect("task events should list");
    assert!(task_events.iter().any(|event| {
        event.provenance.as_ref().is_some_and(|provenance| {
            provenance.task_id == Some(export_task.id)
                && provenance
                    .initiator
                    .as_ref()
                    .is_some_and(|initiator| initiator.principal_id.get() == admin_id.get())
        })
    }));

    let initiated_events = harness
        .client
        .events()
        .initiator_user_id(admin_id)
        .entity_type("task")
        .entity_id(export_task.id.get())
        .limit(20)
        .list()
        .expect("global events should filter by root-task initiator");
    assert!(
        !initiated_events.is_empty(),
        "expected task lifecycle events initiated by admin"
    );

    harness
        .client
        .objects(class_id)
        .delete(object_id)
        .expect("object cleanup should succeed");
    harness
        .client
        .classes()
        .delete(class_id)
        .expect("class cleanup should succeed");
    harness
        .client
        .collections()
        .delete(collection_id)
        .expect("collection cleanup should succeed");
}
