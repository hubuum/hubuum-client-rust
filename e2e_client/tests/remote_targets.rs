use std::time::Duration;

use hubuum_client::{
    FilterOperator, NewRemoteTarget, RemoteAuthConfig, RemoteHttpMethod, RemoteInvocationSubject,
    RemoteTargetInvokeRequest, RemoteTargetSubjectType, TaskKind, UpdateRemoteTarget,
};
use serde_json::json;

use e2e_client::harness::{E2EHarness, admin_context};
use e2e_client::naming::unique_case_prefix;

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_remote_target_lifecycle_invocation_history_and_events() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let (_, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");
    let (collection_id, _class_id, _object_id) = harness
        .create_collection_class_object("remote-targets", admin_group_id)
        .expect("failed to create remote target collection");
    let prefix = unique_case_prefix("remote-targets");

    let target = harness
        .client
        .remote_targets()
        .create()
        .params(NewRemoteTarget {
            collection_id,
            name: format!("{prefix}-target"),
            description: "e2e remote target".to_string(),
            method: RemoteHttpMethod::Post,
            url_template: "http://127.0.0.1:9/e2e/{{ subject.type }}".to_string(),
            allowed_subject_types: vec![RemoteTargetSubjectType::Collection],
            auth_config: Some(RemoteAuthConfig::None),
            body_template: Some("{\"collection_id\": {{ subject.collection_id }}}".to_string()),
            class_id: None,
            enabled: Some(true),
            headers_template: Some(json!({"x-e2e": "hubuum-client"})),
            timeout_ms: Some(500),
        })
        .send()
        .expect("remote target should create");
    assert_eq!(target.collection_id, collection_id);

    let selected = harness
        .client
        .remote_targets()
        .get(target.id)
        .expect("remote target should be selectable");
    assert_eq!(selected.resource().name, target.name);

    let updated = harness
        .client
        .remote_targets()
        .update_raw(
            target.id,
            UpdateRemoteTarget {
                description: Some("e2e remote target updated".to_string()),
                timeout_ms: Some(750),
                ..Default::default()
            },
        )
        .expect("remote target should update");
    assert_eq!(updated.timeout_ms, 750);

    let matching_targets = harness
        .client
        .remote_targets()
        .query()
        .filter(
            "collection_id",
            FilterOperator::Equals { is_negated: false },
            collection_id,
        )
        .filter(
            "name",
            FilterOperator::Equals { is_negated: false },
            &target.name,
        )
        .limit(10)
        .list()
        .expect("remote target query should list");
    assert!(
        matching_targets
            .iter()
            .any(|candidate| candidate.id == target.id)
    );

    let invoked = selected
        .invoke(
            RemoteTargetInvokeRequest::new(RemoteInvocationSubject::Collection { collection_id })
                .parameters(json!({"case": prefix})),
        )
        .expect("remote target invocation should enqueue task");
    assert_eq!(invoked.kind, TaskKind::RemoteCall);

    let completed = harness
        .client
        .tasks()
        .wait(invoked.id)
        .poll_interval(Duration::from_millis(100))
        .timeout(Some(Duration::from_secs(30)))
        .send()
        .expect("remote call task should reach a terminal state");
    assert!(completed.status.is_terminal(), "{completed:?}");

    let task_events = harness
        .client
        .tasks()
        .events(invoked.id)
        .limit(20)
        .list()
        .expect("remote call task events should list");
    assert!(
        task_events
            .iter()
            .any(|event| event.task_id == invoked.id && !event.message.is_empty())
    );

    let history = harness
        .client
        .remote_target_history(target.id)
        .limit(20)
        .list()
        .expect("remote target history should list");
    assert!(
        history
            .iter()
            .any(|entry| entry.id == target.id && entry.timeout_ms == 750)
    );
    let as_of = harness
        .client
        .remote_target_history_as_of(target.id, history[0].history.valid_from.clone())
        .expect("remote target history as-of should fetch");
    assert_eq!(as_of.id, target.id);

    let events = harness
        .client
        .remote_target_events(target.id)
        .limit(20)
        .list()
        .expect("remote target events should list");
    assert!(
        events
            .iter()
            .any(|event| event.entity_id == Some(target.id))
    );

    harness
        .client
        .remote_targets()
        .delete(target.id)
        .expect("remote target should delete");
}
