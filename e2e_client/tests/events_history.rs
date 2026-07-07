use std::{thread, time::Duration};

use hubuum_client::{
    ClassPatch, EventDeliveryStatus, EventSinkKind, GroupPatch, NewEventSink, NewEventSubscription,
    ObjectPatch, ReportContentType, ReportTemplateKind, ReportTemplatePost,
    UpdateEventSubscription, UserPatch,
};
use serde_json::json;

use e2e_client::harness::{E2EHarness, admin_context};
use e2e_client::naming::unique_case_prefix;

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_event_subscriptions_create_delivery_rows() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let (_, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");
    let (namespace_id, class_id, _object_id) = harness
        .create_namespace_class_object("events-history", admin_group_id)
        .expect("failed to create namespace/class/object");
    let prefix = unique_case_prefix("events-history");

    let first_class_name = format!("{prefix}-class-events-1");
    let updated_class = harness
        .client
        .classes()
        .update_raw(
            class_id,
            ClassPatch {
                name: Some(first_class_name.clone()),
                description: Some("e2e class update for audit event".to_string()),
                namespace_id,
                json_schema: None,
                validate_schema: Some(false),
            },
        )
        .expect("class update should produce event/history");
    assert_eq!(updated_class.name, first_class_name);

    let sink = harness
        .client
        .event_sinks()
        .create()
        .params(NewEventSink {
            name: format!("{prefix}-sink"),
            kind: EventSinkKind::Webhook,
            config: Some(json!({})),
            enabled: Some(true),
            secret_ref: None,
        })
        .send()
        .expect("event sink should create");

    let subscription = harness
        .client
        .event_subscriptions(namespace_id)
        .create(NewEventSubscription {
            sink_id: sink.id,
            name: format!("{prefix}-class-updates"),
            description: Some("e2e class update delivery subscription".to_string()),
            entity_types: vec!["class".to_string()],
            actions: vec!["updated".to_string()],
            routing: Some(json!({"url": "https://example.test/hubuum/events"})),
            enabled: Some(true),
            filter: None,
        })
        .expect("event subscription should create");
    assert_eq!(subscription.sink_id, sink.id);

    let listed_subscriptions = harness
        .client
        .event_subscriptions(namespace_id)
        .query()
        .list()
        .expect("event subscriptions should list");
    assert!(
        listed_subscriptions
            .iter()
            .any(|candidate| candidate.id == subscription.id)
    );

    let second_class_name = format!("{prefix}-class-events-2");
    harness
        .client
        .classes()
        .update_raw(
            class_id,
            ClassPatch {
                name: Some(second_class_name),
                description: Some("e2e class update for delivery fanout".to_string()),
                namespace_id,
                json_schema: None,
                validate_schema: Some(false),
            },
        )
        .expect("class update should fan out to subscription");

    let matching_delivery = (0..20)
        .find_map(|_| {
            let deliveries = harness
                .client
                .event_deliveries()
                .query()
                .limit(100)
                .list()
                .expect("event deliveries should list");
            let found = deliveries
                .into_iter()
                .find(|delivery| delivery.subscription_id == subscription.id);
            if found.is_none() {
                thread::sleep(Duration::from_millis(250));
            }
            found
        })
        .expect("expected delivery row for event subscription");

    let fetched_delivery = harness
        .client
        .event_deliveries()
        .get(matching_delivery.id)
        .expect("event delivery should be fetchable");
    assert_eq!(fetched_delivery.subscription_id, subscription.id);

    let dead_delivery = harness
        .client
        .event_deliveries()
        .mark_dead(matching_delivery.id)
        .expect("event delivery should be markable dead");
    assert_eq!(dead_delivery.status, EventDeliveryStatus::Dead);

    let retried_delivery = harness
        .client
        .event_deliveries()
        .retry(matching_delivery.id)
        .expect("event delivery should be retryable");
    assert_eq!(retried_delivery.status, EventDeliveryStatus::Pending);

    let health = harness
        .client
        .event_deliveries()
        .health()
        .expect("event delivery health should deserialize");
    assert!(health.delivery.counts.total >= 1);
    assert!(
        health
            .subscriptions
            .iter()
            .any(|candidate| candidate.subscription_id == subscription.id),
        "expected subscription in delivery health, got {health:?}"
    );

    let disabled_subscription = harness
        .client
        .event_subscriptions(namespace_id)
        .update(
            subscription.id,
            UpdateEventSubscription {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .expect("event subscription should update");
    assert!(!disabled_subscription.enabled);

    harness
        .client
        .event_subscriptions(namespace_id)
        .delete(subscription.id)
        .expect("event subscription should delete");
    harness
        .client
        .event_sinks()
        .delete(sink.id)
        .expect("event sink should delete");
}

#[test]
#[ignore = "requires Docker and hubuum server image"]
fn e2e_events_and_history_cover_core_and_templates() {
    let harness = E2EHarness::from_env().expect("failed to start e2e harness");
    let (admin_id, admin_group_id) =
        admin_context(&harness.client).expect("failed to resolve admin context");
    let (namespace_id, class_id, object_id) = harness
        .create_namespace_class_object("events-history-read", admin_group_id)
        .expect("failed to create namespace/class/object");
    let prefix = unique_case_prefix("events-history-read");

    let updated_class_name = format!("{prefix}-class-history-updated");
    harness
        .client
        .classes()
        .update_raw(
            class_id,
            ClassPatch {
                name: Some(updated_class_name.clone()),
                description: Some("e2e class history update".to_string()),
                namespace_id,
                json_schema: None,
                validate_schema: Some(false),
            },
        )
        .expect("class update should produce history");

    let updated_object_name = format!("{prefix}-object-history-updated");
    harness
        .client
        .objects(class_id)
        .update_raw(
            object_id,
            ObjectPatch {
                name: Some(updated_object_name.clone()),
                namespace_id: Some(namespace_id),
                hubuum_class_id: Some(class_id),
                description: Some("e2e object history update".to_string()),
                data: Some(json!({"source": "e2e-client", "history": true})),
            },
        )
        .expect("object update should produce history");

    let template = harness
        .client
        .templates()
        .create_raw(ReportTemplatePost {
            namespace_id,
            name: format!("{prefix}-template"),
            description: "e2e report template".to_string(),
            content_type: ReportContentType::TextPlain,
            template: "count={{ meta.count }}".to_string(),
            kind: ReportTemplateKind::Fragment,
            scope_kind: None,
            class_id: None,
            default_query: None,
            include: None,
            relation_context: None,
            default_missing_data_policy: None,
            default_limits: None,
        })
        .expect("template create should produce history");

    let user = harness
        .create_user("events-history-user")
        .expect("failed to create user for audit events");
    harness
        .client
        .users()
        .update_raw(
            user.id,
            UserPatch {
                email: Some(format!("{prefix}-updated-user@example.test")),
                proper_name: Some(format!("{prefix} Updated User")),
            },
        )
        .expect("user update should produce audit event");

    let (_groupname, group_id) = harness
        .create_group("events-history-group")
        .expect("failed to create group for audit events");
    harness
        .client
        .groups()
        .update_raw(
            group_id,
            GroupPatch {
                groupname: Some(format!("{prefix}-updated-group")),
                description: Some("e2e group audit update".to_string()),
            },
        )
        .expect("group update should produce audit event");

    let namespace_history = harness
        .client
        .namespace_history(namespace_id)
        .limit(20)
        .list()
        .expect("namespace history should list");
    assert!(
        namespace_history
            .iter()
            .any(|entry| entry.id == namespace_id && !entry.history.op.is_empty())
    );
    let namespace_as_of = harness
        .client
        .namespace_history_as_of(
            namespace_id,
            namespace_history[0].history.valid_from.clone(),
        )
        .expect("namespace history as-of should fetch");
    assert_eq!(namespace_as_of.id, namespace_id);

    let class_history = harness
        .client
        .class_history(class_id)
        .limit(20)
        .list()
        .expect("class history should list");
    assert!(
        class_history
            .iter()
            .any(|entry| entry.id == class_id && entry.name == updated_class_name)
    );
    let class_as_of = harness
        .client
        .class_history_as_of(class_id, class_history[0].history.valid_from.clone())
        .expect("class history as-of should fetch");
    assert_eq!(class_as_of.id, class_id);

    let object_history = harness
        .client
        .object_history(class_id, object_id)
        .limit(20)
        .list()
        .expect("object history should list");
    assert!(
        object_history
            .iter()
            .any(|entry| entry.id == object_id && entry.name == updated_object_name)
    );
    let object_as_of = harness
        .client
        .object_history_as_of(
            class_id,
            object_id,
            object_history[0].history.valid_from.clone(),
        )
        .expect("object history as-of should fetch");
    assert_eq!(object_as_of.id, object_id);

    let template_history = harness
        .client
        .template_history(template.id)
        .limit(20)
        .list()
        .expect("template history should list");
    assert!(
        template_history
            .iter()
            .any(|entry| entry.id == template.id && entry.namespace_id == namespace_id)
    );
    let template_as_of = harness
        .client
        .template_history_as_of(template.id, template_history[0].history.valid_from.clone())
        .expect("template history as-of should fetch");
    assert_eq!(template_as_of.id, template.id);

    let events = harness
        .client
        .events()
        .actor_user_id(admin_id)
        .namespace_id(namespace_id)
        .limit(100)
        .list()
        .expect("global event listing should support filters");
    assert!(events.iter().any(|event| event.entity_type == "class"
        && event.entity_id == Some(class_id)
        && event.action == "updated"));
    assert!(events.iter().any(|event| event.entity_type == "object"
        && event.entity_id == Some(object_id)
        && event.action == "updated"));

    let user_global_events = harness
        .client
        .events()
        .entity_type("user")
        .entity_id(user.id)
        .limit(20)
        .list()
        .expect("global event listing should filter by user entity");
    assert!(
        user_global_events
            .iter()
            .any(|event| event.entity_type == "user" && event.entity_id == Some(user.id))
    );

    let group_global_events = harness
        .client
        .events()
        .entity_type("group")
        .entity_id(group_id)
        .limit(20)
        .list()
        .expect("global event listing should filter by group entity");
    assert!(
        group_global_events
            .iter()
            .any(|event| event.entity_type == "group" && event.entity_id == Some(group_id))
    );

    let namespace_events = harness
        .client
        .namespace_events(namespace_id)
        .limit(100)
        .list()
        .expect("namespace events should list");
    assert!(
        namespace_events
            .iter()
            .any(|event| event.namespace_id == Some(namespace_id))
    );

    let class_events = harness
        .client
        .class_events(class_id)
        .action("updated")
        .limit(20)
        .list()
        .expect("class events should list");
    assert!(
        class_events
            .iter()
            .any(|event| event.entity_id == Some(class_id) && event.action == "updated")
    );

    let object_events = harness
        .client
        .object_events(class_id, object_id)
        .action("updated")
        .limit(20)
        .list()
        .expect("object events should list");
    assert!(
        object_events
            .iter()
            .any(|event| event.entity_id == Some(object_id) && event.action == "updated")
    );

    let template_events = harness
        .client
        .template_events(template.id)
        .limit(20)
        .list()
        .expect("template events should list");
    assert!(
        template_events
            .iter()
            .any(|event| event.entity_id == Some(template.id.into()))
    );

    let user_events = harness
        .client
        .user_events(user.id)
        .limit(20)
        .list()
        .expect("user events should list");
    assert!(
        user_events
            .iter()
            .any(|event| event.entity_type == "user" && event.entity_id == Some(user.id))
    );

    let group_events = harness
        .client
        .group_events(group_id)
        .limit(20)
        .list()
        .expect("group events should list");
    assert!(
        group_events
            .iter()
            .any(|event| event.entity_type == "group" && event.entity_id == Some(group_id))
    );
}
