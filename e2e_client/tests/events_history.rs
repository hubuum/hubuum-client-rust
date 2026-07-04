use std::{thread, time::Duration};

use hubuum_client::{
    ClassPatch, EventSinkKind, NewEventSink, NewEventSubscription, UpdateEventSubscription,
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
