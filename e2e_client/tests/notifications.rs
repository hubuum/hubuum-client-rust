use e2e_client::harness::{AsyncE2EHarness, E2EHarness};
use e2e_client::naming::unique_case_prefix;
use hubuum_client::{
    EventDeliveryPolicy, EventDeliveryPurpose, EventNotificationRequest, EventSubscriptionFilter,
    NewEventSink, NewEventSubscription, PrincipalKind, TaskKind, UpdateEventSink,
    UpdateEventSubscription,
};
use serde_json::json;

macro_rules! notifications {
    ($harness:ident, $send:ident) => {{
        let client = &$harness.client;
        let prefix = unique_case_prefix("notifications");
        let sink = $send!(client.event_sinks().create_raw(NewEventSink {
            name: format!("{prefix}-sink"),
            config: Some(json!({
                "url_secret_ref": "unresolved_test_url",
                "body_template": r#"{"text":{{ (test_marker ~ summary) | tojson }}}"#
            })),
            enabled: Some(false),
            delivery_policy: Some(EventDeliveryPolicy::new(60_000).unwrap()),
            ..Default::default()
        })).unwrap();
        assert_eq!(sink.delivery_policy.as_ref().unwrap().min_interval_ms(), Some(60_000));

        let subscriptions = client.system_event_subscriptions();
        let me = $send!(client.me()).unwrap();
        let subscription = $send!(subscriptions.create(NewEventSubscription {
                sink_id: sink.id,
                name: format!("{prefix}-subscription"),
                entity_types: vec!["authentication".into()],
                actions: vec!["succeeded".into()],
                enabled: Some(false),
                filter: Some(EventSubscriptionFilter {
                    subject_principal_ids: Some(vec![me.principal.principal_id]),
                    subject_identity_scopes: Some(vec!["local".into()]),
                    subject_is_admin: Some(true),
                    ..Default::default()
                }),
 description: None,
 routing: None
})).unwrap();
        let subscription_id = subscription.id;
        let filter = subscription.filter.as_ref().unwrap();
        assert_eq!(filter.subject_is_admin, Some(true));
        assert_eq!(filter.subject_principal_ids.as_ref().unwrap(), &[me.principal.principal_id]);
        let fetched = $send!(subscriptions.get(subscription_id)).unwrap();
        assert_eq!(fetched.id, subscription_id);
        let listed = $send!(subscriptions.list()).unwrap();
        assert!(listed.iter().any(|item| item.id == subscription_id));
        let updated = $send!(subscriptions.update(subscription_id, UpdateEventSubscription {
            description:Some("updated system subscription".into()),
            filter:Some(EventSubscriptionFilter { task_kinds:Some(vec![TaskKind::Backup]), ..Default::default() }),
            entity_types:Some(vec!["task".into()]), actions:Some(vec!["failed".into()]),
            ..Default::default()
        })).unwrap();
        assert_eq!(updated.description, "updated system subscription");
        assert_eq!(updated.filter.unwrap().task_kinds, Some(vec![TaskKind::Backup]));

        let logins = $send!(client.events().entity_type("authentication").action("succeeded").all()).unwrap();
        let subject = logins.iter().filter_map(|event| event.subject().unwrap())
            .find(|subject| subject.principal_id == me.principal.principal_id).expect("login subject");
        assert!(subject.is_admin);
        assert_eq!(subject.kind, PrincipalKind::Human);
        assert_eq!(subject.identity_scope, "local");

        let health = $send!(client.event_deliveries().health()).unwrap();
        let system_health = health.subscriptions.iter()
            .find(|item| item.subscription_id == subscription_id).unwrap();
        assert_eq!(system_health.collection_id, None);

        // Use the real sink-created event; preview/test deliberately bypass filters.
        let events = $send!(client.events().entity_type("event_sink").entity_id(sink.id.get()).action("created").all()).unwrap();
        let input = EventNotificationRequest { subscription_id, event_id:events[0].event_id.clone() };
        let preview = $send!(client.preview_event_notification(sink.id, input.clone())).unwrap();
        assert!(preview.payload["text"].as_str().unwrap().starts_with("[TEST]"));
        let delivery = $send!(client.test_event_notification(sink.id, input)).unwrap();
        assert_eq!(delivery.purpose, EventDeliveryPurpose::Test);
        assert_eq!(delivery.event_id, events[0].id);
        let fetched = $send!(client.event_deliveries().get(delivery.id)).unwrap();
        assert_eq!(fetched.purpose, EventDeliveryPurpose::Test);

        let cleared = $send!(client.event_sinks().update_raw(sink.id, UpdateEventSink {
            delivery_policy: Some(EventDeliveryPolicy::default()),
            ..Default::default()
        })).unwrap();
        assert!(cleared.delivery_policy.as_ref().is_none_or(|policy| policy.min_interval_ms().is_none()));
        $send!(subscriptions.delete(subscription_id)).unwrap();
        $send!(client.event_sinks().delete(sink.id)).unwrap();
    }};
}

#[test]
#[ignore = "requires Docker and Hubuum server v0.0.19 image"]
fn blocking_system_notifications_and_nullable_health() {
    let harness = E2EHarness::from_env().unwrap();
    macro_rules! send {
        ($value:expr) => {
            $value
        };
    }
    notifications!(harness, send);
}

#[tokio::test]
#[ignore = "requires Docker and Hubuum server v0.0.19 image"]
async fn async_system_notifications_and_nullable_health() {
    let harness = AsyncE2EHarness::from_env().await.unwrap();
    macro_rules! send {
        ($value:expr) => {
            $value.await
        };
    }
    notifications!(harness, send);
}
