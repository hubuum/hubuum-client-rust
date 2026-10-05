use e2e_client::harness::{AsyncE2EHarness, E2EHarness};
use e2e_client::naming::unique_case_prefix;
use hubuum_client::{
    EventDelivery, EventDeliveryPolicy, EventDeliveryPurpose, EventSubscriptionFilter,
    NewEventSink, NewEventSubscription, TaskKind, UpdateEventSink,
};
use serde_json::{Value, json};

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

        let subscriptions = "/api/v1/system-event-subscriptions";
        let subscription: Value = $send!(client.raw("POST".parse().unwrap(), subscriptions)
            .json(&NewEventSubscription {
                sink_id: sink.id,
                name: format!("{prefix}-subscription"),
                entity_types: vec!["task".into()],
                actions: vec!["failed".into()],
                enabled: Some(false),
                filter: Some(EventSubscriptionFilter {
                    task_kinds: Some(vec![TaskKind::Backup]),
                    ..Default::default()
                }),
                ..Default::default()
            }).unwrap().send()).unwrap();
        let subscription_id = subscription["id"].as_i64().unwrap();
        assert!(subscription.get("collection_id").is_none());
        assert_eq!(subscription["filter"]["task_kinds"], json!(["backup"]));
        let path = format!("{subscriptions}/{subscription_id}");
        let fetched: Value = $send!(client.raw("GET".parse().unwrap(), &path).send()).unwrap();
        assert_eq!(fetched["id"], subscription_id);
        let listed: Vec<Value> = $send!(client.raw("GET".parse().unwrap(), subscriptions).send()).unwrap();
        assert!(listed.iter().any(|item| item["id"] == subscription_id));
        let updated: Value = $send!(client.raw("PATCH".parse().unwrap(), &path)
            .json(&json!({"description":"updated system subscription"})).unwrap().send()).unwrap();
        assert_eq!(updated["description"], "updated system subscription");

        let health = $send!(client.event_deliveries().health()).unwrap();
        let system_health = health.subscriptions.iter()
            .find(|item| i64::from(item.subscription_id.get()) == subscription_id).unwrap();
        assert_eq!(system_health.collection_id, None);

        // Use the real sink-created event; preview/test deliberately bypass filters.
        let events: Vec<Value> = $send!(client.raw("GET".parse().unwrap(), "/api/v1/events")
            .query_param("entity_type", "event_sink")
            .query_param("entity_id", sink.id)
            .query_param("action", "created").send()).unwrap();
        let input = json!({"subscription_id":subscription_id,"event_id":events[0]["event_id"]});
        let preview: Value = $send!(client.raw("POST".parse().unwrap(), format!("/api/v1/event-sinks/{}/preview", sink.id))
            .json(&input).unwrap().send()).unwrap();
        assert!(preview["payload"]["text"].as_str().unwrap().starts_with("[TEST]"));
        let delivery: EventDelivery = $send!(client.raw("POST".parse().unwrap(), format!("/api/v1/event-sinks/{}/test", sink.id))
            .json(&input).unwrap().send()).unwrap();
        assert_eq!(delivery.purpose, EventDeliveryPurpose::Test);
        assert_eq!(delivery.event_id, events[0]["id"].as_i64().unwrap());
        let fetched = $send!(client.event_deliveries().get(delivery.id)).unwrap();
        assert_eq!(fetched.purpose, EventDeliveryPurpose::Test);

        let cleared = $send!(client.event_sinks().update_raw(sink.id, UpdateEventSink {
            delivery_policy: Some(EventDeliveryPolicy::default()),
            ..Default::default()
        })).unwrap();
        assert!(cleared.delivery_policy.as_ref().is_none_or(|policy| policy.min_interval_ms().is_none()));
        $send!(client.raw("DELETE".parse().unwrap(), path).send_optional::<Value>()).unwrap();
        $send!(client.event_sinks().delete(sink.id)).unwrap();
    }};
}

#[test]
#[ignore = "requires Docker and Hubuum server v0.0.17 image"]
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
#[ignore = "requires Docker and Hubuum server v0.0.17 image"]
async fn async_system_notifications_and_nullable_health() {
    let harness = AsyncE2EHarness::from_env().await.unwrap();
    macro_rules! send {
        ($value:expr) => {
            $value.await
        };
    }
    notifications!(harness, send);
}
