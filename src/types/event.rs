use serde::{Deserialize, Serialize};

use crate::resources::{CollectionId, EventSinkId, UserId};

use super::{EventDeliveryId, EventSubscriptionId, HubuumDateTime};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct EventResponse {
    pub id: i64,
    pub event_id: String,
    pub occurred_at: HubuumDateTime,
    pub entity_type: String,
    #[serde(default)]
    pub entity_id: Option<i32>,
    #[serde(default)]
    pub entity_name: Option<String>,
    #[serde(default)]
    pub collection_id: Option<CollectionId>,
    pub action: String,
    pub actor_kind: String,
    #[serde(default)]
    pub actor_user_id: Option<UserId>,
    #[serde(default)]
    pub correlation_id: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    pub summary: String,
    #[serde(default)]
    pub before: Option<serde_json::Value>,
    #[serde(default)]
    pub after: Option<serde_json::Value>,
    pub metadata: serde_json::Value,
    pub schema_version: i32,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum EventSinkKind {
    #[default]
    Webhook,
    Amqp,
    ValkeyStream,
    Email,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Default)]
#[non_exhaustive]
pub struct EventSink {
    pub id: EventSinkId,
    pub name: String,
    pub kind: EventSinkKind,
    pub config: serde_json::Value,
    pub enabled: bool,
    #[serde(default)]
    pub secret_ref: Option<String>,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct NewEventSink {
    pub name: String,
    pub kind: EventSinkKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UpdateEventSink {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<EventSinkKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct EventSinkGet {
    pub id: Option<EventSinkId>,
    pub name: Option<String>,
    pub kind: Option<EventSinkKind>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct EventSubscriptionFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_kinds: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_user_ids: Option<Vec<UserId>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_ids: Option<Vec<i32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collection_ids: Option<Vec<CollectionId>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_collection_ids: Option<Vec<CollectionId>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_ids: Option<Vec<String>>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct EventSubscription {
    pub id: EventSubscriptionId,
    pub collection_id: CollectionId,
    pub sink_id: EventSinkId,
    pub name: String,
    pub description: String,
    pub entity_types: Vec<String>,
    pub actions: Vec<String>,
    pub routing: serde_json::Value,
    pub enabled: bool,
    #[serde(default)]
    pub filter: Option<EventSubscriptionFilter>,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct NewEventSubscription {
    pub sink_id: EventSinkId,
    pub name: String,
    pub entity_types: Vec<String>,
    pub actions: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<EventSubscriptionFilter>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UpdateEventSubscription {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink_id: Option<EventSinkId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_types: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<EventSubscriptionFilter>,
}

fn redacted_if_present<T>(value: &Option<T>) -> Option<&'static str> {
    value.as_ref().map(|_| "[REDACTED]")
}

impl std::fmt::Debug for EventSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventSink")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("config", &"[REDACTED]")
            .field("enabled", &self.enabled)
            .field("secret_ref", &redacted_if_present(&self.secret_ref))
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl std::fmt::Debug for NewEventSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewEventSink")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("config", &redacted_if_present(&self.config))
            .field("enabled", &self.enabled)
            .field("secret_ref", &redacted_if_present(&self.secret_ref))
            .finish()
    }
}

impl std::fmt::Debug for UpdateEventSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateEventSink")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("config", &redacted_if_present(&self.config))
            .field("enabled", &self.enabled)
            .field("secret_ref", &redacted_if_present(&self.secret_ref))
            .finish()
    }
}

impl std::fmt::Debug for EventSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventSubscription")
            .field("id", &self.id)
            .field("collection_id", &self.collection_id)
            .field("sink_id", &self.sink_id)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("entity_types", &self.entity_types)
            .field("actions", &self.actions)
            .field("routing", &"[REDACTED]")
            .field("enabled", &self.enabled)
            .field("filter", &self.filter)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl std::fmt::Debug for NewEventSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewEventSubscription")
            .field("sink_id", &self.sink_id)
            .field("name", &self.name)
            .field("entity_types", &self.entity_types)
            .field("actions", &self.actions)
            .field("description", &self.description)
            .field("routing", &redacted_if_present(&self.routing))
            .field("enabled", &self.enabled)
            .field("filter", &self.filter)
            .finish()
    }
}

impl std::fmt::Debug for UpdateEventSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateEventSubscription")
            .field("sink_id", &self.sink_id)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("entity_types", &self.entity_types)
            .field("actions", &self.actions)
            .field("routing", &redacted_if_present(&self.routing))
            .field("enabled", &self.enabled)
            .field("filter", &self.filter)
            .finish()
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventDeliveryStatus {
    Pending,
    InFlight,
    Succeeded,
    Failed,
    Dead,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct EventDelivery {
    pub id: EventDeliveryId,
    pub event_id: i64,
    pub subscription_id: EventSubscriptionId,
    pub status: EventDeliveryStatus,
    pub attempts: i32,
    pub next_attempt_at: HubuumDateTime,
    #[serde(default)]
    pub claim_token: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub locked_until: Option<HubuumDateTime>,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
}

impl std::fmt::Debug for EventDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventDelivery")
            .field("id", &self.id)
            .field("event_id", &self.event_id)
            .field("subscription_id", &self.subscription_id)
            .field("status", &self.status)
            .field("attempts", &self.attempts)
            .field("next_attempt_at", &self.next_attempt_at)
            .field(
                "claim_token",
                &self.claim_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "last_error",
                &self.last_error.as_ref().map(|_| "[REDACTED]"),
            )
            .field("locked_until", &self.locked_until)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventDeliveryUpdateResponse {
    pub delivery: EventDelivery,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventDeliveryStatusCounts {
    pub total: i64,
    pub pending: i64,
    pub in_flight: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub dead: i64,
    pub retryable: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventWorkerWakeupStats {
    pub notifications_sent: i64,
    pub notification_wakeups: i64,
    pub poll_wakeups: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventWorkerHealth {
    pub workers_configured: usize,
    pub batch_size: usize,
    pub poll_interval_ms: i64,
    pub lock_timeout_ms: i64,
    pub wakeups: EventWorkerWakeupStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventFanoutHealth {
    pub pending_events: i64,
    pub in_flight_events: i64,
    pub stale_claims: i64,
    #[serde(default)]
    pub oldest_pending_age_seconds: Option<i64>,
    pub worker: EventWorkerHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventDeliveryQueueHealth {
    pub counts: EventDeliveryStatusCounts,
    pub stale_claims: i64,
    #[serde(default)]
    pub oldest_due_age_seconds: Option<i64>,
    pub worker: EventWorkerHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventSinkDeliveryHealth {
    pub sink_id: EventSinkId,
    pub sink_name: String,
    pub sink_kind: String,
    pub sink_enabled: bool,
    pub subscription_count: i64,
    pub counts: EventDeliveryStatusCounts,
    pub stale_claims: i64,
    #[serde(default)]
    pub oldest_due_age_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventSubscriptionDeliveryHealth {
    pub subscription_id: EventSubscriptionId,
    pub subscription_name: String,
    pub collection_id: CollectionId,
    pub sink_id: EventSinkId,
    pub sink_name: String,
    pub sink_kind: String,
    pub subscription_enabled: bool,
    pub sink_enabled: bool,
    pub counts: EventDeliveryStatusCounts,
    pub stale_claims: i64,
    #[serde(default)]
    pub oldest_due_age_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventDeliveryHealthResponse {
    pub fanout: EventFanoutHealth,
    pub delivery: EventDeliveryQueueHealth,
    pub sinks: Vec<EventSinkDeliveryHealth>,
    pub subscriptions: Vec<EventSubscriptionDeliveryHealth>,
}

#[cfg(test)]
mod tests {
    use super::{
        EventDelivery, EventSink, EventSinkKind, EventSubscription, NewEventSink,
        NewEventSubscription, UpdateEventSink, UpdateEventSubscription,
    };
    use crate::EventSinkId;
    use serde_json::json;

    #[test]
    fn delivery_debug_redacts_claim_and_error_details() {
        let delivery: EventDelivery = serde_json::from_value(json!({
            "id": 41,
            "event_id": 42,
            "subscription_id": 43,
            "status": "failed",
            "attempts": 2,
            "next_attempt_at": "2026-07-23T08:00:00Z",
            "claim_token": "delivery-claim-secret",
            "last_error": "sink rejected bearer sink-secret",
            "locked_until": "2026-07-23T08:01:00Z",
            "created_at": "2026-07-23T07:59:00Z",
            "updated_at": "2026-07-23T08:00:00Z"
        }))
        .expect("delivery fixture should deserialize");

        let diagnostic = format!("{delivery:?}");
        assert!(diagnostic.contains("claim_token: Some(\"[REDACTED]\")"));
        assert!(diagnostic.contains("last_error: Some(\"[REDACTED]\")"));
        assert!(!diagnostic.contains("delivery-claim-secret"));
        assert!(!diagnostic.contains("sink-secret"));
        assert_eq!(
            delivery.claim_token.as_deref(),
            Some("delivery-claim-secret")
        );
        assert_eq!(
            delivery.last_error.as_deref(),
            Some("sink rejected bearer sink-secret")
        );
    }

    #[test]
    fn event_configuration_debug_redacts_sink_and_routing_details() {
        let sink: EventSink = serde_json::from_value(json!({
            "id": 1,
            "name": "sink",
            "kind": "webhook",
            "config": {"url": "https://example.invalid?token=response-secret"},
            "enabled": true,
            "secret_ref": "response-secret-ref",
            "created_at": "2026-07-23T08:00:00Z",
            "updated_at": "2026-07-23T08:00:00Z"
        }))
        .unwrap();
        let create_sink = NewEventSink {
            name: "sink".into(),
            kind: EventSinkKind::Webhook,
            config: Some(json!({"authorization": "create-secret"})),
            enabled: Some(true),
            secret_ref: Some("create-secret-ref".into()),
        };
        let update_sink = UpdateEventSink {
            config: Some(json!({"password": "update-secret"})),
            secret_ref: Some("update-secret-ref".into()),
            ..Default::default()
        };
        let subscription: EventSubscription = serde_json::from_value(json!({
            "id": 2,
            "collection_id": 3,
            "sink_id": 1,
            "name": "subscription",
            "description": "",
            "entity_types": ["object"],
            "actions": ["updated"],
            "routing": {"url": "https://example.invalid?token=routing-secret"},
            "enabled": true,
            "filter": null,
            "created_at": "2026-07-23T08:00:00Z",
            "updated_at": "2026-07-23T08:00:00Z"
        }))
        .unwrap();
        let create_subscription = NewEventSubscription {
            sink_id: EventSinkId::new(1),
            name: "subscription".into(),
            entity_types: vec!["object".into()],
            actions: vec!["updated".into()],
            routing: Some(json!({"token": "create-routing-secret"})),
            ..Default::default()
        };
        let update_subscription = UpdateEventSubscription {
            routing: Some(json!({"token": "update-routing-secret"})),
            ..Default::default()
        };

        let debug = format!(
            "{sink:?} {create_sink:?} {update_sink:?} {subscription:?} \
             {create_subscription:?} {update_subscription:?}"
        );
        for secret in [
            "response-secret",
            "response-secret-ref",
            "create-secret",
            "create-secret-ref",
            "update-secret",
            "update-secret-ref",
            "routing-secret",
            "create-routing-secret",
            "update-routing-secret",
        ] {
            assert!(!debug.contains(secret));
        }

        assert_eq!(
            create_sink.config.as_ref().unwrap()["authorization"],
            "create-secret"
        );
        assert_eq!(
            create_subscription.routing.as_ref().unwrap()["token"],
            "create-routing-secret"
        );
    }
}
