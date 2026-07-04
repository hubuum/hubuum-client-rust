use serde::{Deserialize, Serialize};

use super::HubuumDateTime;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    pub namespace_id: Option<i32>,
    pub action: String,
    pub actor_kind: String,
    #[serde(default)]
    pub actor_user_id: Option<i32>,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum EventSinkKind {
    #[default]
    Webhook,
    Amqp,
    ValkeyStream,
    Email,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct EventSink {
    pub id: i32,
    pub name: String,
    pub kind: EventSinkKind,
    pub config: serde_json::Value,
    pub enabled: bool,
    #[serde(default)]
    pub secret_ref: Option<String>,
    pub created_at: HubuumDateTime,
    pub updated_at: HubuumDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
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
    pub id: Option<i32>,
    pub name: Option<String>,
    pub kind: Option<EventSinkKind>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct EventSubscriptionFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_kinds: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_user_ids: Option<Vec<i32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_ids: Option<Vec<i32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_names: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace_ids: Option<Vec<i32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related_namespace_ids: Option<Vec<i32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventSubscription {
    pub id: i32,
    pub namespace_id: i32,
    pub sink_id: i32,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct NewEventSubscription {
    pub sink_id: i32,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UpdateEventSubscription {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sink_id: Option<i32>,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventDeliveryStatus {
    Pending,
    InFlight,
    Succeeded,
    Failed,
    Dead,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventDelivery {
    pub id: i64,
    pub event_id: i64,
    pub subscription_id: i32,
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
    pub sink_id: i32,
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
    pub subscription_id: i32,
    pub subscription_name: String,
    pub namespace_id: i32,
    pub sink_id: i32,
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
