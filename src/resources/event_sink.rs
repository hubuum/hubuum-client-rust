use crate::{
    endpoints::Endpoint,
    resources::ResourceId,
    types::{
        EventSink, EventSinkGet, EventSinkKind, FilterOperator, NewEventSink, QueryFilter,
        UpdateEventSink,
    },
};

#[derive(
    Default, Debug, serde::Serialize, serde::Deserialize, Clone, Copy, PartialEq, Eq, Hash,
)]
#[serde(transparent)]
pub struct EventSinkId(i32);

impl EventSinkId {
    pub fn new(value: i32) -> Self {
        Self(value)
    }

    pub fn get(self) -> i32 {
        self.0
    }
}

impl std::fmt::Display for EventSinkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for EventSinkId {
    type Err = <i32 as std::str::FromStr>::Err;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse::<i32>().map(Self)
    }
}

impl From<i32> for EventSinkId {
    fn from(value: i32) -> Self {
        Self(value)
    }
}

impl From<&EventSinkId> for EventSinkId {
    fn from(value: &EventSinkId) -> Self {
        *value
    }
}

impl From<EventSinkId> for i32 {
    fn from(value: EventSinkId) -> Self {
        value.0
    }
}

impl PartialEq<i32> for EventSinkId {
    fn eq(&self, other: &i32) -> bool {
        self.0 == *other
    }
}

impl PartialEq<EventSinkId> for i32 {
    fn eq(&self, other: &EventSinkId) -> bool {
        *self == other.0
    }
}

impl ResourceId for EventSinkId {
    fn new(value: i32) -> Self {
        Self(value)
    }

    fn get(self) -> i32 {
        self.0
    }
}

impl crate::client::GetID for EventSink {
    fn id(&self) -> Self::Id {
        self.id
    }
}

impl std::fmt::Display for EventSink {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl crate::resources::sealed::Sealed for EventSink {}

impl crate::resources::ApiResource for EventSink {
    type Id = EventSinkId;
    type GetParams = EventSinkGet;
    type GetOutput = EventSink;
    type PostParams = NewEventSink;
    type PostOutput = EventSink;
    type PatchParams = UpdateEventSink;
    type PatchOutput = EventSink;
    type DeleteParams = ();
    type DeleteOutput = ();

    const COLLECTION_ENDPOINT: Endpoint = Endpoint::EventSinks;
    const ITEM_ENDPOINT: Option<Endpoint> = Some(Endpoint::EventSinksById);
    const ID_PARAM: &'static str = "sink_id";

    fn endpoint(&self) -> Endpoint {
        Self::COLLECTION_ENDPOINT
    }

    fn build_params(filters: Vec<(String, FilterOperator, String)>) -> Vec<QueryFilter> {
        filters
            .into_iter()
            .map(|(key, operator, value)| QueryFilter {
                key,
                value,
                operator,
            })
            .collect()
    }

    fn filters_from_get(params: Self::GetParams) -> Vec<QueryFilter> {
        let mut queries = vec![];
        let mut push = |key: &str, value: String| {
            queries.push(QueryFilter {
                key: key.to_string(),
                value,
                operator: FilterOperator::Equals { is_negated: false },
            });
        };
        if let Some(id) = params.id {
            push("id", id.to_string());
        }
        if let Some(name) = params.name {
            push("name", name);
        }
        if let Some(kind) = params.kind {
            push("kind", event_sink_kind_value(kind).to_string());
        }
        if let Some(enabled) = params.enabled {
            push("enabled", enabled.to_string());
        }
        queries
    }
}

fn event_sink_kind_value(kind: EventSinkKind) -> &'static str {
    match kind {
        EventSinkKind::Webhook => "webhook",
        EventSinkKind::Amqp => "amqp",
        EventSinkKind::ValkeyStream => "valkey_stream",
        EventSinkKind::Email => "email",
        EventSinkKind::Unknown => "unknown",
    }
}
