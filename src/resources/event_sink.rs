use crate::{
    endpoints::Endpoint,
    types::{
        EventSink, EventSinkGet, EventSinkKind, FilterOperator, NewEventSink, QueryFilter,
        UpdateEventSink,
    },
};

impl crate::client::GetID for EventSink {
    fn id(&self) -> i32 {
        self.id
    }
}

impl std::fmt::Display for EventSink {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl crate::resources::ApiResource for EventSink {
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
    }
}
