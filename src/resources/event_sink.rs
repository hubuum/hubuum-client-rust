use crate::ApiError;
use crate::{
    endpoints::Endpoint,
    resources::ResourceId,
    types::{
        CollectionEventSink, CollectionEventSinkGet, EventSink, EventSinkGet, EventSinkKind,
        FilterOperator, NewEventSink, QueryFilter, UpdateEventSink,
    },
};

crate::types::id::define_id!(EventSinkId, i32);

impl ResourceId for EventSinkId {
    fn new(value: i32) -> Result<Self, ApiError> {
        Self::new(value)
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
    type PostBuilder = Option<NewEventSink>;
    fn finish_post(builder: Self::PostBuilder) -> Result<Self::PostParams, ApiError> {
        builder.ok_or(ApiError::MissingRequiredField { field: "params" })
    }
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

impl crate::client::GetID for CollectionEventSink {
    fn id(&self) -> Self::Id {
        self.id
    }
}

impl std::fmt::Display for CollectionEventSink {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl crate::resources::sealed::Sealed for CollectionEventSink {}

impl crate::resources::ApiResource for CollectionEventSink {
    type Id = EventSinkId;
    type GetParams = CollectionEventSinkGet;
    type GetOutput = CollectionEventSink;
    type PostParams = NewEventSink;
    type PostBuilder = Option<NewEventSink>;
    fn finish_post(builder: Self::PostBuilder) -> Result<Self::PostParams, ApiError> {
        builder.ok_or(ApiError::MissingRequiredField { field: "params" })
    }
    type PostOutput = CollectionEventSink;
    type PatchParams = UpdateEventSink;
    type PatchOutput = CollectionEventSink;
    type DeleteParams = ();
    type DeleteOutput = ();

    const COLLECTION_ENDPOINT: Endpoint = Endpoint::CollectionEventSinks;
    const ITEM_ENDPOINT: Option<Endpoint> = Some(Endpoint::CollectionEventSinksById);
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
        queries
    }
}
