use super::*;

impl Client<Authenticated> {
    /// Expand a root object's visible neighborhood without changing search results.
    /// The server can reject traversal work or report concurrent changes; no cursor is returned.
    pub async fn hydrate_search(
        &self,
        request: SearchHydrationRequest,
    ) -> Result<SearchHydrationResponse, ApiError> {
        self.request_with_endpoint::<SearchHydrationRequest, SearchHydrationResponse>(
            reqwest::Method::POST,
            &Endpoint::SearchHydration,
            UrlParams::default(),
            vec![],
            request,
        )
        .await
        .and_then(|value| {
            value.ok_or_else(|| {
                ApiError::EmptyResult("Search hydration returned empty result".into())
            })
        })
    }
}

pub struct UnifiedSearchRequest {
    pub(super) client: Client<Authenticated>,
    pub(super) query: String,
    pub(super) query_params: Vec<QueryFilter>,
}

pub type UnifiedSearchEventStream = std::pin::Pin<
    Box<dyn futures_core::Stream<Item = Result<UnifiedSearchEvent, ApiError>> + Send + 'static>,
>;

impl UnifiedSearchRequest {
    pub(super) fn new(client: Client<Authenticated>, query: String) -> Self {
        Self {
            client,
            query,
            query_params: Vec::new(),
        }
    }

    pub fn kinds<I>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = UnifiedSearchKind>,
    {
        let joined = kinds
            .into_iter()
            .map(|kind| kind.to_string())
            .collect::<Vec<_>>()
            .join(",");

        if !joined.is_empty() {
            shared::set_raw_query_param(&mut self.query_params, "kinds", joined);
        } else {
            shared::remove_raw_query_param(&mut self.query_params, "kinds");
        }
        self
    }

    pub fn limit_per_kind(mut self, limit: usize) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "limit_per_kind", limit.to_string());
        self
    }

    pub fn cursor_collections(mut self, cursor: impl Into<String>) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "cursor_collections", cursor.into());
        self
    }

    pub fn cursor_classes(mut self, cursor: impl Into<String>) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "cursor_classes", cursor.into());
        self
    }

    pub fn cursor_objects(mut self, cursor: impl Into<String>) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "cursor_objects", cursor.into());
        self
    }

    pub fn search_class_schema(mut self, enabled: bool) -> Self {
        shared::set_raw_query_param(
            &mut self.query_params,
            "search_class_schema",
            enabled.to_string(),
        );
        self
    }

    pub fn search_object_data(mut self, enabled: bool) -> Self {
        shared::set_raw_query_param(
            &mut self.query_params,
            "search_object_data",
            enabled.to_string(),
        );
        self
    }

    pub async fn send(self) -> Result<UnifiedSearchResponse, ApiError> {
        let mut query_params = self.query_params;
        query_params.push(QueryFilter::raw("q", self.query));

        self.client
            .request_with_endpoint::<EmptyPostParams, UnifiedSearchResponse>(
                reqwest::Method::GET,
                &Endpoint::Search,
                UrlParams::default(),
                query_params,
                EmptyPostParams,
            )
            .await?
            .ok_or(ApiError::EmptyResult(
                "Unified search returned empty result".into(),
            ))
    }

    #[deprecated(since = "0.3.0", note = "use send()")]
    pub async fn execute(self) -> Result<UnifiedSearchResponse, ApiError> {
        self.send().await
    }

    pub async fn stream(self) -> Result<UnifiedSearchEventStream, ApiError> {
        let mut query_params = self.query_params;
        query_params.push(QueryFilter::raw("q", self.query));

        let response = self
            .client
            .request_stream_with_endpoint(
                reqwest::Method::GET,
                &Endpoint::SearchStream,
                UrlParams::default(),
                query_params,
                EmptyPostParams,
            )
            .await?;

        Ok(search_event_stream(
            response,
            self.client.options().max_response_body_bytes,
            UnifiedSearchEvent::from_sse_parts,
        ))
    }

    pub async fn collect_stream(self) -> Result<Vec<UnifiedSearchEvent>, ApiError> {
        use futures_util::TryStreamExt;

        self.stream().await?.try_collect().await
    }
}

pub(super) fn search_event_stream<T: Send + 'static>(
    response: StreamingResponse,
    max_event_bytes: usize,
    parse_event: fn(String, String) -> Result<T, ApiError>,
) -> ItemStream<T> {
    use futures_util::StreamExt;
    let mut bytes = response.into_body();
    Box::pin(async_stream::try_stream! {
        let mut decoder = SearchSseDecoder::new(max_event_bytes, parse_event);
        while let Some(chunk) = bytes.next().await {
            for event in decoder.push_bytes(&chunk?) { yield event?; }
        }
        for event in decoder.finish() { yield event?; }
    })
}

pub type StructuredSearchEventStream = ItemStream<StructuredSearchEvent>;

/// An authenticated structured search operation.
pub struct StructuredSearchOp {
    pub(super) client: Client<Authenticated>,
    pub(super) request: StructuredSearchRequest,
}

impl StructuredSearchOp {
    pub async fn send(self) -> Result<StructuredSearchResponse, ApiError> {
        self.request.validate()?;
        self.client
            .request_with_endpoint(
                reqwest::Method::POST,
                &Endpoint::Search,
                UrlParams::default(),
                vec![],
                self.request,
            )
            .await?
            .ok_or_else(|| ApiError::EmptyResult("Structured search returned empty result".into()))
    }

    /// Decode SSE incrementally, bounding each event by `max_response_body_bytes`.
    pub async fn stream(self) -> Result<StructuredSearchEventStream, ApiError> {
        self.request.validate()?;
        let response = self
            .client
            .request_stream_with_endpoint(
                reqwest::Method::POST,
                &Endpoint::SearchStream,
                UrlParams::default(),
                vec![],
                self.request,
            )
            .await?;
        Ok(search_event_stream(
            response,
            self.client.options().max_response_body_bytes,
            StructuredSearchEvent::from_sse_parts,
        ))
    }

    pub async fn collect_stream(self) -> Result<Vec<StructuredSearchEvent>, ApiError> {
        use futures_util::TryStreamExt;
        self.stream().await?.try_collect().await
    }
}
