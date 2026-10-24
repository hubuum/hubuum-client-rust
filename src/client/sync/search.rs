use super::*;

impl Client<Authenticated> {
    /// Expand a root object's visible neighborhood without changing search results.
    /// The server can reject traversal work or report concurrent changes; no cursor is returned.
    pub fn hydrate_search(
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

pub(super) struct BlockingSearchStream<T> {
    pub(super) response: StreamingResponse,
    pub(super) decoder: SearchSseDecoder<T>,
    pub(super) pending_events: std::collections::VecDeque<Result<T, ApiError>>,
    pub(super) buffer: Box<[u8; 8192]>,
    pub(super) finished: bool,
}

impl<T> BlockingSearchStream<T> {
    pub(super) fn new(
        response: StreamingResponse,
        max_event_bytes: usize,
        parse_event: fn(String, String) -> Result<T, ApiError>,
    ) -> Self {
        Self {
            response,
            decoder: SearchSseDecoder::new(max_event_bytes, parse_event),
            pending_events: std::collections::VecDeque::new(),
            buffer: Box::new([0; 8192]),
            finished: false,
        }
    }
}

impl<T> Iterator for BlockingSearchStream<T> {
    type Item = Result<T, ApiError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        if let Some(event) = self.pending_events.pop_front() {
            if event.is_err() {
                self.finished = true;
            }
            return Some(event);
        }

        loop {
            match std::io::Read::read(&mut self.response, self.buffer.as_mut_slice()) {
                Ok(0) => {
                    self.finished = true;
                    self.pending_events.extend(self.decoder.finish());
                    return self.pending_events.pop_front();
                }
                Ok(bytes_read) => {
                    self.pending_events
                        .extend(self.decoder.push_bytes(&self.buffer[..bytes_read]));
                    if let Some(event) = self.pending_events.pop_front() {
                        if event.is_err() {
                            self.finished = true;
                        }
                        return Some(event);
                    }
                }
                Err(error) => {
                    self.finished = true;
                    return Some(Err(ApiError::Io(error)));
                }
            }
        }
    }
}

pub struct BlockingUnifiedSearchStream {
    pub(super) inner: BlockingSearchStream<UnifiedSearchEvent>,
}

impl BlockingUnifiedSearchStream {
    pub(super) fn new(response: StreamingResponse, max_event_bytes: usize) -> Self {
        Self {
            inner: BlockingSearchStream::new(
                response,
                max_event_bytes,
                UnifiedSearchEvent::from_sse_parts,
            ),
        }
    }
}

impl Iterator for BlockingUnifiedSearchStream {
    type Item = Result<UnifiedSearchEvent, ApiError>;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

pub struct BlockingStructuredSearchStream {
    pub(super) inner: BlockingSearchStream<StructuredSearchEvent>,
}

impl BlockingStructuredSearchStream {
    pub(super) fn new(response: StreamingResponse, max_event_bytes: usize) -> Self {
        Self {
            inner: BlockingSearchStream::new(
                response,
                max_event_bytes,
                StructuredSearchEvent::from_sse_parts,
            ),
        }
    }
}

impl Iterator for BlockingStructuredSearchStream {
    type Item = Result<StructuredSearchEvent, ApiError>;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

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

    pub fn send(self) -> Result<UnifiedSearchResponse, ApiError> {
        let mut query_params = self.query_params;
        query_params.push(QueryFilter::raw("q", self.query));

        self.client
            .request_with_endpoint::<EmptyPostParams, UnifiedSearchResponse>(
                reqwest::Method::GET,
                &Endpoint::Search,
                UrlParams::default(),
                query_params,
                EmptyPostParams,
            )?
            .ok_or(ApiError::EmptyResult(
                "Unified search returned empty result".into(),
            ))
    }

    #[deprecated(since = "0.3.0", note = "use send()")]
    pub fn execute(self) -> Result<UnifiedSearchResponse, ApiError> {
        self.send()
    }

    pub fn stream(self) -> Result<BlockingUnifiedSearchStream, ApiError> {
        let max_event_bytes = self.client.options().max_response_body_bytes;
        let mut query_params = self.query_params;
        query_params.push(QueryFilter::raw("q", self.query));

        let response = self.client.request_stream_with_endpoint(
            reqwest::Method::GET,
            &Endpoint::SearchStream,
            UrlParams::default(),
            query_params,
            EmptyPostParams,
        )?;

        Ok(BlockingUnifiedSearchStream::new(response, max_event_bytes))
    }

    pub fn collect_stream(self) -> Result<Vec<UnifiedSearchEvent>, ApiError> {
        self.stream()?.collect()
    }
}

/// An authenticated structured search operation.
pub struct StructuredSearchOp {
    pub(super) client: Client<Authenticated>,
    pub(super) request: StructuredSearchRequest,
}

impl StructuredSearchOp {
    pub fn send(self) -> Result<StructuredSearchResponse, ApiError> {
        self.request.validate()?;
        self.client
            .request_with_endpoint(
                reqwest::Method::POST,
                &Endpoint::Search,
                UrlParams::default(),
                vec![],
                self.request,
            )?
            .ok_or_else(|| ApiError::EmptyResult("Structured search returned empty result".into()))
    }

    /// Decode SSE incrementally, bounding each event by `max_response_body_bytes`.
    pub fn stream(self) -> Result<BlockingStructuredSearchStream, ApiError> {
        self.request.validate()?;
        let response = self.client.request_stream_with_endpoint(
            reqwest::Method::POST,
            &Endpoint::SearchStream,
            UrlParams::default(),
            vec![],
            self.request,
        )?;
        Ok(BlockingStructuredSearchStream::new(
            response,
            self.client.options().max_response_body_bytes,
        ))
    }

    pub fn collect_stream(self) -> Result<Vec<StructuredSearchEvent>, ApiError> {
        self.stream()?.collect()
    }
}
