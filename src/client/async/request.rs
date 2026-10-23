use super::*;
use crate::client::shared::EndpointRequest;

pub(super) struct StreamingResponse {
    pub(super) headers: reqwest::header::HeaderMap,
    pub(super) content_length: Option<u64>,
    pub(super) body: std::pin::Pin<
        Box<dyn futures_core::Stream<Item = Result<bytes::Bytes, ApiError>> + Send + 'static>,
    >,
}

impl StreamingResponse {
    pub(super) fn headers(&self) -> &reqwest::header::HeaderMap {
        &self.headers
    }

    pub(super) fn content_length(&self) -> Option<u64> {
        self.content_length
    }

    pub(super) fn into_body(
        self,
    ) -> std::pin::Pin<
        Box<dyn futures_core::Stream<Item = Result<bytes::Bytes, ApiError>> + Send + 'static>,
    > {
        self.body
    }
}

impl Client<Authenticated> {
    pub fn raw(&self, method: reqwest::Method, path: impl Into<String>) -> RawRequest {
        RawRequest {
            client: self.clone(),
            request: shared::RawRequestParts {
                method,
                path: path.into(),
                path_has_encoded_segments: false,
                query: Vec::new(),
                headers: Vec::new(),
                body: None,
            },
        }
    }

    pub(super) fn raw_with_encoded_segments(
        &self,
        method: reqwest::Method,
        path: impl Into<String>,
    ) -> RawRequest {
        RawRequest {
            client: self.clone(),
            request: shared::RawRequestParts {
                method,
                path: path.into(),
                path_has_encoded_segments: true,
                query: Vec::new(),
                headers: Vec::new(),
                body: None,
            },
        }
    }

    pub(crate) async fn request_with_endpoint_raw<T: Serialize>(
        &self,
        method: reqwest::Method,
        endpoint: &Endpoint,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
        post_params: T,
    ) -> Result<shared::RawResponse, ApiError> {
        self.request_endpoint(EndpointRequest {
            method,
            endpoint,
            url_params,
            query_params,
            body: post_params,
            headers: &[],
        })
        .await
    }

    pub(super) async fn request_stream_with_endpoint<T: Serialize>(
        &self,
        method: reqwest::Method,
        endpoint: &Endpoint,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
        post_params: T,
    ) -> Result<StreamingResponse, ApiError> {
        let token = self.ready_token().await?;
        TraceSpan::request("stream", &method, endpoint.path())
            .run_async(async {
                use futures_util::StreamExt;

                let plan = EndpointRequest {
                    method: method.clone(),
                    endpoint,
                    url_params,
                    query_params,
                    body: post_params,
                    headers: &[],
                }
                .prepare(self.base_url(), &token)?
                .plan;
                let request_url = plan.url.to_string();
                debug!("{} {}", method, shared::redacted_url_for_log(&request_url));
                if let Some(transport) = self.transport() {
                    let response = self
                        .execute_transport_with_retry(&method, false, transport.as_ref(), plan)
                        .await?;
                    let response = shared::check_transport_response_success(
                        &method,
                        &request_url,
                        response,
                        self.options().max_error_body_bytes,
                    )?;
                    let content_length =
                        shared::transport_content_length(&response.headers, response.body.len());
                    let body = futures_util::stream::once(async move {
                        Ok::<_, ApiError>(bytes::Bytes::from(response.body))
                    });
                    return Ok(StreamingResponse {
                        headers: response.headers,
                        content_length,
                        body: diagnostics::stream(Box::pin(body)),
                    });
                }

                let request = plan.into_async_request(self.http_client());
                let response = self.send_with_retry(&method, false, request).await?;
                let response = self.check_success(&method, &request_url, response).await?;
                let headers = response.headers().clone();
                let content_length = response.content_length();
                let body = response
                    .bytes_stream()
                    .map(|chunk| chunk.map_err(ApiError::from));
                Ok(StreamingResponse {
                    headers,
                    content_length,
                    body: diagnostics::stream(Box::pin(body)),
                })
            })
            .await
    }

    pub(crate) async fn request_endpoint<T: Serialize>(
        &self,
        request: EndpointRequest<'_, T>,
    ) -> Result<shared::RawResponse, ApiError> {
        let token = self.ready_token().await?;
        let span = TraceSpan::request("request", &request.method, request.endpoint.path());
        let operation = async {
            self.execute_prepared(request.prepare(self.base_url(), &token)?)
                .await
        };
        span.run_async(operation).await
    }

    pub(super) async fn execute_prepared(
        &self,
        prepared: shared::PreparedRequest,
    ) -> Result<shared::RawResponse, ApiError> {
        let shared::PreparedRequest {
            plan,
            has_idempotency_key,
        } = prepared;
        let method = plan.method.clone();
        let request_url = plan.url.to_string();
        debug!("{} {}", method, shared::redacted_url_for_log(&request_url));
        if let Some(transport) = self.transport() {
            let response = self
                .execute_transport_with_retry(
                    &method,
                    has_idempotency_key,
                    transport.as_ref(),
                    plan,
                )
                .await?;
            return shared::process_transport_response(
                &method,
                &request_url,
                response,
                self.options(),
            );
        }
        let request = plan.into_async_request(self.http_client());
        let now = std::time::Instant::now();
        let response = self
            .send_with_retry(&method, has_idempotency_key, request)
            .await?;
        trace!("Request took {:?}", now.elapsed());
        let response = self.check_success(&method, &request_url, response).await?;
        let status = response.status();
        let headers = response.headers().clone();
        let body =
            shared::read_async_body(response, self.options().max_response_body_bytes).await?;
        shared::RawResponse::new(status, &headers, body)
    }

    pub async fn request_with_endpoint<T: Serialize, U: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        endpoint: &Endpoint,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
        post_params: T,
    ) -> Result<Option<U>, ApiError> {
        let raw = self
            .request_with_endpoint_raw(
                method.clone(),
                endpoint,
                url_params,
                query_params,
                post_params,
            )
            .await?;
        shared::parse_response(&method, raw.status, raw.body)
    }

    pub async fn request<R: ApiResource, T: Serialize, U: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
        post_params: T,
    ) -> Result<Option<U>, ApiError> {
        self.request_with_endpoint(
            method,
            &R::COLLECTION_ENDPOINT,
            url_params,
            query_params,
            post_params,
        )
        .await
    }

    pub async fn get<R: ApiResource, F: IntoQueryFilters<R>>(
        &self,
        url_params: UrlParams,
        filter: F,
    ) -> Result<Vec<R::GetOutput>, ApiError> {
        self.request::<R, _, _>(
            reqwest::Method::GET,
            url_params,
            filter.into_query_filters(),
            EmptyPostParams,
        )
        .await
        .and_then(|opt| opt.ok_or(ApiError::EmptyResult("GET returned empty result".into())))
    }

    pub(crate) async fn search_resource<R: ApiResource>(
        &self,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
    ) -> Result<Vec<R::GetOutput>, ApiError> {
        self.request::<R, _, _>(
            reqwest::Method::GET,
            url_params,
            query_params,
            EmptyPostParams,
        )
        .await
        .and_then(|opt| opt.ok_or(ApiError::EmptyResult("SEARCH returned empty result".into())))
    }

    pub(crate) async fn search_resource_page<R: ApiResource>(
        &self,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
    ) -> Result<shared::Page<R::GetOutput>, ApiError> {
        let raw = self
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &R::COLLECTION_ENDPOINT,
                url_params,
                query_params,
                EmptyPostParams,
            )
            .await?;
        shared::parse_page_response(&reqwest::Method::GET, raw)
    }

    pub async fn post<R: ApiResource>(
        &self,
        url_params: UrlParams,
        params: R::PostParams,
    ) -> Result<R::PostOutput, ApiError> {
        self.request::<R, _, _>(reqwest::Method::POST, url_params, vec![], params)
            .await
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("POST returned empty result".into())))
    }

    pub async fn patch<R: ApiResource, I>(
        &self,
        id: I,
        url_params: UrlParams,
        params: R::PatchParams,
    ) -> Result<R::PatchOutput, ApiError>
    where
        I: Into<R::Id>,
    {
        let id = id.into();
        let mut url_params = url_params;
        url_params.push(("patch_id".into(), id.to_string().into()));
        self.request::<R, _, _>(reqwest::Method::PATCH, url_params, vec![], params)
            .await
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("PATCH returned empty result".into())))
    }

    pub(super) async fn patch_with_headers<R: ApiResource, I>(
        &self,
        id: I,
        mut url_params: UrlParams,
        params: R::PatchParams,
        headers: &[(&str, String)],
    ) -> Result<R::PatchOutput, ApiError>
    where
        I: Into<R::Id>,
    {
        url_params.push(("patch_id".into(), id.into().to_string().into()));
        let raw = self
            .request_endpoint(EndpointRequest {
                method: reqwest::Method::PATCH,
                endpoint: &R::COLLECTION_ENDPOINT,
                url_params,
                query_params: vec![],
                body: params,
                headers,
            })
            .await?;
        shared::parse_response(&reqwest::Method::PATCH, raw.status, raw.body)?
            .ok_or_else(|| ApiError::EmptyResult("Conditional PATCH returned empty result".into()))
    }

    pub async fn delete<R: ApiResource, I>(
        &self,
        id: I,
        url_params: UrlParams,
    ) -> Result<(), ApiError>
    where
        I: Into<R::Id>,
    {
        let id = id.into();
        let mut url_params = url_params;
        url_params.push(("delete_id".into(), id.to_string().into()));
        self.request::<R, _, DeleteResponse>(
            reqwest::Method::DELETE,
            url_params,
            vec![],
            EmptyPostParams,
        )
        .await
        .map(|_| ())
    }

    pub(super) async fn delete_with_headers<R: ApiResource, I>(
        &self,
        id: I,
        mut url_params: UrlParams,
        headers: &[(&str, String)],
    ) -> Result<(), ApiError>
    where
        I: Into<R::Id>,
    {
        url_params.push(("delete_id".into(), id.into().to_string().into()));
        self.request_endpoint(EndpointRequest {
            method: reqwest::Method::DELETE,
            endpoint: &R::COLLECTION_ENDPOINT,
            url_params,
            query_params: vec![],
            body: EmptyPostParams,
            headers,
        })
        .await?;
        Ok(())
    }
}

pub struct RawRequest {
    pub(super) client: Client<Authenticated>,
    pub(super) request: shared::RawRequestParts,
}

impl RawRequest {
    pub fn query_param(mut self, key: impl Into<String>, value: impl ToString) -> Self {
        self.request.query.push((key.into(), value.to_string()));
        self
    }

    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.request.headers.push((name.into(), value.into()));
        self
    }

    pub fn json<T: Serialize>(mut self, value: &T) -> Result<Self, ApiError> {
        self.request.body = Some(serde_json::to_vec(value)?);
        Ok(self)
    }

    pub(super) async fn execute(self) -> Result<shared::RawResponse, ApiError> {
        let token = self.client.ready_token().await?;
        let span = TraceSpan::request("raw", &self.request.method, "(custom route)");
        let operation = async {
            let prepared = self.request.prepare(self.client.base_url(), &token)?;
            self.client.execute_prepared(prepared).await
        };
        span.run_async(operation).await
    }

    pub async fn send_optional<T: DeserializeOwned>(self) -> Result<Option<T>, ApiError> {
        let method = self.request.method.clone();
        let raw = self.execute().await?;
        shared::parse_response(&method, raw.status, raw.body)
    }

    pub async fn send<T: DeserializeOwned>(self) -> Result<T, ApiError> {
        self.send_optional()
            .await?
            .ok_or_else(|| ApiError::EmptyResult("Raw request returned an empty response".into()))
    }

    pub async fn send_text(self) -> Result<String, ApiError> {
        Ok(self.execute().await?.body)
    }
}
