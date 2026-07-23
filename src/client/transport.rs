use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use reqwest::{Method, StatusCode, header::HeaderMap};

use crate::ApiError;

/// Transport-neutral HTTP request used by custom and mock transports.
#[derive(Clone)]
pub struct RequestPlan {
    pub method: Method,
    pub url: url::Url,
    pub headers: HeaderMap,
    body: Option<Arc<[u8]>>,
}

impl RequestPlan {
    pub fn new(method: Method, url: url::Url) -> Self {
        Self {
            method,
            url,
            headers: HeaderMap::new(),
            body: None,
        }
    }

    pub fn body(&self) -> &[u8] {
        self.body.as_deref().unwrap_or_default()
    }

    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(Arc::from(body.into()));
        self
    }
}

impl std::fmt::Debug for RequestPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestPlan")
            .field("method", &self.method)
            .field(
                "url",
                &super::shared::redacted_url_for_log(self.url.as_str()),
            )
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
            .field("body", &"[REDACTED]")
            .field("body_len", &self.body().len())
            .finish()
    }
}

#[derive(Clone)]
pub struct TransportResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for TransportResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportResponse")
            .field("status", &self.status)
            .field("header_names", &self.headers.keys().collect::<Vec<_>>())
            .field("body", &"[REDACTED]")
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl TransportResponse {
    pub fn json<T: serde::Serialize>(status: StatusCode, body: &T) -> Result<Self, ApiError> {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        Ok(Self {
            status,
            headers,
            body: serde_json::to_vec(body)?,
        })
    }

    pub fn empty(status: StatusCode) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: Vec::new(),
        }
    }
}

#[cfg(feature = "async")]
pub trait AsyncTransport: std::fmt::Debug + Send + Sync {
    fn execute<'a>(
        &'a self,
        request: RequestPlan,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TransportResponse, ApiError>> + Send + 'a>,
    >;
}

#[cfg(feature = "blocking")]
pub trait BlockingTransport: std::fmt::Debug + Send + Sync {
    fn execute(&self, request: RequestPlan) -> Result<TransportResponse, ApiError>;
}

#[derive(Debug, Clone, Default)]
pub struct MockTransport {
    state: Arc<Mutex<MockState>>,
}

#[derive(Debug, Default)]
struct MockState {
    requests: Vec<RequestPlan>,
    responses: VecDeque<TransportResponse>,
}

impl MockTransport {
    pub fn push_response(&self, response: TransportResponse) {
        self.state
            .lock()
            .expect("mock transport lock poisoned")
            .responses
            .push_back(response);
    }

    pub fn requests(&self) -> Vec<RequestPlan> {
        self.state
            .lock()
            .expect("mock transport lock poisoned")
            .requests
            .clone()
    }

    fn execute_inner(&self, request: RequestPlan) -> Result<TransportResponse, ApiError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ApiError::Transport("mock transport lock poisoned".into()))?;
        state.requests.push(request);
        state
            .responses
            .pop_front()
            .ok_or_else(|| ApiError::Transport("mock transport response queue is empty".into()))
    }
}

#[cfg(feature = "async")]
impl AsyncTransport for MockTransport {
    fn execute<'a>(
        &'a self,
        request: RequestPlan,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TransportResponse, ApiError>> + Send + 'a>,
    > {
        Box::pin(async move { self.execute_inner(request) })
    }
}

#[cfg(feature = "blocking")]
impl BlockingTransport for MockTransport {
    fn execute(&self, request: RequestPlan) -> Result<TransportResponse, ApiError> {
        self.execute_inner(request)
    }
}

#[cfg(test)]
mod tests {
    use super::RequestPlan;

    #[test]
    fn request_plan_clones_share_the_immutable_body() {
        let plan = RequestPlan::new(
            reqwest::Method::POST,
            url::Url::parse("https://example.invalid/api/v1/imports").unwrap(),
        )
        .with_body(vec![42; 1024]);

        let cloned = plan.clone();

        assert_eq!(cloned.body(), plan.body());
        assert!(std::ptr::eq(cloned.body(), plan.body()));
    }
}
