use super::*;
use crate::client::UrlParams;
use crate::client::transport::RequestPlan;
use crate::endpoints::Endpoint;
use crate::{ApiError, BaseUrl, QueryFilter, Token};
use reqwest::{
    Method,
    header::{AUTHORIZATION, CONTENT_TYPE, HeaderName, HeaderValue},
};
use serde::Serialize;

pub(crate) struct PreparedRequest {
    pub(crate) plan: RequestPlan,
    pub(crate) has_idempotency_key: bool,
}

pub(crate) struct EndpointRequest<'a, T> {
    pub(crate) method: Method,
    pub(crate) endpoint: &'a Endpoint,
    pub(crate) url_params: UrlParams,
    pub(crate) query_params: Vec<QueryFilter>,
    pub(crate) body: T,
    pub(crate) headers: &'a [(&'a str, String)],
}

impl<T: Serialize> EndpointRequest<'_, T> {
    pub(crate) fn prepare(
        self,
        base_url: &BaseUrl,
        token: &Token,
    ) -> Result<PreparedRequest, ApiError> {
        if !matches!(
            self.method,
            Method::GET | Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        ) {
            return Err(ApiError::UnsupportedHttpOperation(self.method.to_string()));
        }
        let url = build_request_url(
            &self.method,
            build_url(base_url, self.endpoint, &self.url_params),
            &self.url_params,
            self.query_params,
        )?;
        let has_idempotency_key = has_valid_idempotency_key(
            self.headers
                .iter()
                .map(|(name, value)| (*name, value.as_str())),
        )?;
        let plan =
            build_request_plan(&self.method, &url, &self.body, token.as_str(), self.headers)?;
        Ok(PreparedRequest {
            plan,
            has_idempotency_key,
        })
    }
}

pub(crate) struct RawRequestParts {
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) path_has_encoded_segments: bool,
    pub(crate) query: Vec<(String, String)>,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Option<Vec<u8>>,
}

impl RawRequestParts {
    pub(crate) fn prepare(
        self,
        base_url: &BaseUrl,
        token: &Token,
    ) -> Result<PreparedRequest, ApiError> {
        if self
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        {
            return Err(ApiError::Transport(
                "raw requests cannot override the Authorization header".into(),
            ));
        }
        let has_idempotency_key = has_valid_idempotency_key(
            self.headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        )?;
        let url = if self.path_has_encoded_segments {
            build_encoded_relative_url(base_url, &self.path, &self.query)?
        } else {
            build_relative_url(base_url, &self.path, &self.query)?
        };
        let mut plan = RequestPlan::new(self.method, url);
        plan.headers
            .insert(AUTHORIZATION, bearer_header_value(token.as_str())?);
        for (name, value) in self.headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|error| ApiError::Transport(error.to_string()))?;
            plan.headers.insert(name, sensitive_header_value(&value)?);
        }
        if let Some(body) = self.body {
            plan.headers
                .entry(CONTENT_TYPE)
                .or_insert(HeaderValue::from_static("application/json"));
            plan = plan.with_body(body);
        }
        Ok(PreparedRequest {
            plan,
            has_idempotency_key,
        })
    }
}

pub(crate) fn build_request_plan<T: Serialize>(
    method: &Method,
    request_url: &str,
    body: &T,
    bearer_token: &str,
    headers: &[(&str, String)],
) -> Result<RequestPlan, ApiError> {
    let url = url::Url::parse(request_url)?;
    let mut plan = RequestPlan::new(method.clone(), url);
    let authorization = bearer_header_value(bearer_token)?;
    plan.headers.insert(AUTHORIZATION, authorization);
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| ApiError::Transport(format!("invalid header name: {error}")))?;
        let value = sensitive_header_value(value)?;
        plan.headers.insert(name, value);
    }
    if matches!(*method, Method::POST | Method::PUT | Method::PATCH) {
        plan.headers
            .entry(CONTENT_TYPE)
            .or_insert(HeaderValue::from_static("application/json"));
        plan = plan.with_body(serde_json::to_vec(body)?);
    }
    Ok(plan)
}

pub(crate) fn build_unauthenticated_request_plan(
    method: &Method,
    request_url: &str,
    headers: &[(&str, String)],
) -> Result<RequestPlan, ApiError> {
    let url = url::Url::parse(request_url)?;
    let mut plan = RequestPlan::new(method.clone(), url);
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| ApiError::Transport(format!("invalid header name: {error}")))?;
        let value = sensitive_header_value(value)?;
        plan.headers.insert(name, value);
    }
    Ok(plan)
}

pub(crate) fn sensitive_header_value(value: &str) -> Result<HeaderValue, ApiError> {
    let mut value = HeaderValue::from_str(value)
        .map_err(|error| ApiError::Transport(format!("invalid header value: {error}")))?;
    value.set_sensitive(true);
    Ok(value)
}

pub(crate) fn bearer_header_value(token: &str) -> Result<HeaderValue, ApiError> {
    sensitive_header_value(&format!("Bearer {token}"))
}

pub(crate) fn build_unauthenticated_json_request_plan<T: Serialize>(
    method: &Method,
    request_url: &str,
    body: &T,
    headers: &[(&str, String)],
) -> Result<RequestPlan, ApiError> {
    let mut plan = build_unauthenticated_request_plan(method, request_url, headers)?;
    plan.headers
        .entry(CONTENT_TYPE)
        .or_insert(HeaderValue::from_static("application/json"));
    Ok(plan.with_body(serde_json::to_vec(body)?))
}
