use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use reqwest::{
    Method, StatusCode,
    header::{CONTENT_TYPE, HeaderMap, RETRY_AFTER},
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::any::type_name;
use std::borrow::Cow;
use std::collections::HashSet;
use std::marker::PhantomData;
use std::ops::Deref;

use super::{GetID, UrlParams};
use crate::QueryFilter;
use crate::endpoints::Endpoint;
use crate::errors::ApiError;
use crate::resources::ApiResource;
use crate::types::FilterOperator;
use crate::types::{BaseUrl, ExportContentType, IntoQueryTuples, TaskResponse};

pub(crate) const NEXT_CURSOR_HEADER: &str = "X-Next-Cursor";
pub(crate) const TOTAL_COUNT_HEADER: &str = "X-Total-Count";
pub(crate) const PAGE_LIMIT_HEADER: &str = "X-Page-Limit";

pub const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TaskWaitOptions {
    poll_interval: std::time::Duration,
    timeout: Option<std::time::Duration>,
}

impl TaskWaitOptions {
    pub(crate) fn with_poll_interval(mut self, poll_interval: std::time::Duration) -> Self {
        self.poll_interval = poll_interval;
        self
    }

    pub(crate) fn with_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    pub(crate) fn poll_interval(self) -> std::time::Duration {
        self.poll_interval
    }

    pub(crate) fn timeout(self) -> Option<std::time::Duration> {
        self.timeout
    }
}

impl Default for TaskWaitOptions {
    fn default() -> Self {
        Self {
            poll_interval: std::time::Duration::from_secs(1),
            timeout: Some(std::time::Duration::from_secs(300)),
        }
    }
}

/// Retry configuration applied to requests that are safe to replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: usize,
    pub initial_delay: std::time::Duration,
    pub max_delay: std::time::Duration,
}

impl RetryPolicy {
    pub fn disabled() -> Self {
        Self {
            max_attempts: 1,
            ..Self::default()
        }
    }

    pub(crate) fn should_retry_status(&self, status: StatusCode) -> bool {
        matches!(status.as_u16(), 408 | 429 | 502 | 503 | 504)
    }

    pub(crate) fn delay(&self, attempt: usize, headers: Option<&HeaderMap>) -> std::time::Duration {
        if let Some(delay) = headers.and_then(retry_after) {
            return delay.min(self.max_delay);
        }

        let exponent = attempt.saturating_sub(1).min(31) as u32;
        let ceiling = self
            .initial_delay
            .saturating_mul(2_u32.saturating_pow(exponent))
            .min(self.max_delay);
        if ceiling.is_zero() {
            return ceiling;
        }

        let max_millis = ceiling.as_millis().min(u64::MAX as u128) as u64;
        std::time::Duration::from_millis(fastrand::u64(0..=max_millis))
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: std::time::Duration::from_millis(100),
            max_delay: std::time::Duration::from_secs(2),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ClientOptions {
    pub max_response_body_bytes: usize,
    pub max_error_body_bytes: usize,
    pub retry_policy: RetryPolicy,
    pub max_auto_pages: usize,
    pub max_auto_items: usize,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            max_response_body_bytes: DEFAULT_MAX_RESPONSE_BODY_BYTES,
            max_error_body_bytes: DEFAULT_MAX_ERROR_BODY_BYTES,
            retry_policy: RetryPolicy::default(),
            max_auto_pages: 10_000,
            max_auto_items: 1_000_000,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct AutoPaginationGuard {
    max_pages: usize,
    max_items: usize,
    pages: usize,
    items: usize,
}

impl AutoPaginationGuard {
    pub(crate) fn new(options: &ClientOptions) -> Self {
        Self {
            max_pages: options.max_auto_pages,
            max_items: options.max_auto_items,
            pages: 0,
            items: 0,
        }
    }

    pub(crate) fn before_request(&self) -> Result<(), ApiError> {
        if self.pages >= self.max_pages || self.items >= self.max_items {
            return Err(self.limit_error());
        }
        Ok(())
    }

    pub(crate) fn record_page(&mut self, items: usize) -> Result<(), ApiError> {
        self.pages = self.pages.saturating_add(1);
        self.items = self.items.saturating_add(items);
        if self.items > self.max_items {
            return Err(self.limit_error());
        }
        Ok(())
    }

    fn limit_error(&self) -> ApiError {
        ApiError::PaginationLimit {
            pages: self.pages,
            items: self.items,
        }
    }
}

pub(crate) fn is_replay_safe(method: &Method, has_idempotency_key: bool) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) || has_idempotency_key
}

pub(crate) fn has_valid_idempotency_key<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<bool, ApiError> {
    let mut present = false;
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("idempotency-key") {
            if value.trim().is_empty() {
                return Err(ApiError::InvalidIdempotencyKey);
            }
            present = true;
        }
    }
    Ok(present)
}

pub(crate) fn redacted_url_for_log(value: &str) -> String {
    let Ok(mut url) = url::Url::parse(value) else {
        return "[INVALID URL]".to_string();
    };
    redact_url_query(&mut url);
    url.to_string()
}

fn redact_url_query(url: &mut url::Url) {
    let keys = url
        .query_pairs()
        .map(|(key, _)| key.into_owned())
        .collect::<Vec<_>>();
    if !keys.is_empty() {
        url.set_query(None);
        let mut pairs = url.query_pairs_mut();
        for key in keys {
            pairs.append_pair(&key, "[REDACTED]");
        }
    }
}

pub(crate) fn redact_reqwest_error(mut error: reqwest::Error) -> reqwest::Error {
    if let Some(url) = error.url_mut() {
        redact_url_query(url);
    }
    error
}

pub(crate) fn build_relative_url(
    base_url: &BaseUrl,
    path: &str,
    query: &[(String, String)],
) -> Result<url::Url, ApiError> {
    build_relative_url_impl(base_url, path, query, true)
}

/// Join a relative path assembled internally from fixed endpoint text and
/// dynamic segments escaped by [`build_url`].
///
/// Percent-encoded slashes in those opaque segments must not be decoded for
/// traversal validation: a name such as `a/../b` is one encoded segment, not
/// three structural path segments. Public raw request paths continue to use
/// [`build_relative_url`] and its stricter decoded-path checks.
pub(crate) fn build_encoded_relative_url(
    base_url: &BaseUrl,
    path: &str,
    query: &[(String, String)],
) -> Result<url::Url, ApiError> {
    reject_url_dot_segments(path)?;
    build_relative_url_impl(base_url, path, query, false)
}

fn reject_url_dot_segments(value: &str) -> Result<(), ApiError> {
    let path = value.split(['?', '#']).next().unwrap_or(value);
    if path.split('/').any(|segment| {
        matches!(segment, "." | "..")
            || segment.eq_ignore_ascii_case("%2e")
            || segment.eq_ignore_ascii_case("%2e%2e")
    }) {
        return Err(ApiError::InvalidUrlPath(
            "standalone `.` and `..` segments cannot be addressed because URL parsing normalizes them"
                .into(),
        ));
    }
    Ok(())
}

fn build_relative_url_impl(
    base_url: &BaseUrl,
    path: &str,
    query: &[(String, String)],
    validate_decoded_path: bool,
) -> Result<url::Url, ApiError> {
    let invalid_path = || {
        ApiError::InvalidBaseUrl(
            "raw request paths must stay within the configured base URL".into(),
        )
    };
    if path
        .chars()
        .any(|character| matches!(character, '\\' | '?' | '#'))
        || url::Url::parse(path).is_ok()
    {
        return Err(invalid_path());
    }

    // Accept one leading slash for API-style paths, but reject network-path
    // references and decoded dot segments before URL resolution.
    let relative_path = path.strip_prefix('/').unwrap_or(path);
    if relative_path.starts_with('/') {
        return Err(invalid_path());
    }
    if validate_decoded_path {
        let decoded_path = percent_decode_str(relative_path)
            .decode_utf8()
            .map_err(|_| invalid_path())?;
        if decoded_path.starts_with('/')
            || decoded_path.starts_with('\\')
            || decoded_path
                .split(['/', '\\'])
                .any(|segment| matches!(segment, "." | ".."))
        {
            return Err(invalid_path());
        }
    }

    let mut url = base_url.as_url().join(relative_path)?;
    if url.origin() != base_url.as_url().origin()
        || !url.path().starts_with(base_url.as_url().path())
    {
        return Err(invalid_path());
    }
    if !query.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in query {
            pairs.append_pair(key, value);
        }
    }
    Ok(url)
}

pub(crate) fn build_request_plan<T: Serialize>(
    method: &Method,
    request_url: &str,
    body: &T,
    bearer_token: &str,
    headers: &[(&str, String)],
) -> Result<super::transport::RequestPlan, ApiError> {
    let url = url::Url::parse(request_url)?;
    let mut plan = super::transport::RequestPlan::new(method.clone(), url);
    let authorization = reqwest::header::HeaderValue::from_str(&format!("Bearer {bearer_token}"))
        .map_err(|error| {
        ApiError::Transport(format!("invalid authorization header: {error}"))
    })?;
    plan.headers
        .insert(reqwest::header::AUTHORIZATION, authorization);
    for (name, value) in headers {
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| ApiError::Transport(format!("invalid header name: {error}")))?;
        let value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|error| ApiError::Transport(format!("invalid header value: {error}")))?;
        plan.headers.insert(name, value);
    }
    if matches!(*method, Method::POST | Method::PUT | Method::PATCH) {
        plan.headers.entry(reqwest::header::CONTENT_TYPE).or_insert(
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        plan = plan.with_body(serde_json::to_vec(body)?);
    }
    Ok(plan)
}

pub(crate) fn build_unauthenticated_request_plan(
    method: &Method,
    request_url: &str,
    headers: &[(&str, String)],
) -> Result<super::transport::RequestPlan, ApiError> {
    let url = url::Url::parse(request_url)?;
    let mut plan = super::transport::RequestPlan::new(method.clone(), url);
    for (name, value) in headers {
        let name = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|error| ApiError::Transport(format!("invalid header name: {error}")))?;
        let value = reqwest::header::HeaderValue::from_str(value)
            .map_err(|error| ApiError::Transport(format!("invalid header value: {error}")))?;
        plan.headers.insert(name, value);
    }
    Ok(plan)
}

pub(crate) fn build_unauthenticated_json_request_plan<T: Serialize>(
    method: &Method,
    request_url: &str,
    body: &T,
    headers: &[(&str, String)],
) -> Result<super::transport::RequestPlan, ApiError> {
    let mut plan = build_unauthenticated_request_plan(method, request_url, headers)?;
    plan.headers.entry(reqwest::header::CONTENT_TYPE).or_insert(
        reqwest::header::HeaderValue::from_static("application/json"),
    );
    Ok(plan.with_body(serde_json::to_vec(body)?))
}

pub(crate) fn process_transport_response(
    method: &Method,
    request_url: &str,
    response: super::transport::TransportResponse,
    options: &ClientOptions,
) -> Result<RawResponse, ApiError> {
    let response = check_transport_response_success(
        method,
        request_url,
        response,
        options.max_error_body_bytes,
    )?;
    if response.body.len() > options.max_response_body_bytes {
        return Err(ApiError::ResponseTooLarge {
            limit: options.max_response_body_bytes,
            content_length: Some(response.body.len() as u64),
        });
    }
    let (next_cursor, total_count, page_limit, content_type) = response_metadata(&response.headers);
    Ok(RawResponse {
        status: response.status,
        body: decode_response_text(response.body)?,
        next_cursor,
        total_count,
        page_limit,
        content_type,
    })
}

pub(crate) fn check_transport_response_success(
    method: &Method,
    request_url: &str,
    mut response: super::transport::TransportResponse,
    max_error_body_bytes: usize,
) -> Result<super::transport::TransportResponse, ApiError> {
    if !response.status.is_success() {
        response.body.truncate(max_error_body_bytes);
        let body = String::from_utf8_lossy(&response.body).into_owned();
        return Err(ApiError::HttpWithBody {
            method: method.clone(),
            url: request_url.to_string(),
            status: response.status,
            message: parse_http_error_message(&body),
            body,
        });
    }
    Ok(response)
}

pub(crate) fn transport_content_length(headers: &HeaderMap, body_len: usize) -> Option<u64> {
    headers
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .or(Some(body_len as u64))
}

fn retry_after(headers: &HeaderMap) -> Option<std::time::Duration> {
    retry_after_at(headers, std::time::SystemTime::now())
}

fn retry_after_at(headers: &HeaderMap, now: std::time::SystemTime) -> Option<std::time::Duration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?;
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(std::time::Duration::from_secs(seconds));
    }

    let retry_at = httpdate::parse_http_date(value).ok()?;
    Some(
        retry_at
            .duration_since(now)
            .unwrap_or(std::time::Duration::ZERO),
    )
}

fn decode_response_text(body: Vec<u8>) -> Result<String, ApiError> {
    String::from_utf8(body).map_err(|error| {
        ApiError::DeserializationError(format!(
            "response body is not valid UTF-8 at byte {}",
            error.utf8_error().valid_up_to()
        ))
    })
}

#[cfg(feature = "async")]
pub(crate) async fn read_async_body(
    response: reqwest::Response,
    limit: usize,
) -> Result<String, ApiError> {
    use futures_util::StreamExt;

    let content_length = response.content_length();
    if content_length.is_some_and(|length| length > limit as u64) {
        return Err(ApiError::ResponseTooLarge {
            limit,
            content_length,
        });
    }

    let mut body = Vec::with_capacity(content_length.unwrap_or(0).min(limit as u64) as usize);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(ApiError::ResponseTooLarge {
                limit,
                content_length,
            });
        }
        body.extend_from_slice(&chunk);
    }
    decode_response_text(body)
}

#[cfg(feature = "async")]
pub(crate) async fn read_async_body_preview(response: reqwest::Response, limit: usize) -> String {
    use futures_util::StreamExt;

    let mut body = Vec::with_capacity(limit.min(4096));
    let mut stream = response.bytes_stream();
    while body.len() < limit {
        let Some(chunk) = stream.next().await else {
            break;
        };
        let Ok(chunk) = chunk else {
            break;
        };
        let remaining = limit - body.len();
        body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }
    String::from_utf8_lossy(&body).into_owned()
}

#[cfg(feature = "blocking")]
pub(crate) fn read_blocking_body(
    response: reqwest::blocking::Response,
    limit: usize,
) -> Result<String, ApiError> {
    use std::io::Read;

    let content_length = response.content_length();
    if content_length.is_some_and(|length| length > limit as u64) {
        return Err(ApiError::ResponseTooLarge {
            limit,
            content_length,
        });
    }

    let mut body = Vec::with_capacity(content_length.unwrap_or(0).min(limit as u64) as usize);
    response
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut body)?;
    if body.len() > limit {
        return Err(ApiError::ResponseTooLarge {
            limit,
            content_length,
        });
    }
    decode_response_text(body)
}

#[cfg(feature = "blocking")]
pub(crate) fn read_blocking_body_preview(
    response: reqwest::blocking::Response,
    limit: usize,
) -> String {
    use std::io::Read;

    let mut body = Vec::with_capacity(limit.min(4096));
    let _ = response.take(limit as u64).read_to_end(&mut body);
    String::from_utf8_lossy(&body).into_owned()
}

/// Characters that must be escaped when interpolating an opaque value into a
/// single URL path segment. Unreserved characters (including base64url's `-`
/// and `_`) are left untouched; reserved/delimiter characters are escaped.
const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b'\\')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}');

/// Percent-encode a value for safe use as a single URL path segment.
pub(crate) fn encode_path_segment(segment: &str) -> String {
    utf8_percent_encode(segment, PATH_SEGMENT).to_string()
}

/// Whether an opaque name cannot safely be represented as a URL path segment
/// by `url::Url`.
///
/// WHATWG URL parsing normalizes both literal and percent-encoded standalone
/// dot segments. Name-addressed scopes resolve these two valid names through
/// collection queries and continue on the equivalent ID-addressed routes.
pub(crate) fn requires_name_route_fallback(name: &str) -> bool {
    matches!(name, "." | "..")
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    /// Exact number of matching items across all pages, when supplied by the server.
    pub total_count: Option<u64>,
    /// Effective page size after applying the server's default and maximum.
    pub page_limit: Option<usize>,
}

impl<T> Page<T> {
    /// Number of items in this page.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether this page contains no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Whether the server supplied a cursor for a following page.
    pub fn has_next(&self) -> bool {
        self.next_cursor.is_some()
    }

    /// Iterate over page items without consuming the page metadata.
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.items.iter()
    }

    /// Consume the page and return its items.
    pub fn into_items(self) -> Vec<T> {
        self.items
    }
}

impl<T> Deref for Page<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl<T> AsRef<[T]> for Page<T> {
    fn as_ref(&self) -> &[T] {
        self
    }
}

impl<T> IntoIterator for Page<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Page<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RawResponse {
    pub status: StatusCode,
    pub body: String,
    pub next_cursor: Option<String>,
    pub total_count: Option<u64>,
    pub page_limit: Option<usize>,
    pub content_type: Option<ExportContentType>,
}

impl std::fmt::Debug for RawResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawResponse")
            .field("status", &self.status)
            .field("body", &"[REDACTED]")
            .field("body_len", &self.body.len())
            .field(
                "next_cursor",
                &self.next_cursor.as_ref().map(|_| "[REDACTED]"),
            )
            .field("total_count", &self.total_count)
            .field("page_limit", &self.page_limit)
            .field("content_type", &self.content_type)
            .finish()
    }
}

pub(crate) fn build_url(base_url: &BaseUrl, endpoint: &Endpoint, url_params: UrlParams) -> String {
    let mut url = format!("{}{}", base_url.as_str(), endpoint.trim_start_matches('/'));

    for (key, value) in url_params {
        url = url.replace(&format!("{{{key}}}"), &encode_path_segment(value.as_ref()));
    }
    url
}

pub(crate) fn build_request_url(
    method: &reqwest::Method,
    url: String,
    url_params: &UrlParams,
    query_params: Vec<QueryFilter>,
) -> Result<String, ApiError> {
    ensure_no_unresolved_url_params(&url)?;
    reject_url_dot_segments(&url)?;

    if *method == reqwest::Method::GET {
        validate_page_limits(&query_params)?;
        let query = query_params.into_query_string()?;
        if query.is_empty() {
            Ok(url)
        } else {
            Ok(format!("{url}?{query}"))
        }
    } else if *method == reqwest::Method::POST || *method == reqwest::Method::PUT {
        Ok(url)
    } else if *method == reqwest::Method::PATCH {
        let id = url_param(url_params, "patch_id").ok_or(ApiError::MissingUrlIdentifier)?;
        Ok(append_identifier(url, id))
    } else if *method == reqwest::Method::DELETE {
        match url_param(url_params, "delete_id") {
            Some(id) => Ok(append_identifier(url, id)),
            None => Ok(url),
        }
    } else {
        Err(ApiError::UnsupportedHttpOperation(method.to_string()))
    }
}

const MIN_PAGE_LIMIT: usize = 1;
const MAX_PAGE_LIMIT: usize = 250;

fn validate_page_limits(query_params: &[QueryFilter]) -> Result<(), ApiError> {
    for parameter in query_params.iter().filter(|parameter| {
        matches!(parameter.operator, FilterOperator::Raw)
            && matches!(parameter.key.as_str(), "limit" | "limit_per_kind")
    }) {
        let Ok(value) = parameter.value.parse::<usize>() else {
            continue;
        };
        if !(MIN_PAGE_LIMIT..=MAX_PAGE_LIMIT).contains(&value) {
            return Err(ApiError::InvalidPageLimit {
                value,
                min: MIN_PAGE_LIMIT,
                max: MAX_PAGE_LIMIT,
            });
        }
    }
    Ok(())
}

fn ensure_no_unresolved_url_params(url: &str) -> Result<(), ApiError> {
    if let Some(start) = url.find('{')
        && let Some(end_offset) = url[start + 1..].find('}')
    {
        let end = start + 1 + end_offset;
        return Err(ApiError::MissingUrlParameter(
            url[start + 1..end].to_string(),
        ));
    }

    Ok(())
}

fn append_identifier(url: String, id: &str) -> String {
    let id = encode_path_segment(id);
    if url.ends_with('/') {
        format!("{url}{id}")
    } else {
        format!("{url}/{id}")
    }
}

fn url_param<'a>(url_params: &'a UrlParams, key: &str) -> Option<&'a str> {
    url_params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_ref())
}

pub(crate) fn response_metadata(
    headers: &HeaderMap,
) -> (
    Option<String>,
    Option<u64>,
    Option<usize>,
    Option<ExportContentType>,
) {
    let next_cursor = headers
        .get(NEXT_CURSOR_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let total_count = headers
        .get(TOTAL_COUNT_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok());
    let page_limit = headers
        .get(PAGE_LIMIT_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok());
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(ExportContentType::from_header);
    (next_cursor, total_count, page_limit, content_type)
}

pub(crate) fn parse_http_error_message(body: &str) -> String {
    match serde_json::from_str::<Value>(body) {
        Ok(json) => json["message"]
            .as_str()
            .unwrap_or("Error without message.")
            .to_string(),
        Err(_) => body.to_string(),
    }
}

pub(crate) fn parse_response<U: DeserializeOwned>(
    method: &reqwest::Method,
    response_code: StatusCode,
    response_text: String,
) -> Result<Option<U>, ApiError> {
    if *method == reqwest::Method::DELETE {
        if response_text.trim().is_empty() {
            return Ok(None);
        }
        return Err(ApiError::DeserializationError(format!(
            "DELETE response contained {} unexpected bytes",
            response_text.len()
        )));
    }

    if response_code == StatusCode::NO_CONTENT || response_text.trim().is_empty() {
        return Ok(None);
    }

    let mut deserializer = serde_json::Deserializer::from_str(&response_text);
    let obj = serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
        ApiError::DeserializationError(format!(
            "failed to decode {} at {}: {}",
            type_name::<U>(),
            error.path(),
            error.inner()
        ))
    })?;
    deserializer.end().map_err(|error| {
        ApiError::DeserializationError(format!(
            "failed to decode {}: trailing data: {error}",
            type_name::<U>()
        ))
    })?;
    Ok(Some(obj))
}

pub(crate) fn parse_page_response<U: DeserializeOwned>(
    method: &reqwest::Method,
    raw: RawResponse,
) -> Result<Page<U>, ApiError> {
    let next_cursor = raw.next_cursor;
    let total_count = raw.total_count;
    let page_limit = raw.page_limit;
    let items: Vec<U> = parse_response(method, raw.status, raw.body)?
        .ok_or(ApiError::EmptyResult("GET returned empty result".into()))?;
    Ok(Page {
        items,
        next_cursor,
        total_count,
        page_limit,
    })
}

pub(crate) fn pagination_cursors(query_params: &[QueryFilter]) -> HashSet<String> {
    query_params
        .iter()
        .filter(|param| param.key == "cursor")
        .map(|param| param.value.clone())
        .collect()
}

pub(crate) fn set_raw_query_param(
    query_params: &mut Vec<QueryFilter>,
    key: impl Into<String>,
    value: impl Into<String>,
) {
    let key = key.into();
    remove_raw_query_param(query_params, &key);
    query_params.push(QueryFilter::raw(key, value));
}

pub(crate) fn remove_raw_query_param(query_params: &mut Vec<QueryFilter>, key: &str) {
    query_params.retain(|param| param.key != key || !matches!(param.operator, FilterOperator::Raw));
}

pub(crate) fn set_sort_query_param(
    query_params: &mut Vec<QueryFilter>,
    key: &'static str,
    value: String,
) {
    remove_raw_query_param(query_params, "sort");
    remove_raw_query_param(query_params, "order_by");
    set_raw_query_param(query_params, key, value);
}

pub(crate) fn advance_cursor(
    query_params: &mut Vec<QueryFilter>,
    seen_cursors: &mut HashSet<String>,
    cursor: String,
) -> Result<(), ApiError> {
    if !seen_cursors.insert(cursor.clone()) {
        return Err(ApiError::PaginationCycle(cursor));
    }

    set_raw_query_param(query_params, "cursor", cursor);
    Ok(())
}

/// Decode a raw-text response body (e.g. a freshly-minted token shown once).
///
/// The server may return the value as plain text or as a JSON string literal;
/// accept both and strip surrounding whitespace.
pub(crate) fn decode_raw_text(body: String) -> String {
    match serde_json::from_str::<String>(body.trim()) {
        Ok(s) => s,
        Err(_) => body.trim().to_string(),
    }
}

pub(crate) fn one_or_err<T>(mut v: Vec<T>) -> Result<T, ApiError> {
    let name = type_name::<T>();
    let name = name.rsplit("::").next().unwrap_or(name);

    if v.len() == 1 {
        Ok(v.pop().unwrap())
    } else if v.is_empty() {
        Err(ApiError::EmptyResult(format!("{name} not found")))
    } else {
        Err(ApiError::TooManyResults(format!(
            "Type: {name}, Count: {} (expected 1)",
            v.len()
        )))
    }
}

pub(crate) fn task_unsuccessful_error(task: &TaskResponse) -> ApiError {
    ApiError::TaskUnsuccessful {
        task_id: task.id,
        status: task.status,
    }
}

pub trait QueryFilterTarget: Sized {
    fn push_filter<K: Into<String>, V: ToString>(
        self,
        field: K,
        op: FilterOperator,
        value: V,
    ) -> Self;

    fn push_raw_param<K: Into<String>, V: ToString>(self, key: K, value: V) -> Self;
}

#[derive(Debug, Clone)]
pub struct QueryValueField<Q, V> {
    query: Q,
    field: &'static str,
    _phantom: PhantomData<V>,
}

impl<Q, V> QueryValueField<Q, V> {
    pub(crate) fn new(query: Q, field: &'static str) -> Self {
        Self {
            query,
            field,
            _phantom: PhantomData,
        }
    }
}

impl<Q: QueryFilterTarget, V: ToString> QueryValueField<Q, V> {
    pub fn eq(self, value: V) -> Q {
        self.query.push_filter(
            self.field,
            FilterOperator::Equals { is_negated: false },
            value,
        )
    }

    pub fn ne(self, value: V) -> Q {
        self.query.push_filter(
            self.field,
            FilterOperator::Equals { is_negated: true },
            value,
        )
    }
}

#[derive(Debug, Clone)]
pub struct QueryTextField<Q>(QueryValueField<Q, String>);

impl<Q> QueryTextField<Q> {
    pub(crate) fn new(query: Q, field: &'static str) -> Self {
        Self(QueryValueField::new(query, field))
    }
}

impl<Q: QueryFilterTarget> QueryTextField<Q> {
    pub fn eq(self, value: impl AsRef<str>) -> Q {
        self.0.eq(value.as_ref().to_string())
    }

    pub fn ne(self, value: impl AsRef<str>) -> Q {
        self.0.ne(value.as_ref().to_string())
    }

    pub fn ieq(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::IEquals { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_ieq(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::IEquals { is_negated: true },
            value.as_ref(),
        )
    }

    pub fn contains(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Contains { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_contains(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Contains { is_negated: true },
            value.as_ref(),
        )
    }

    pub fn icontains(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::IContains { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_icontains(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::IContains { is_negated: true },
            value.as_ref(),
        )
    }

    pub fn starts_with(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::StartsWith { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_starts_with(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::StartsWith { is_negated: true },
            value.as_ref(),
        )
    }

    pub fn istarts_with(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::IStartsWith { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_istarts_with(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::IStartsWith { is_negated: true },
            value.as_ref(),
        )
    }

    pub fn ends_with(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::EndsWith { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_ends_with(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::EndsWith { is_negated: true },
            value.as_ref(),
        )
    }

    pub fn iends_with(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::IEndsWith { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_iends_with(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::IEndsWith { is_negated: true },
            value.as_ref(),
        )
    }

    pub fn like(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Like { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_like(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Like { is_negated: true },
            value.as_ref(),
        )
    }

    pub fn regex(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Regex { is_negated: false },
            value.as_ref(),
        )
    }

    pub fn not_regex(self, value: impl AsRef<str>) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Regex { is_negated: true },
            value.as_ref(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct QueryNumericField<Q, V>(QueryValueField<Q, V>);

impl<Q, V> QueryNumericField<Q, V> {
    pub(crate) fn new(query: Q, field: &'static str) -> Self {
        Self(QueryValueField::new(query, field))
    }
}

impl<Q: QueryFilterTarget, V: ToString> QueryNumericField<Q, V> {
    pub fn eq(self, value: V) -> Q {
        self.0.eq(value)
    }

    pub fn ne(self, value: V) -> Q {
        self.0.ne(value)
    }

    pub fn gt(self, value: V) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Gt { is_negated: false },
            value,
        )
    }

    pub fn gte(self, value: V) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Gte { is_negated: false },
            value,
        )
    }

    pub fn lt(self, value: V) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Lt { is_negated: false },
            value,
        )
    }

    pub fn lte(self, value: V) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Lte { is_negated: false },
            value,
        )
    }

    pub fn between(self, start: V, end: V) -> Q {
        self.0.query.push_filter(
            self.0.field,
            FilterOperator::Between { is_negated: false },
            format!("{},{}", start.to_string(), end.to_string()),
        )
    }
}

#[derive(Debug, Clone)]
pub struct QueryBoolField<Q>(QueryValueField<Q, bool>);

impl<Q> QueryBoolField<Q> {
    pub(crate) fn new(query: Q, field: &'static str) -> Self {
        Self(QueryValueField::new(query, field))
    }
}

impl<Q: QueryFilterTarget> QueryBoolField<Q> {
    pub fn eq(self, value: bool) -> Q {
        self.0.eq(value)
    }

    pub fn ne(self, value: bool) -> Q {
        self.0.ne(value)
    }
}

#[derive(Debug, Clone)]
pub struct QueryJsonField<Q> {
    query: Q,
    field: &'static str,
    path: Vec<String>,
}

impl<Q> QueryJsonField<Q> {
    pub(crate) fn new(query: Q, field: &'static str) -> Self {
        Self {
            query,
            field,
            path: Vec::new(),
        }
    }
}

impl<Q: QueryFilterTarget> QueryJsonField<Q> {
    pub fn path<I, S>(mut self, path: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.path = path
            .into_iter()
            .map(|segment| segment.as_ref().to_string())
            .collect();
        self
    }

    fn encoded_value<V: ToString>(&self, value: V) -> String {
        if self.path.is_empty() {
            value.to_string()
        } else {
            format!("{}={}", self.path.join(","), value.to_string())
        }
    }

    pub fn eq<V: ToString>(self, value: V) -> Q {
        let value = self.encoded_value(value);
        self.query.push_filter(
            self.field,
            FilterOperator::Equals { is_negated: false },
            value,
        )
    }

    pub fn ne<V: ToString>(self, value: V) -> Q {
        let value = self.encoded_value(value);
        self.query.push_filter(
            self.field,
            FilterOperator::Equals { is_negated: true },
            value,
        )
    }

    pub fn gt<V: ToString>(self, value: V) -> Q {
        let value = self.encoded_value(value);
        self.query
            .push_filter(self.field, FilterOperator::Gt { is_negated: false }, value)
    }

    pub fn gte<V: ToString>(self, value: V) -> Q {
        let value = self.encoded_value(value);
        self.query
            .push_filter(self.field, FilterOperator::Gte { is_negated: false }, value)
    }

    pub fn lt<V: ToString>(self, value: V) -> Q {
        let value = self.encoded_value(value);
        self.query
            .push_filter(self.field, FilterOperator::Lt { is_negated: false }, value)
    }

    pub fn lte<V: ToString>(self, value: V) -> Q {
        let value = self.encoded_value(value);
        self.query
            .push_filter(self.field, FilterOperator::Lte { is_negated: false }, value)
    }

    pub fn between<V: ToString>(self, start: V, end: V) -> Q {
        let value = self.encoded_value(format!("{},{}", start.to_string(), end.to_string()));
        self.query.push_filter(
            self.field,
            FilterOperator::Between { is_negated: false },
            value,
        )
    }
}

#[derive(Clone, Serialize)]
pub struct Handle<C, T> {
    #[serde(skip)]
    client: C,
    #[serde(flatten)]
    resource: T,
}

impl<C, T> Handle<C, T>
where
    T: ApiResource + GetID + Default,
{
    pub fn new(client: C, resource: T) -> Self {
        Handle { client, resource }
    }

    pub fn resource(&self) -> &T {
        &self.resource
    }

    pub fn into_inner(self) -> T {
        self.resource
    }

    pub fn id(&self) -> T::Id {
        self.resource.id()
    }

    pub fn client(&self) -> &C {
        &self.client
    }
}

impl<C, T> Deref for Handle<C, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.resource
    }
}

impl<C, T> AsRef<T> for Handle<C, T> {
    fn as_ref(&self) -> &T {
        &self.resource
    }
}

pub(crate) fn select_id_lookup_params(id: impl ToString) -> (UrlParams, Vec<QueryFilter>) {
    let id = id.to_string();
    (
        vec![(Cow::Borrowed("id"), id.clone().into())],
        vec![QueryFilter {
            key: "id".to_string(),
            value: id,
            operator: FilterOperator::Equals { is_negated: false },
        }],
    )
}

pub(crate) fn select_name_lookup_params<T: ApiResource>(
    name: &str,
) -> (UrlParams, Vec<QueryFilter>) {
    (
        vec![(Cow::Borrowed(T::NAME_FIELD), name.to_string().into())],
        vec![QueryFilter {
            key: T::NAME_FIELD.to_string(),
            value: name.to_string(),
            operator: FilterOperator::Equals { is_negated: false },
        }],
    )
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::types::FilterOperator;
    use reqwest::header::HeaderValue;
    use std::borrow::Cow;
    use std::str::FromStr;

    #[test]
    fn task_wait_options_have_shared_defaults_and_builder_updates() {
        let defaults = TaskWaitOptions::default();
        assert_eq!(defaults.poll_interval(), std::time::Duration::from_secs(1));
        assert_eq!(
            defaults.timeout(),
            Some(std::time::Duration::from_secs(300))
        );

        let customized = defaults
            .with_poll_interval(std::time::Duration::from_millis(25))
            .with_timeout(None);
        assert_eq!(
            customized.poll_interval(),
            std::time::Duration::from_millis(25)
        );
        assert_eq!(customized.timeout(), None);
        assert_eq!(defaults.poll_interval(), std::time::Duration::from_secs(1));
    }

    #[test]
    fn encode_path_segment_escapes_reserved_characters() {
        // base64url ids (alphanumerics plus '-' and '_') pass through unchanged.
        assert_eq!(encode_path_segment("dTp0ZXN0-_"), "dTp0ZXN0-_");
        // Reserved / delimiter characters are percent-encoded.
        assert_eq!(encode_path_segment("a/b"), "a%2Fb");
        assert_eq!(encode_path_segment(r"a\b"), "a%5Cb");
        assert_eq!(encode_path_segment("a?b#c"), "a%3Fb%23c");
        assert_eq!(encode_path_segment("a b"), "a%20b");
        assert_eq!(encode_path_segment("a%b"), "a%25b");
        assert_eq!(encode_path_segment("."), ".");
        assert_eq!(encode_path_segment(".."), "..");
        assert_eq!(encode_path_segment("a.b"), "a.b");
        assert!(requires_name_route_fallback("."));
        assert!(requires_name_route_fallback(".."));
        assert!(!requires_name_route_fallback("a/../b"));
    }

    #[test]
    fn build_url_replaces_placeholders() {
        let base_url = BaseUrl::from_str("https://api.example.com").unwrap();
        let url = build_url(
            &base_url,
            &Endpoint::GroupMembers,
            vec![(Cow::Borrowed("group_id"), Cow::Borrowed("10"))],
        );
        assert_eq!(url, "https://api.example.com/api/v1/iam/groups/10/members");
    }

    #[test]
    fn build_url_treats_placeholder_values_as_opaque_segments() {
        let base_url = BaseUrl::from_str("https://api.example.com").unwrap();
        let url = build_url(
            &base_url,
            &Endpoint::GroupMembers,
            vec![(
                Cow::Borrowed("group_id"),
                Cow::Borrowed(r"1/../2?scope#frag%2F\tail"),
            )],
        );

        assert_eq!(
            url,
            "https://api.example.com/api/v1/iam/groups/1%2F..%2F2%3Fscope%23frag%252F%5Ctail/members"
        );
    }

    #[test]
    fn idempotency_key_validation_is_case_insensitive_and_rejects_blanks() {
        assert!(
            has_valid_idempotency_key([("IDEMPOTENCY-KEY", "task-1")])
                .expect("nonblank key should be accepted")
        );
        assert!(
            !has_valid_idempotency_key([("content-type", "application/json")])
                .expect("unrelated headers should be accepted")
        );
        for value in ["", " ", "\t"] {
            assert!(matches!(
                has_valid_idempotency_key([("Idempotency-Key", value)]),
                Err(ApiError::InvalidIdempotencyKey)
            ));
        }
    }

    #[test]
    fn build_request_url_for_get_appends_query_string() {
        let url = build_request_url(
            &reqwest::Method::GET,
            "https://api.example.com/api/v1/classes".to_string(),
            &vec![],
            vec![QueryFilter {
                key: "name".to_string(),
                value: "alpha".to_string(),
                operator: FilterOperator::Equals { is_negated: false },
            }],
        )
        .expect("GET URL should build");

        assert_eq!(
            url,
            "https://api.example.com/api/v1/classes?name__equals=alpha"
        );
    }

    #[test]
    fn build_request_url_accepts_page_limit_boundaries() {
        for key in ["limit", "limit_per_kind"] {
            for limit in [MIN_PAGE_LIMIT, MAX_PAGE_LIMIT] {
                let url = build_request_url(
                    &reqwest::Method::GET,
                    "https://api.example.com/api/v1/search".to_string(),
                    &vec![],
                    vec![QueryFilter::raw(key, limit.to_string())],
                )
                .expect("page limit boundary should build");

                assert!(url.ends_with(&format!("{key}={limit}")));
            }
        }
    }

    #[test]
    fn build_request_url_rejects_out_of_range_page_limits() {
        for (key, value) in [("limit", 0), ("limit_per_kind", MAX_PAGE_LIMIT + 1)] {
            let error = build_request_url(
                &reqwest::Method::GET,
                "https://api.example.com/api/v1/search".to_string(),
                &vec![],
                vec![QueryFilter::raw(key, value.to_string())],
            )
            .expect_err("out-of-range page limit should fail");

            assert!(matches!(
                error,
                ApiError::InvalidPageLimit {
                    value: rejected,
                    min: MIN_PAGE_LIMIT,
                    max: MAX_PAGE_LIMIT,
                } if rejected == value
            ));
        }
    }

    #[test]
    fn build_request_url_does_not_treat_field_filters_as_page_limits() {
        let url = build_request_url(
            &reqwest::Method::GET,
            "https://api.example.com/api/v1/classes".to_string(),
            &vec![],
            vec![QueryFilter::filter(
                "limit",
                FilterOperator::Equals { is_negated: false },
                "0",
            )],
        )
        .expect("a filter on a field named limit should build");

        assert!(url.ends_with("limit__equals=0"));
    }

    #[test]
    fn build_request_url_rejects_unresolved_placeholders() {
        let err = build_request_url(
            &reqwest::Method::GET,
            "https://api.example.com/api/v1/classes/{class_id}/".to_string(),
            &vec![],
            vec![],
        )
        .expect_err("unresolved placeholder should fail before request");

        assert!(matches!(err, ApiError::MissingUrlParameter(param) if param == "class_id"));
    }

    #[test]
    fn build_request_url_for_patch_requires_patch_id() {
        let err = build_request_url(
            &reqwest::Method::PATCH,
            "https://api.example.com/api/v1/classes/".to_string(),
            &vec![],
            vec![],
        )
        .expect_err("PATCH URL should require patch_id");

        assert!(matches!(err, ApiError::MissingUrlIdentifier));
    }

    #[test]
    fn build_request_url_for_put_keeps_base_url() {
        let url = build_request_url(
            &reqwest::Method::PUT,
            "https://api.example.com/api/v1/collections/1/permissions/group/2".to_string(),
            &vec![],
            vec![],
        )
        .expect("PUT URL should build");

        assert_eq!(
            url,
            "https://api.example.com/api/v1/collections/1/permissions/group/2"
        );
    }

    #[test]
    fn build_request_url_for_patch_inserts_separator_when_missing() {
        let url = build_request_url(
            &reqwest::Method::PATCH,
            "https://api.example.com/api/v1/export-templates".to_string(),
            &vec![(Cow::Borrowed("patch_id"), Cow::Borrowed("12"))],
            vec![],
        )
        .expect("PATCH URL should build");

        assert_eq!(url, "https://api.example.com/api/v1/export-templates/12");
    }

    #[test]
    fn build_request_url_treats_appended_identifiers_as_opaque_segments() {
        let url = build_request_url(
            &reqwest::Method::PATCH,
            "https://api.example.com/api/v1/export-templates".to_string(),
            &vec![(
                Cow::Borrowed("patch_id"),
                Cow::Borrowed(r"1/../2?scope#frag%2F\tail"),
            )],
            vec![],
        )
        .expect("PATCH URL should build");

        assert_eq!(
            url,
            "https://api.example.com/api/v1/export-templates/1%2F..%2F2%3Fscope%23frag%252F%5Ctail"
        );
    }

    #[test]
    fn build_request_url_for_delete_inserts_separator_when_missing() {
        let url = build_request_url(
            &reqwest::Method::DELETE,
            "https://api.example.com/api/v1/relations/classes".to_string(),
            &vec![(Cow::Borrowed("delete_id"), Cow::Borrowed("55"))],
            vec![],
        )
        .expect("DELETE URL should build");

        assert_eq!(url, "https://api.example.com/api/v1/relations/classes/55");
    }

    #[test]
    fn successful_response_text_rejects_invalid_utf8() {
        let error = decode_response_text(vec![b'{', b'"', 0xff, b'"', b'}'])
            .expect_err("invalid UTF-8 must not be rewritten");

        assert!(matches!(
            error,
            ApiError::DeserializationError(message)
                if message == "response body is not valid UTF-8 at byte 2"
        ));
    }

    #[test]
    fn custom_transport_success_rejects_invalid_utf8() {
        let response = super::super::transport::TransportResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: vec![b'{', b'"', 0xff, b'"', b'}'],
        };

        let error = process_transport_response(
            &reqwest::Method::GET,
            "https://api.example.com/api/v1/classes",
            response,
            &ClientOptions::default(),
        )
        .expect_err("invalid UTF-8 must not reach JSON parsing");

        assert!(matches!(error, ApiError::DeserializationError(_)));
    }

    #[test]
    fn parse_http_error_message_uses_message_field_when_available() {
        let message = parse_http_error_message(r#"{"message":"invalid credentials"}"#);
        assert_eq!(message, "invalid credentials");
    }

    #[test]
    fn parse_response_rejects_non_empty_delete_body() {
        let err = parse_response::<serde_json::Value>(
            &reqwest::Method::DELETE,
            StatusCode::OK,
            "{\"ok\":true}".to_string(),
        )
        .expect_err("DELETE with body should fail");

        assert!(matches!(err, ApiError::DeserializationError(_)));
    }

    #[test]
    fn parse_response_returns_none_for_no_content() {
        let result = parse_response::<serde_json::Value>(
            &reqwest::Method::POST,
            StatusCode::NO_CONTENT,
            String::new(),
        )
        .expect("NO_CONTENT should return None");

        assert!(result.is_none());
    }

    #[test]
    fn parse_response_returns_none_for_empty_success_body() {
        let result = parse_response::<serde_json::Value>(
            &reqwest::Method::POST,
            StatusCode::CREATED,
            String::new(),
        )
        .expect("empty successful body should return None");

        assert!(result.is_none());
    }

    #[test]
    fn parse_response_rejects_trailing_json_data() {
        let err = parse_response::<serde_json::Value>(
            &reqwest::Method::GET,
            StatusCode::OK,
            r#"{"ok":true} {"ignored":true}"#.to_string(),
        )
        .expect_err("trailing JSON data should fail");

        assert!(
            matches!(err, ApiError::DeserializationError(message) if message.contains("trailing data"))
        );
    }

    #[test]
    fn parse_response_allows_trailing_whitespace() {
        let result = parse_response::<serde_json::Value>(
            &reqwest::Method::GET,
            StatusCode::OK,
            "{\"ok\":true}\n\t ".to_string(),
        )
        .expect("JSON followed only by whitespace should succeed")
        .expect("JSON response should be present");

        assert_eq!(result["ok"], true);
    }

    #[test]
    fn parse_page_response_preserves_next_cursor() {
        let page = parse_page_response::<serde_json::Value>(
            &reqwest::Method::GET,
            RawResponse {
                status: StatusCode::OK,
                body: "[{\"id\":1}]".to_string(),
                next_cursor: Some("abc".to_string()),
                total_count: Some(12),
                page_limit: Some(25),
                content_type: Some(ExportContentType::ApplicationJson),
            },
        )
        .expect("page should parse");

        assert_eq!(page.len(), 1);
        assert!(!page.is_empty());
        assert!(page.has_next());
        assert_eq!(page.first().and_then(|item| item["id"].as_i64()), Some(1));
        assert_eq!(page.iter().count(), 1);
        assert_eq!(AsRef::<[serde_json::Value]>::as_ref(&page).len(), 1);
        assert_eq!(page.next_cursor.as_deref(), Some("abc"));
        assert_eq!(page.total_count, Some(12));
        assert_eq!(page.page_limit, Some(25));
    }

    #[test]
    fn raw_response_debug_redacts_body_and_cursor() {
        let response = RawResponse {
            status: StatusCode::OK,
            body: "response-body-secret".into(),
            next_cursor: Some("cursor-secret".into()),
            total_count: Some(1),
            page_limit: Some(25),
            content_type: Some(ExportContentType::ApplicationJson),
        };
        let debug = format!("{response:?}");

        assert!(!debug.contains("response-body-secret"), "{debug}");
        assert!(!debug.contains("cursor-secret"), "{debug}");
        assert!(debug.contains("body_len: 20"), "{debug}");
    }

    #[test]
    fn advance_cursor_rejects_a_repeated_cursor() {
        let mut params = vec![QueryFilter::raw("cursor", "abc")];
        let mut seen = pagination_cursors(&params);

        let err = advance_cursor(&mut params, &mut seen, "abc".to_string())
            .expect_err("a repeated cursor should stop pagination");

        assert!(matches!(err, ApiError::PaginationCycle(cursor) if cursor == "abc"));
    }

    #[test]
    fn set_raw_query_param_replaces_only_the_scalar_value() {
        let mut params = vec![
            QueryFilter::raw("limit", "10"),
            QueryFilter::filter(
                "limit",
                FilterOperator::Equals { is_negated: false },
                "unrelated-filter",
            ),
        ];

        set_raw_query_param(&mut params, "limit", "25");

        assert_eq!(params.len(), 2);
        assert!(params.iter().any(|param| {
            param.key == "limit"
                && matches!(param.operator, FilterOperator::Raw)
                && param.value == "25"
        }));
        assert!(params.iter().any(|param| {
            param.key == "limit"
                && matches!(param.operator, FilterOperator::Equals { .. })
                && param.value == "unrelated-filter"
        }));
    }

    #[test]
    fn sort_aliases_replace_each_other() {
        let mut params = vec![QueryFilter::raw("sort", "name.asc")];

        set_sort_query_param(&mut params, "order_by", "created_at.desc".to_string());

        assert_eq!(
            params,
            vec![QueryFilter::raw("order_by", "created_at.desc")]
        );
    }

    #[test]
    fn retry_after_delta_seconds_are_preserved() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("17"));

        assert_eq!(
            retry_after(&headers),
            Some(std::time::Duration::from_secs(17))
        );
    }

    #[test]
    fn elapsed_retry_after_date_requests_an_immediate_retry() {
        let mut headers = HeaderMap::new();
        headers.insert(
            RETRY_AFTER,
            HeaderValue::from_static("Thu, 01 Jan 1970 00:00:00 GMT"),
        );

        assert_eq!(retry_after(&headers), Some(std::time::Duration::ZERO));
    }

    #[test]
    fn future_retry_after_date_uses_the_remaining_delay() {
        let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let retry_at = now + std::time::Duration::from_secs(90);
        let mut headers = HeaderMap::new();
        headers.insert(
            RETRY_AFTER,
            HeaderValue::from_str(&httpdate::fmt_http_date(retry_at)).unwrap(),
        );

        assert_eq!(
            retry_after_at(&headers, now),
            Some(std::time::Duration::from_secs(90))
        );
    }
}
