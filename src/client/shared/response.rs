use super::*;

pub(crate) fn process_transport_response(
    method: &Method,
    request_url: &str,
    response: crate::client::transport::TransportResponse,
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
    RawResponse::new(
        response.status,
        &response.headers,
        decode_response_text(response.body)?,
    )
}

pub(crate) fn check_transport_response_success(
    method: &Method,
    request_url: &str,
    mut response: crate::client::transport::TransportResponse,
    max_error_body_bytes: usize,
) -> Result<crate::client::transport::TransportResponse, ApiError> {
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

pub(super) fn decode_response_text(body: Vec<u8>) -> Result<String, ApiError> {
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

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RawResponse {
    pub status: StatusCode,
    pub body: String,
    pub etag: Option<crate::types::EntityTag>,
    pub next_cursor: Option<String>,
    pub total_count: Option<u64>,
    pub page_limit: Option<usize>,
    pub content_type: Option<ExportContentType>,
}

impl RawResponse {
    pub(crate) fn new(
        status: StatusCode,
        headers: &HeaderMap,
        body: String,
    ) -> Result<Self, ApiError> {
        let (next_cursor, total_count, page_limit, content_type) = response_metadata(headers);
        Ok(Self {
            status,
            body,
            etag: response_etag(headers)?,
            next_cursor,
            total_count,
            page_limit,
            content_type,
        })
    }
}

/// Decode a response body while preserving its optional strong ETag.
pub(crate) fn decode_revisioned<T: DeserializeOwned>(
    raw: RawResponse,
) -> Result<Revisioned<T>, ApiError> {
    let value = decode_json_body(&raw.body)?;
    Ok(Revisioned::new(value, raw.etag))
}

/// Build the conditional request header accepted by endpoint-aware helpers.
pub(crate) fn if_match_headers(etag: &EntityTag) -> [(&'static str, String); 1] {
    [(reqwest::header::IF_MATCH.as_str(), etag.as_str().into())]
}

impl std::fmt::Debug for RawResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawResponse")
            .field("status", &self.status)
            .field("body", &"[REDACTED]")
            .field("body_len", &self.body.len())
            .field("etag", &self.etag)
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

pub(crate) fn response_etag(headers: &HeaderMap) -> Result<Option<EntityTag>, ApiError> {
    let Some(value) = headers.get(reqwest::header::ETAG) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| ApiError::InvalidEntityTag)?;
    EntityTag::new(value).map(Some)
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

/// Decode one complete JSON response body with a path-aware error.
pub(crate) fn decode_json_body<U: DeserializeOwned>(response_text: &str) -> Result<U, ApiError> {
    let mut deserializer = serde_json::Deserializer::from_str(response_text);
    let value = serde_path_to_error::deserialize(&mut deserializer).map_err(|error| {
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
    Ok(value)
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

    decode_json_body(&response_text).map(Some)
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
