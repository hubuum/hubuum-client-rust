use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error payload returned by Hubuum API endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct ApiErrorResponse {
    pub error: String,
    pub message: String,
}

#[non_exhaustive]
#[derive(Error)]
pub enum ApiError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("API error: {0}")]
    Api(String),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Invalid URL scheme: {0}")]
    InvalidScheme(String),

    #[error("URL cannot be a base: {0}")]
    UrlNotBase(String),

    #[error("Invalid base URL: {0}")]
    InvalidBaseUrl(String),

    #[error("Invalid URL: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("Invalid URL path: {0}")]
    InvalidUrlPath(String),

    #[error("URL serialization error: {0}")]
    UrlSerialize(#[from] serde_urlencoded::ser::Error),

    #[error("Query encoding error: {0}")]
    QueryEncoding(String),

    #[error("Principal settings must be a JSON object")]
    InvalidPrincipalSettings,

    #[error("Missing location header for: {0}")]
    MissingLocationHeader(String),

    #[error("HTTP {method} request failed with {status}: {message}")]
    HttpWithBody {
        method: reqwest::Method,
        url: String,
        status: StatusCode,
        message: String,
        body: String,
    },

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Response body exceeded the configured {limit} byte limit")]
    ResponseTooLarge {
        limit: usize,
        content_length: Option<u64>,
    },

    #[error("Timed out waiting for task {task_id} after {timeout:?}")]
    TaskTimeout {
        task_id: crate::types::TaskId,
        timeout: std::time::Duration,
    },

    #[error("Task {task_id} completed unsuccessfully with status {status}")]
    TaskUnsuccessful {
        task_id: crate::types::TaskId,
        status: crate::types::TaskStatus,
    },

    #[error("Request retries exhausted after {attempts} attempts: {last_error}")]
    RetryExhausted { attempts: usize, last_error: String },

    #[error("Unsupported HTTP operation: {0}")]
    UnsupportedHttpOperation(String),

    #[error("Unexpected empty result: {0}")]
    EmptyResult(String),

    #[error("Too many results: {0}")]
    TooManyResults(String),

    #[error("Missing URL identifier")]
    MissingUrlIdentifier,

    #[error("Missing URL parameter: {0}")]
    MissingUrlParameter(String),

    #[error("Pagination cursor repeated: {0}")]
    PaginationCycle(String),

    #[error("Automatic pagination exceeded its safety limit ({pages} pages, {items} items)")]
    PaginationLimit { pages: usize, items: usize },

    #[error("Unknown permission `{0}`")]
    UnknownPermission(#[from] strum::ParseError),
}

impl std::fmt::Debug for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(error) => f.debug_tuple("Http").field(error).finish(),
            Self::Json(error) => f.debug_tuple("Json").field(error).finish(),
            Self::Io(error) => f.debug_tuple("Io").field(error).finish(),
            Self::Api(message) => f.debug_tuple("Api").field(message).finish(),
            Self::Transport(message) => f.debug_tuple("Transport").field(message).finish(),
            Self::InvalidScheme(scheme) => f.debug_tuple("InvalidScheme").field(scheme).finish(),
            Self::UrlNotBase(url) => f.debug_tuple("UrlNotBase").field(url).finish(),
            Self::InvalidBaseUrl(message) => {
                f.debug_tuple("InvalidBaseUrl").field(message).finish()
            }
            Self::UrlParse(error) => f.debug_tuple("UrlParse").field(error).finish(),
            Self::InvalidUrlPath(message) => {
                f.debug_tuple("InvalidUrlPath").field(message).finish()
            }
            Self::UrlSerialize(error) => f.debug_tuple("UrlSerialize").field(error).finish(),
            Self::QueryEncoding(message) => f.debug_tuple("QueryEncoding").field(message).finish(),
            Self::InvalidPrincipalSettings => f.write_str("InvalidPrincipalSettings"),
            Self::MissingLocationHeader(message) => f
                .debug_tuple("MissingLocationHeader")
                .field(message)
                .finish(),
            Self::HttpWithBody {
                method,
                url,
                status,
                message,
                body,
            } => f
                .debug_struct("HttpWithBody")
                .field("method", method)
                .field("url", &crate::client::redacted_url_for_log(url))
                .field("status", status)
                .field("message", message)
                .field("body", &"[REDACTED]")
                .field("body_len", &body.len())
                .finish(),
            Self::DeserializationError(message) => f
                .debug_tuple("DeserializationError")
                .field(message)
                .finish(),
            Self::ResponseTooLarge {
                limit,
                content_length,
            } => f
                .debug_struct("ResponseTooLarge")
                .field("limit", limit)
                .field("content_length", content_length)
                .finish(),
            Self::TaskTimeout { task_id, timeout } => f
                .debug_struct("TaskTimeout")
                .field("task_id", task_id)
                .field("timeout", timeout)
                .finish(),
            Self::TaskUnsuccessful { task_id, status } => f
                .debug_struct("TaskUnsuccessful")
                .field("task_id", task_id)
                .field("status", status)
                .finish(),
            Self::RetryExhausted {
                attempts,
                last_error,
            } => f
                .debug_struct("RetryExhausted")
                .field("attempts", attempts)
                .field("last_error", last_error)
                .finish(),
            Self::UnsupportedHttpOperation(method) => f
                .debug_tuple("UnsupportedHttpOperation")
                .field(method)
                .finish(),
            Self::EmptyResult(message) => f.debug_tuple("EmptyResult").field(message).finish(),
            Self::TooManyResults(message) => {
                f.debug_tuple("TooManyResults").field(message).finish()
            }
            Self::MissingUrlIdentifier => f.write_str("MissingUrlIdentifier"),
            Self::MissingUrlParameter(parameter) => f
                .debug_tuple("MissingUrlParameter")
                .field(parameter)
                .finish(),
            Self::PaginationCycle(cursor) => f
                .debug_struct("PaginationCycle")
                .field("cursor", &"[REDACTED]")
                .field("cursor_len", &cursor.len())
                .finish(),
            Self::PaginationLimit { pages, items } => f
                .debug_struct("PaginationLimit")
                .field("pages", pages)
                .field("items", items)
                .finish(),
            Self::UnknownPermission(error) => {
                f.debug_tuple("UnknownPermission").field(error).finish()
            }
        }
    }
}

impl ApiError {
    /// HTTP status for API response errors.
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Self::HttpWithBody { status, .. } => Some(*status),
            Self::Http(error) => error.status(),
            _ => None,
        }
    }

    /// Parse the standard Hubuum error payload when the response uses it.
    pub fn api_response(&self) -> Option<ApiErrorResponse> {
        let Self::HttpWithBody { body, .. } = self else {
            return None;
        };
        serde_json::from_str(body).ok()
    }

    /// Return whether this error represents the supplied HTTP status.
    pub fn is_status(&self, status: StatusCode) -> bool {
        self.status() == Some(status)
    }

    /// Request method associated with a detailed API response error.
    pub fn request_method(&self) -> Option<&reqwest::Method> {
        match self {
            Self::HttpWithBody { method, .. } => Some(method),
            _ => None,
        }
    }

    /// Request URL associated with a detailed API response error.
    pub fn request_url(&self) -> Option<&str> {
        match self {
            Self::HttpWithBody { url, .. } => Some(url),
            _ => None,
        }
    }

    /// Raw response body associated with a detailed API response error.
    pub fn response_body(&self) -> Option<&str> {
        match self {
            Self::HttpWithBody { body, .. } => Some(body),
            _ => None,
        }
    }

    /// Server-provided message for API and detailed HTTP errors.
    pub fn api_message(&self) -> Option<&str> {
        match self {
            Self::HttpWithBody { message, .. } => Some(message),
            Self::Api(message) => Some(message),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_structured_api_error_response() {
        let error = ApiError::HttpWithBody {
            method: reqwest::Method::GET,
            url: "https://api.example.com/api/v1/classes".to_string(),
            status: StatusCode::UNAUTHORIZED,
            message: "Authentication failure".to_string(),
            body: r#"{"error":"Unauthorized","message":"Authentication failure"}"#.to_string(),
        };

        assert_eq!(error.status(), Some(StatusCode::UNAUTHORIZED));
        assert!(error.is_status(StatusCode::UNAUTHORIZED));
        assert_eq!(error.request_method(), Some(&reqwest::Method::GET));
        assert_eq!(
            error.request_url(),
            Some("https://api.example.com/api/v1/classes")
        );
        assert_eq!(error.api_message(), Some("Authentication failure"));
        assert!(error.response_body().is_some());
        assert_eq!(
            error.api_response(),
            Some(ApiErrorResponse {
                error: "Unauthorized".to_string(),
                message: "Authentication failure".to_string(),
            })
        );
    }
}
