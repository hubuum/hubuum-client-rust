use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error payload returned by Hubuum API endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiErrorResponse {
    pub error: String,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("API error: {0}")]
    Api(String),

    #[error("Invalid URL scheme: {0}")]
    InvalidScheme(String),

    #[error("URL cannot be a base: {0}")]
    UrlNotBase(String),

    #[error("Invalid base URL: {0}")]
    InvalidBaseUrl(String),

    #[error("Invalid URL: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("Invalid token.")]
    InvalidToken,

    #[error("URL serialization error: {0}")]
    UrlSerialize(#[from] serde_urlencoded::ser::Error),

    #[error("Query encoding error: {0}")]
    QueryEncoding(String),

    #[error("Missing location header for: {0}")]
    MissingLocationHeader(String),

    #[error("HTTP {method} {url} failed with {status}: {message}")]
    HttpWithBody {
        method: reqwest::Method,
        url: String,
        status: StatusCode,
        message: String,
        body: String,
    },

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

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

    #[error("Unknown permission `{0}`")]
    UnknownPermission(#[from] strum::ParseError),
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
