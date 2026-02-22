use reqwest::StatusCode;
use thiserror::Error;

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

    #[error("HTTP error {status}: {message}")]
    HttpWithBody { status: StatusCode, message: String },

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

    #[error("Unknown permission `{0}`")]
    UnknownPermission(#[from] strum::ParseError),
}
