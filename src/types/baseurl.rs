use std::str::FromStr;
use url::Url;

use crate::errors::ApiError;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BaseUrl(Url);

impl BaseUrl {
    /// Parse and validate an HTTP(S) API base URL.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ApiError> {
        Self::from_str(value.as_ref())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Borrow the parsed URL.
    pub fn as_url(&self) -> &Url {
        &self.0
    }

    /// Consume the wrapper and return the parsed URL.
    pub fn into_url(self) -> Url {
        self.0
    }

    /// Return the normalized base URL as an owned string.
    ///
    /// `BaseUrl` always stores a trailing slash; this compatibility helper only
    /// allocates the owned return value.
    pub fn with_trailing_slash(&self) -> String {
        self.as_str().to_owned()
    }

    fn validate(mut url: Url) -> Result<Self, ApiError> {
        if !(url.scheme() == "http" || url.scheme() == "https") {
            return Err(ApiError::InvalidScheme(url.scheme().to_string()));
        }
        if url.cannot_be_a_base() {
            return Err(ApiError::UrlNotBase(url.to_string()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ApiError::InvalidBaseUrl(
                "credentials are not allowed".to_string(),
            ));
        }
        if url.query().is_some() {
            return Err(ApiError::InvalidBaseUrl(
                "query parameters are not allowed".to_string(),
            ));
        }
        if url.fragment().is_some() {
            return Err(ApiError::InvalidBaseUrl(
                "fragments are not allowed".to_string(),
            ));
        }

        if !url.path().ends_with('/') {
            let original = url.to_string();
            url.path_segments_mut()
                .map_err(|_| ApiError::UrlNotBase(original))?
                .push("");
        }

        Ok(Self(url))
    }
}

impl FromStr for BaseUrl {
    type Err = ApiError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::validate(Url::parse(s)?)
    }
}

impl std::fmt::Display for BaseUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for BaseUrl {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<Url> for BaseUrl {
    fn as_ref(&self) -> &Url {
        self.as_url()
    }
}

impl TryFrom<Url> for BaseUrl {
    type Error = ApiError;

    fn try_from(value: Url) -> Result<Self, Self::Error> {
        Self::validate(value)
    }
}

impl TryFrom<&str> for BaseUrl {
    type Error = ApiError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl TryFrom<String> for BaseUrl {
    type Error = ApiError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use yare::parameterized;

    #[parameterized(
        https = {
            "https://api.example.com",
            "https://api.example.com/",
        },
        http = {
            "http://api.example.com",
            "http://api.example.com/",
        }
    )]
    fn test_base_url_with_trailing_slash(url: &str, expected: &str) {
        let base_url = BaseUrl::from_str(url).unwrap();
        assert_eq!(base_url.with_trailing_slash(), expected);
    }

    #[parameterized(
        http = { "http" },
        https = { "https" } 
    )]
    fn test_valid_schema(schema: &str) {
        let base_url = BaseUrl::from_str(&format!("{}://api.example.com", schema));
        assert!(base_url.is_ok());
    }

    #[parameterized(
        ftp = { "ftp" },
        file = { "file" },
        mailto = { "mailto" }
    )]
    fn test_invalid_schema(schema: &str) {
        let base_url = BaseUrl::from_str(&format!("{}://api.example.com", schema));
        assert!(base_url.is_err());
        assert_eq!(
            base_url.unwrap_err().to_string(),
            format!("Invalid URL scheme: {}", schema)
        );
    }

    #[test]
    fn test_base_url_with_trailing_slash() {
        let base_url = BaseUrl::from_str("https://api.example.com").unwrap();
        assert_eq!(base_url.with_trailing_slash(), "https://api.example.com/");
    }

    #[test]
    fn test_base_url_from_str() {
        let base_url = BaseUrl::from_str("https://api.example.com").unwrap();
        assert_eq!(base_url.as_str(), "https://api.example.com/");
    }

    #[test]
    fn new_normalizes_paths_without_double_encoding() {
        let base_url = BaseUrl::new("https://api.example.com/hubuum%20api").unwrap();

        assert_eq!(base_url.as_str(), "https://api.example.com/hubuum%20api/");
        assert_eq!(base_url.to_string(), base_url.as_str());
        assert_eq!(AsRef::<str>::as_ref(&base_url), base_url.as_str());
    }

    #[parameterized(
        credentials = { "https://alice:secret@api.example.com", "credentials are not allowed" },
        query = { "https://api.example.com?tenant=one", "query parameters are not allowed" },
        fragment = { "https://api.example.com#docs", "fragments are not allowed" }
    )]
    fn rejects_ambiguous_base_urls(value: &str, expected: &str) {
        let error = BaseUrl::new(value).expect_err("base URL should be rejected");

        assert!(matches!(error, ApiError::InvalidBaseUrl(message) if message == expected));
    }
}
