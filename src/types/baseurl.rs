use std::str::FromStr;
use url::Url;

use crate::errors::ApiError;

#[derive(Clone, Debug)]
pub struct BaseUrl(Url);

impl BaseUrl {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    // New method to get the base URL with a guaranteed trailing slash
    pub fn with_trailing_slash(&self) -> String {
        let mut url_str = self.0.to_string();
        if !url_str.ends_with('/') {
            url_str.push('/');
        }
        url_str
    }
}

impl FromStr for BaseUrl {
    type Err = ApiError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut url = Url::parse(s)?;

        // Additional validation
        if !(url.scheme() == "http" || url.scheme() == "https") {
            return Err(ApiError::InvalidScheme(url.scheme().to_string()));
        }
        if url.cannot_be_a_base() {
            return Err(ApiError::UrlNotBase(url.to_string()));
        }

        // Ensure the URL ends with a single '/'
        if !url.path().ends_with('/') {
            url.set_path(&format!("{}/", url.path()));
        }

        Ok(BaseUrl(url))
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
}
