use log::error;
use reqwest::{
    StatusCode,
    header::{CONTENT_TYPE, HeaderMap},
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::any::type_name;
use std::borrow::Cow;

use super::{GetID, UrlParams};
use crate::QueryFilter;
use crate::endpoints::Endpoint;
use crate::errors::ApiError;
use crate::resources::ApiResource;
use crate::types::FilterOperator;
use crate::types::{BaseUrl, IntoQueryTuples, ReportContentType};

pub(crate) const NEXT_CURSOR_HEADER: &str = "X-Next-Cursor";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawResponse {
    pub status: StatusCode,
    pub body: String,
    pub next_cursor: Option<String>,
    pub content_type: Option<ReportContentType>,
}

pub(crate) fn build_url(base_url: &BaseUrl, endpoint: &Endpoint, url_params: UrlParams) -> String {
    let mut url = format!(
        "{}{}",
        base_url.with_trailing_slash(),
        endpoint.trim_start_matches('/')
    );

    for (key, value) in url_params {
        url = url.replace(&format!("{{{}}}", key), value.as_ref());
    }
    url
}

pub(crate) fn build_request_url(
    method: &reqwest::Method,
    url: String,
    url_params: &UrlParams,
    query_params: Vec<QueryFilter>,
) -> Result<String, ApiError> {
    if *method == reqwest::Method::GET {
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

fn append_identifier(url: String, id: &str) -> String {
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
) -> (Option<String>, Option<ReportContentType>) {
    let next_cursor = headers
        .get(NEXT_CURSOR_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(ReportContentType::from_header);
    (next_cursor, content_type)
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
        error!("Expected empty response, got: {response_text}");
        return Err(ApiError::DeserializationError(response_text));
    }

    if response_code == StatusCode::NO_CONTENT || response_text.trim().is_empty() {
        return Ok(None);
    }

    match serde_json::from_str(&response_text) {
        Ok(obj) => Ok(Some(obj)),
        Err(err) => {
            error!("Failed to deserialize response: {err} Response text: {response_text}");
            Err(ApiError::DeserializationError(response_text))
        }
    }
}

pub(crate) fn parse_page_response<U: DeserializeOwned>(
    method: &reqwest::Method,
    raw: RawResponse,
) -> Result<Page<U>, ApiError> {
    let next_cursor = raw.next_cursor;
    let items: Vec<U> = parse_response(method, raw.status, raw.body)?
        .ok_or(ApiError::EmptyResult("GET returned empty result".into()))?;
    Ok(Page { items, next_cursor })
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

    pub fn id(&self) -> i32 {
        self.resource.id()
    }

    pub fn client(&self) -> &C {
        &self.client
    }
}

pub(crate) fn select_id_lookup_params(id: i32) -> (UrlParams, Vec<QueryFilter>) {
    (
        vec![(Cow::Borrowed("id"), id.to_string().into())],
        vec![QueryFilter {
            key: "id".to_string(),
            value: id.to_string(),
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
    use std::borrow::Cow;
    use std::str::FromStr;

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
            "https://api.example.com/api/v1/namespaces/1/permissions/group/2".to_string(),
            &vec![],
            vec![],
        )
        .expect("PUT URL should build");

        assert_eq!(
            url,
            "https://api.example.com/api/v1/namespaces/1/permissions/group/2"
        );
    }

    #[test]
    fn build_request_url_for_patch_inserts_separator_when_missing() {
        let url = build_request_url(
            &reqwest::Method::PATCH,
            "https://api.example.com/api/v1/templates".to_string(),
            &vec![(Cow::Borrowed("patch_id"), Cow::Borrowed("12"))],
            vec![],
        )
        .expect("PATCH URL should build");

        assert_eq!(url, "https://api.example.com/api/v1/templates/12");
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
    fn parse_page_response_preserves_next_cursor() {
        let page = parse_page_response::<serde_json::Value>(
            &reqwest::Method::GET,
            RawResponse {
                status: StatusCode::OK,
                body: "[{\"id\":1}]".to_string(),
                next_cursor: Some("abc".to_string()),
                content_type: Some(ReportContentType::ApplicationJson),
            },
        )
        .expect("page should parse");

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.next_cursor.as_deref(), Some("abc"));
    }
}
