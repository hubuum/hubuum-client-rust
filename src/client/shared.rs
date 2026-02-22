use log::error;
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use std::any::type_name;
use std::borrow::Cow;
use std::fmt::Display;
use tabled::Tabled;

use super::{GetID, UrlParams};
use crate::endpoints::Endpoint;
use crate::errors::ApiError;
use crate::resources::ApiResource;
use crate::types::FilterOperator;
use crate::types::{BaseUrl, IntoQueryTuples};
use crate::QueryFilter;

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
    } else if *method == reqwest::Method::POST {
        Ok(url)
    } else if *method == reqwest::Method::PATCH {
        let id = url_param(url_params, "patch_id").ok_or(ApiError::MissingUrlIdentifier)?;
        Ok(format!("{url}{id}"))
    } else if *method == reqwest::Method::DELETE {
        match url_param(url_params, "delete_id") {
            Some(id) => Ok(format!("{url}{id}")),
            None => Ok(url),
        }
    } else {
        Err(ApiError::UnsupportedHttpOperation(method.to_string()))
    }
}

fn url_param<'a>(url_params: &'a UrlParams, key: &str) -> Option<&'a str> {
    url_params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_ref())
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
        if response_text.is_empty() {
            return Ok(None);
        } else {
            error!("Expected empty response, got: {response_text}");
            return Err(ApiError::DeserializationError(response_text));
        }
    }

    if response_code == StatusCode::NO_CONTENT {
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

#[derive(Clone, Tabled, Serialize)]
pub struct Handle<C, T>
where
    T: Tabled + Display,
{
    #[tabled(skip)]
    #[serde(skip)]
    client: C,
    #[tabled(inline)]
    #[serde(flatten)]
    resource: T,
}

impl<C, T> Handle<C, T>
where
    T: ApiResource + Tabled + GetID + Display + Default,
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
            "https://api.example.com/api/v1/classes/".to_string(),
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
            "https://api.example.com/api/v1/classes/?name__equals=alpha"
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
    fn one_or_err_returns_errors_for_empty_and_multiple() {
        let empty_err = one_or_err::<i32>(vec![]).expect_err("empty vec should error");
        assert!(matches!(empty_err, ApiError::EmptyResult(_)));

        let too_many = one_or_err(vec![1, 2]).expect_err("multiple values should error");
        assert!(matches!(too_many, ApiError::TooManyResults(_)));
    }

    #[test]
    fn select_lookup_helpers_build_expected_filters() {
        let (id_url_params, id_filters) = select_id_lookup_params(42);
        assert_eq!(id_url_params[0].0.as_ref(), "id");
        assert_eq!(id_url_params[0].1.as_ref(), "42");
        assert_eq!(id_filters[0].key, "id");
        assert_eq!(id_filters[0].value, "42");

        let (name_url_params, name_filters) =
            select_name_lookup_params::<crate::resources::Class>("alpha");
        assert_eq!(name_url_params[0].0.as_ref(), "name");
        assert_eq!(name_url_params[0].1.as_ref(), "alpha");
        assert_eq!(name_filters[0].key, "name");
        assert_eq!(name_filters[0].value, "alpha");
    }
}
