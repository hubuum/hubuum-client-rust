use super::*;

pub(crate) fn redacted_url_for_log(value: &str) -> String {
    let Ok(mut url) = url::Url::parse(value) else {
        return "[INVALID URL]".to_string();
    };
    redact_url_query(&mut url);
    url.to_string()
}

pub(super) fn redact_url_query(url: &mut url::Url) {
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

pub(super) fn reject_url_dot_segments(value: &str) -> Result<(), ApiError> {
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

pub(super) fn build_relative_url_impl(
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

/// Characters that must be escaped when interpolating an opaque value into a
/// single URL path segment. Unreserved characters (including base64url's `-`
/// and `_`) are left untouched; reserved/delimiter characters are escaped.
pub(super) const PATH_SEGMENT: &AsciiSet = &CONTROLS
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

pub(crate) fn build_url(base_url: &BaseUrl, endpoint: &Endpoint, url_params: &UrlParams) -> String {
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
        validate_json_paths(&query_params)?;
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
        let url = match url_param(url_params, "delete_id") {
            Some(id) => append_identifier(url, id),
            None => url,
        };
        let query = query_params.into_query_string()?;
        if query.is_empty() {
            Ok(url)
        } else {
            Ok(format!("{url}?{query}"))
        }
    } else {
        Err(ApiError::UnsupportedHttpOperation(method.to_string()))
    }
}

pub(super) const MIN_PAGE_LIMIT: usize = 1;

pub(super) const INVALID_JSON_PATH_QUERY_KEY: &str = "\0hubuum-invalid-json-path";

pub(super) fn validate_json_paths(query_params: &[QueryFilter]) -> Result<(), ApiError> {
    if query_params
        .iter()
        .any(|parameter| parameter.key == INVALID_JSON_PATH_QUERY_KEY)
    {
        return Err(ApiError::InvalidJsonPath {
            reason: "JSON filter operators require a non-empty path whose segments contain only ASCII letters, digits, `_`, or `$`",
        });
    }
    Ok(())
}

pub(super) fn validate_page_limits(query_params: &[QueryFilter]) -> Result<(), ApiError> {
    for parameter in query_params.iter().filter(|parameter| {
        matches!(parameter.operator, FilterOperator::Raw)
            && matches!(parameter.key.as_str(), "limit" | "limit_per_kind")
    }) {
        let Ok(value) = parameter.value.parse::<usize>() else {
            continue;
        };
        if value < MIN_PAGE_LIMIT {
            return Err(ApiError::InvalidPageLimit {
                value,
                min: MIN_PAGE_LIMIT,
                max: usize::MAX,
            });
        }
    }
    Ok(())
}

pub(super) fn ensure_no_unresolved_url_params(url: &str) -> Result<(), ApiError> {
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

pub(super) fn append_identifier(url: String, id: &str) -> String {
    let id = encode_path_segment(id);
    if url.ends_with('/') {
        format!("{url}{id}")
    } else {
        format!("{url}/{id}")
    }
}

pub(super) fn url_param<'a>(url_params: &'a UrlParams, key: &str) -> Option<&'a str> {
    url_params
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_ref())
}
