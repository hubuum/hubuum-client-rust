use super::*;
use crate::types::FilterOperator;
use reqwest::header::HeaderValue;
use std::borrow::Cow;
use std::str::FromStr;

#[test]
fn failed_download_publication_removes_temporary_file() {
    let directory = tempfile::tempdir().expect("temporary directory should be created");
    let destination = directory.path().join("existing-directory");
    std::fs::create_dir(&destination).expect("destination fixture should be created");
    let mut temporary =
        temporary_download_file(&destination).expect("sibling temporary file should be created");
    std::io::Write::write_all(&mut temporary, b"download")
        .expect("temporary file should be writable");

    persist_download_file(temporary, &destination).expect_err("a file cannot replace a directory");

    let entries = std::fs::read_dir(directory.path())
        .expect("temporary directory should remain readable")
        .map(|entry| entry.expect("directory entry should be readable").path())
        .collect::<Vec<_>>();
    assert_eq!(entries, [destination]);
}

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
    let url_params = vec![(
        Cow::Owned("group_id".to_string()),
        Cow::Owned("10".to_string()),
    )];
    let url = build_url(&base_url, &Endpoint::GroupMembers, &url_params);
    assert_eq!(url, "https://api.example.com/api/v1/iam/groups/10/members");
    assert_eq!(url_params[0].1, "10");
}

#[test]
fn build_url_treats_placeholder_values_as_opaque_segments() {
    let base_url = BaseUrl::from_str("https://api.example.com").unwrap();
    let url_params = vec![(
        Cow::Owned("group_id".to_string()),
        Cow::Owned(r"1/../2?scope#frag%2F\tail".to_string()),
    )];
    let url = build_url(&base_url, &Endpoint::GroupMembers, &url_params);

    assert_eq!(
        url,
        "https://api.example.com/api/v1/iam/groups/1%2F..%2F2%3Fscope%23frag%252F%5Ctail/members"
    );
    assert_eq!(url_params[0].1, r"1/../2?scope#frag%2F\tail");
}

#[test]
fn idempotency_key_validation_enforces_the_v004_contract() {
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
    let maximum = "x".repeat(255);
    assert!(
        has_valid_idempotency_key([("Idempotency-Key", maximum.as_str())])
            .expect("255-byte key should be accepted")
    );
    let oversized = "x".repeat(256);
    assert!(matches!(
        has_valid_idempotency_key([("Idempotency-Key", oversized.as_str())]),
        Err(ApiError::InvalidIdempotencyKey)
    ));
    let oversized_unicode = "ø".repeat(128);
    assert!(matches!(
        has_valid_idempotency_key([("Idempotency-Key", oversized_unicode.as_str())]),
        Err(ApiError::InvalidIdempotencyKey)
    ));
}

#[test]
fn request_plans_mark_secret_headers_sensitive() {
    let authenticated = build_request_plan(
        &Method::GET,
        "https://api.example.com/api/v1/classes",
        &(),
        "bearer-secret",
        &[("X-Api-Key", "header-secret".to_string())],
    )
    .expect("authenticated request plan should build");
    let authorization = authenticated
        .headers
        .get(reqwest::header::AUTHORIZATION)
        .expect("authorization header should be present");
    let api_key = authenticated
        .headers
        .get("X-Api-Key")
        .expect("caller header should be present");

    assert!(authorization.is_sensitive());
    assert!(api_key.is_sensitive());
    assert!(!format!("{authorization:?}").contains("bearer-secret"));
    assert!(!format!("{api_key:?}").contains("header-secret"));

    let capability = build_unauthenticated_request_plan(
        &Method::GET,
        "https://api.example.com/api/v1/restores/7/status",
        &[("X-Hubuum-Restore-Capability", "restore-secret".to_string())],
    )
    .expect("capability request plan should build");
    let capability = capability
        .headers
        .get("X-Hubuum-Restore-Capability")
        .expect("restore capability header should be present");

    assert!(capability.is_sensitive());
    assert!(!format!("{capability:?}").contains("restore-secret"));
}

#[rstest::rstest]
#[case(None, "https://example.test/items?expected_revision=3")]
#[case(Some("7"), "https://example.test/items/7?expected_revision=3")]
fn delete_preserves_revision_query(#[case] id: Option<&str>, #[case] expected: &str) {
    let params = id
        .map(|id| vec![("delete_id".into(), id.to_string().into())])
        .unwrap_or_default();
    let actual = build_request_url(
        &reqwest::Method::DELETE,
        "https://example.test/items".into(),
        &params,
        vec![QueryFilter::raw("expected_revision", "3")],
    )
    .unwrap();
    assert_eq!(actual, expected);
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
fn build_request_url_accepts_positive_page_limits() {
    for key in ["limit", "limit_per_kind"] {
        for limit in [MIN_PAGE_LIMIT, 250, 500, usize::MAX] {
            let url = build_request_url(
                &reqwest::Method::GET,
                "https://api.example.com/api/v1/search".to_string(),
                &vec![],
                vec![QueryFilter::raw(key, limit.to_string())],
            )
            .expect("positive page limit should build");

            assert!(url.ends_with(&format!("{key}={limit}")));
        }
    }
}

#[test]
fn build_request_url_rejects_zero_page_limits() {
    for key in ["limit", "limit_per_kind"] {
        let value = 0;
        let error = build_request_url(
            &reqwest::Method::GET,
            "https://api.example.com/api/v1/search".to_string(),
            &vec![],
            vec![QueryFilter::raw(key, value.to_string())],
        )
        .expect_err("zero page limit should fail");

        assert!(matches!(
            error,
            ApiError::InvalidPageLimit {
                value: rejected,
                min: MIN_PAGE_LIMIT,
                max: usize::MAX,
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
fn response_etags_are_validated_instead_of_silently_discarded() {
    let mut headers = HeaderMap::new();
    assert!(response_etag(&headers).unwrap().is_none());

    headers.insert(reqwest::header::ETAG, HeaderValue::from_static("\"valid\""));
    assert_eq!(
        response_etag(&headers).unwrap().unwrap().as_str(),
        "\"valid\""
    );

    headers.insert(reqwest::header::ETAG, HeaderValue::from_static("unquoted"));
    assert!(matches!(
        response_etag(&headers),
        Err(ApiError::InvalidEntityTag)
    ));
}

#[test]
fn parse_page_response_preserves_next_cursor() {
    let page = parse_page_response::<serde_json::Value>(
        &reqwest::Method::GET,
        RawResponse {
            status: StatusCode::OK,
            body: "[{\"id\":1}]".to_string(),
            etag: None,
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
        etag: None,
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
        param.key == "limit" && matches!(param.operator, FilterOperator::Raw) && param.value == "25"
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
