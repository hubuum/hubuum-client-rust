use super::*;

pub(crate) fn history_url_params(
    class_id: ClassId,
    object_id: Option<ObjectId>,
    history_id: Option<HistoryId>,
) -> UrlParams {
    let mut params = vec![(Cow::Borrowed("class_id"), class_id.to_string().into())];
    if let Some(id) = object_id {
        params.push((Cow::Borrowed("object_id"), id.to_string().into()));
    }
    if let Some(id) = history_id {
        params.push((Cow::Borrowed("history_id"), id.to_string().into()));
    }
    params
}

pub(super) fn history_page_query(options: HistoryPageOptions) -> Vec<QueryFilter> {
    let mut query = Vec::new();
    if let Some(limit) = options.limit {
        query.push(QueryFilter::raw("limit", limit.to_string()));
    }
    if let Some(cursor) = options.cursor {
        query.push(QueryFilter::raw("cursor", cursor));
    }
    if let Some(include_total) = options.include_total {
        query.push(QueryFilter::raw("include_total", include_total.to_string()));
    }
    query
}

pub(crate) fn history_timeline_query(options: HistoryTimelineOptions) -> Vec<QueryFilter> {
    let mut query = history_page_query(options.page);
    for (key, value) in [("from", options.from), ("until", options.until)] {
        if let Some(at) = value {
            query.push(QueryFilter::raw(key, at.0.to_rfc3339()));
        }
    }
    match options.position {
        Some(HistoryPosition::At(at)) => query.push(QueryFilter::raw("at", at.0.to_rfc3339())),
        Some(HistoryPosition::Anchor(id)) => query.push(QueryFilter::raw("anchor", id.to_string())),
        None => {}
    }
    query.push(QueryFilter::raw(
        "direction",
        match options.direction {
            HistoryDirection::Older => "older",
            HistoryDirection::Newer => "newer",
        },
    ));
    query
}

pub(super) fn history_sort(field: HistorySortField, direction: SortDirection) -> QueryFilter {
    let field = match field {
        HistorySortField::HistoryId => "history_id",
        HistorySortField::Revision => "revision",
    };
    let prefix = match direction {
        SortDirection::Asc => "",
        SortDirection::Desc => "-",
    };
    QueryFilter::raw("sort", format!("{prefix}{field}"))
}

pub(crate) fn object_history_query(options: ObjectHistoryOptions) -> Vec<QueryFilter> {
    let mut query = history_page_query(options.page);
    if let Some((field, direction)) = options.sort {
        query.push(history_sort(field, direction));
    }
    if let Some(revision) = options.revision {
        query.push(QueryFilter::raw("revision", revision.to_string()));
    }
    query
}

pub(crate) fn relation_history_query(options: RelationHistoryOptions) -> Vec<QueryFilter> {
    let mut query = history_page_query(options.page);
    if let Some(direction) = options.order {
        query.push(history_sort(HistorySortField::HistoryId, direction));
    }
    query
}

pub(crate) fn parse_history_page<T: DeserializeOwned>(
    raw: RawResponse,
) -> Result<HistoryPage<T>, ApiError> {
    Ok(HistoryPage {
        next_cursor: raw.next_cursor,
        total_count: raw.total_count,
        page_limit: raw.page_limit,
        data: parse_response(&Method::GET, raw.status, raw.body)?
            .ok_or_else(|| ApiError::EmptyResult("History returned an empty response".into()))?,
    })
}
