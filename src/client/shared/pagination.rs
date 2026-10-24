use super::*;
#[cfg(any(feature = "async", feature = "blocking"))]
use crate::client::diagnostics;

pub(crate) const NEXT_CURSOR_HEADER: &str = "X-Next-Cursor";

pub(crate) const TOTAL_COUNT_HEADER: &str = "X-Total-Count";

pub(crate) const PAGE_LIMIT_HEADER: &str = "X-Page-Limit";

#[derive(Debug, Clone)]
pub(crate) struct AutoPaginationGuard {
    pub(super) max_pages: usize,
    pub(super) max_items: usize,
    pub(super) pages: usize,
    pub(super) items: usize,
}

impl AutoPaginationGuard {
    pub(crate) fn new(options: &ClientOptions) -> Self {
        Self {
            max_pages: options.max_auto_pages,
            max_items: options.max_auto_items,
            pages: 0,
            items: 0,
        }
    }

    pub(crate) fn before_request(&self) -> Result<(), ApiError> {
        if self.pages >= self.max_pages || self.items >= self.max_items {
            return Err(self.limit_error());
        }
        Ok(())
    }

    pub(crate) fn record_page(&mut self, items: usize) -> Result<(), ApiError> {
        self.pages = self.pages.saturating_add(1);
        self.items = self.items.saturating_add(items);
        #[cfg(any(feature = "async", feature = "blocking"))]
        diagnostics::page(self.pages, items);
        if self.items > self.max_items {
            return Err(self.limit_error());
        }
        Ok(())
    }

    pub(super) fn limit_error(&self) -> ApiError {
        ApiError::PaginationLimit {
            pages: self.pages,
            items: self.items,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
    /// Exact number of matching items across all pages, when supplied by the server.
    pub total_count: Option<u64>,
    /// Effective page size after applying the server's default and maximum.
    pub page_limit: Option<usize>,
}

impl<T: fmt::Debug> fmt::Debug for Page<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Page")
            .field("items", &self.items)
            .field(
                "next_cursor",
                &self.next_cursor.as_ref().map(|_| "[REDACTED]"),
            )
            .field("total_count", &self.total_count)
            .field("page_limit", &self.page_limit)
            .finish()
    }
}

impl<T> Page<T> {
    /// Number of items in this page.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether this page contains no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Whether the server supplied a cursor for a following page.
    pub fn has_next(&self) -> bool {
        self.next_cursor.is_some()
    }

    /// Iterate over page items without consuming the page metadata.
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.items.iter()
    }

    /// Consume the page and return its items.
    pub fn into_items(self) -> Vec<T> {
        self.items
    }
}

impl<T> Deref for Page<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl<T> AsRef<[T]> for Page<T> {
    fn as_ref(&self) -> &[T] {
        self
    }
}

impl<T> IntoIterator for Page<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Page<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

pub(crate) fn pagination_cursors(query_params: &[QueryFilter]) -> HashSet<String> {
    query_params
        .iter()
        .filter(|param| param.key == "cursor")
        .map(|param| param.value.clone())
        .collect()
}

pub(crate) fn set_raw_query_param(
    query_params: &mut Vec<QueryFilter>,
    key: impl Into<String>,
    value: impl Into<String>,
) {
    let key = key.into();
    remove_raw_query_param(query_params, &key);
    query_params.push(QueryFilter::raw(key, value));
}

pub(crate) fn remove_raw_query_param(query_params: &mut Vec<QueryFilter>, key: &str) {
    query_params.retain(|param| param.key != key || !matches!(param.operator, FilterOperator::Raw));
}

pub(crate) fn set_sort_query_param(
    query_params: &mut Vec<QueryFilter>,
    key: &'static str,
    value: String,
) {
    remove_raw_query_param(query_params, "sort");
    remove_raw_query_param(query_params, "order_by");
    set_raw_query_param(query_params, key, value);
}

pub(crate) fn advance_cursor(
    query_params: &mut Vec<QueryFilter>,
    seen_cursors: &mut HashSet<String>,
    cursor: String,
) -> Result<(), ApiError> {
    if !seen_cursors.insert(cursor.clone()) {
        return Err(ApiError::PaginationCycle(cursor));
    }

    set_raw_query_param(query_params, "cursor", cursor);
    Ok(())
}
