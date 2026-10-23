use super::*;

pub struct QueryOp<T: ApiResource> {
    pub(super) client: Client<Authenticated>,
    pub(super) query_params: Vec<QueryFilter>,
    pub(super) url_params: UrlParams,
    pub(super) _phantom: PhantomData<T>,
}

impl<T: ApiResource> QueryOp<T> {
    pub(super) fn with_query_params(
        client: Client<Authenticated>,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
    ) -> Self {
        QueryOp {
            client,
            url_params,
            query_params,
            _phantom: PhantomData,
        }
    }

    pub fn params(mut self, params: T::GetParams) -> Self {
        self.query_params.extend(T::filters_from_get(params));
        self
    }

    pub fn filters(mut self, filters: impl IntoQueryFilters<T>) -> Self {
        self.query_params.extend(filters.into_query_filters());
        self
    }

    pub fn filter<K: Into<String>, V: ToString>(
        mut self,
        field: K,
        op: FilterOperator,
        value: V,
    ) -> Self {
        self.query_params
            .push(QueryFilter::filter(field.into(), op, value.to_string()));
        self
    }

    pub fn raw_param<K: Into<String>, V: ToString>(mut self, key: K, value: V) -> Self {
        self.query_params
            .push(QueryFilter::raw(key.into(), value.to_string()));
        self
    }

    /// Set a scalar raw parameter, replacing an earlier value for the key.
    pub fn set_raw_param<K: Into<String>, V: ToString>(mut self, key: K, value: V) -> Self {
        shared::set_raw_query_param(&mut self.query_params, key, value.to_string());
        self
    }

    pub fn sort_by<V: ToString>(mut self, sort: V) -> Self {
        shared::set_sort_query_param(&mut self.query_params, "sort", sort.to_string());
        self
    }

    pub fn order_by<V: ToString>(mut self, sort: V) -> Self {
        shared::set_sort_query_param(&mut self.query_params, "order_by", sort.to_string());
        self
    }

    pub fn sort<S: AsRef<str>>(self, field: S, direction: SortDirection) -> Self {
        self.sort_by(format!("{}.{}", field.as_ref(), direction))
    }

    pub fn sort_by_fields<I, S>(self, fields: I) -> Self
    where
        I: IntoIterator<Item = (S, SortDirection)>,
        S: AsRef<str>,
    {
        let sort_spec = fields
            .into_iter()
            .map(|(field, direction)| format!("{}.{}", field.as_ref(), direction))
            .collect::<Vec<_>>()
            .join(",");
        self.sort_by(sort_spec)
    }

    pub fn limit(mut self, limit: usize) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "limit", limit.to_string());
        self
    }

    /// Control whether the server computes and returns an exact total count.
    pub fn include_total(mut self, include_total: bool) -> Self {
        shared::set_raw_query_param(
            &mut self.query_params,
            "include_total",
            include_total.to_string(),
        );
        self
    }

    pub fn cursor<V: ToString>(mut self, cursor: V) -> Self {
        shared::set_raw_query_param(&mut self.query_params, "cursor", cursor.to_string());
        self
    }

    pub fn list(self) -> Result<Vec<T::GetOutput>, ApiError> {
        self.client
            .search_resource::<T>(self.url_params, self.query_params)
    }

    pub fn all(self) -> Result<Vec<T::GetOutput>, ApiError> {
        let mut query = self;
        let mut items = Vec::new();
        let mut pagination = shared::AutoPaginationGuard::new(query.client.options());
        let mut seen_cursors = shared::pagination_cursors(&query.query_params);

        loop {
            pagination.before_request()?;
            let page = QueryOp::<T>::with_query_params(
                query.client.clone(),
                query.url_params.clone(),
                query.query_params.clone(),
            )
            .page()?;
            pagination.record_page(page.items.len())?;
            items.extend(page.items);

            match page.next_cursor {
                Some(cursor) => {
                    shared::advance_cursor(&mut query.query_params, &mut seen_cursors, cursor)?;
                }
                None => return Ok(items),
            }
        }
    }

    pub fn page(self) -> Result<shared::Page<T::GetOutput>, ApiError> {
        self.client
            .search_resource_page::<T>(self.url_params, self.query_params)
    }

    pub fn one(self) -> Result<T::GetOutput, ApiError> {
        one_or_err(self.list()?)
    }

    pub fn optional(self) -> Result<Option<T::GetOutput>, ApiError> {
        let mut results = self.list()?;
        match results.len() {
            0 => Ok(None),
            1 => Ok(results.pop()),
            n => Err(ApiError::TooManyResults(format!(
                "Type: {}, Count: {} (expected 0..=1)",
                std::any::type_name::<T>()
                    .rsplit("::")
                    .next()
                    .unwrap_or("resource"),
                n
            ))),
        }
    }
}

impl<T: ApiResource> QueryOp<T> {
    pub fn pages(self) -> QueryPageIterator<T> {
        QueryPageIterator::new(self)
    }

    pub fn items(self) -> QueryItemIterator<T> {
        QueryItemIterator {
            pages: self.pages(),
            current: Vec::new().into_iter(),
        }
    }
}

impl<T: ApiResource> shared::QueryFilterTarget for QueryOp<T> {
    fn push_filter<K: Into<String>, V: ToString>(
        self,
        field: K,
        op: FilterOperator,
        value: V,
    ) -> Self {
        self.filter(field, op, value)
    }

    fn push_raw_param<K: Into<String>, V: ToString>(self, key: K, value: V) -> Self {
        self.raw_param(key, value)
    }
}

impl QueryOp<Object> {
    /// Add a named related-object predicate to this class object list.
    ///
    /// Rejects duplicate aliases, more than four groups, and invalid JSON paths
    /// before transport. Raw related parameters already present count toward
    /// the alias limit; subsequent raw parameters remain server-validated.
    pub fn related(mut self, filter: RelatedObjectFilter) -> Result<Self, ApiError> {
        filter.append_to(&mut self.query_params)?;
        Ok(self)
    }

    /// Filter an object list using an enabled shared or owned personal computed field.
    pub fn computed_filter<V: ToString>(
        self,
        selector: ComputedFieldSelector,
        operator: FilterOperator,
        value: V,
    ) -> Self {
        self.filter(selector.to_string(), operator, value)
    }

    /// Sort an object list using an enabled shared or owned personal computed field.
    pub fn computed_sort(self, selector: ComputedFieldSelector, direction: SortDirection) -> Self {
        self.sort(selector.to_string(), direction)
    }
}

pub struct GraphRequest<T> {
    pub(super) client: Client<Authenticated>,
    pub(super) endpoint: Endpoint,
    pub(super) query_params: Vec<QueryFilter>,
    pub(super) url_params: UrlParams,
    pub(super) name_route_fallback: Option<NameRouteFallback>,
    pub(super) _phantom: PhantomData<T>,
}

impl<T> GraphRequest<T> {
    pub fn new(client: Client<Authenticated>, endpoint: Endpoint, url_params: UrlParams) -> Self {
        Self {
            client,
            endpoint,
            query_params: Vec::new(),
            url_params,
            name_route_fallback: None,
            _phantom: PhantomData,
        }
    }

    pub(super) fn with_class_name_fallback(
        mut self,
        class_name: String,
        class_id: Arc<OnceLock<ClassId>>,
        endpoint: Endpoint,
    ) -> Self {
        if shared::requires_name_route_fallback(&class_name) {
            self.name_route_fallback = Some(NameRouteFallback::Class {
                class_name,
                class_id,
                endpoint,
            });
        }
        self
    }

    pub(super) fn with_object_name_fallback(
        mut self,
        class_name: String,
        object_name: String,
        class_id: Arc<OnceLock<ClassId>>,
        object_id: Arc<OnceLock<ObjectId>>,
        endpoint: Endpoint,
    ) -> Self {
        if shared::requires_name_route_fallback(&class_name)
            || shared::requires_name_route_fallback(&object_name)
        {
            self.name_route_fallback = Some(NameRouteFallback::Object {
                class_name,
                object_name,
                class_id,
                object_id,
                endpoint,
            });
        }
        self
    }

    pub fn filters<I>(mut self, filters: I) -> Self
    where
        I: IntoIterator<Item = QueryFilter>,
    {
        self.query_params.extend(filters);
        self
    }

    pub fn query_param<K: Into<String>, V: ToString>(mut self, key: K, value: V) -> Self {
        self.query_params
            .push(QueryFilter::raw(key.into(), value.to_string()));
        self
    }

    /// Set a scalar raw query parameter, replacing an earlier value for the key.
    pub fn set_query_param<K: Into<String>, V: ToString>(mut self, key: K, value: V) -> Self {
        shared::set_raw_query_param(&mut self.query_params, key, value.to_string());
        self
    }

    pub fn filter<K: Into<String>, V: ToString>(
        mut self,
        field: K,
        op: FilterOperator,
        value: V,
    ) -> Self {
        self.query_params
            .push(QueryFilter::filter(field.into(), op, value.to_string()));
        self
    }
}

impl<T> GraphRequest<T>
where
    T: DeserializeOwned,
{
    pub fn send(self) -> Result<T, ApiError> {
        let (endpoint, url_params) = match &self.name_route_fallback {
            Some(fallback) => fallback.resolve(&self.client)?,
            None => (self.endpoint, self.url_params),
        };
        self.client
            .request_with_endpoint::<EmptyPostParams, T>(
                reqwest::Method::GET,
                &endpoint,
                url_params,
                self.query_params,
                EmptyPostParams,
            )?
            .ok_or(ApiError::EmptyResult(
                "Graph request returned empty result".into(),
            ))
    }

    #[deprecated(since = "0.3.0", note = "use send()")]
    pub fn fetch(self) -> Result<T, ApiError> {
        self.send()
    }
}
