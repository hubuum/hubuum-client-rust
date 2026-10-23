use super::*;

pub type PageStream<T> = std::pin::Pin<
    Box<dyn futures_core::Stream<Item = Result<shared::Page<T>, ApiError>> + Send + 'static>,
>;

pub type ItemStream<T> =
    std::pin::Pin<Box<dyn futures_core::Stream<Item = Result<T, ApiError>> + Send + 'static>>;

#[derive(Debug, Clone)]
pub(super) enum NameRouteFallback {
    Class {
        class_name: String,
        class_id: Arc<OnceLock<ClassId>>,
        endpoint: Endpoint,
    },
    Object {
        class_name: String,
        object_name: String,
        class_id: Arc<OnceLock<ClassId>>,
        object_id: Arc<OnceLock<ObjectId>>,
        endpoint: Endpoint,
    },
}

impl NameRouteFallback {
    pub(super) async fn resolve(
        &self,
        client: &Client<Authenticated>,
    ) -> Result<(Endpoint, UrlParams), ApiError> {
        match self {
            Self::Class {
                class_name,
                class_id,
                endpoint,
            } => {
                let class_id = client.resolve_class_name_id(class_name, class_id).await?;
                Ok((
                    *endpoint,
                    vec![(Cow::Borrowed("class_id"), class_id.to_string().into())],
                ))
            }
            Self::Object {
                class_name,
                object_name,
                class_id,
                object_id,
                endpoint,
            } => {
                let (class_id, object_id) = client
                    .resolve_object_name_ids(class_name, object_name, class_id, object_id)
                    .await?;
                Ok((
                    *endpoint,
                    vec![
                        (Cow::Borrowed("class_id"), class_id.to_string().into()),
                        (Cow::Borrowed("object_id"), object_id.to_string().into()),
                    ],
                ))
            }
        }
    }
}

pub struct CursorRequest<T> {
    pub(super) client: Client<Authenticated>,
    pub(super) endpoint: Endpoint,
    pub(super) query_params: Vec<QueryFilter>,
    pub(super) url_params: UrlParams,
    pub(super) name_route_fallback: Option<NameRouteFallback>,
    pub(super) _phantom: PhantomData<T>,
}

impl<T> CursorRequest<T> {
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

impl CursorRequest<Object> {
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

impl CursorRequest<ObjectAggregateRow> {
    /// Append one ordered aggregation dimension. The server accepts one to three.
    pub fn group_by(self, dimension: ObjectAggregateDimension) -> Self {
        self.query_param("group_by", dimension)
    }

    pub fn group_by_all(
        mut self,
        dimensions: impl IntoIterator<Item = ObjectAggregateDimension>,
    ) -> Self {
        for dimension in dimensions {
            self = self.group_by(dimension);
        }
        self
    }

    /// Append one ordered numeric measure. The server accepts up to four.
    pub fn aggregate(self, measure: ObjectAggregateMeasure) -> Self {
        self.query_param("aggregate", measure)
    }

    pub fn aggregate_all(
        mut self,
        measures: impl IntoIterator<Item = ObjectAggregateMeasure>,
    ) -> Self {
        for measure in measures {
            self = self.aggregate(measure);
        }
        self
    }

    pub fn aggregate_sort(self, sort: ObjectAggregateSort) -> Self {
        self.sort_by(sort)
    }

    pub fn computed_filter<V: ToString>(
        self,
        selector: ComputedFieldSelector,
        operator: FilterOperator,
        value: V,
    ) -> Self {
        self.filter(selector.to_string(), operator, value)
    }
}

impl<T> CursorRequest<T>
where
    T: DeserializeOwned,
{
    pub async fn page(self) -> Result<shared::Page<T>, ApiError> {
        let (endpoint, url_params) = match &self.name_route_fallback {
            Some(fallback) => fallback.resolve(&self.client).await?,
            None => (self.endpoint, self.url_params),
        };
        let raw = self
            .client
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &endpoint,
                url_params,
                self.query_params,
                EmptyPostParams,
            )
            .await?;
        shared::parse_page_response(&reqwest::Method::GET, raw)
    }

    pub async fn list(self) -> Result<Vec<T>, ApiError> {
        Ok(self.page().await?.items)
    }

    pub async fn all(self) -> Result<Vec<T>, ApiError> {
        let mut request = self;
        let mut items = Vec::new();
        let mut pagination = shared::AutoPaginationGuard::new(request.client.options());
        let mut seen_cursors = shared::pagination_cursors(&request.query_params);

        loop {
            pagination.before_request()?;
            let page = CursorRequest::<T> {
                client: request.client.clone(),
                endpoint: request.endpoint,
                query_params: request.query_params.clone(),
                url_params: request.url_params.clone(),
                name_route_fallback: request.name_route_fallback.clone(),
                _phantom: PhantomData,
            }
            .page()
            .await?;
            pagination.record_page(page.items.len())?;
            items.extend(page.items);

            match page.next_cursor {
                Some(cursor) => {
                    shared::advance_cursor(&mut request.query_params, &mut seen_cursors, cursor)?;
                }
                None => return Ok(items),
            }
        }
    }
}

impl<T> CursorRequest<T>
where
    T: DeserializeOwned + Send + 'static,
{
    pub fn pages(mut self) -> PageStream<T> {
        Box::pin(async_stream::try_stream! {
            let mut pagination = shared::AutoPaginationGuard::new(self.client.options());
            let mut seen_cursors = shared::pagination_cursors(&self.query_params);
            loop {
                pagination.before_request()?;
                let page = (CursorRequest::<T> {
                    client: self.client.clone(),
                    endpoint: self.endpoint,
                    query_params: self.query_params.clone(),
                    url_params: self.url_params.clone(),
                    name_route_fallback: self.name_route_fallback.clone(),
                    _phantom: PhantomData,
                })
                .page()
                .await?;
                pagination.record_page(page.items.len())?;
                let next_cursor = page.next_cursor.clone();
                yield page;
                let Some(cursor) = next_cursor else {
                    break;
                };
                shared::advance_cursor(
                    &mut self.query_params,
                    &mut seen_cursors,
                    cursor,
                )?;
            }
        })
    }

    pub fn items(self) -> ItemStream<T> {
        use futures_util::StreamExt;

        Box::pin(async_stream::try_stream! {
            let mut pages = self.pages();
            while let Some(page) = pages.next().await {
                for item in page?.items {
                    yield item;
                }
            }
        })
    }
}
