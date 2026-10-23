use super::*;

#[derive(Debug, Clone)]
pub struct CollectionScope {
    pub(super) client: Client<Authenticated>,
    pub(super) collection_id: CollectionId,
}

impl CollectionScope {
    pub fn id(&self) -> CollectionId {
        self.collection_id
    }

    pub fn classes(&self) -> Resource<Class> {
        self.client
            .classes()
            .set_raw_param("collection_id", self.collection_id)
    }

    pub fn export_templates(&self) -> Resource<ExportTemplate> {
        self.client
            .export_templates()
            .set_raw_param("collection_id", self.collection_id)
    }

    pub fn remote_targets(&self) -> Resource<RemoteTarget> {
        self.client
            .remote_targets()
            .set_raw_param("collection_id", self.collection_id)
    }

    pub fn events(&self) -> EventListRequest {
        self.client.collection_events(self.collection_id)
    }

    pub fn history(&self) -> HistoryRequest<CollectionHistory> {
        self.client.collection_history(self.collection_id)
    }

    pub fn history_full(&self) -> HistoryRequest<FullCollectionHistory> {
        self.client.collection_history_full(self.collection_id)
    }

    /// Collection-owned and explicitly granted event destinations.
    pub fn event_sinks(&self) -> Resource<CollectionEventSink> {
        self.client.collection_event_sinks(self.collection_id)
    }

    pub fn event_subscriptions(&self) -> EventSubscriptions {
        self.client.event_subscriptions(self.collection_id)
    }

    #[cfg(feature = "typed-schemas")]
    pub fn create_typed_class<T>(
        &self,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Result<TypedClass<T>, ApiError>
    where
        T: schemars::JsonSchema,
    {
        let class = self
            .client
            .classes()
            .create_checked()
            .name(name)
            .description(description)
            .collection_id(self.collection_id)
            .json_schema(crate::types::schema_for::<T>()?)
            .validate_schema(true)
            .send()?;
        Ok(self.client.typed_class(class.id))
    }
}

pub struct TypedClass<T> {
    pub(super) client: Client<Authenticated>,
    pub(super) class_id: ClassId,
    pub(super) _phantom: PhantomData<T>,
}

impl<T> Clone for TypedClass<T> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            class_id: self.class_id,
            _phantom: PhantomData,
        }
    }
}

impl<T> TypedClass<T> {
    pub fn id(&self) -> ClassId {
        self.class_id
    }
}

impl<T> TypedClass<T>
where
    T: DeserializeOwned,
{
    pub fn get(&self, object_id: impl Into<ObjectId>) -> Result<TypedObject<T>, ApiError> {
        self.client
            .objects(self.class_id)
            .get(object_id)?
            .into_inner()
            .try_into()
    }

    pub fn all(&self) -> Result<Vec<TypedObject<T>>, ApiError> {
        self.client
            .objects(self.class_id)
            .all()?
            .into_iter()
            .map(TryInto::try_into)
            .collect()
    }

    pub fn items(&self) -> impl Iterator<Item = Result<TypedObject<T>, ApiError>> {
        self.client
            .objects(self.class_id)
            .items()
            .map(|object| object.and_then(TryInto::try_into))
    }
}

impl<T> TypedClass<T>
where
    T: Serialize + DeserializeOwned,
{
    pub fn create(
        &self,
        collection_id: impl Into<CollectionId>,
        name: impl Into<String>,
        description: impl Into<String>,
        data: T,
    ) -> Result<TypedObject<T>, ApiError> {
        let data = serde_json::to_value(data)?;
        self.client
            .objects(self.class_id)
            .create_checked()
            .name(name)
            .collection_id(collection_id)
            .hubuum_class_id(self.class_id)
            .description(description)
            .data(data)
            .send()?
            .try_into()
    }
}

pub struct CreateOp<T: ApiResource> {
    pub(super) client: Client<Authenticated>,
    pub(super) url_params: UrlParams,
    pub(super) params: T::PostBuilder,
    pub(super) _phantom: PhantomData<T>,
}

impl<T: ApiResource> CreateOp<T> {
    pub(super) fn new(client: Client<Authenticated>, url_params: UrlParams) -> Self {
        Self {
            client,
            url_params,
            params: T::PostBuilder::default(),
            _phantom: PhantomData,
        }
    }

    pub fn params(mut self, params: T::PostParams) -> Self {
        self.params = params.into();
        self
    }

    pub(crate) fn edit_params<F>(mut self, edit: F) -> Self
    where
        F: FnOnce(&mut T::PostBuilder),
    {
        edit(&mut self.params);
        self
    }

    pub fn send(self) -> Result<T::PostOutput, ApiError> {
        let params = T::finish_post(self.params)?;
        T::validate_post(&params)?;
        self.client.post::<T>(self.url_params, params)
    }
}

pub struct UpdateOp<T: ApiResource> {
    pub(super) client: Client<Authenticated>,
    pub(super) id: T::Id,
    pub(super) url_params: UrlParams,
    pub(super) params: T::PatchParams,
    pub(super) if_match: Option<crate::types::EntityTag>,
    pub(super) _phantom: PhantomData<T>,
}

impl<T: ApiResource> UpdateOp<T> {
    pub(super) fn new(client: Client<Authenticated>, id: T::Id, url_params: UrlParams) -> Self {
        Self {
            client,
            id,
            url_params,
            params: T::PatchParams::default(),
            if_match: None,
            _phantom: PhantomData,
        }
    }

    pub fn params(mut self, params: T::PatchParams) -> Self {
        self.params = params;
        self
    }

    pub(crate) fn edit_params<F>(mut self, edit: F) -> Self
    where
        F: FnOnce(&mut T::PatchParams),
    {
        edit(&mut self.params);
        self
    }

    /// Apply this update only if the resource still matches `etag`.
    pub fn if_match(mut self, etag: impl Into<crate::types::EntityTag>) -> Self {
        self.if_match = Some(etag.into());
        self
    }

    pub fn send(self) -> Result<T::PatchOutput, ApiError> {
        T::validate_patch(&self.params)?;
        match self.if_match {
            Some(etag) => self.client.patch_with_headers::<T, _>(
                self.id,
                self.url_params,
                self.params,
                &shared::if_match_headers(&etag),
            ),
            None => self
                .client
                .patch::<T, _>(self.id, self.url_params, self.params),
        }
    }
}

pub struct Resource<T: ApiResource> {
    pub(super) client: Client<Authenticated>,
    pub(super) url_params: UrlParams,
    pub(super) query_params: Vec<QueryFilter>,
    pub(super) _phantom: PhantomData<T>,
}

impl<T: ApiResource> Resource<T> {
    pub(super) fn new<I, K, V>(client: Client<Authenticated>, url_params: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<Cow<'static, str>>,
        V: Into<Cow<'static, str>>,
    {
        Resource {
            client,
            url_params: url_params
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
            query_params: Vec::new(),
            _phantom: PhantomData,
        }
    }

    pub fn query(&self) -> QueryOp<T> {
        QueryOp::with_query_params(
            self.client.clone(),
            self.url_params.clone(),
            self.query_params.clone(),
        )
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
        self.query().list()
    }

    pub fn page(self) -> Result<shared::Page<T::GetOutput>, ApiError> {
        self.query().page()
    }

    pub fn all(self) -> Result<Vec<T::GetOutput>, ApiError> {
        self.query().all()
    }

    pub fn pages(self) -> QueryPageIterator<T> {
        self.query().pages()
    }

    pub fn items(self) -> QueryItemIterator<T> {
        self.query().items()
    }

    pub fn one(self) -> Result<T::GetOutput, ApiError> {
        self.query().one()
    }

    pub fn optional(self) -> Result<Option<T::GetOutput>, ApiError> {
        self.query().optional()
    }

    #[deprecated(since = "0.3.0", note = "use create_checked() or create_raw()")]
    pub fn create(&self) -> CreateOp<T> {
        CreateOp::<T>::new(self.client.clone(), self.url_params.clone())
    }

    pub fn create_raw(&self, params: T::PostParams) -> Result<T::PostOutput, ApiError> {
        CreateOp::<T>::new(self.client.clone(), self.url_params.clone())
            .params(params)
            .send()
    }

    pub fn update<I: Into<T::Id>>(&self, id: I) -> UpdateOp<T> {
        UpdateOp::new(self.client.clone(), id.into(), self.url_params.clone())
    }

    pub fn update_raw<I>(&self, id: I, params: T::PatchParams) -> Result<T::PatchOutput, ApiError>
    where
        I: Into<T::Id>,
    {
        self.update(id).params(params).send()
    }

    pub fn delete<I: Into<T::Id>>(&self, id: I) -> Result<(), ApiError> {
        self.client
            .delete::<T, _>(id.into(), self.url_params.clone())
    }

    /// Delete a resource only if it still matches `etag`.
    pub fn delete_if_match<I: Into<T::Id>>(
        &self,
        id: I,
        etag: &crate::types::EntityTag,
    ) -> Result<(), ApiError> {
        self.client.delete_with_headers::<T, _>(
            id.into(),
            self.url_params.clone(),
            &shared::if_match_headers(etag),
        )
    }
}

impl<T: ApiResource> shared::QueryFilterTarget for Resource<T> {
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

impl Resource<Object> {
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

pub type Handle<T> = shared::Handle<Client<Authenticated>, T>;

impl<T> Resource<T>
where
    T: ApiResource<GetOutput = T> + DeserializeOwned + GetID + 'static,
{
    pub fn get<I: Into<T::Id>>(&self, id: I) -> Result<Handle<T>, ApiError> {
        let id = id.into();
        if let Some(endpoint) = T::ITEM_ENDPOINT {
            let mut url_params = self.url_params.clone();
            url_params.push((Cow::Borrowed(T::ID_PARAM), id.to_string().into()));
            match self.client.request_with_endpoint_raw(
                reqwest::Method::GET,
                &endpoint,
                url_params,
                vec![],
                EmptyPostParams,
            ) {
                Ok(raw) => {
                    if let Some(resource) =
                        shared::parse_response::<T>(&reqwest::Method::GET, raw.status, raw.body)?
                    {
                        return Ok(Handle::new_with_etag(
                            self.client.clone(),
                            resource,
                            raw.etag,
                        ));
                    }
                }
                Err(ApiError::HttpWithBody { status, .. })
                    if status == reqwest::StatusCode::NOT_FOUND => {}
                Err(err) => return Err(err),
            }
        }

        let (id_params, filters) = shared::select_id_lookup_params(id);
        let mut url_params = self.url_params.clone();
        url_params.extend(id_params);
        let raw: Vec<<T as ApiResource>::GetOutput> =
            self.client.get::<T, _>(url_params, filters)?;

        let resource: T = one_or_err(raw)?;
        Ok(Handle::new(self.client.clone(), resource))
    }

    pub fn get_by_name(&self, name: &str) -> Result<Handle<T>, ApiError> {
        if !shared::requires_name_route_fallback(name)
            && let Some(endpoint) = T::NAME_ITEM_ENDPOINT
        {
            let mut url_params = self.url_params.clone();
            url_params.push((Cow::Borrowed(T::NAME_PARAM), name.to_string().into()));
            match self.client.request_with_endpoint_raw(
                reqwest::Method::GET,
                &endpoint,
                url_params,
                vec![],
                EmptyPostParams,
            ) {
                Ok(raw) => {
                    if let Some(resource) =
                        shared::parse_response::<T>(&reqwest::Method::GET, raw.status, raw.body)?
                    {
                        return Ok(Handle::new_with_etag(
                            self.client.clone(),
                            resource,
                            raw.etag,
                        ));
                    }
                }
                Err(ApiError::HttpWithBody { status, .. })
                    if status == reqwest::StatusCode::NOT_FOUND => {}
                Err(error) => return Err(error),
            }
        }

        let (name_params, filters) = shared::select_name_lookup_params::<T>(name);
        let mut url_params = self.url_params.clone();
        url_params.extend(name_params);
        let raw: Vec<<T as ApiResource>::GetOutput> =
            self.client.get::<T, _>(url_params, filters)?;

        let got = one_or_err(raw)?;
        let resource: T = got;
        Ok(Handle::new(self.client.clone(), resource))
    }
}
