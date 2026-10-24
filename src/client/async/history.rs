use super::*;

impl Client<Authenticated> {
    pub(super) async fn history_as_of<T: DeserializeOwned>(
        &self,
        endpoint: Endpoint,
        url_params: UrlParams,
        at: HubuumDateTime,
        empty_message: &str,
    ) -> Result<T, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, T>(
            reqwest::Method::GET,
            &endpoint,
            url_params,
            vec![QueryFilter::raw("at", at.0.to_rfc3339())],
            EmptyPostParams,
        )
        .await?
        .ok_or(ApiError::EmptyResult(empty_message.into()))
    }

    pub fn collection_history(
        &self,
        collection_id: impl Into<CollectionId>,
    ) -> HistoryRequest<CollectionHistory> {
        let collection_id = collection_id.into();
        HistoryRequest::new(
            self.clone(),
            Endpoint::CollectionHistory,
            vec![(
                Cow::Borrowed("collection_id"),
                collection_id.to_string().into(),
            )],
        )
    }

    pub fn collection_history_full(
        &self,
        collection_id: impl Into<CollectionId>,
    ) -> HistoryRequest<FullCollectionHistory> {
        let collection_id = collection_id.into();
        HistoryRequest::new(
            self.clone(),
            Endpoint::CollectionHistory,
            vec![(
                Cow::Borrowed("collection_id"),
                collection_id.to_string().into(),
            )],
        )
    }

    pub async fn collection_history_as_of(
        &self,
        collection_id: impl Into<CollectionId>,
        at: HubuumDateTime,
    ) -> Result<CollectionHistory, ApiError> {
        let collection_id = collection_id.into();
        self.history_as_of(
            Endpoint::CollectionHistoryAsOf,
            vec![(
                Cow::Borrowed("collection_id"),
                collection_id.to_string().into(),
            )],
            at,
            "Collection history as-of returned empty result",
        )
        .await
    }

    pub async fn collection_history_as_of_full(
        &self,
        collection_id: impl Into<CollectionId>,
        at: HubuumDateTime,
    ) -> Result<FullCollectionHistory, ApiError> {
        let collection_id = collection_id.into();
        self.history_as_of(
            Endpoint::CollectionHistoryAsOf,
            vec![(
                Cow::Borrowed("collection_id"),
                collection_id.to_string().into(),
            )],
            at,
            "Full collection history as-of returned empty result",
        )
        .await
    }

    /// Read lightweight retained timeline markers. Continue with the same selection and cursor.
    pub async fn class_history_timeline(
        &self,
        class_id: ClassId,
        options: HistoryTimelineOptions,
    ) -> Result<shared::Page<HistoryMarker<ClassId>>, ApiError> {
        let params = shared::history_url_params(class_id, None, None);
        let query = shared::history_timeline_query(options);
        let raw = self
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ClassHistoryTimeline,
                params,
                query,
                EmptyPostParams,
            )
            .await?;
        shared::parse_page_response(&reqwest::Method::GET, raw)
    }

    /// Read one resource-scoped retained entry, including an authorized deletion marker.
    pub async fn class_history_entry(
        &self,
        class_id: ClassId,
        history_id: HistoryId,
    ) -> Result<ClassHistory, ApiError> {
        let params = shared::history_url_params(class_id, None, Some(history_id));
        let query = Vec::new();
        let raw = self
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ClassHistoryEntry,
                params,
                query,
                EmptyPostParams,
            )
            .await?;
        shared::parse_response(&reqwest::Method::GET, raw.status, raw.body)?
            .ok_or_else(|| ApiError::EmptyResult("History returned an empty response".into()))
    }

    /// Read retained direct relationship changes with endpoint context at each change's timestamp.
    pub async fn class_relation_history(
        &self,
        class_id: ClassId,
        options: RelationHistoryOptions,
    ) -> Result<HistoryPage<HistoricalRelationships>, ApiError> {
        let params = shared::history_url_params(class_id, None, None);
        let query = shared::relation_history_query(options);
        let raw = self
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ClassRelationHistory,
                params,
                query,
                EmptyPostParams,
            )
            .await?;
        shared::parse_history_page(raw)
    }

    /// Read retained direct relationships and endpoint context at one instant.
    pub async fn class_relations_as_of(
        &self,
        class_id: ClassId,
        at: HubuumDateTime,
        options: RelationHistoryOptions,
    ) -> Result<HistoryPage<HistoricalRelationships>, ApiError> {
        let params = shared::history_url_params(class_id, None, None);
        let mut query = shared::relation_history_query(options);
        query.push(QueryFilter::raw("at", at.0.to_rfc3339()));
        let raw = self
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ClassRelationHistoryAsOf,
                params,
                query,
                EmptyPostParams,
            )
            .await?;
        shared::parse_history_page(raw)
    }

    /// Read lightweight retained timeline markers. Continue with the same selection and cursor.
    pub async fn object_history_timeline(
        &self,
        class_id: ClassId,
        object_id: ObjectId,
        options: HistoryTimelineOptions,
    ) -> Result<shared::Page<HistoryMarker<ObjectId>>, ApiError> {
        let params = shared::history_url_params(class_id, Some(object_id), None);
        let query = shared::history_timeline_query(options);
        let raw = self
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ObjectHistoryTimeline,
                params,
                query,
                EmptyPostParams,
            )
            .await?;
        shared::parse_page_response(&reqwest::Method::GET, raw)
    }

    /// Read one resource-scoped retained entry, including an authorized deletion marker.
    pub async fn object_history_entry(
        &self,
        class_id: ClassId,
        object_id: ObjectId,
        history_id: HistoryId,
    ) -> Result<ObjectHistory, ApiError> {
        let params = shared::history_url_params(class_id, Some(object_id), Some(history_id));
        let query = Vec::new();
        let raw = self
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ObjectHistoryEntry,
                params,
                query,
                EmptyPostParams,
            )
            .await?;
        shared::parse_response(&reqwest::Method::GET, raw.status, raw.body)?
            .ok_or_else(|| ApiError::EmptyResult("History returned an empty response".into()))
    }

    /// Read retained direct relationship changes with endpoint context at each change's timestamp.
    pub async fn object_relation_history(
        &self,
        class_id: ClassId,
        object_id: ObjectId,
        options: RelationHistoryOptions,
    ) -> Result<HistoryPage<HistoricalRelationships>, ApiError> {
        let params = shared::history_url_params(class_id, Some(object_id), None);
        let query = shared::relation_history_query(options);
        let raw = self
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ObjectRelationHistory,
                params,
                query,
                EmptyPostParams,
            )
            .await?;
        shared::parse_history_page(raw)
    }

    /// Read retained direct relationships and endpoint context at one instant.
    pub async fn object_relations_as_of(
        &self,
        class_id: ClassId,
        object_id: ObjectId,
        at: HubuumDateTime,
        options: RelationHistoryOptions,
    ) -> Result<HistoryPage<HistoricalRelationships>, ApiError> {
        let params = shared::history_url_params(class_id, Some(object_id), None);
        let mut query = shared::relation_history_query(options);
        query.push(QueryFilter::raw("at", at.0.to_rfc3339()));
        let raw = self
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ObjectRelationHistoryAsOf,
                params,
                query,
                EmptyPostParams,
            )
            .await?;
        shared::parse_history_page(raw)
    }

    /// Read exact-name snapshots across object identities. Numeric names remain names; empty matches return an empty page.
    pub async fn object_history_by_name(
        &self,
        class_id: ClassId,
        name: impl Into<String>,
        options: ObjectHistoryOptions,
    ) -> Result<shared::Page<ObjectHistory>, ApiError> {
        let params = shared::history_url_params(class_id, None, None);
        let mut query = shared::object_history_query(options);
        query.push(QueryFilter::raw("name", name.into()));
        let raw = self
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ObjectHistoryByName,
                params,
                query,
                EmptyPostParams,
            )
            .await?;
        shared::parse_page_response(&reqwest::Method::GET, raw)
    }

    /// Read the retained class/schema and effective object population at the same instant. Coverage is limited to retained history.
    pub async fn class_objects_as_of(
        &self,
        class_id: ClassId,
        at: HubuumDateTime,
        options: ObjectHistoryOptions,
    ) -> Result<HistoryPage<HistoricalClassObjects>, ApiError> {
        let params = shared::history_url_params(class_id, None, None);
        let mut query = shared::object_history_query(options);
        query.push(QueryFilter::raw("at", at.0.to_rfc3339()));
        let raw = self
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ClassObjectsHistoryAsOf,
                params,
                query,
                EmptyPostParams,
            )
            .await?;
        shared::parse_history_page(raw)
    }

    /// Recompute shared fields from retained object and definition snapshots. Personal fields are unsupported; unavailability is explicit.
    pub async fn object_computed_as_of(
        &self,
        class_id: ClassId,
        object_id: ObjectId,
        at: HubuumDateTime,
    ) -> Result<HistoricalComputedValues, ApiError> {
        let params = shared::history_url_params(class_id, Some(object_id), None);
        let query = vec![QueryFilter::raw("at", at.0.to_rfc3339())];
        let raw = self
            .request_with_endpoint_raw(
                reqwest::Method::GET,
                &Endpoint::ObjectComputedHistoryAsOf,
                params,
                query,
                EmptyPostParams,
            )
            .await?;
        shared::parse_response(&reqwest::Method::GET, raw.status, raw.body)?
            .ok_or_else(|| ApiError::EmptyResult("History returned an empty response".into()))
    }

    pub fn class_history(&self, class_id: impl Into<ClassId>) -> HistoryRequest<ClassHistory> {
        let class_id = class_id.into();
        HistoryRequest::new(
            self.clone(),
            Endpoint::ClassHistory,
            vec![(Cow::Borrowed("class_id"), class_id.to_string().into())],
        )
    }

    pub async fn class_history_as_of(
        &self,
        class_id: impl Into<ClassId>,
        at: HubuumDateTime,
    ) -> Result<ClassHistory, ApiError> {
        let class_id = class_id.into();
        self.history_as_of(
            Endpoint::ClassHistoryAsOf,
            vec![(Cow::Borrowed("class_id"), class_id.to_string().into())],
            at,
            "Class history as-of returned empty result",
        )
        .await
    }

    pub fn object_history(
        &self,
        class_id: impl Into<ClassId>,
        object_id: impl Into<ObjectId>,
    ) -> HistoryRequest<ObjectHistory> {
        let class_id = class_id.into();
        let object_id = object_id.into();
        HistoryRequest::new(
            self.clone(),
            Endpoint::ObjectHistory,
            vec![
                (Cow::Borrowed("class_id"), class_id.to_string().into()),
                (Cow::Borrowed("object_id"), object_id.to_string().into()),
            ],
        )
    }

    pub async fn object_history_as_of(
        &self,
        class_id: impl Into<ClassId>,
        object_id: impl Into<ObjectId>,
        at: HubuumDateTime,
    ) -> Result<ObjectHistory, ApiError> {
        let class_id = class_id.into();
        let object_id = object_id.into();
        self.history_as_of(
            Endpoint::ObjectHistoryAsOf,
            vec![
                (Cow::Borrowed("class_id"), class_id.to_string().into()),
                (Cow::Borrowed("object_id"), object_id.to_string().into()),
            ],
            at,
            "Object history as-of returned empty result",
        )
        .await
    }

    pub fn export_template_history(
        &self,
        template_id: impl Into<ExportTemplateId>,
    ) -> HistoryRequest<ExportTemplateHistory> {
        let template_id = template_id.into();
        HistoryRequest::new(
            self.clone(),
            Endpoint::ExportTemplateHistory,
            vec![(Cow::Borrowed("template_id"), template_id.to_string().into())],
        )
    }

    pub fn template_history(
        &self,
        template_id: impl Into<ExportTemplateId>,
    ) -> HistoryRequest<ExportTemplateHistory> {
        self.export_template_history(template_id)
    }

    pub async fn export_template_history_as_of(
        &self,
        template_id: impl Into<ExportTemplateId>,
        at: HubuumDateTime,
    ) -> Result<ExportTemplateHistory, ApiError> {
        let template_id = template_id.into();
        self.history_as_of(
            Endpoint::ExportTemplateHistoryAsOf,
            vec![(Cow::Borrowed("template_id"), template_id.to_string().into())],
            at,
            "Export template history as-of returned empty result",
        )
        .await
    }

    pub async fn template_history_as_of(
        &self,
        template_id: impl Into<ExportTemplateId>,
        at: HubuumDateTime,
    ) -> Result<ExportTemplateHistory, ApiError> {
        self.export_template_history_as_of(template_id, at).await
    }

    pub fn remote_target_history(
        &self,
        remote_target_id: impl Into<RemoteTargetId>,
    ) -> HistoryRequest<RemoteTargetHistory> {
        let remote_target_id = remote_target_id.into();
        HistoryRequest::new(
            self.clone(),
            Endpoint::RemoteTargetHistory,
            vec![(
                Cow::Borrowed("remote_target_id"),
                remote_target_id.to_string().into(),
            )],
        )
    }

    pub async fn remote_target_history_as_of(
        &self,
        remote_target_id: impl Into<RemoteTargetId>,
        at: HubuumDateTime,
    ) -> Result<RemoteTargetHistory, ApiError> {
        let remote_target_id = remote_target_id.into();
        self.history_as_of(
            Endpoint::RemoteTargetHistoryAsOf,
            vec![(
                Cow::Borrowed("remote_target_id"),
                remote_target_id.to_string().into(),
            )],
            at,
            "Remote target history as-of returned empty result",
        )
        .await
    }
}

pub struct HistoryRequest<T> {
    pub(super) inner: CursorRequest<T>,
}

impl<T> HistoryRequest<T>
where
    T: DeserializeOwned,
{
    pub(super) fn new(
        client: Client<Authenticated>,
        endpoint: Endpoint,
        url_params: UrlParams,
    ) -> Self {
        Self {
            inner: CursorRequest::new(client, endpoint, url_params),
        }
    }

    pub fn limit(mut self, limit: usize) -> Self {
        self.inner = self.inner.limit(limit);
        self
    }

    pub fn include_total(mut self, include_total: bool) -> Self {
        self.inner = self.inner.include_total(include_total);
        self
    }

    pub fn sort<S: AsRef<str>>(mut self, field: S, direction: SortDirection) -> Self {
        self.inner = self.inner.sort(field, direction);
        self
    }

    pub fn cursor<V: ToString>(mut self, cursor: V) -> Self {
        self.inner = self.inner.cursor(cursor);
        self
    }

    pub async fn page(self) -> Result<shared::Page<T>, ApiError> {
        self.inner.page().await
    }

    pub async fn list(self) -> Result<Vec<T>, ApiError> {
        self.inner.list().await
    }

    pub async fn all(self) -> Result<Vec<T>, ApiError> {
        self.inner.all().await
    }
}

impl<T> HistoryRequest<T>
where
    T: DeserializeOwned + Send + 'static,
{
    pub fn pages(self) -> PageStream<T> {
        self.inner.pages()
    }

    pub fn items(self) -> ItemStream<T> {
        self.inner.items()
    }
}
