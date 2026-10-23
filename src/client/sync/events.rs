use super::*;

impl Client<Authenticated> {
    /// Render a source event without sending it. Requires administrator access.
    pub fn preview_event_notification(
        &self,
        sink_id: impl Into<EventSinkId>,
        request: EventNotificationRequest,
    ) -> Result<EventNotificationPreview, ApiError> {
        let raw = self.request_with_endpoint_raw(
            reqwest::Method::POST,
            &Endpoint::EventSinkPreview,
            vec![("sink_id".into(), sink_id.into().to_string().into())],
            vec![],
            request,
        )?;
        shared::decode_json_body(&raw.body)
    }

    /// Queue a real test delivery, bypassing enabled flags and subscription filters.
    pub fn test_event_notification(
        &self,
        sink_id: impl Into<EventSinkId>,
        request: EventNotificationRequest,
    ) -> Result<EventDelivery, ApiError> {
        let raw = self.request_with_endpoint_raw(
            reqwest::Method::POST,
            &Endpoint::EventSinkTest,
            vec![("sink_id".into(), sink_id.into().to_string().into())],
            vec![],
            request,
        )?;
        shared::decode_json_body(&raw.body)
    }

    /// List direct collection grants for a global sink. Administrator-only.
    pub fn event_sink_collections(
        &self,
        sink_id: impl Into<EventSinkId>,
    ) -> Result<Vec<CollectionId>, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, Vec<CollectionId>>(
            reqwest::Method::GET,
            &Endpoint::EventSinkCollections,
            vec![("sink_id".into(), sink_id.into().to_string().into())],
            vec![],
            EmptyPostParams,
        )?
        .ok_or(ApiError::EmptyResult(
            "Sink collection grants returned empty result".into(),
        ))
    }

    /// Permit one collection to use a global sink. Administrator-only.
    pub fn grant_event_sink(
        &self,
        sink_id: impl Into<EventSinkId>,
        collection_id: impl Into<CollectionId>,
    ) -> Result<(), ApiError> {
        self.change_event_sink_grant(sink_id.into(), collection_id.into(), reqwest::Method::PUT)
    }

    /// Revoke a collection's grant, including admission of queued deliveries.
    pub fn revoke_event_sink(
        &self,
        sink_id: impl Into<EventSinkId>,
        collection_id: impl Into<CollectionId>,
    ) -> Result<(), ApiError> {
        self.change_event_sink_grant(
            sink_id.into(),
            collection_id.into(),
            reqwest::Method::DELETE,
        )
    }

    pub(super) fn change_event_sink_grant(
        &self,
        sink_id: EventSinkId,
        collection_id: CollectionId,
        method: reqwest::Method,
    ) -> Result<(), ApiError> {
        self.request_with_endpoint::<EmptyPostParams, serde_json::Value>(
            method,
            &Endpoint::EventSinkCollectionGrant,
            vec![
                ("sink_id".into(), sink_id.to_string().into()),
                ("collection_id".into(), collection_id.to_string().into()),
            ],
            vec![],
            EmptyPostParams,
        )
        .map(|_| ())
    }
}

pub struct EventListRequest {
    pub(super) inner: CursorRequest<EventResponse>,
}

impl EventListRequest {
    pub(super) fn new(
        client: Client<Authenticated>,
        endpoint: Endpoint,
        url_params: UrlParams,
    ) -> Self {
        Self {
            inner: CursorRequest::new(client, endpoint, url_params),
        }
    }

    /// Include direct class/object relation activity for the selected entity.
    pub fn include_relations(mut self, include: bool) -> Self {
        self.inner = self.inner.set_query_param("include_relations", include);
        self
    }

    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.inner = self.inner.set_query_param("action", action.into());
        self
    }

    pub fn actor_kind(mut self, actor_kind: impl Into<String>) -> Self {
        self.inner = self.inner.set_query_param("actor_kind", actor_kind.into());
        self
    }

    pub fn actor_user_id(mut self, actor_user_id: impl Into<UserId>) -> Self {
        self.inner = self
            .inner
            .set_query_param("actor_user_id", actor_user_id.into());
        self
    }

    pub fn initiator_user_id(mut self, initiator_user_id: impl Into<PrincipalId>) -> Self {
        self.inner = self
            .inner
            .set_query_param("initiator_user_id", initiator_user_id.into());
        self
    }

    pub fn entity_type(mut self, entity_type: impl Into<String>) -> Self {
        self.inner = self
            .inner
            .set_query_param("entity_type", entity_type.into());
        self
    }

    pub fn entity_id(mut self, entity_id: i32) -> Self {
        self.inner = self.inner.set_query_param("entity_id", entity_id);
        self
    }

    pub fn collection_id(mut self, collection_id: impl Into<CollectionId>) -> Self {
        self.inner = self
            .inner
            .set_query_param("collection_id", collection_id.into());
        self
    }

    pub fn occurred_after(mut self, occurred_after: impl Into<String>) -> Self {
        self.inner = self
            .inner
            .set_query_param("occurred_after", occurred_after.into());
        self
    }

    pub fn occurred_before(mut self, occurred_before: impl Into<String>) -> Self {
        self.inner = self
            .inner
            .set_query_param("occurred_before", occurred_before.into());
        self
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

    pub fn page(self) -> Result<shared::Page<EventResponse>, ApiError> {
        self.inner.page()
    }

    pub fn list(self) -> Result<Vec<EventResponse>, ApiError> {
        self.inner.list()
    }

    pub fn all(self) -> Result<Vec<EventResponse>, ApiError> {
        self.inner.all()
    }

    pub fn pages(self) -> CursorPageIterator<EventResponse> {
        self.inner.pages()
    }

    pub fn items(self) -> CursorItemIterator<EventResponse> {
        self.inner.items()
    }
}

/// Administrator-only subscriptions for events outside collection scope.
pub struct SystemEventSubscriptions {
    pub(super) client: Client<Authenticated>,
}

impl SystemEventSubscriptions {
    pub fn list(&self) -> Result<Vec<SystemEventSubscription>, ApiError> {
        let raw = self.client.request_with_endpoint_raw(
            reqwest::Method::GET,
            &Endpoint::SystemEventSubscriptions,
            vec![],
            vec![],
            EmptyPostParams,
        )?;
        shared::decode_json_body(&raw.body)
    }
    pub fn get(
        &self,
        subscription_id: impl Into<EventSubscriptionId>,
    ) -> Result<SystemEventSubscription, ApiError> {
        let raw = self.client.request_with_endpoint_raw(
            reqwest::Method::GET,
            &Endpoint::SystemEventSubscriptionsById,
            vec![(
                "subscription_id".into(),
                subscription_id.into().to_string().into(),
            )],
            vec![],
            EmptyPostParams,
        )?;
        shared::decode_json_body(&raw.body)
    }
    pub fn create(
        &self,
        request: NewEventSubscription,
    ) -> Result<SystemEventSubscription, ApiError> {
        let raw = self.client.request_with_endpoint_raw(
            reqwest::Method::POST,
            &Endpoint::SystemEventSubscriptions,
            vec![],
            vec![],
            request,
        )?;
        shared::decode_json_body(&raw.body)
    }
    pub fn update(
        &self,
        subscription_id: impl Into<EventSubscriptionId>,
        request: UpdateEventSubscription,
    ) -> Result<SystemEventSubscription, ApiError> {
        let raw = self.client.request_with_endpoint_raw(
            reqwest::Method::PATCH,
            &Endpoint::SystemEventSubscriptions,
            vec![("patch_id".into(), subscription_id.into().to_string().into())],
            vec![],
            request,
        )?;
        shared::decode_json_body(&raw.body)
    }
    pub fn delete(&self, subscription_id: impl Into<EventSubscriptionId>) -> Result<(), ApiError> {
        let raw = self.client.request_with_endpoint_raw(
            reqwest::Method::DELETE,
            &Endpoint::SystemEventSubscriptionsById,
            vec![(
                "subscription_id".into(),
                subscription_id.into().to_string().into(),
            )],
            vec![],
            EmptyPostParams,
        )?;
        drop(raw);
        Ok(())
    }
}

pub struct EventSubscriptions {
    pub(super) client: Client<Authenticated>,
    pub(super) collection_id: CollectionId,
}

impl EventSubscriptions {
    pub(super) fn new(client: Client<Authenticated>, collection_id: CollectionId) -> Self {
        Self {
            client,
            collection_id,
        }
    }

    pub(super) fn url_params(&self) -> UrlParams {
        vec![(
            Cow::Borrowed("collection_id"),
            self.collection_id.to_string().into(),
        )]
    }

    pub(super) fn url_params_with_subscription(
        &self,
        subscription_id: EventSubscriptionId,
    ) -> UrlParams {
        vec![
            (
                Cow::Borrowed("collection_id"),
                self.collection_id.to_string().into(),
            ),
            (
                Cow::Borrowed("subscription_id"),
                subscription_id.to_string().into(),
            ),
        ]
    }

    pub fn query(&self) -> CursorRequest<EventSubscription> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::CollectionEventSubscriptions,
            self.url_params(),
        )
    }

    pub fn get(
        &self,
        subscription_id: impl Into<EventSubscriptionId>,
    ) -> Result<EventSubscription, ApiError> {
        let subscription_id = subscription_id.into();
        self.client
            .request_with_endpoint::<EmptyPostParams, EventSubscription>(
                reqwest::Method::GET,
                &Endpoint::CollectionEventSubscriptionsById,
                self.url_params_with_subscription(subscription_id),
                vec![],
                EmptyPostParams,
            )?
            .ok_or(ApiError::EmptyResult(
                "Event subscription returned empty result".into(),
            ))
    }

    pub fn create(&self, request: NewEventSubscription) -> Result<EventSubscription, ApiError> {
        self.client
            .request_with_endpoint::<NewEventSubscription, EventSubscription>(
                reqwest::Method::POST,
                &Endpoint::CollectionEventSubscriptions,
                self.url_params(),
                vec![],
                request,
            )?
            .ok_or(ApiError::EmptyResult(
                "Event subscription create returned empty result".into(),
            ))
    }

    pub fn update(
        &self,
        subscription_id: impl Into<EventSubscriptionId>,
        request: UpdateEventSubscription,
    ) -> Result<EventSubscription, ApiError> {
        let subscription_id = subscription_id.into();
        let mut url_params = self.url_params();
        url_params.push(("patch_id".into(), subscription_id.to_string().into()));
        self.client
            .request_with_endpoint::<UpdateEventSubscription, EventSubscription>(
                reqwest::Method::PATCH,
                &Endpoint::CollectionEventSubscriptions,
                url_params,
                vec![],
                request,
            )?
            .ok_or(ApiError::EmptyResult(
                "Event subscription update returned empty result".into(),
            ))
    }

    pub fn delete(&self, subscription_id: impl Into<EventSubscriptionId>) -> Result<(), ApiError> {
        let subscription_id = subscription_id.into();
        let mut url_params = self.url_params();
        url_params.push(("delete_id".into(), subscription_id.to_string().into()));
        self.client
            .request_with_endpoint::<EmptyPostParams, serde_json::Value>(
                reqwest::Method::DELETE,
                &Endpoint::CollectionEventSubscriptions,
                url_params,
                vec![],
                EmptyPostParams,
            )
            .map(|_| ())
    }
}

pub struct EventDeliveries {
    pub(super) client: Client<Authenticated>,
}

impl EventDeliveries {
    pub(super) fn new(client: Client<Authenticated>) -> Self {
        Self { client }
    }

    pub fn query(&self) -> CursorRequest<EventDelivery> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::EventDeliveries,
            UrlParams::default(),
        )
    }

    pub fn get(&self, delivery_id: impl Into<EventDeliveryId>) -> Result<EventDelivery, ApiError> {
        let delivery_id = delivery_id.into();
        self.client
            .request_with_endpoint::<EmptyPostParams, EventDelivery>(
                reqwest::Method::GET,
                &Endpoint::EventDeliveriesById,
                vec![(Cow::Borrowed("delivery_id"), delivery_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )?
            .ok_or(ApiError::EmptyResult(
                "Event delivery returned empty result".into(),
            ))
    }

    pub fn health(&self) -> Result<EventDeliveryHealthResponse, ApiError> {
        self.client
            .request_with_endpoint::<EmptyPostParams, EventDeliveryHealthResponse>(
                reqwest::Method::GET,
                &Endpoint::EventDeliveryHealth,
                UrlParams::default(),
                vec![],
                EmptyPostParams,
            )?
            .ok_or(ApiError::EmptyResult(
                "Event delivery health returned empty result".into(),
            ))
    }

    pub fn retry(
        &self,
        delivery_id: impl Into<EventDeliveryId>,
    ) -> Result<EventDelivery, ApiError> {
        self.update_delivery(Endpoint::EventDeliveryRetry, delivery_id, "retry")
    }

    pub fn mark_dead(
        &self,
        delivery_id: impl Into<EventDeliveryId>,
    ) -> Result<EventDelivery, ApiError> {
        self.update_delivery(Endpoint::EventDeliveryDead, delivery_id, "mark dead")
    }

    pub(super) fn update_delivery(
        &self,
        endpoint: Endpoint,
        delivery_id: impl Into<EventDeliveryId>,
        operation: &str,
    ) -> Result<EventDelivery, ApiError> {
        let delivery_id = delivery_id.into();
        self.client
            .request_with_endpoint::<EmptyPostParams, EventDeliveryUpdateResponse>(
                reqwest::Method::POST,
                &endpoint,
                vec![(Cow::Borrowed("delivery_id"), delivery_id.to_string().into())],
                vec![],
                EmptyPostParams,
            )?
            .map(|response| response.delivery)
            .ok_or(ApiError::EmptyResult(format!(
                "Event delivery {operation} returned empty result"
            )))
    }
}
