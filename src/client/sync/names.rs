use super::*;

impl Client<Authenticated> {
    pub(super) fn resolve_class_name_id(
        &self,
        class_name: &str,
        cached_id: &OnceLock<ClassId>,
    ) -> Result<ClassId, ApiError> {
        if let Some(class_id) = cached_id.get() {
            return Ok(*class_id);
        }

        let class_id = self.classes().get_by_name(class_name)?.id();
        let _ = cached_id.set(class_id);
        Ok(class_id)
    }

    pub(super) fn resolve_object_name_ids(
        &self,
        class_name: &str,
        object_name: &str,
        cached_class_id: &OnceLock<ClassId>,
        cached_object_id: &OnceLock<ObjectId>,
    ) -> Result<(ClassId, ObjectId), ApiError> {
        let class_id = self.resolve_class_name_id(class_name, cached_class_id)?;
        if let Some(object_id) = cached_object_id.get() {
            return Ok((class_id, *object_id));
        }

        let object_id = self.objects(class_id).get_by_name(object_name)?.id();
        let _ = cached_object_id.set(object_id);
        Ok((class_id, object_id))
    }
}

/// Operations rooted at a class's exact natural key.
#[derive(Debug, Clone)]
pub struct ClassNameScope {
    pub(super) client: Client<Authenticated>,
    pub(super) class_name: String,
    pub(super) class_id: Arc<OnceLock<ClassId>>,
}

impl ClassNameScope {
    pub(super) fn new(client: Client<Authenticated>, class_name: String) -> Self {
        Self {
            client,
            class_name,
            class_id: Arc::new(OnceLock::new()),
        }
    }

    pub(super) fn encoded_name(&self) -> String {
        shared::encode_path_segment(&self.class_name)
    }

    pub(super) fn class_params(&self) -> UrlParams {
        vec![(Cow::Borrowed("class_name"), self.class_name.clone().into())]
    }

    pub(super) fn class_path(&self) -> String {
        Endpoint::ClassesByName
            .path()
            .replace("{class_name}", &self.encoded_name())
    }

    pub fn name(&self) -> &str {
        &self.class_name
    }

    pub fn get(&self) -> Result<Handle<Class>, ApiError> {
        if shared::requires_name_route_fallback(&self.class_name) {
            let class_id = self
                .client
                .resolve_class_name_id(&self.class_name, &self.class_id)?;
            return self.client.classes().get(class_id);
        }

        let raw = self.client.request_with_endpoint_raw(
            reqwest::Method::GET,
            &Endpoint::ClassesByName,
            self.class_params(),
            vec![],
            EmptyPostParams,
        )?;
        let class =
            shared::parse_response::<Class>(&reqwest::Method::GET, raw.status, raw.body)?
                .ok_or_else(|| ApiError::EmptyResult("Class returned an empty response".into()))?;
        let _ = self.class_id.set(class.id);
        Ok(Handle::new_with_etag(self.client.clone(), class, raw.etag))
    }

    pub fn update(&self, patch: ClassPatch) -> Result<Class, ApiError> {
        if shared::requires_name_route_fallback(&self.class_name) {
            let class_id = self
                .client
                .resolve_class_name_id(&self.class_name, &self.class_id)?;
            return self.client.classes().update_raw(class_id, patch);
        }

        let class: Class = self
            .client
            .raw_with_encoded_segments(reqwest::Method::PATCH, self.class_path())
            .json(&patch)?
            .send()?;
        let _ = self.class_id.set(class.id);
        Ok(class)
    }

    pub fn delete(&self) -> Result<(), ApiError> {
        if shared::requires_name_route_fallback(&self.class_name) {
            let class_id = self
                .client
                .resolve_class_name_id(&self.class_name, &self.class_id)?;
            return self.client.classes().delete(class_id);
        }

        self.client.request_with_endpoint::<EmptyPostParams, ()>(
            reqwest::Method::DELETE,
            &Endpoint::ClassesByName,
            self.class_params(),
            vec![],
            EmptyPostParams,
        )?;
        Ok(())
    }

    pub fn objects(&self) -> ClassNameObjects {
        ClassNameObjects {
            client: self.client.clone(),
            class_name: self.class_name.clone(),
            class_id: self.class_id.clone(),
        }
    }

    pub fn object_aggregates(&self) -> CursorRequest<ObjectAggregateRow> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::ClassByNameObjectAggregates,
            self.class_params(),
        )
        .with_class_name_fallback(
            self.class_name.clone(),
            self.class_id.clone(),
            Endpoint::ClassObjectAggregates,
        )
    }

    pub fn permissions(&self) -> CursorRequest<GroupPermissionsResult> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::ClassByNamePermissions,
            self.class_params(),
        )
        .with_class_name_fallback(
            self.class_name.clone(),
            self.class_id.clone(),
            Endpoint::ClassPermissions,
        )
    }

    pub fn related_classes(&self) -> CursorRequest<ClassWithPath> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::ClassByNameRelatedClasses,
            self.class_params(),
        )
        .with_class_name_fallback(
            self.class_name.clone(),
            self.class_id.clone(),
            Endpoint::ClassRelatedClasses,
        )
    }

    pub fn related_relations(&self) -> CursorRequest<ClassRelation> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::ClassByNameRelatedRelations,
            self.class_params(),
        )
        .with_class_name_fallback(
            self.class_name.clone(),
            self.class_id.clone(),
            Endpoint::ClassRelatedRelations,
        )
    }

    pub fn related_graph(&self) -> GraphRequest<RelatedClassGraph> {
        GraphRequest::new(
            self.client.clone(),
            Endpoint::ClassByNameRelatedGraph,
            self.class_params(),
        )
        .with_class_name_fallback(
            self.class_name.clone(),
            self.class_id.clone(),
            Endpoint::ClassRelatedGraph,
        )
    }
}

/// Class-scoped object collection addressed through a class name.
#[derive(Debug, Clone)]
pub struct ClassNameObjects {
    pub(super) client: Client<Authenticated>,
    pub(super) class_name: String,
    pub(super) class_id: Arc<OnceLock<ClassId>>,
}

impl ClassNameObjects {
    pub(super) fn class_params(&self) -> UrlParams {
        vec![(Cow::Borrowed("class_name"), self.class_name.clone().into())]
    }

    pub fn query(&self) -> CursorRequest<Object> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::ClassByNameObjects,
            self.class_params(),
        )
        .with_class_name_fallback(
            self.class_name.clone(),
            self.class_id.clone(),
            Endpoint::Objects,
        )
    }

    pub fn create_raw(&self, request: ObjectPost) -> Result<Object, ApiError> {
        if shared::requires_name_route_fallback(&self.class_name) {
            let class_id = self
                .client
                .resolve_class_name_id(&self.class_name, &self.class_id)?;
            return self.client.objects(class_id).create_raw(request);
        }

        let object: Object = self
            .client
            .request_with_endpoint(
                reqwest::Method::POST,
                &Endpoint::ClassByNameObjects,
                self.class_params(),
                vec![],
                request,
            )?
            .ok_or_else(|| {
                ApiError::EmptyResult("Object create returned an empty response".into())
            })?;
        let _ = self.class_id.set(object.hubuum_class_id);
        Ok(object)
    }

    pub fn create(
        &self,
        name: impl Into<String>,
        description: impl Into<String>,
        data: serde_json::Value,
    ) -> Result<Object, ApiError> {
        self.create_raw(ObjectPost {
            name: name.into(),
            collection_id: None,
            hubuum_class_id: None,
            description: description.into(),
            data: Some(data),
        })
    }

    pub fn by_name(&self, object_name: impl Into<String>) -> ObjectNameScope {
        ObjectNameScope {
            client: self.client.clone(),
            class_name: self.class_name.clone(),
            object_name: object_name.into(),
            class_id: self.class_id.clone(),
            object_id: Arc::new(OnceLock::new()),
        }
    }
}

/// Operations rooted at exact class and object natural keys.
#[derive(Debug, Clone)]
pub struct ObjectNameScope {
    pub(super) client: Client<Authenticated>,
    pub(super) class_name: String,
    pub(super) object_name: String,
    pub(super) class_id: Arc<OnceLock<ClassId>>,
    pub(super) object_id: Arc<OnceLock<ObjectId>>,
}

impl ObjectNameScope {
    pub(super) fn object_params(&self) -> UrlParams {
        vec![
            (Cow::Borrowed("class_name"), self.class_name.clone().into()),
            (
                Cow::Borrowed("object_name"),
                self.object_name.clone().into(),
            ),
        ]
    }

    pub(super) fn object_path(&self, endpoint: Endpoint) -> String {
        endpoint
            .path()
            .replace(
                "{class_name}",
                &shared::encode_path_segment(&self.class_name),
            )
            .replace(
                "{object_name}",
                &shared::encode_path_segment(&self.object_name),
            )
    }

    pub(super) fn requires_fallback(&self) -> bool {
        shared::requires_name_route_fallback(&self.class_name)
            || shared::requires_name_route_fallback(&self.object_name)
    }

    pub fn get(&self) -> Result<Handle<Object>, ApiError> {
        if self.requires_fallback() {
            let (class_id, object_id) = self.client.resolve_object_name_ids(
                &self.class_name,
                &self.object_name,
                &self.class_id,
                &self.object_id,
            )?;
            return self.client.objects(class_id).get(object_id);
        }

        let raw = self.client.request_with_endpoint_raw(
            reqwest::Method::GET,
            &Endpoint::ObjectByName,
            self.object_params(),
            vec![],
            EmptyPostParams,
        )?;
        let object = shared::parse_response::<Object>(&reqwest::Method::GET, raw.status, raw.body)?
            .ok_or_else(|| ApiError::EmptyResult("Object returned an empty response".into()))?;
        let _ = self.object_id.set(object.id);
        Ok(Handle::new_with_etag(self.client.clone(), object, raw.etag))
    }

    pub fn get_computed(&self) -> Result<ComputedObject, ApiError> {
        if self.requires_fallback() {
            let (class_id, object_id) = self.client.resolve_object_name_ids(
                &self.class_name,
                &self.object_name,
                &self.class_id,
                &self.object_id,
            )?;
            return self.client.computed_object(class_id, object_id);
        }

        self.client
            .request_with_endpoint::<EmptyPostParams, ComputedObject>(
                reqwest::Method::GET,
                &Endpoint::ObjectByName,
                self.object_params(),
                vec![QueryFilter::raw("include", "computed")],
                EmptyPostParams,
            )?
            .ok_or_else(|| {
                ApiError::EmptyResult("Computed object returned an empty response".into())
            })
    }

    pub fn update(&self, patch: ObjectPatch) -> Result<Object, ApiError> {
        if self.requires_fallback() {
            let (class_id, object_id) = self.client.resolve_object_name_ids(
                &self.class_name,
                &self.object_name,
                &self.class_id,
                &self.object_id,
            )?;
            return self.client.objects(class_id).update_raw(object_id, patch);
        }

        self.client
            .raw_with_encoded_segments(
                reqwest::Method::PATCH,
                self.object_path(Endpoint::ObjectByName),
            )
            .json(&patch)?
            .send()
    }

    pub fn delete(&self) -> Result<(), ApiError> {
        if self.requires_fallback() {
            let (class_id, object_id) = self.client.resolve_object_name_ids(
                &self.class_name,
                &self.object_name,
                &self.class_id,
                &self.object_id,
            )?;
            return self.client.objects(class_id).delete(object_id);
        }

        self.client.request_with_endpoint::<EmptyPostParams, ()>(
            reqwest::Method::DELETE,
            &Endpoint::ObjectByName,
            self.object_params(),
            vec![],
            EmptyPostParams,
        )?;
        Ok(())
    }

    pub fn patch_data(&self, patch: &ObjectDataPatchDocument) -> Result<Object, ApiError> {
        patch.validate()?;
        if self.requires_fallback() {
            let (class_id, object_id) = self.client.resolve_object_name_ids(
                &self.class_name,
                &self.object_name,
                &self.class_id,
                &self.object_id,
            )?;
            return self.client.patch_object_data(class_id, object_id, patch);
        }

        self.client
            .raw_with_encoded_segments(
                reqwest::Method::PATCH,
                self.object_path(Endpoint::ObjectByNameData),
            )
            .header("Content-Type", "application/json-patch+json")
            .json(patch)?
            .send()
    }

    pub fn related_objects(&self) -> CursorRequest<ObjectWithPath> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::ObjectByNameRelatedObjects,
            self.object_params(),
        )
        .with_object_name_fallback(
            self.class_name.clone(),
            self.object_name.clone(),
            self.class_id.clone(),
            self.object_id.clone(),
            Endpoint::ObjectRelatedObjects,
        )
    }

    pub fn related_relations(&self) -> CursorRequest<ObjectRelation> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::ObjectByNameRelatedRelations,
            self.object_params(),
        )
        .with_object_name_fallback(
            self.class_name.clone(),
            self.object_name.clone(),
            self.class_id.clone(),
            self.object_id.clone(),
            Endpoint::ObjectRelatedRelations,
        )
    }

    pub fn related_graph(&self) -> GraphRequest<RelatedObjectGraph> {
        GraphRequest::new(
            self.client.clone(),
            Endpoint::ObjectByNameRelatedGraph,
            self.object_params(),
        )
        .with_object_name_fallback(
            self.class_name.clone(),
            self.object_name.clone(),
            self.class_id.clone(),
            self.object_id.clone(),
            Endpoint::ObjectRelatedGraph,
        )
    }
}
