use super::*;

/// Shared computed-field definitions and rebuild state for one class.
pub struct SharedComputedFields {
    pub(super) client: Client<Authenticated>,
    pub(super) class_id: ClassId,
}

impl SharedComputedFields {
    pub(super) fn new(client: Client<Authenticated>, class_id: ClassId) -> Self {
        Self { client, class_id }
    }

    pub(super) fn class_params(&self) -> UrlParams {
        vec![(Cow::Borrowed("class_id"), self.class_id.to_string().into())]
    }

    pub async fn list(&self) -> Result<ComputedFieldListResponse, ApiError> {
        self.client
            .request_with_endpoint::<EmptyPostParams, ComputedFieldListResponse>(
                reqwest::Method::GET,
                &Endpoint::ClassComputedFields,
                self.class_params(),
                vec![],
                EmptyPostParams,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Shared computed fields returned empty result".into())
            })
    }

    pub async fn create(
        &self,
        request: ComputedFieldDefinitionRequest,
    ) -> Result<ComputedFieldMutationResponse, ApiError> {
        self.client
            .request_with_endpoint(
                reqwest::Method::POST,
                &Endpoint::ClassComputedFields,
                self.class_params(),
                vec![],
                request,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Computed-field create returned empty result".into())
            })
    }

    /// Fetch one canonical shared definition and its strong ETag.
    pub async fn get(
        &self,
        field_id: impl Into<ComputedFieldDefinitionId>,
    ) -> Result<Revisioned<ComputedFieldDefinition>, ApiError> {
        let path = Endpoint::ClassComputedFieldById
            .path()
            .replace("{class_id}", &self.class_id.to_string())
            .replace("{field_id}", &field_id.into().to_string());
        let raw = self
            .client
            .raw(reqwest::Method::GET, path)
            .execute()
            .await?;
        shared::decode_revisioned(raw)
    }

    pub async fn update(
        &self,
        field_id: impl Into<ComputedFieldDefinitionId>,
        patch: ComputedFieldDefinitionPatch,
    ) -> Result<ComputedFieldMutationResponse, ApiError> {
        let field_id = field_id.into();
        let mut params = self.class_params();
        params.push((Cow::Borrowed("patch_id"), field_id.to_string().into()));
        self.client
            .request_with_endpoint(
                reqwest::Method::PATCH,
                &Endpoint::ClassComputedFields,
                params,
                vec![],
                patch,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Computed-field update returned empty result".into())
            })
    }

    pub async fn update_if_match(
        &self,
        field_id: impl Into<ComputedFieldDefinitionId>,
        patch: ComputedFieldDefinitionPatch,
        etag: &crate::types::EntityTag,
    ) -> Result<ComputedFieldMutationResponse, ApiError> {
        let path = Endpoint::ClassComputedFieldById
            .path()
            .replace("{class_id}", &self.class_id.to_string())
            .replace("{field_id}", &field_id.into().to_string());
        self.client
            .raw(reqwest::Method::PATCH, path)
            .header(reqwest::header::IF_MATCH.as_str(), etag.as_str())
            .json(&patch)?
            .send()
            .await
    }

    pub async fn delete(
        &self,
        field_id: impl Into<ComputedFieldDefinitionId>,
    ) -> Result<ComputedFieldDeleteResponse, ApiError> {
        let path = Endpoint::ClassComputedFieldById
            .path()
            .replace("{class_id}", &self.class_id.to_string())
            .replace("{field_id}", &field_id.into().to_string());
        let raw = self
            .client
            .raw(reqwest::Method::DELETE, path)
            .execute()
            .await?;
        shared::decode_json_body(&raw.body)
    }

    pub async fn delete_if_match(
        &self,
        field_id: impl Into<ComputedFieldDefinitionId>,
        etag: &crate::types::EntityTag,
    ) -> Result<ComputedFieldDeleteResponse, ApiError> {
        let path = Endpoint::ClassComputedFieldById
            .path()
            .replace("{class_id}", &self.class_id.to_string())
            .replace("{field_id}", &field_id.into().to_string());
        let raw = self
            .client
            .raw(reqwest::Method::DELETE, path)
            .header(reqwest::header::IF_MATCH.as_str(), etag.as_str())
            .execute()
            .await?;
        shared::decode_json_body(&raw.body)
    }

    pub async fn preview(
        &self,
        request: ComputedFieldPreviewRequest,
    ) -> Result<ComputedFieldPreviewResponse, ApiError> {
        self.client
            .request_with_endpoint(
                reqwest::Method::POST,
                &Endpoint::ClassComputedFieldsPreview,
                self.class_params(),
                vec![],
                request,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Computed-field preview returned empty result".into())
            })
    }

    pub async fn rebuild(&self) -> Result<ClassComputationState, ApiError> {
        self.client
            .request_with_endpoint::<EmptyPostParams, ClassComputationState>(
                reqwest::Method::POST,
                &Endpoint::ClassComputedFieldsRebuild,
                self.class_params(),
                vec![],
                EmptyPostParams,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Computed-field rebuild returned empty result".into())
            })
    }
}

/// Personal computed-field definitions owned by the current human user.
pub struct PersonalComputedFields {
    pub(super) client: Client<Authenticated>,
}

impl PersonalComputedFields {
    pub(super) fn new(client: Client<Authenticated>) -> Self {
        Self { client }
    }

    pub fn query(&self) -> CursorRequest<ComputedFieldDefinition> {
        CursorRequest::new(
            self.client.clone(),
            Endpoint::MeComputedFields,
            UrlParams::default(),
        )
    }

    pub fn for_class(
        &self,
        class_id: impl Into<ClassId>,
    ) -> CursorRequest<ComputedFieldDefinition> {
        self.query().query_param("class_id", class_id.into())
    }

    pub async fn create(
        &self,
        request: PersonalComputedFieldDefinitionRequest,
    ) -> Result<ComputedFieldDefinition, ApiError> {
        self.client
            .request_with_endpoint(
                reqwest::Method::POST,
                &Endpoint::MeComputedFields,
                UrlParams::default(),
                vec![],
                request,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Personal computed-field create returned empty result".into())
            })
    }

    /// Fetch one canonical personal definition and its strong ETag.
    pub async fn get(
        &self,
        field_id: impl Into<ComputedFieldDefinitionId>,
    ) -> Result<Revisioned<ComputedFieldDefinition>, ApiError> {
        let path = Endpoint::MeComputedFieldById
            .path()
            .replace("{field_id}", &field_id.into().to_string());
        let raw = self
            .client
            .raw(reqwest::Method::GET, path)
            .execute()
            .await?;
        shared::decode_revisioned(raw)
    }

    pub async fn update(
        &self,
        field_id: impl Into<ComputedFieldDefinitionId>,
        patch: ComputedFieldDefinitionPatch,
    ) -> Result<ComputedFieldDefinition, ApiError> {
        let field_id = field_id.into();
        self.client
            .request_with_endpoint(
                reqwest::Method::PATCH,
                &Endpoint::MeComputedFields,
                vec![(Cow::Borrowed("patch_id"), field_id.to_string().into())],
                vec![],
                patch,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult("Personal computed-field update returned empty result".into())
            })
    }

    pub async fn update_if_match(
        &self,
        field_id: impl Into<ComputedFieldDefinitionId>,
        patch: ComputedFieldDefinitionPatch,
        etag: &crate::types::EntityTag,
    ) -> Result<ComputedFieldDefinition, ApiError> {
        let path = Endpoint::MeComputedFieldById
            .path()
            .replace("{field_id}", &field_id.into().to_string());
        self.client
            .raw(reqwest::Method::PATCH, path)
            .header(reqwest::header::IF_MATCH.as_str(), etag.as_str())
            .json(&patch)?
            .send()
            .await
    }

    pub async fn delete(
        &self,
        field_id: impl Into<ComputedFieldDefinitionId>,
    ) -> Result<(), ApiError> {
        let path = Endpoint::MeComputedFieldById
            .path()
            .replace("{field_id}", &field_id.into().to_string());
        self.client
            .raw(reqwest::Method::DELETE, path)
            .execute()
            .await?;
        Ok(())
    }

    pub async fn delete_if_match(
        &self,
        field_id: impl Into<ComputedFieldDefinitionId>,
        etag: &crate::types::EntityTag,
    ) -> Result<(), ApiError> {
        let path = Endpoint::MeComputedFieldById
            .path()
            .replace("{field_id}", &field_id.into().to_string());
        self.client
            .raw(reqwest::Method::DELETE, path)
            .header(reqwest::header::IF_MATCH.as_str(), etag.as_str())
            .execute()
            .await?;
        Ok(())
    }

    pub async fn preview(
        &self,
        request: ComputedFieldPreviewRequest,
    ) -> Result<ComputedFieldPreviewResponse, ApiError> {
        self.client
            .request_with_endpoint(
                reqwest::Method::POST,
                &Endpoint::MeComputedFieldsPreview,
                UrlParams::default(),
                vec![],
                request,
            )
            .await?
            .ok_or_else(|| {
                ApiError::EmptyResult(
                    "Personal computed-field preview returned empty result".into(),
                )
            })
    }
}
