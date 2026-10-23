use super::*;

#[derive(Clone, Serialize)]
pub struct Handle<C, T> {
    #[serde(skip)]
    pub(super) client: C,
    #[serde(flatten)]
    pub(super) resource: T,
    #[serde(skip)]
    pub(super) etag: Option<crate::types::EntityTag>,
}

impl<C, T> Handle<C, T>
where
    T: ApiResource + GetID,
{
    pub fn new(client: C, resource: T) -> Self {
        Handle {
            client,
            resource,
            etag: None,
        }
    }

    pub(crate) fn new_with_etag(
        client: C,
        resource: T,
        etag: Option<crate::types::EntityTag>,
    ) -> Self {
        Handle {
            client,
            resource,
            etag,
        }
    }

    pub fn resource(&self) -> &T {
        &self.resource
    }

    pub fn into_inner(self) -> T {
        self.resource
    }

    pub fn id(&self) -> T::Id {
        self.resource.id()
    }

    pub fn client(&self) -> &C {
        &self.client
    }

    /// Strong validator returned by the canonical point response, when that
    /// representation supports conditional mutations.
    pub fn etag(&self) -> Option<&crate::types::EntityTag> {
        self.etag.as_ref()
    }
}

impl<C, T> Deref for Handle<C, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.resource
    }
}

impl<C, T> AsRef<T> for Handle<C, T> {
    fn as_ref(&self) -> &T {
        &self.resource
    }
}

pub(crate) fn select_id_lookup_params(id: impl ToString) -> (UrlParams, Vec<QueryFilter>) {
    let id = id.to_string();
    (
        vec![(Cow::Borrowed("id"), id.clone().into())],
        vec![QueryFilter {
            key: "id".to_string(),
            value: id,
            operator: FilterOperator::Equals { is_negated: false },
        }],
    )
}

pub(crate) fn select_name_lookup_params<T: ApiResource>(
    name: &str,
) -> (UrlParams, Vec<QueryFilter>) {
    (
        vec![(Cow::Borrowed(T::NAME_FIELD), name.to_string().into())],
        vec![QueryFilter {
            key: T::NAME_FIELD.to_string(),
            value: name.to_string(),
            operator: FilterOperator::Equals { is_negated: false },
        }],
    )
}
