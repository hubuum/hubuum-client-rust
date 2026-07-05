use std::borrow::Cow;

#[cfg(feature = "async")]
use crate::client::r#async::Handle as AsyncHandle;
#[cfg(feature = "blocking")]
use crate::client::sync::Handle as SyncHandle;
use crate::{
    ApiError,
    endpoints::Endpoint,
    types::{
        FilterOperator, NewRemoteTarget, QueryFilter, RemoteTarget, RemoteTargetGet,
        RemoteTargetInvokeRequest, TaskResponse, UpdateRemoteTarget,
    },
};

// `RemoteTarget` is hand-wired rather than derived because its fields carry
// nested tagged-enum config (`auth_config`) and free-form JSON (`headers_template`)
// that the `ApiResource` derive macro cannot express.

impl crate::client::GetID for RemoteTarget {
    fn id(&self) -> i32 {
        self.id
    }
}

impl std::fmt::Display for RemoteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl crate::resources::ApiResource for RemoteTarget {
    type GetParams = RemoteTargetGet;
    type GetOutput = RemoteTarget;
    type PostParams = NewRemoteTarget;
    type PostOutput = RemoteTarget;
    type PatchParams = UpdateRemoteTarget;
    type PatchOutput = RemoteTarget;
    type DeleteParams = ();
    type DeleteOutput = ();

    const COLLECTION_ENDPOINT: Endpoint = Endpoint::RemoteTargets;
    const ITEM_ENDPOINT: Option<Endpoint> = Some(Endpoint::RemoteTargetsById);
    const ID_PARAM: &'static str = "target_id";

    fn endpoint(&self) -> Endpoint {
        Self::COLLECTION_ENDPOINT
    }

    fn build_params(filters: Vec<(String, FilterOperator, String)>) -> Vec<QueryFilter> {
        filters
            .into_iter()
            .map(|(key, operator, value)| QueryFilter {
                key,
                value,
                operator,
            })
            .collect()
    }

    fn filters_from_get(params: Self::GetParams) -> Vec<QueryFilter> {
        let mut queries = vec![];
        let mut push = |key: &str, value: String| {
            queries.push(QueryFilter {
                key: key.to_string(),
                value,
                operator: FilterOperator::Equals { is_negated: false },
            });
        };
        if let Some(id) = params.id {
            push("id", id.to_string());
        }
        if let Some(name) = params.name {
            push("name", name);
        }
        if let Some(namespace_id) = params.namespace_id {
            push("namespace_id", namespace_id.to_string());
        }
        if let Some(enabled) = params.enabled {
            push("enabled", enabled.to_string());
        }
        queries
    }
}

#[cfg(feature = "blocking")]
impl SyncHandle<RemoteTarget> {
    /// Invoke this remote target. Returns the async task tracking the call.
    pub fn invoke(&self, request: RemoteTargetInvokeRequest) -> Result<TaskResponse, ApiError> {
        let url_params = vec![(Cow::Borrowed("target_id"), self.id().to_string().into())];
        self.client()
            .request_with_endpoint::<RemoteTargetInvokeRequest, TaskResponse>(
                reqwest::Method::POST,
                &Endpoint::RemoteTargetInvoke,
                url_params,
                vec![],
                request,
            )?
            .ok_or(ApiError::EmptyResult(
                "Remote target invocation returned empty result".into(),
            ))
    }
}

#[cfg(feature = "async")]
impl AsyncHandle<RemoteTarget> {
    /// Invoke this remote target. Returns the async task tracking the call.
    pub async fn invoke(
        &self,
        request: RemoteTargetInvokeRequest,
    ) -> Result<TaskResponse, ApiError> {
        let url_params = vec![(Cow::Borrowed("target_id"), self.id().to_string().into())];
        self.client()
            .request_with_endpoint::<RemoteTargetInvokeRequest, TaskResponse>(
                reqwest::Method::POST,
                &Endpoint::RemoteTargetInvoke,
                url_params,
                vec![],
                request,
            )
            .await?
            .ok_or(ApiError::EmptyResult(
                "Remote target invocation returned empty result".into(),
            ))
    }
}
