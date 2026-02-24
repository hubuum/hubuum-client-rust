use log::{debug, trace};
use reqwest::Response;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::borrow::Cow;
use std::fmt::Display;
use std::marker::PhantomData;
use tabled::Tabled;

use super::{
    shared, Authenticated, ClientCore, GetID, IntoResourceFilter, Unauthenticated, UrlParams,
};
use crate::endpoints::Endpoint;
use crate::errors::ApiError;
use crate::resources::{ApiResource, Class, ClassRelation, Group, Namespace, Object, User};
use crate::types::{
    BaseUrl, CountsResponse, Credentials, DbStateResponse, FilterOperator, SortDirection, Token,
};
use crate::{ObjectRelation, QueryFilter};

#[derive(Deserialize, Debug)]
struct DeleteResponse;

#[derive(Clone, Serialize, Deserialize)]
pub struct EmptyPostParams;

impl std::fmt::Debug for EmptyPostParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("")
    }
}

#[derive(Debug, Clone)]
pub struct Client<S> {
    http_client: reqwest::Client,
    base_url: BaseUrl,
    state: S,
}

impl<S> ClientCore for Client<S> {
    fn build_url(&self, endpoint: &Endpoint, url_params: UrlParams) -> String {
        shared::build_url(&self.base_url, endpoint, url_params)
    }
}

impl<S> Client<S> {
    async fn check_success(&self, response: Response) -> Result<Response, ApiError> {
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await?;
            let error_message = shared::parse_http_error_message(&body);
            return Err(ApiError::HttpWithBody {
                status,
                message: error_message,
            });
        }
        Ok(response)
    }
}

impl Client<Unauthenticated> {
    pub fn new(base_url: BaseUrl) -> Self {
        Self::new_with_certificate_validation(base_url, true)
    }

    pub fn new_without_certificate_validation(base_url: BaseUrl) -> Self {
        Self::new_with_certificate_validation(base_url, false)
    }

    pub fn new_with_certificate_validation(
        base_url: BaseUrl,
        validate_server_certificate: bool,
    ) -> Self {
        Client {
            http_client: reqwest::Client::builder()
                .danger_accept_invalid_certs(!validate_server_certificate)
                .build()
                .unwrap(),
            base_url,
            state: Unauthenticated,
        }
    }
}

impl Client<Unauthenticated> {
    pub async fn login(self, credentials: Credentials) -> Result<Client<Authenticated>, ApiError> {
        let response = self
            .http_client
            .post(self.build_url(&Endpoint::Login, UrlParams::default()))
            .json(&credentials)
            .send()
            .await?;
        let response = self.check_success(response).await?;
        let token: Token = response.json().await?;

        Ok(Client {
            http_client: self.http_client,
            base_url: self.base_url,
            state: Authenticated { token: token.token },
        })
    }

    pub async fn login_with_token(self, token: Token) -> Result<Client<Authenticated>, ApiError> {
        let status = self
            .http_client
            .get(self.build_url(&Endpoint::LoginWithToken, UrlParams::default()))
            .header("Authorization", format!("Bearer {}", token.token))
            .send()
            .await?;

        if status.status().is_success() {
            Ok(Client {
                http_client: self.http_client,
                base_url: self.base_url,
                state: Authenticated { token: token.token },
            })
        } else {
            Err(ApiError::InvalidToken)
        }
    }
}

impl Client<Authenticated> {
    pub fn get_token(&self) -> &str {
        &self.state.token
    }

    pub async fn logout(&self) -> Result<(), ApiError> {
        self.request_with_endpoint::<EmptyPostParams, serde_json::Value>(
            reqwest::Method::GET,
            &Endpoint::Logout,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .await
        .map(|_| ())
    }

    pub async fn logout_token(&self, token: &str) -> Result<(), ApiError> {
        self.request_with_endpoint::<EmptyPostParams, serde_json::Value>(
            reqwest::Method::GET,
            &Endpoint::LogoutToken,
            vec![(Cow::Borrowed("token"), token.to_string().into())],
            vec![],
            EmptyPostParams,
        )
        .await
        .map(|_| ())
    }

    pub async fn logout_user(&self, user_id: i32) -> Result<(), ApiError> {
        self.request_with_endpoint::<EmptyPostParams, serde_json::Value>(
            reqwest::Method::GET,
            &Endpoint::LogoutUser,
            vec![(Cow::Borrowed("user_id"), user_id.to_string().into())],
            vec![],
            EmptyPostParams,
        )
        .await
        .map(|_| ())
    }

    pub async fn logout_all(&self) -> Result<(), ApiError> {
        self.request_with_endpoint::<EmptyPostParams, serde_json::Value>(
            reqwest::Method::GET,
            &Endpoint::LogoutAll,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .await
        .map(|_| ())
    }

    pub async fn meta_counts(&self) -> Result<CountsResponse, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, CountsResponse>(
            reqwest::Method::GET,
            &Endpoint::MetaCounts,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .await
        .and_then(|opt| {
            opt.ok_or(ApiError::EmptyResult(
                "META counts returned empty result".into(),
            ))
        })
    }

    pub async fn meta_db(&self) -> Result<DbStateResponse, ApiError> {
        self.request_with_endpoint::<EmptyPostParams, DbStateResponse>(
            reqwest::Method::GET,
            &Endpoint::MetaDb,
            UrlParams::default(),
            vec![],
            EmptyPostParams,
        )
        .await
        .and_then(|opt| {
            opt.ok_or(ApiError::EmptyResult(
                "META db state returned empty result".into(),
            ))
        })
    }

    pub async fn request_with_endpoint<T: Serialize + std::fmt::Debug, U: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        endpoint: &Endpoint,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
        post_params: T,
    ) -> Result<Option<U>, ApiError> {
        let base_url = self.build_url(endpoint, url_params.clone());
        let request_url = shared::build_request_url(&method, base_url, &url_params, query_params)?;

        let request = if method == reqwest::Method::GET {
            debug!("GET {}", request_url);
            self.http_client.get(&request_url)
        } else if method == reqwest::Method::POST {
            debug!("POST {} with {:?}", &request_url, post_params);
            self.http_client.post(&request_url).json(&post_params)
        } else if method == reqwest::Method::PUT {
            debug!("PUT {} with {:?}", &request_url, post_params);
            self.http_client.put(&request_url).json(&post_params)
        } else if method == reqwest::Method::PATCH {
            debug!("PATCH {} with {:?}", &request_url, post_params);
            self.http_client.patch(&request_url).json(&post_params)
        } else if method == reqwest::Method::DELETE {
            debug!("DELETE {}", &request_url);
            self.http_client.delete(&request_url)
        } else {
            return Err(ApiError::UnsupportedHttpOperation(method.to_string()));
        }
        .header("Authorization", format!("Bearer {}", self.state.token));

        let now = std::time::Instant::now();
        let response = request.send().await?;
        trace!("Request took {:?}", now.elapsed());
        let response_code = response.status();
        let response_text = self.check_success(response).await?.text().await?;
        debug!("Response: {}", response_text);
        shared::parse_response(&method, response_code, response_text)
    }

    pub async fn request<R: ApiResource, T: Serialize + std::fmt::Debug, U: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        resource: R,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
        post_params: T,
    ) -> Result<Option<U>, ApiError> {
        self.request_with_endpoint(
            method,
            &resource.endpoint(),
            url_params,
            query_params,
            post_params,
        )
        .await
    }

    pub async fn get<R: ApiResource, F: IntoResourceFilter<R>>(
        &self,
        resource: R,
        url_params: UrlParams,
        filter: F,
    ) -> Result<Vec<R::GetOutput>, ApiError> {
        self.request(
            reqwest::Method::GET,
            resource,
            url_params,
            filter.into_resource_filter(),
            EmptyPostParams,
        )
        .await
        .and_then(|opt| opt.ok_or(ApiError::EmptyResult("GET returned empty result".into())))
    }

    pub async fn search<R: ApiResource>(
        &self,
        resource: R,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
    ) -> Result<Vec<R::GetOutput>, ApiError> {
        self.request(
            reqwest::Method::GET,
            resource,
            url_params,
            query_params,
            EmptyPostParams,
        )
        .await
        .and_then(|opt| opt.ok_or(ApiError::EmptyResult("SEARCH returned empty result".into())))
    }

    pub async fn post<R: ApiResource>(
        &self,
        resource: R,
        url_params: UrlParams,
        params: R::PostParams,
    ) -> Result<R::PostOutput, ApiError> {
        self.request(reqwest::Method::POST, resource, url_params, vec![], params)
            .await
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("POST returned empty result".into())))
    }

    pub async fn patch<R: ApiResource>(
        &self,
        resource: R,
        id: i32,
        url_params: UrlParams,
        params: R::PatchParams,
    ) -> Result<R::PatchOutput, ApiError> {
        let mut url_params = url_params;
        url_params.push(("patch_id".into(), id.to_string().into()));
        self.request(reqwest::Method::PATCH, resource, url_params, vec![], params)
            .await
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("PATCH returned empty result".into())))
    }

    pub async fn delete<R: ApiResource>(
        &self,
        resource: R,
        id: i32,
        url_params: UrlParams,
    ) -> Result<(), ApiError> {
        let mut url_params = url_params;
        url_params.push(("delete_id".into(), id.to_string().into()));
        self.request::<_, _, DeleteResponse>(
            reqwest::Method::DELETE,
            resource,
            url_params,
            vec![],
            EmptyPostParams,
        )
        .await
        .map(|_| ())
    }

    pub fn users(&self) -> Resource<User> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn classes(&self) -> Resource<Class> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn namespaces(&self) -> Resource<Namespace> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn groups(&self) -> Resource<Group> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn objects(&self, class_id: i32) -> Resource<Object> {
        Resource::new(self.clone(), vec![("class_id", class_id.to_string())])
    }

    pub fn class_relation(&self) -> Resource<ClassRelation> {
        Resource::new(self.clone(), UrlParams::default())
    }

    pub fn object_relation(&self) -> Resource<ObjectRelation> {
        Resource::new(self.clone(), UrlParams::default())
    }
}

pub struct CreateOp<T: ApiResource> {
    client: Client<Authenticated>,
    url_params: UrlParams,
    params: T::PostParams,
    _phantom: PhantomData<T>,
}

impl<T: ApiResource> CreateOp<T> {
    fn new(client: Client<Authenticated>, url_params: UrlParams) -> Self {
        Self {
            client,
            url_params,
            params: T::PostParams::default(),
            _phantom: PhantomData,
        }
    }

    pub fn params(mut self, params: T::PostParams) -> Self {
        self.params = params;
        self
    }

    pub(crate) fn edit_params<F>(mut self, edit: F) -> Self
    where
        F: FnOnce(&mut T::PostParams),
    {
        edit(&mut self.params);
        self
    }

    pub async fn send(self) -> Result<T::PostOutput, ApiError> {
        self.client
            .post::<T>(T::default(), self.url_params, self.params)
            .await
    }
}

pub struct UpdateOp<T: ApiResource> {
    client: Client<Authenticated>,
    id: i32,
    url_params: UrlParams,
    params: T::PatchParams,
    _phantom: PhantomData<T>,
}

impl<T: ApiResource> UpdateOp<T> {
    fn new(client: Client<Authenticated>, id: i32, url_params: UrlParams) -> Self {
        Self {
            client,
            id,
            url_params,
            params: T::PatchParams::default(),
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

    pub async fn send(self) -> Result<T::PatchOutput, ApiError> {
        self.client
            .patch::<T>(T::default(), self.id, self.url_params, self.params)
            .await
    }
}

pub struct QueryOp<T: ApiResource> {
    client: Client<Authenticated>,
    query_params: Vec<QueryFilter>,
    url_params: UrlParams,
    _phantom: PhantomData<T>,
}

impl<T: ApiResource> QueryOp<T> {
    fn new(client: Client<Authenticated>, url_params: UrlParams) -> Self {
        QueryOp {
            client,
            url_params,
            query_params: Vec::new(),
            _phantom: PhantomData,
        }
    }

    pub fn params(mut self, params: T::GetParams) -> Self {
        self.query_params.extend(T::filters_from_get(params));
        self
    }

    pub fn filters(mut self, filters: impl IntoResourceFilter<T>) -> Self {
        self.query_params.extend(filters.into_resource_filter());
        self
    }

    pub fn add_filter<V: ToString>(mut self, field: &str, op: FilterOperator, value: V) -> Self {
        self.query_params
            .push(QueryFilter::filter(field, op, value.to_string()));
        self
    }

    pub fn add_filter_equals<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Equals { is_negated: false }, value)
    }

    pub fn add_filter_not_equals<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Equals { is_negated: true }, value)
    }

    pub fn add_filter_iequals<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::IEquals { is_negated: false }, value)
    }

    pub fn add_filter_not_iequals<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::IEquals { is_negated: true }, value)
    }

    pub fn add_filter_contains<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Contains { is_negated: false }, value)
    }

    pub fn add_filter_not_contains<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Contains { is_negated: true }, value)
    }

    pub fn add_filter_icontains<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(
            field,
            FilterOperator::IContains { is_negated: false },
            value,
        )
    }

    pub fn add_filter_not_icontains<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::IContains { is_negated: true }, value)
    }

    pub fn add_filter_startswith<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(
            field,
            FilterOperator::StartsWith { is_negated: false },
            value,
        )
    }

    pub fn add_filter_not_startswith<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(
            field,
            FilterOperator::StartsWith { is_negated: true },
            value,
        )
    }

    pub fn add_filter_istartswith<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(
            field,
            FilterOperator::IStartsWith { is_negated: false },
            value,
        )
    }

    pub fn add_filter_not_istartswith<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(
            field,
            FilterOperator::IStartsWith { is_negated: true },
            value,
        )
    }

    pub fn add_filter_endswith<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::EndsWith { is_negated: false }, value)
    }

    pub fn add_filter_not_endswith<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::EndsWith { is_negated: true }, value)
    }

    pub fn add_filter_iendswith<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(
            field,
            FilterOperator::IEndsWith { is_negated: false },
            value,
        )
    }

    pub fn add_filter_not_iendswith<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::IEndsWith { is_negated: true }, value)
    }

    pub fn add_filter_like<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Like { is_negated: false }, value)
    }

    pub fn add_filter_not_like<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Like { is_negated: true }, value)
    }

    pub fn add_filter_regex<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Regex { is_negated: false }, value)
    }

    pub fn add_filter_not_regex<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Regex { is_negated: true }, value)
    }

    pub fn add_filter_gt<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Gt { is_negated: false }, value)
    }

    pub fn add_filter_not_gt<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Gt { is_negated: true }, value)
    }

    pub fn add_filter_gte<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Gte { is_negated: false }, value)
    }

    pub fn add_filter_not_gte<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Gte { is_negated: true }, value)
    }

    pub fn add_filter_lt<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Lt { is_negated: false }, value)
    }

    pub fn add_filter_not_lt<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Lt { is_negated: true }, value)
    }

    pub fn add_filter_lte<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Lte { is_negated: false }, value)
    }

    pub fn add_filter_not_lte<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Lte { is_negated: true }, value)
    }

    pub fn add_filter_between<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Between { is_negated: false }, value)
    }

    pub fn add_filter_not_between<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Between { is_negated: true }, value)
    }

    pub fn add_filter_id<V: ToString>(self, value: V) -> Self {
        self.add_filter_equals("id", value)
    }

    pub fn add_filter_name_exact<V: ToString>(self, value: V) -> Self {
        self.add_filter_equals(T::NAME_FIELD, value)
    }

    pub fn add_json_path_filter<I, S, V>(
        self,
        field: &str,
        path: I,
        op: FilterOperator,
        value: V,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        V: ToString,
    {
        let path = path
            .into_iter()
            .map(|segment| segment.as_ref().to_string())
            .collect::<Vec<_>>()
            .join(",");
        let value = if path.is_empty() {
            value.to_string()
        } else {
            format!("{path}={}", value.to_string())
        };
        self.add_filter(field, op, value)
    }

    pub fn add_json_path_lt<I, S, V>(self, field: &str, path: I, value: V) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        V: ToString,
    {
        self.add_json_path_filter(field, path, FilterOperator::Lt { is_negated: false }, value)
    }

    pub fn sort_by<V: ToString>(mut self, sort: V) -> Self {
        self.query_params
            .push(QueryFilter::raw("sort", sort.to_string()));
        self
    }

    pub fn order_by<V: ToString>(mut self, sort: V) -> Self {
        self.query_params
            .push(QueryFilter::raw("order_by", sort.to_string()));
        self
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
        self.query_params
            .push(QueryFilter::raw("limit", limit.to_string()));
        self
    }

    pub async fn execute_expecting_single_result(self) -> Result<T::GetOutput, ApiError> {
        self.one().await
    }

    pub async fn execute(self) -> Result<Vec<T::GetOutput>, ApiError> {
        self.list().await
    }

    pub async fn list(self) -> Result<Vec<T::GetOutput>, ApiError> {
        self.client
            .search::<T>(T::default(), self.url_params, self.query_params)
            .await
    }

    pub async fn one(self) -> Result<T::GetOutput, ApiError> {
        shared::one_or_err(self.list().await?)
    }

    pub async fn optional(self) -> Result<Option<T::GetOutput>, ApiError> {
        let mut results = self.list().await?;
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

pub type FilterBuilder<T> = QueryOp<T>;

pub struct Resource<T: ApiResource> {
    client: Client<Authenticated>,
    url_params: UrlParams,
    _phantom: PhantomData<T>,
}

impl<T: ApiResource> Resource<T> {
    fn new<I, K, V>(client: Client<Authenticated>, url_params: I) -> Self
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
            _phantom: PhantomData,
        }
    }

    pub fn query(&self) -> QueryOp<T> {
        QueryOp::new(self.client.clone(), self.url_params.clone())
    }

    pub fn find(&self) -> QueryOp<T> {
        self.query()
    }

    pub async fn filter_raw<F: IntoResourceFilter<T>>(
        &self,
        filter: F,
    ) -> Result<Vec<T::GetOutput>, ApiError> {
        self.query().filters(filter).list().await
    }

    pub async fn filter_one_raw<F: IntoResourceFilter<T>>(
        &self,
        filter: F,
    ) -> Result<T::GetOutput, ApiError> {
        self.query().filters(filter).one().await
    }

    pub async fn filter<F: IntoResourceFilter<T>>(
        &self,
        filter: F,
    ) -> Result<Vec<T::GetOutput>, ApiError> {
        self.filter_raw(filter).await
    }

    pub async fn filter_expecting_single_result<F: IntoResourceFilter<T>>(
        &self,
        filter: F,
    ) -> Result<T::GetOutput, ApiError> {
        self.filter_one_raw(filter).await
    }

    pub fn create(&self) -> CreateOp<T> {
        CreateOp::new(self.client.clone(), self.url_params.clone())
    }

    pub async fn create_raw(&self, params: T::PostParams) -> Result<T::PostOutput, ApiError> {
        self.create().params(params).send().await
    }

    pub fn update(&self, id: i32) -> UpdateOp<T> {
        UpdateOp::new(self.client.clone(), id, self.url_params.clone())
    }

    pub async fn update_raw(
        &self,
        id: i32,
        params: T::PatchParams,
    ) -> Result<T::PatchOutput, ApiError> {
        self.update(id).params(params).send().await
    }

    pub async fn delete(&self, id: i32) -> Result<(), ApiError> {
        self.client
            .delete::<T>(T::default(), id, self.url_params.clone())
            .await
    }
}

pub type Handle<T> = shared::Handle<Client<Authenticated>, T>;

impl<T> Resource<T>
where
    T: ApiResource<GetOutput = T> + DeserializeOwned + Tabled + Display + GetID + Default + 'static,
{
    pub async fn select(&self, id: i32) -> Result<Handle<T>, ApiError> {
        match T::default().endpoint() {
            Endpoint::Users => {
                match self
                    .client
                    .request_with_endpoint::<EmptyPostParams, T>(
                        reqwest::Method::GET,
                        &Endpoint::UsersById,
                        vec![(Cow::Borrowed("user_id"), id.to_string().into())],
                        vec![],
                        EmptyPostParams,
                    )
                    .await
                {
                    Ok(Some(resource)) => return Ok(Handle::new(self.client.clone(), resource)),
                    Ok(None) => {}
                    Err(ApiError::HttpWithBody { status, .. })
                        if status == reqwest::StatusCode::NOT_FOUND => {}
                    Err(err) => return Err(err),
                }
            }
            Endpoint::Groups => {
                match self
                    .client
                    .request_with_endpoint::<EmptyPostParams, T>(
                        reqwest::Method::GET,
                        &Endpoint::GroupsById,
                        vec![(Cow::Borrowed("group_id"), id.to_string().into())],
                        vec![],
                        EmptyPostParams,
                    )
                    .await
                {
                    Ok(Some(resource)) => return Ok(Handle::new(self.client.clone(), resource)),
                    Ok(None) => {}
                    Err(ApiError::HttpWithBody { status, .. })
                        if status == reqwest::StatusCode::NOT_FOUND => {}
                    Err(err) => return Err(err),
                }
            }
            _ => {}
        }

        let (url_params, filters) = shared::select_id_lookup_params(id);
        let raw: Vec<<T as ApiResource>::GetOutput> =
            self.client.get(T::default(), url_params, filters).await?;

        let resource: T = shared::one_or_err(raw)?;
        Ok(Handle::new(self.client.clone(), resource))
    }

    pub async fn select_by_name(&self, name: &str) -> Result<Handle<T>, ApiError> {
        let (url_params, filters) = shared::select_name_lookup_params::<T>(name);
        let raw: Vec<<T as ApiResource>::GetOutput> =
            self.client.get(T::default(), url_params, filters).await?;

        let resource: T = shared::one_or_err(raw)?;
        Ok(Handle::new(self.client.clone(), resource))
    }
}
