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
use crate::types::{BaseUrl, Credentials, FilterOperator, Token};
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

pub struct FilterBuilder<T: ApiResource> {
    client: Client<Authenticated>,
    filters: Vec<(String, FilterOperator, String)>,
    url_params: UrlParams,
    _phantom: PhantomData<T>,
}

impl<T: ApiResource> FilterBuilder<T> {
    fn new(client: Client<Authenticated>, url_params: UrlParams) -> Self {
        FilterBuilder {
            client,
            url_params,
            filters: Vec::new(),
            _phantom: PhantomData,
        }
    }

    pub fn add_filter<V: ToString>(mut self, field: &str, op: FilterOperator, value: V) -> Self {
        self.filters
            .push((field.to_string(), op, value.to_string()));
        self
    }

    pub fn add_filter_equals<V: ToString>(self, field: &str, value: V) -> Self {
        self.add_filter(field, FilterOperator::Equals { is_negated: false }, value)
    }

    pub fn add_filter_id<V: ToString>(self, value: V) -> Self {
        self.add_filter_equals("id", value)
    }

    pub fn add_filter_name_exact<V: ToString>(self, value: V) -> Self {
        self.add_filter_equals(T::NAME_FIELD, value)
    }

    pub async fn execute_expecting_single_result(self) -> Result<T::GetOutput, ApiError> {
        shared::one_or_err(self.execute().await?)
    }

    pub async fn execute(self) -> Result<Vec<T::GetOutput>, ApiError> {
        let params = T::build_params(self.filters);
        self.client
            .search::<T>(T::default(), self.url_params, params)
            .await
    }
}

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

    pub fn find(&self) -> FilterBuilder<T> {
        FilterBuilder::new(self.client.clone(), self.url_params.clone())
    }

    pub async fn filter<F: IntoResourceFilter<T>>(
        &self,
        filter: F,
    ) -> Result<Vec<T::GetOutput>, ApiError> {
        let params = filter.into_resource_filter();
        self.client
            .search::<T>(T::default(), self.url_params.clone(), params)
            .await
    }

    pub async fn filter_expecting_single_result<F: IntoResourceFilter<T>>(
        &self,
        filter: F,
    ) -> Result<T::GetOutput, ApiError> {
        let params = filter.into_resource_filter();
        shared::one_or_err(
            self.client
                .search::<T>(T::default(), self.url_params.clone(), params)
                .await?,
        )
    }

    pub async fn create(&self, params: T::PostParams) -> Result<T::PostOutput, ApiError> {
        self.client
            .post::<T>(T::default(), self.url_params.clone(), params)
            .await
    }

    pub async fn update(
        &self,
        id: i32,
        params: T::PatchParams,
    ) -> Result<T::PatchOutput, ApiError> {
        self.client
            .patch::<T>(T::default(), id, self.url_params.clone(), params)
            .await
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
    T: ApiResource<GetOutput = T> + Tabled + Display + GetID + Default + 'static,
{
    pub async fn select(&self, id: i32) -> Result<Handle<T>, ApiError> {
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
