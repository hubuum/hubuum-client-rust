use log::{debug, error, trace};
use reqwest::blocking::Response;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::any::type_name;
use std::borrow::Cow;
use std::fmt::Display;
use std::marker::PhantomData;
use std::vec;
use tabled::Tabled;

use super::{Authenticated, ClientCore, IntoResourceFilter, Unauthenticated, UrlParams};
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
    pub http_client: reqwest::blocking::Client,
    base_url: BaseUrl,
    state: S,
}

impl<S> ClientCore for Client<S> {
    fn build_url(&self, endpoint: &Endpoint, url_params: UrlParams) -> String {
        let mut url = format!(
            "{}{}",
            self.base_url.with_trailing_slash(),
            endpoint.trim_start_matches('/')
        );

        for (key, value) in url_params {
            url = url.replace(&format!("{{{}}}", key), value.as_ref());
        }
        url
    }
}

trait ResponseHandler {
    fn check_success(&self, response: Response) -> Result<Response, ApiError>;
}

impl<T> ResponseHandler for Client<T> {
    fn check_success(&self, response: Response) -> Result<Response, ApiError> {
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text()?;
            let error_message = match serde_json::from_str::<Value>(&body) {
                Ok(json) => json["message"]
                    .as_str()
                    .unwrap_or("Error without message.")
                    .to_string(),
                Err(_) => body,
            };
            return Err(ApiError::HttpWithBody {
                status,
                message: error_message,
            });
        }
        Ok(response)
    }
}

impl Client<Unauthenticated> {
    pub fn new(base_url: BaseUrl, validate_server_certificate: bool) -> Self {
        Client {
            http_client: reqwest::blocking::Client::builder()
                .danger_accept_invalid_certs(!validate_server_certificate)
                .build()
                .unwrap(),
            base_url,
            state: Unauthenticated,
        }
    }
}

impl Client<Unauthenticated> {
    pub fn login(self, credentials: Credentials) -> Result<Client<Authenticated>, ApiError> {
        let token: Token = self
            .http_client
            .post(&self.build_url(&Endpoint::Login, UrlParams::default()))
            .json(&credentials)
            .send()?
            .error_for_status()?
            .json()?;

        Ok(Client {
            http_client: self.http_client,
            base_url: self.base_url,
            state: Authenticated { token: token.token },
        })
    }

    pub fn login_with_token(self, token: Token) -> Result<Client<Authenticated>, ApiError> {
        let status = self
            .http_client
            .get(self.build_url(&Endpoint::LoginWithToken, UrlParams::default()))
            .header("Authorization", format!("Bearer {}", token.token))
            .send()?;

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

    pub fn request_with_endpoint<T: Serialize + std::fmt::Debug, U: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        endpoint: &Endpoint,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
        post_params: T,
    ) -> Result<Option<U>, ApiError> {
        let url = self.build_url(&endpoint, url_params.clone());

        let request = match method {
            reqwest::Method::GET => {
                use crate::types::IntoQueryTuples;
                let query = query_params.into_query_string();
                let url = if !query.is_empty() {
                    format!("{}?{}", url, query)
                } else {
                    url
                };
                debug!("GET {}", url);
                self.http_client.get(&url)
            }
            reqwest::Method::POST => {
                debug!("POST {} with {:?}", &url, post_params);
                self.http_client.post(&url).json(&post_params)
            }
            reqwest::Method::PATCH => {
                let id = url_params
                    .iter()
                    .find(|(k, _)| k == "patch_id")
                    .map(|(_, v)| v)
                    .ok_or(ApiError::MissingUrlIdentifier)?;
                let url = format!("{}{}", url, id);
                debug!("PATCH {} with {:?}", &url, post_params);
                self.http_client.patch(&url).json(&post_params)
            }
            reqwest::Method::DELETE => {
                let url = format!("{}{:?}", url, post_params);
                debug!("DELETE {}", &url);
                self.http_client.delete(&url)
            }
            _ => return Err(ApiError::UnsupportedHttpOperation(method.to_string())),
        }
        .header("Authorization", format!("Bearer {}", self.state.token));

        let now = std::time::Instant::now();
        let response = request.send()?;
        trace!("Request took {:?}", now.elapsed());
        let response_code = response.status();
        let response_text = self.check_success(response)?.text()?;
        debug!("Response: {}", response_text);

        if method == reqwest::Method::DELETE {
            if response_text.is_empty() {
                return Ok(None);
            } else {
                error!("Expected empty response, got: {}", response_text);
                return Err(ApiError::DeserializationError(response_text));
            }
        }

        if response_code == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }

        let obj: U = match serde_json::from_str(&response_text) {
            Ok(obj) => obj,
            Err(err) => {
                error!(
                    "Failed to deserialize response: {} Response text: {}",
                    err, response_text
                );
                return Err(ApiError::DeserializationError(response_text));
            }
        };

        Ok(Some(obj))
    }

    pub fn request<R: ApiResource, T: Serialize + std::fmt::Debug, U: DeserializeOwned>(
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
    }

    pub fn get<R: ApiResource>(
        &self,
        resource: R,
        url_params: UrlParams,
        query_params: Vec<QueryFilter>,
        params: R::GetParams,
    ) -> Result<Vec<R::GetOutput>, ApiError> {
        self.request(
            reqwest::Method::GET,
            resource,
            url_params,
            query_params,
            params,
        )
        .and_then(|opt| opt.ok_or(ApiError::EmptyResult("GET returned empty result".into())))
    }

    pub fn search<R: ApiResource>(
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
        .and_then(|opt| opt.ok_or(ApiError::EmptyResult("SEARCH returned empty result".into())))
    }

    pub fn post<R: ApiResource>(
        &self,
        resource: R,
        url_params: UrlParams,
        params: R::PostParams,
    ) -> Result<R::PostOutput, ApiError> {
        self.request(reqwest::Method::POST, resource, url_params, vec![], params)
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("POST returned empty result".into())))
    }

    pub fn patch<R: ApiResource>(
        &self,
        resource: R,
        id: i32,
        url_params: UrlParams,
        params: R::PatchParams,
    ) -> Result<R::PatchOutput, ApiError> {
        let mut url_params = url_params;
        url_params.push(("patch_id".into(), id.to_string().into()));
        self.request(reqwest::Method::PATCH, resource, url_params, vec![], params)
            .and_then(|opt| opt.ok_or(ApiError::EmptyResult("PATCH returned empty result".into())))
    }

    pub fn delete<R: ApiResource>(
        &self,
        resource: R,
        id: i32,
        url_params: UrlParams,
    ) -> Result<(), ApiError> {
        self.request::<_, _, DeleteResponse>(
            reqwest::Method::DELETE,
            resource,
            url_params,
            vec![],
            id,
        )
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

    /// Add a filter for the ideomatic `name` field.
    ///
    /// For most resources, this will be the `name` field, but for some it may be different.
    /// This cloaks all `name` fields behind the resource's specific name field.
    pub fn add_filter_name_exact<V: ToString>(self, value: V) -> Self {
        self.add_filter_equals(T::NAME_FIELD, value)
    }

    pub fn execute_expecting_single_result(self) -> Result<T::GetOutput, ApiError> {
        one_or_err(self.execute()?)
    }

    pub fn execute(self) -> Result<Vec<T::GetOutput>, ApiError> {
        let params = T::build_params(self.filters);
        self.client
            .search::<T>(T::default(), self.url_params, params)
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
        let resource = Resource {
            client,
            url_params: url_params
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
            _phantom: PhantomData,
        };

        resource
    }

    pub fn find(&self) -> FilterBuilder<T> {
        FilterBuilder::new(self.client.clone(), self.url_params.clone())
    }

    pub fn filter(
        &self,
        filter: impl IntoResourceFilter<T>,
    ) -> Result<Vec<T::GetOutput>, ApiError> {
        let params = filter.into_resource_filter();
        self.client
            .search::<T>(T::default(), self.url_params.clone(), params)
    }

    pub fn filter_expecting_single_result(
        &self,
        filter: impl IntoResourceFilter<T>,
    ) -> Result<T::GetOutput, ApiError> {
        let params = filter.into_resource_filter();
        one_or_err(
            self.client
                .search::<T>(T::default(), self.url_params.clone(), params)?,
        )
    }

    pub fn create(&self, params: T::PostParams) -> Result<T::PostOutput, ApiError> {
        self.client
            .post::<T>(T::default(), self.url_params.clone(), params)
    }

    pub fn update(&self, id: i32, params: T::PatchParams) -> Result<T::PatchOutput, ApiError> {
        self.client
            .patch::<T>(T::default(), id, self.url_params.clone(), params)
    }

    pub fn delete(&self, id: i32) -> Result<(), ApiError> {
        self.client
            .delete::<T>(T::default(), id, self.url_params.clone())
    }
}

pub fn one_or_err<T>(mut v: Vec<T>) -> Result<T, ApiError> {
    let name = type_name::<T>();
    let name = name.rsplit("::").next().unwrap_or(name);

    if v.len() == 1 {
        Ok(v.pop().unwrap())
    } else if v.is_empty() {
        Err(ApiError::EmptyResult(format!("{} not found", name)))
    } else {
        Err(ApiError::TooManyResults(format!(
            "Type: {}, Count: {} (expected 1)",
            name,
            v.len()
        )))
    }
}

pub trait GetID {
    fn id(&self) -> i32;
}

impl GetID for Group {
    fn id(&self) -> i32 {
        self.id
    }
}
impl GetID for Namespace {
    fn id(&self) -> i32 {
        self.id
    }
}
impl GetID for User {
    fn id(&self) -> i32 {
        self.id
    }
}
impl GetID for Object {
    fn id(&self) -> i32 {
        self.id
    }
}
impl GetID for Class {
    fn id(&self) -> i32 {
        self.id
    }
}

impl GetID for ClassRelation {
    fn id(&self) -> i32 {
        self.id
    }
}

impl GetID for ObjectRelation {
    fn id(&self) -> i32 {
        self.id
    }
}

#[derive(Clone, Tabled, Serialize)]
pub struct Handle<T>
where
    T: Tabled + Display,
{
    #[tabled(skip)]
    #[serde(skip)]
    client: Client<Authenticated>,
    #[tabled(inline)]
    #[serde(flatten)]
    resource: T,
}

impl<T> Handle<T>
where
    T: ApiResource + Tabled + GetID + Display + Default,
{
    pub fn new(client: Client<Authenticated>, resource: T) -> Self {
        Handle { client, resource }
    }

    pub fn resource(&self) -> &T {
        &self.resource
    }

    pub fn id(&self) -> i32 {
        self.resource.id()
    }

    pub fn client(&self) -> &Client<Authenticated> {
        &self.client
    }
}

impl<T> Resource<T>
where
    T: ApiResource<GetOutput = T> + Tabled + Display + GetID + Default + 'static,
{
    pub fn select(&self, id: i32) -> Result<Handle<T>, ApiError> {
        let url_params = vec![(Cow::Borrowed("id"), id.to_string().into())];
        let raw: Vec<<T as ApiResource>::GetOutput> = self.client.get(
            T::default(),
            url_params,
            vec![QueryFilter {
                key: "id".to_string(),
                value: id.to_string(),
                operator: FilterOperator::Equals { is_negated: false },
            }],
            T::GetParams::default(),
        )?;

        let got = one_or_err(raw)?;
        let resource: T = got.into();
        Ok(Handle {
            client: self.client.clone(),
            resource,
        })
    }

    /// Select a resource by its name.
    ///
    /// This will use the appropriate field for the resource type.
    ///   - Group: groupname
    ///   - User: username
    ///   - Everything else: name
    pub fn select_by_name(&self, name: &str) -> Result<Handle<T>, ApiError> {
        let url_params = vec![(Cow::Borrowed(T::NAME_FIELD), name.to_string().into())];
        let raw: Vec<<T as ApiResource>::GetOutput> = self.client.get(
            T::default(),
            url_params,
            vec![QueryFilter {
                key: T::NAME_FIELD.to_string(),
                value: name.to_string(),
                operator: FilterOperator::Equals { is_negated: false },
            }],
            T::GetParams::default(),
        )?;

        let got = one_or_err(raw)?;
        let resource: T = got.into();
        Ok(Handle {
            client: self.client.clone(),
            resource,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;
    use yare::parameterized;

    #[parameterized(
        login_foo = { "https://foo.bar.com", Endpoint::Login },
        get_user_foo = { "https://foo.bar.com", Endpoint::Users },
        get_class_foo = { "https://foo.bar.com", Endpoint::Classes },
        login_bar = { "https://bar.baz.com", Endpoint::Login },
        get_user_bar = { "https://bar.baz.com", Endpoint::Users },
        get_class_bar = { "https://bar.baz.com", Endpoint::Classes }

    )]

    fn test_build_url(server: &str, endpoint: Endpoint) {
        let base_url = BaseUrl::from_str(server).unwrap();
        let client = Client::new(base_url.clone(), false);

        assert_eq!(
            client.build_url(&endpoint, UrlParams::default()),
            format!(
                "{}{}",
                base_url.with_trailing_slash(),
                endpoint.trim_start_matches('/')
            )
        );
    }
}
