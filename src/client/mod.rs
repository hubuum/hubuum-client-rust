use std::borrow::Cow;

use crate::QueryFilter;
use crate::endpoints::Endpoint;
use secrecy::{ExposeSecret, SecretString};

#[cfg(feature = "async")]
pub mod r#async;
mod shared;
#[cfg(feature = "blocking")]
pub mod sync;
#[cfg(all(test, feature = "async", feature = "blocking"))]
mod tests;
pub mod transport;

#[cfg(feature = "async")]
pub use self::r#async::{
    Client, CollectionScope, ExportOutputStream, ItemStream, PageStream, PrincipalSettingsScope,
    TypedClass,
};
pub(crate) use self::shared::redacted_url_for_log;
pub use self::shared::{
    Page, QueryBoolField, QueryJsonField, QueryNumericField, QueryTextField, QueryValueField,
    RetryPolicy,
};
#[cfg(feature = "async")]
pub use self::transport::AsyncTransport;
#[cfg(feature = "blocking")]
pub use self::transport::BlockingTransport;
pub use self::transport::{MockTransport, RequestPlan, TransportResponse};

use crate::resources::ApiResource;

pub type UrlParams = Vec<(Cow<'static, str>, Cow<'static, str>)>;

pub trait GetID: ApiResource {
    fn id(&self) -> Self::Id;
}

trait ClientCore {
    fn build_url(&self, endpoint: &Endpoint, url_params: UrlParams) -> String;
}

pub trait IntoQueryFilters<T: ApiResource> {
    fn into_query_filters(self) -> Vec<QueryFilter>;
}

impl<T: ApiResource> IntoQueryFilters<T> for Vec<QueryFilter> {
    fn into_query_filters(self) -> Vec<QueryFilter> {
        self
    }
}

impl<T: ApiResource> IntoQueryFilters<T> for QueryFilter {
    fn into_query_filters(self) -> Vec<QueryFilter> {
        vec![self]
    }
}

impl<T: ApiResource> IntoQueryFilters<T> for () {
    fn into_query_filters(self) -> Vec<QueryFilter> {
        vec![]
    }
}

#[derive(Debug, Clone)]
pub struct Unauthenticated;

#[derive(Clone)]
pub struct Authenticated {
    token: SecretString,
}

impl std::fmt::Debug for Authenticated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authenticated")
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl Authenticated {
    fn new(token: crate::types::Token) -> Self {
        Self {
            token: token.into_secret(),
        }
    }

    fn token(&self) -> &str {
        self.token.expose_secret()
    }
}

#[cfg(all(test, feature = "async", feature = "blocking"))]
mod parity_contract {
    use super::{Authenticated, Unauthenticated, r#async as async_client, sync as sync_client};
    use crate::resources::{
        Class, ClassId, ClassRelation, ClassRelationId, Collection, ExportTemplate, Group, Object,
        ObjectId, ObjectRelation, RelatedClassGraph, RemoteTarget, ServiceAccount, User,
    };
    use crate::types::BaseUrl;

    macro_rules! assert_constructor_capabilities {
        ($module:ident) => {
            let _: fn(BaseUrl) -> $module::ClientBuilder =
                $module::Client::<Unauthenticated>::builder;
            let _ = $module::Client::<Unauthenticated>::try_new;
            let _ = || $module::Client::<Unauthenticated>::from_url("https://example.invalid");
            let _ =
                || $module::Client::<Unauthenticated>::builder_from_url("https://example.invalid");
            let _ = $module::Client::<Unauthenticated>::base_url;
            let _ = $module::Client::<Unauthenticated>::http_client;
            let _ = $module::Client::<Unauthenticated>::healthz;
            let _ = $module::Client::<Unauthenticated>::readyz;
        };
    }

    macro_rules! assert_client_resource_accessors {
        ($module:ident) => {
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<User> =
                $module::Client::<Authenticated>::users;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<ServiceAccount> =
                $module::Client::<Authenticated>::service_accounts;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<RemoteTarget> =
                $module::Client::<Authenticated>::remote_targets;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<Class> =
                $module::Client::<Authenticated>::classes;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<Collection> =
                $module::Client::<Authenticated>::collections;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<Group> =
                $module::Client::<Authenticated>::groups;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<ExportTemplate> =
                $module::Client::<Authenticated>::export_templates;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<ExportTemplate> =
                $module::Client::<Authenticated>::templates;
            let _: fn(&$module::Client<Authenticated>, i32) -> $module::Resource<Object> =
                $module::Client::<Authenticated>::objects;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<ClassRelation> =
                $module::Client::<Authenticated>::class_relation;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<ObjectRelation> =
                $module::Client::<Authenticated>::object_relation;
            let _ = $module::Client::<Authenticated>::exports;
            let _ = $module::Client::<Authenticated>::imports;
            let _ = $module::Client::<Authenticated>::tasks;
        };
    }

    macro_rules! assert_authenticated_client_auth_surface {
        ($module:ident) => {
            let _ = $module::Client::<Authenticated>::token;
            let _ = $module::Client::<Authenticated>::logout;
            let _ = $module::Client::<Authenticated>::logout_token;
            let _ = $module::Client::<Authenticated>::logout_user::<i32>;
            let _ = $module::Client::<Authenticated>::logout_all;
            let _ = $module::Client::<Authenticated>::meta_counts;
            let _ = $module::Client::<Authenticated>::meta_db;
            let _ = $module::Client::<Authenticated>::meta_tasks;
            let _ = $module::Client::<Authenticated>::me;
            let _ = $module::Client::<Authenticated>::me_groups;
            let _ = $module::Client::<Authenticated>::me_groups_request;
            let _ = $module::Client::<Authenticated>::me_tokens;
            let _ = $module::Client::<Authenticated>::me_tokens_request;
            let _ = $module::Client::<Authenticated>::me_permissions;
            let _ = $module::Client::<Authenticated>::me_permissions_request;
            let _ = $module::Client::<Authenticated>::settings;
            let _ = $module::Client::<Authenticated>::principal_settings::<i32>;
            let _ = $module::PrincipalSettingsScope::get;
            let _ = $module::PrincipalSettingsScope::replace::<serde_json::Value>;
            let _ = $module::PrincipalSettingsScope::patch::<serde_json::Value>;
            let _ = $module::PrincipalSettingsScope::reset;
        };
    }

    macro_rules! assert_filter_builder_surface {
        ($module:ident) => {
            let _ = $module::QueryOp::<Class>::filter::<&str, i32>;
            let _ = $module::QueryOp::<Class>::raw_param::<&str, &str>;
            let _ = $module::QueryOp::<Class>::set_raw_param::<&str, &str>;
            let _ = $module::QueryOp::<Class>::sort_by::<&str>;
            let _ = $module::QueryOp::<Class>::order_by::<&str>;
            let _ = $module::QueryOp::<Class>::sort::<&str>;
            let _ = $module::QueryOp::<Class>::sort_by_fields::<
                Vec<(&str, crate::types::SortDirection)>,
                &str,
            >;
            let _ = $module::QueryOp::<Class>::limit;
            let _ = $module::QueryOp::<Class>::cursor::<&str>;
            let _ = $module::QueryOp::<Class>::list;
            let _ = $module::QueryOp::<Class>::all;
            let _ = $module::QueryOp::<Class>::page;
            let _ = $module::QueryOp::<Class>::one;
            let _ = $module::QueryOp::<Class>::optional;
        };
    }

    macro_rules! assert_resource_surface {
        ($module:ident) => {
            let _ = $module::Resource::<Class>::query;
            let _ = $module::Resource::<Class>::all;
            let _ = $module::Resource::<Class>::create_checked;
            let _ = $module::Resource::<Class>::create_raw;
            let _ = $module::Resource::<Class>::update::<ClassId>;
            let _ = $module::Resource::<Class>::delete::<ClassId>;
            let _ = $module::Resource::<Class>::set_raw_param::<&str, &str>;
            let _ = $module::Resource::<Class>::get::<ClassId>;
            let _ = $module::Resource::<Class>::get_by_name;
        };
    }

    macro_rules! assert_handle_core_surface {
        ($module:ident) => {
            let _ = $module::Handle::<Class>::new;
            let _ = $module::Handle::<Class>::resource;
            let _ = $module::Handle::<Class>::id;
            let _ = $module::Handle::<Class>::client;
        };
    }

    macro_rules! assert_cursor_request_surface {
        ($module:ident) => {
            let _ = $module::EventListRequest::all;
            let _ = $module::HistoryRequest::<crate::types::ClassHistory>::all;
            let _ = $module::TaskListRequest::all;
            let _ = $module::CursorRequest::<crate::types::TaskEventResponse>::all;
            let _ = $module::CursorRequest::<crate::types::TaskEventResponse>::set_query_param::<
                &str,
                &str,
            >;
            let _ = $module::GraphRequest::<RelatedClassGraph>::set_query_param::<&str, &str>;
        };
    }

    macro_rules! assert_handle_extension_surface {
        ($module:ident) => {
            let _ = $module::Handle::<Class>::objects;
            let _ = $module::Handle::<Class>::objects_query;
            let _ = $module::Handle::<Class>::object_by_name;
            let _ = $module::Handle::<Class>::delete;
            let _ = $module::Handle::<Class>::permissions;
            let _ = $module::Handle::<Class>::permissions_request;
            let _ = $module::Handle::<Class>::related_classes;
            let _ = $module::Handle::<Class>::related_relations;
            let _ = $module::Handle::<Class>::related_graph;
            let _ = $module::Handle::<Class>::relation::<ClassRelationId>;
            let _ = $module::Handle::<Class>::create_relation::<ClassId>;
            let _ = $module::Handle::<Class>::delete_relation::<ClassRelationId>;

            let _ = $module::Handle::<Object>::related_objects;
            let _ = $module::Handle::<Object>::related_relations;
            let _ = $module::Handle::<Object>::related_graph;
            let _ = $module::Handle::<Object>::relation_to::<ClassId, ObjectId>;
            let _ = $module::Handle::<Object>::create_relation_to::<ClassId, ObjectId>;
            let _ = $module::Handle::<Object>::delete_relation_to::<ClassId, ObjectId>;

            let _ = $module::Handle::<User>::groups;
            let _ = $module::Handle::<User>::groups_request;
            let _ = $module::Handle::<User>::tokens;
            let _ = $module::Handle::<User>::tokens_request;
            let _ = $module::Handle::<User>::tokens_create;
            let _ = $module::Handle::<User>::settings;

            let _ = $module::Handle::<ServiceAccount>::disable;
            let _ = $module::Handle::<ServiceAccount>::tokens;
            let _ = $module::Handle::<ServiceAccount>::tokens_create;
            let _ = $module::Handle::<ServiceAccount>::settings;

            let _ = $module::Handle::<RemoteTarget>::invoke;

            let _ = $module::Handle::<Group>::members;
            let _ = $module::Handle::<Group>::members_request;

            let _ = $module::Handle::<Collection>::permissions;
            let _ = $module::Handle::<Collection>::permissions_request;
            let _ = $module::Handle::<Collection>::groups_with_permission;
        };
    }

    #[test]
    fn sync_async_parity_contract_compiles() {
        assert_constructor_capabilities!(sync_client);
        assert_constructor_capabilities!(async_client);

        assert_client_resource_accessors!(sync_client);
        assert_client_resource_accessors!(async_client);
        assert_authenticated_client_auth_surface!(sync_client);
        assert_authenticated_client_auth_surface!(async_client);

        assert_filter_builder_surface!(sync_client);
        assert_filter_builder_surface!(async_client);
        assert_cursor_request_surface!(sync_client);
        assert_cursor_request_surface!(async_client);

        assert_resource_surface!(sync_client);
        assert_resource_surface!(async_client);

        assert_handle_core_surface!(sync_client);
        assert_handle_core_surface!(async_client);

        assert_handle_extension_surface!(sync_client);
        assert_handle_extension_surface!(async_client);
    }
}
