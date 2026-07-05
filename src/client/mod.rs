use std::borrow::Cow;

use crate::QueryFilter;
use crate::endpoints::Endpoint;

#[cfg(feature = "async")]
pub mod r#async;
mod shared;
#[cfg(feature = "blocking")]
pub mod sync;
#[cfg(test)]
mod tests;

#[cfg(feature = "async")]
pub use self::r#async::Client;
pub use self::shared::{
    Page, QueryBoolField, QueryJsonField, QueryNumericField, QueryTextField, QueryValueField,
};

use crate::resources::ApiResource;

pub type UrlParams = Vec<(Cow<'static, str>, Cow<'static, str>)>;

pub trait GetID {
    fn id(&self) -> i32;
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

#[derive(Debug, Clone)]
pub struct Authenticated {
    token: String,
}

#[cfg(all(test, feature = "async", feature = "blocking"))]
mod parity_contract {
    use super::{Authenticated, Unauthenticated, r#async as async_client, sync as sync_client};
    use crate::resources::{
        Class, ClassRelation, Group, Namespace, Object, ObjectRelation, RemoteTarget,
        ReportTemplate, ServiceAccount, User,
    };
    use crate::types::BaseUrl;

    macro_rules! assert_constructor_capabilities {
        ($module:ident) => {
            let _: fn(BaseUrl, bool) -> $module::Client<Unauthenticated> =
                $module::Client::<Unauthenticated>::new_with_certificate_validation;
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
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<Namespace> =
                $module::Client::<Authenticated>::namespaces;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<Group> =
                $module::Client::<Authenticated>::groups;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<ReportTemplate> =
                $module::Client::<Authenticated>::templates;
            let _: fn(&$module::Client<Authenticated>, i32) -> $module::Resource<Object> =
                $module::Client::<Authenticated>::objects;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<ClassRelation> =
                $module::Client::<Authenticated>::class_relation;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<ObjectRelation> =
                $module::Client::<Authenticated>::object_relation;
            let _ = $module::Client::<Authenticated>::reports;
            let _ = $module::Client::<Authenticated>::imports;
            let _ = $module::Client::<Authenticated>::tasks;
        };
    }

    macro_rules! assert_authenticated_client_auth_surface {
        ($module:ident) => {
            let _ = $module::Client::<Authenticated>::get_token;
            let _ = $module::Client::<Authenticated>::logout;
            let _ = $module::Client::<Authenticated>::logout_token;
            let _ = $module::Client::<Authenticated>::logout_user;
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
        };
    }

    macro_rules! assert_filter_builder_surface {
        ($module:ident) => {
            let _ = $module::QueryOp::<Class>::filter::<i32>;
            let _ = $module::QueryOp::<Class>::raw_param::<&str>;
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
            let _ = $module::QueryOp::<Class>::page;
            let _ = $module::QueryOp::<Class>::one;
            let _ = $module::QueryOp::<Class>::optional;
        };
    }

    macro_rules! assert_resource_surface {
        ($module:ident) => {
            let _ = $module::Resource::<Class>::query;
            let _ = $module::Resource::<Class>::create;
            let _ = $module::Resource::<Class>::update;
            let _ = $module::Resource::<Class>::delete;
            let _ = $module::Resource::<Class>::get;
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
            let _ = $module::Handle::<Class>::relation;
            let _ = $module::Handle::<Class>::create_relation;
            let _ = $module::Handle::<Class>::delete_relation;

            let _ = $module::Handle::<Object>::related_objects;
            let _ = $module::Handle::<Object>::related_relations;
            let _ = $module::Handle::<Object>::related_graph;
            let _ = $module::Handle::<Object>::relation_to;
            let _ = $module::Handle::<Object>::create_relation_to;
            let _ = $module::Handle::<Object>::delete_relation_to;

            let _ = $module::Handle::<User>::groups;
            let _ = $module::Handle::<User>::groups_request;
            let _ = $module::Handle::<User>::tokens;
            let _ = $module::Handle::<User>::tokens_request;
            let _ = $module::Handle::<User>::tokens_create;
            let _ = $module::Handle::<User>::token_revoke;

            let _ = $module::Handle::<ServiceAccount>::disable;
            let _ = $module::Handle::<ServiceAccount>::tokens;
            let _ = $module::Handle::<ServiceAccount>::tokens_create;
            let _ = $module::Handle::<ServiceAccount>::token_revoke;

            let _ = $module::Handle::<RemoteTarget>::invoke;

            let _ = $module::Handle::<Group>::add_member;
            let _ = $module::Handle::<Group>::remove_member;
            let _ = $module::Handle::<Group>::members;
            let _ = $module::Handle::<Group>::members_request;

            let _ = $module::Handle::<Namespace>::permissions;
            let _ = $module::Handle::<Namespace>::permissions_request;
            let _ = $module::Handle::<Namespace>::group_permissions;
            let _ = $module::Handle::<Namespace>::replace_permissions;
            let _ = $module::Handle::<Namespace>::grant_permissions;
            let _ = $module::Handle::<Namespace>::revoke_permissions;
            let _ = $module::Handle::<Namespace>::has_group_permission;
            let _ = $module::Handle::<Namespace>::grant_permission;
            let _ = $module::Handle::<Namespace>::revoke_permission;
            let _ = $module::Handle::<Namespace>::principal_permissions;
            let _ = $module::Handle::<Namespace>::principal_permissions_request;
            let _ = $module::Handle::<Namespace>::groups_with_permission;
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

        assert_resource_surface!(sync_client);
        assert_resource_surface!(async_client);

        assert_handle_core_surface!(sync_client);
        assert_handle_core_surface!(async_client);

        assert_handle_extension_surface!(sync_client);
        assert_handle_extension_surface!(async_client);
    }
}
