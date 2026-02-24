use std::borrow::Cow;

use crate::endpoints::Endpoint;
use crate::QueryFilter;

pub mod r#async;
mod shared;
pub mod sync;
#[cfg(test)]
mod tests;

pub use self::r#async::Client as AsyncClient;
pub use self::sync::Client as SyncClient;

use crate::resources::ApiResource;

pub type UrlParams = Vec<(Cow<'static, str>, Cow<'static, str>)>;

pub trait GetID {
    fn id(&self) -> i32;
}

trait ClientCore {
    fn build_url(&self, endpoint: &Endpoint, url_params: UrlParams) -> String;
}

pub trait IntoResourceFilter<T: ApiResource> {
    fn into_resource_filter(self) -> Vec<QueryFilter>;
}

impl<T: ApiResource> IntoResourceFilter<T> for Vec<QueryFilter> {
    fn into_resource_filter(self) -> Vec<QueryFilter> {
        self
    }
}

impl<T: ApiResource> IntoResourceFilter<T> for QueryFilter {
    fn into_resource_filter(self) -> Vec<QueryFilter> {
        vec![self]
    }
}

impl<T: ApiResource> IntoResourceFilter<T> for () {
    fn into_resource_filter(self) -> Vec<QueryFilter> {
        vec![]
    }
}

#[derive(Debug, Clone)]
pub struct Unauthenticated;

#[derive(Debug, Clone)]
pub struct Authenticated {
    token: String,
}

#[cfg(test)]
mod parity_contract {
    use super::{
        r#async as async_client, sync as sync_client, Authenticated, IntoResourceFilter,
        Unauthenticated,
    };
    use crate::resources::{Class, ClassRelation, Group, Namespace, Object, ObjectRelation, User};
    use crate::{types::BaseUrl, QueryFilter};

    struct DummyFilter;

    impl IntoResourceFilter<Class> for DummyFilter {
        fn into_resource_filter(self) -> Vec<QueryFilter> {
            vec![]
        }
    }

    fn assert_sync_filter_calls(resource: &sync_client::Resource<Class>) {
        let _ = resource.filter(DummyFilter);
        let _ = resource.filter_expecting_single_result(DummyFilter);
    }

    fn assert_async_filter_calls(resource: &async_client::Resource<Class>) {
        std::mem::drop(resource.filter(DummyFilter));
        std::mem::drop(resource.filter_expecting_single_result(DummyFilter));
    }

    macro_rules! assert_constructor_capabilities {
        ($module:ident) => {
            let _: fn(BaseUrl, bool) -> $module::Client<Unauthenticated> =
                $module::Client::<Unauthenticated>::new_with_certificate_validation;
        };
    }

    macro_rules! assert_client_resource_accessors {
        ($module:ident) => {
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<User> =
                $module::Client::<Authenticated>::users;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<Class> =
                $module::Client::<Authenticated>::classes;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<Namespace> =
                $module::Client::<Authenticated>::namespaces;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<Group> =
                $module::Client::<Authenticated>::groups;
            let _: fn(&$module::Client<Authenticated>, i32) -> $module::Resource<Object> =
                $module::Client::<Authenticated>::objects;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<ClassRelation> =
                $module::Client::<Authenticated>::class_relation;
            let _: fn(&$module::Client<Authenticated>) -> $module::Resource<ObjectRelation> =
                $module::Client::<Authenticated>::object_relation;
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
        };
    }

    macro_rules! assert_filter_builder_surface {
        ($module:ident) => {
            let _ = $module::FilterBuilder::<Class>::add_filter::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_equals::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_not_equals::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_iequals::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_not_iequals::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_contains::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_not_contains::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_icontains::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_not_icontains::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_startswith::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_not_startswith::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_istartswith::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_not_istartswith::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_endswith::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_not_endswith::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_iendswith::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_not_iendswith::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_like::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_not_like::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_regex::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_not_regex::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_gt::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_not_gt::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_gte::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_not_gte::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_lt::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_not_lt::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_lte::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_not_lte::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_between::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_not_between::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_id::<i32>;
            let _ = $module::FilterBuilder::<Class>::add_filter_name_exact::<&str>;
            let _ = $module::FilterBuilder::<Class>::add_json_path_lt::<Vec<&str>, &str, i32>;
            let _ = $module::FilterBuilder::<Class>::sort_by::<&str>;
            let _ = $module::FilterBuilder::<Class>::order_by::<&str>;
            let _ = $module::FilterBuilder::<Class>::sort_by_fields::<
                Vec<(&str, crate::types::SortDirection)>,
                &str,
            >;
            let _ = $module::FilterBuilder::<Class>::limit;
            let _ = $module::FilterBuilder::<Class>::list;
            let _ = $module::FilterBuilder::<Class>::one;
            let _ = $module::FilterBuilder::<Class>::optional;
            let _ = $module::FilterBuilder::<Class>::execute;
            let _ = $module::FilterBuilder::<Class>::execute_expecting_single_result;
        };
    }

    macro_rules! assert_resource_surface {
        ($module:ident) => {
            let _ = $module::Resource::<Class>::find;
            let _ = $module::Resource::<Class>::create;
            let _ = $module::Resource::<Class>::update;
            let _ = $module::Resource::<Class>::delete;
            let _ = $module::Resource::<Class>::select;
            let _ = $module::Resource::<Class>::select_by_name;
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
            let _ = $module::Handle::<Class>::object_by_name;
            let _ = $module::Handle::<Class>::delete;
            let _ = $module::Handle::<Class>::permissions;

            let _ = $module::Handle::<User>::groups;
            let _ = $module::Handle::<User>::tokens;

            let _ = $module::Handle::<Group>::add_user;
            let _ = $module::Handle::<Group>::remove_user;
            let _ = $module::Handle::<Group>::members;

            let _ = $module::Handle::<Namespace>::permissions;
            let _ = $module::Handle::<Namespace>::group_permissions;
            let _ = $module::Handle::<Namespace>::replace_permissions;
            let _ = $module::Handle::<Namespace>::grant_permissions;
            let _ = $module::Handle::<Namespace>::revoke_permissions;
            let _ = $module::Handle::<Namespace>::has_group_permission;
            let _ = $module::Handle::<Namespace>::grant_permission;
            let _ = $module::Handle::<Namespace>::revoke_permission;
            let _ = $module::Handle::<Namespace>::user_permissions;
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

        let _: fn(&sync_client::Resource<Class>) = assert_sync_filter_calls;
        let _: fn(&async_client::Resource<Class>) = assert_async_filter_calls;

        assert_resource_surface!(sync_client);
        assert_resource_surface!(async_client);

        assert_handle_core_surface!(sync_client);
        assert_handle_core_surface!(async_client);

        assert_handle_extension_surface!(sync_client);
        assert_handle_extension_surface!(async_client);
    }
}
