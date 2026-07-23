#![forbid(unsafe_code)]

// #[derive(ApiResource)]
// pub struct Class {
//     #[api(read_only)]
//     pub id: i32,
//     pub name: String,
//     pub description: String,
//     pub collection_id: i32,
//     pub json_schema: Option<serde_json::Value>,
//     pub validate_schema: Option<bool>,
//     #[api(read_only)]
//     pub created_at: chrono::NaiveDateTime,
//     #[api(read_only)]
//     pub updated_at: chrono::NaiveDateTime,
// }
// The endpoint becomes GetClass.

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Data, DeriveInput, Fields, GenericArgument, Meta, PathArguments, Type, parse_macro_input,
};

use syn::punctuated::Punctuated;

fn pluralize(name: &syn::Ident) -> String {
    let name = name.to_string();
    let last_char = name.chars().last().unwrap();
    match last_char {
        's' => format!("{}es", name),
        _ => format!("{}s", name),
    }
}

#[proc_macro_derive(ApiResource, attributes(endpoint, api))]
pub fn derive_api_resource(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand_api_resource(input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn expand_api_resource(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let name = &input.ident;

    let base_name = name.to_string();
    let Some(resource_name) = base_name.strip_suffix("Resource") else {
        return Err(syn::Error::new_spanned(
            name,
            "ApiResource requires a struct name ending in `Resource`",
        ));
    };
    if resource_name.is_empty() {
        return Err(syn::Error::new_spanned(
            name,
            "ApiResource requires a non-empty resource name before `Resource`",
        ));
    }
    let name = format_ident!("{resource_name}");
    let id_name = format_ident!("{}Id", name);
    let plural_name = format_ident!("{}", pluralize(&name));
    let async_checked_name = format_ident!("Async{}Create", name);
    let sync_checked_name = format_ident!("Sync{}Create", name);
    let (name_item_endpoint, name_param) = if name == "Class" {
        (
            quote!(Some(crate::endpoints::Endpoint::ClassesByName)),
            "class_name",
        )
    } else {
        (quote!(None), "name")
    };

    let name_field = match resource_name {
        "Group" => format_ident!("groupname"),
        _ => format_ident!("name"),
    };

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => {
                return Err(syn::Error::new_spanned(
                    &data.fields,
                    "ApiResource requires a struct with named fields",
                ));
            }
        },
        _ => {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "ApiResource can only be derived for structs",
            ));
        }
    };

    let (main_fields, get_fields, post_fields, patch_fields) = process_fields(fields, &id_name);

    let mut get_param_filters = proc_macro2::TokenStream::new();
    let mut create_methods = proc_macro2::TokenStream::new();
    let mut update_methods = proc_macro2::TokenStream::new();
    let mut query_methods = proc_macro2::TokenStream::new();
    let mut async_checked_create_methods = proc_macro2::TokenStream::new();
    let mut sync_checked_create_methods = proc_macro2::TokenStream::new();

    let required_create_fields = fields
        .iter()
        .filter(|field| {
            let is_read_only = has_attribute(field, "read_only");
            let is_post_only = has_attribute(field, "post_only");
            let is_optional = has_attribute(field, "optional");
            let is_post_optional = has_attribute(field, "post_optional");
            (is_post_only || !is_read_only) && !is_optional && !is_post_optional
        })
        .collect::<Vec<_>>();
    let required_state_names = required_create_fields
        .iter()
        .map(|field| {
            format_ident!(
                "{}_SET",
                field
                    .ident
                    .as_ref()
                    .expect("named field")
                    .to_string()
                    .to_uppercase()
            )
        })
        .collect::<Vec<_>>();

    for field in fields {
        let field_ident = field
            .ident
            .as_ref()
            .expect("ApiResource only supports named fields");
        let field_name = field_ident.to_string();
        let field_ty = &field.ty;

        let is_read_only = has_attribute(field, "read_only");
        let is_post_only = has_attribute(field, "post_only");
        let is_optional = has_attribute(field, "optional");
        let is_post_optional = has_attribute(field, "post_optional");
        let is_as_id = has_attribute(field, "as_id");
        let skip_patch = has_attribute(field, "skip_patch");
        let skip_query = has_attribute(field, "skip_query");

        let post_patch_field_ident = if is_as_id {
            format_ident!("{}_id", field_name)
        } else {
            field_ident.clone()
        };

        if !is_post_only && !skip_query {
            get_param_filters.extend(quote! {
                if let Some(value) = params.#post_patch_field_ident {
                    queries.push(crate::types::QueryFilter {
                        key: stringify!(#post_patch_field_ident).to_string(),
                        value: value.to_string(),
                        operator: crate::types::FilterOperator::Equals { is_negated: false },
                    });
                }
            });

            let field_wrapper = query_field_wrapper(field_ty, is_as_id);
            query_methods.extend(quote! {
                pub fn #post_patch_field_ident(self) -> #field_wrapper {
                    <#field_wrapper>::new(self, stringify!(#post_patch_field_ident))
                }
            });
        }

        if is_post_only || !is_read_only {
            let create_field_ty = if is_post_only {
                quote!(#field_ty)
            } else if is_as_id {
                if is_optional || is_post_optional {
                    quote!(Option<<#field_ty as crate::resources::ApiResource>::Id>)
                } else {
                    quote!(<#field_ty as crate::resources::ApiResource>::Id)
                }
            } else if is_optional || is_post_optional {
                quote!(Option<#field_ty>)
            } else {
                quote!(#field_ty)
            };
            let (arg_ty, assign_expr) = fluent_arg_and_assign(&create_field_ty);
            create_methods.extend(quote! {
                pub fn #post_patch_field_ident(self, value: #arg_ty) -> Self {
                    self.edit_params(move |params| {
                        params.#post_patch_field_ident = #assign_expr;
                    })
                }
            });

            let checked_return_states = required_create_fields
                .iter()
                .zip(required_state_names.iter())
                .map(|(required, state)| {
                    if required.ident == field.ident {
                        quote!(true)
                    } else {
                        quote!(#state)
                    }
                });
            let checked_return_states = checked_return_states.collect::<Vec<_>>();
            async_checked_create_methods.extend(quote! {
                pub fn #post_patch_field_ident(self, value: #arg_ty) -> #async_checked_name<
                    #(#checked_return_states),*
                > {
                    #async_checked_name {
                        inner: self.inner.#post_patch_field_ident(value),
                    }
                }
            });
            sync_checked_create_methods.extend(quote! {
                pub fn #post_patch_field_ident(self, value: #arg_ty) -> #sync_checked_name<
                    #(#checked_return_states),*
                > {
                    #sync_checked_name {
                        inner: self.inner.#post_patch_field_ident(value),
                    }
                }
            });
        }

        if !is_post_only && !is_read_only && !skip_patch {
            let patch_field_ty = if is_as_id {
                if is_optional {
                    quote!(Option<<#field_ty as crate::resources::ApiResource>::Id>)
                } else {
                    quote!(<#field_ty as crate::resources::ApiResource>::Id)
                }
            } else {
                quote!(Option<#field_ty>)
            };
            let (arg_ty, assign_expr) = fluent_arg_and_assign(&patch_field_ty);
            update_methods.extend(quote! {
                pub fn #post_patch_field_ident(self, value: #arg_ty) -> Self {
                    self.edit_params(move |params| {
                        params.#post_patch_field_ident = #assign_expr;
                    })
                }
            });
        }
    }

    let get_name = format_ident!("{}Get", name);
    let post_name = format_ident!("{}Post", name);
    let patch_name = format_ident!("{}Patch", name);
    let endpoint = format_ident!("{}", plural_name);
    let item_endpoint = format_ident!("{}ById", plural_name);
    let id_param = id_param_name(&name.to_string());
    let state_definitions = required_state_names
        .iter()
        .map(|state| quote!(const #state: bool))
        .collect::<Vec<_>>();
    let state_arguments = required_state_names.iter().collect::<Vec<_>>();
    let initial_states = required_state_names
        .iter()
        .map(|_| quote!(false))
        .collect::<Vec<_>>();
    let complete_states = required_state_names
        .iter()
        .map(|_| quote!(true))
        .collect::<Vec<_>>();

    // List of field names to check for Display implementation, in order of preference
    let display_field_options = &[
        format_ident!("name"),
        format_ident!("user"),
        format_ident!("username"),
        format_ident!("id"),
    ];

    // Find the first matching field from the options
    let display_field = display_field_options
        .iter()
        .find(|&field| fields.iter().any(|f| f.ident.as_ref() == Some(field)))
        .ok_or_else(|| {
            syn::Error::new_spanned(
                &input.ident,
                "ApiResource requires a `name`, `user`, `username`, or `id` field for Display",
            )
        })?;

    // Generate the Display implementation
    let display_impl = quote! {
        impl std::fmt::Display for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{}", self.#display_field)
            }
        }
    };

    let expanded = quote! {
        #[derive(Default, Debug, serde::Serialize, serde::Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
        #[serde(transparent)]
        pub struct #id_name(i32);

        impl #id_name {
            pub fn new(value: i32) -> Self {
                Self(value)
            }

            pub fn get(self) -> i32 {
                self.0
            }
        }

        impl std::fmt::Display for #id_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl std::str::FromStr for #id_name {
            type Err = <i32 as std::str::FromStr>::Err;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                value.parse::<i32>().map(Self)
            }
        }

        impl From<i32> for #id_name {
            fn from(value: i32) -> Self {
                Self(value)
            }
        }

        impl From<&#id_name> for #id_name {
            fn from(value: &#id_name) -> Self {
                *value
            }
        }

        impl From<#id_name> for i32 {
            fn from(value: #id_name) -> Self {
                value.0
            }
        }

        impl PartialEq<i32> for #id_name {
            fn eq(&self, other: &i32) -> bool {
                self.0 == *other
            }
        }

        impl PartialEq<#id_name> for i32 {
            fn eq(&self, other: &#id_name) -> bool {
                *self == other.0
            }
        }

        impl crate::resources::ResourceId for #id_name {
            fn new(value: i32) -> Self {
                Self(value)
            }

            fn get(self) -> i32 {
                self.0
            }
        }

        #[derive(Default, Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq)]
        #[non_exhaustive]
        pub struct #name {
            #main_fields
        }

        impl crate::client::GetID for #name {
            fn id(&self) -> Self::Id {
                self.id
            }
        }

        #[derive(Default, Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq)]
        pub struct #get_name {
            #get_fields
        }

        #[derive(Default, serde::Serialize, serde::Deserialize, Clone, PartialEq)]
        pub struct #post_name {
            #post_fields
        }

        #[derive(Default, serde::Serialize, serde::Deserialize, Clone, PartialEq)]
        pub struct #patch_name {
            #patch_fields
        }

        #display_impl

        impl crate::resources::sealed::Sealed for #name {}

        impl crate::resources::ApiResource for #name {
            type Id = #id_name;
            type GetParams = #get_name;
            type GetOutput = #name;
            type PostParams = #post_name;
            type PostOutput = #name;
            type PatchParams = #patch_name;
            type PatchOutput = #name;
            type DeleteParams = ();
            type DeleteOutput = ();

            const NAME_FIELD: &'static str = stringify!(#name_field);
            const COLLECTION_ENDPOINT: crate::endpoints::Endpoint = crate::endpoints::Endpoint::#endpoint;
            const ITEM_ENDPOINT: Option<crate::endpoints::Endpoint> = Some(crate::endpoints::Endpoint::#item_endpoint);
            const ID_PARAM: &'static str = #id_param;
            const NAME_ITEM_ENDPOINT: Option<crate::endpoints::Endpoint> = #name_item_endpoint;
            const NAME_PARAM: &'static str = #name_param;

            fn endpoint(&self) -> crate::endpoints::Endpoint {
                Self::COLLECTION_ENDPOINT
            }

            fn build_params(filters: Vec<(String, crate::types::FilterOperator, String)>) -> Vec<crate::types::QueryFilter> {
                let mut queries = vec![];
                for (key, operator, value) in filters {
                    queries.push(crate::types::QueryFilter {
                        key,
                        value,
                        operator,
                    });
                }
                queries
            }

            fn filters_from_get(params: Self::GetParams) -> Vec<crate::types::QueryFilter> {
                let mut queries = vec![];
                #get_param_filters
                queries
            }
        }

        #[cfg(feature = "blocking")]
        impl crate::client::sync::CreateOp<#name> {
            #create_methods
        }

        #[cfg(feature = "async")]
        impl crate::client::r#async::CreateOp<#name> {
            #create_methods
        }

        #[cfg(feature = "async")]
        pub struct #async_checked_name<#(#state_definitions),*> {
            inner: crate::client::r#async::CreateOp<#name>,
        }

        #[cfg(feature = "async")]
        impl<#(const #state_arguments: bool),*> #async_checked_name<#(#state_arguments),*> {
            #async_checked_create_methods
        }

        #[cfg(feature = "async")]
        impl #async_checked_name<#(#complete_states),*> {
            pub async fn send(self) -> Result<#name, crate::ApiError> {
                self.inner.send().await
            }
        }

        #[cfg(feature = "async")]
        impl crate::client::r#async::Resource<#name> {
            #[allow(deprecated)]
            pub fn create_checked(&self) -> #async_checked_name<#(#initial_states),*> {
                #async_checked_name {
                    inner: self.create(),
                }
            }
        }

        #[cfg(feature = "blocking")]
        pub struct #sync_checked_name<#(#state_definitions),*> {
            inner: crate::client::sync::CreateOp<#name>,
        }

        #[cfg(feature = "blocking")]
        impl<#(const #state_arguments: bool),*> #sync_checked_name<#(#state_arguments),*> {
            #sync_checked_create_methods
        }

        #[cfg(feature = "blocking")]
        impl #sync_checked_name<#(#complete_states),*> {
            pub fn send(self) -> Result<#name, crate::ApiError> {
                self.inner.send()
            }
        }

        #[cfg(feature = "blocking")]
        impl crate::client::sync::Resource<#name> {
            #[allow(deprecated)]
            pub fn create_checked(&self) -> #sync_checked_name<#(#initial_states),*> {
                #sync_checked_name {
                    inner: self.create(),
                }
            }
        }

        #[cfg(feature = "blocking")]
        impl crate::client::sync::UpdateOp<#name> {
            #update_methods
        }

        #[cfg(feature = "async")]
        impl crate::client::r#async::UpdateOp<#name> {
            #update_methods
        }

        #[cfg(feature = "blocking")]
        impl crate::client::sync::QueryOp<#name> {
            #query_methods
        }

        #[cfg(feature = "async")]
        impl crate::client::r#async::QueryOp<#name> {
            #query_methods
        }

        #[cfg(feature = "blocking")]
        impl crate::client::sync::Resource<#name> {
            #query_methods
        }

        #[cfg(feature = "async")]
        impl crate::client::r#async::Resource<#name> {
            #query_methods
        }
    };

    Ok(expanded)
}

fn has_attribute(field: &syn::Field, attr_name: &str) -> bool {
    field.attrs.iter().any(|attr| {
        if !attr.path().is_ident("api") {
            return false;
        }
        let Meta::List(list) = &attr.meta else {
            return false;
        };
        let Ok(nested) = list.parse_args_with(Punctuated::<Meta, syn::Token![,]>::parse_terminated)
        else {
            return false;
        };
        nested
            .iter()
            .any(|meta| matches!(meta, Meta::Path(path) if path.is_ident(attr_name)))
    })
}

fn option_inner_type(ty: &Type) -> Option<&Type> {
    let Type::Path(type_path) = ty else {
        return None;
    };
    let segment = type_path.path.segments.last()?;
    if segment.ident != "Option" {
        return None;
    }

    let PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    let Some(GenericArgument::Type(inner)) = args.args.first() else {
        return None;
    };

    Some(inner)
}

fn is_string_type(ty: &Type) -> bool {
    let ty = option_inner_type(ty).unwrap_or(ty);
    let Type::Path(type_path) = ty else {
        return false;
    };
    type_path
        .path
        .segments
        .last()
        .map(|segment| segment.ident == "String")
        .unwrap_or(false)
}

fn is_bool_type(ty: &Type) -> bool {
    let ty = option_inner_type(ty).unwrap_or(ty);
    let Type::Path(type_path) = ty else {
        return false;
    };
    type_path
        .path
        .segments
        .last()
        .map(|segment| segment.ident == "bool")
        .unwrap_or(false)
}

fn is_json_value_type(ty: &Type) -> bool {
    let ty = option_inner_type(ty).unwrap_or(ty);
    let Type::Path(type_path) = ty else {
        return false;
    };
    let segments = &type_path.path.segments;
    let last = segments.last().map(|segment| segment.ident.to_string());
    last.as_deref() == Some("Value")
}

fn is_numeric_or_datetime_type(ty: &Type) -> bool {
    let ty = option_inner_type(ty).unwrap_or(ty);
    let Type::Path(type_path) = ty else {
        return false;
    };
    let Some(segment) = type_path.path.segments.last() else {
        return false;
    };
    matches!(
        segment.ident.to_string().as_str(),
        "i8" | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "f32"
            | "f64"
            | "HubuumDateTime"
            | "DateTime"
            | "NaiveDateTime"
    )
}

fn is_id_type(ty: &Type) -> bool {
    let ty = option_inner_type(ty).unwrap_or(ty);
    let Type::Path(type_path) = ty else {
        return false;
    };
    type_path
        .path
        .segments
        .last()
        .is_some_and(|segment| segment.ident.to_string().ends_with("Id"))
}

fn query_value_type(field_ty: &Type, is_as_id: bool) -> proc_macro2::TokenStream {
    if is_as_id {
        quote!(<#field_ty as crate::resources::ApiResource>::Id)
    } else {
        let ty = option_inner_type(field_ty).unwrap_or(field_ty);
        quote!(#ty)
    }
}

fn query_field_wrapper(field_ty: &Type, is_as_id: bool) -> proc_macro2::TokenStream {
    let value_ty = query_value_type(field_ty, is_as_id);
    if is_as_id || is_numeric_or_datetime_type(field_ty) || is_id_type(field_ty) {
        quote!(crate::client::QueryNumericField<Self, #value_ty>)
    } else if is_string_type(field_ty) {
        quote!(crate::client::QueryTextField<Self>)
    } else if is_bool_type(field_ty) {
        quote!(crate::client::QueryBoolField<Self>)
    } else if is_json_value_type(field_ty) {
        quote!(crate::client::QueryJsonField<Self>)
    } else {
        quote!(crate::client::QueryValueField<Self, #value_ty>)
    }
}

fn id_param_name(name: &str) -> &'static str {
    match name {
        "User" => "user_id",
        "Group" => "group_id",
        "Class" => "class_id",
        "Collection" => "collection_id",
        "Object" => "object_id",
        "ExportTemplate" => "template_id",
        "ServiceAccount" => "service_account_id",
        "ClassRelation" | "ObjectRelation" => "relation_id",
        _ => "id",
    }
}

fn fluent_arg_and_assign(
    field_ty: &proc_macro2::TokenStream,
) -> (proc_macro2::TokenStream, proc_macro2::TokenStream) {
    let parsed_ty: Type = syn::parse2(field_ty.clone()).expect("generated field type should parse");

    if let Some(inner) = option_inner_type(&parsed_ty) {
        if is_string_type(inner) {
            (quote!(impl Into<String>), quote!(Some(value.into())))
        } else if is_id_type(inner) {
            (quote!(impl Into<#inner>), quote!(Some(value.into())))
        } else {
            (quote!(#inner), quote!(Some(value)))
        }
    } else if is_string_type(&parsed_ty) {
        (quote!(impl Into<String>), quote!(value.into()))
    } else if is_id_type(&parsed_ty) {
        (quote!(impl Into<#parsed_ty>), quote!(value.into()))
    } else {
        (quote!(#parsed_ty), quote!(value))
    }
}

fn process_fields(
    fields: &Punctuated<syn::Field, syn::Token![,]>,
    id_name: &syn::Ident,
) -> (
    proc_macro2::TokenStream,
    proc_macro2::TokenStream,
    proc_macro2::TokenStream,
    proc_macro2::TokenStream,
) {
    let mut main_fields = proc_macro2::TokenStream::new();
    let mut get_fields = proc_macro2::TokenStream::new();
    let mut post_fields = proc_macro2::TokenStream::new();
    let mut patch_fields = proc_macro2::TokenStream::new();

    for field in fields {
        let name = &field.ident;
        let fieldname = name.as_ref().unwrap().to_string();
        let ty = &field.ty;

        let is_read_only = has_attribute(field, "read_only");
        let is_post_only = has_attribute(field, "post_only");
        let is_optional = has_attribute(field, "optional");
        let is_post_optional = has_attribute(field, "post_optional");
        let is_as_id = has_attribute(field, "as_id");
        let skip_patch = has_attribute(field, "skip_patch");
        let skip_query = has_attribute(field, "skip_query");
        let serde_default = if has_attribute(field, "default_local") {
            quote!(#[serde(default = "crate::types::default_local_identity_value")])
        } else if has_attribute(field, "default") {
            quote!(#[serde(default)])
        } else {
            quote!()
        };

        let id_field_name = if is_as_id {
            format!("{}_id", fieldname)
        } else {
            fieldname.clone()
        };
        let id_field_ident = syn::Ident::new(&id_field_name, proc_macro2::Span::call_site());

        if !is_post_only {
            let main_field_ty = if fieldname == "id" {
                quote!(#id_name)
            } else if is_optional {
                quote!(Option<#ty>)
            } else {
                quote!(#ty)
            };
            main_fields.extend(quote! {
                #serde_default
                pub #name: #main_field_ty,
            });

            if !skip_query {
                let get_type = if is_as_id {
                    quote!(Option<<#ty as crate::resources::ApiResource>::Id>)
                } else {
                    quote!(Option<#ty>)
                };
                get_fields.extend(quote! { pub #id_field_ident: #get_type, });
            }
        }

        if is_post_only {
            post_fields.extend(quote! { pub #id_field_ident: #ty, });
        } else if !is_read_only {
            if is_as_id {
                let id_type = if is_optional || is_post_optional {
                    quote!(Option<<#ty as crate::resources::ApiResource>::Id>)
                } else {
                    quote!(<#ty as crate::resources::ApiResource>::Id)
                };
                if !skip_patch {
                    patch_fields.extend(quote! { pub #id_field_ident: #id_type, });
                }
                if is_post_optional {
                    post_fields.extend(quote! {
                        #[serde(skip_serializing_if = "Option::is_none")]
                        pub #id_field_ident: #id_type,
                    });
                } else {
                    post_fields.extend(quote! { pub #id_field_ident: #id_type, });
                }
            } else {
                if !skip_patch {
                    patch_fields.extend(quote! { pub #id_field_ident: Option<#ty>, });
                }
                let post_type = if is_optional || is_post_optional {
                    quote!(Option<#ty>)
                } else {
                    quote!(#ty)
                };
                if is_post_optional {
                    post_fields.extend(quote! {
                        #[serde(skip_serializing_if = "Option::is_none")]
                        pub #id_field_ident: #post_type,
                    });
                } else {
                    post_fields.extend(quote! { pub #id_field_ident: #post_type, });
                }
            }
        }
    }

    (main_fields, get_fields, post_fields, patch_fields)
}
