use super::fields::*;
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Fields, ItemStruct};

pub(super) struct ResourceSpec {
    name: syn::Ident,
    fields: Vec<ResourceField>,
    display_field: syn::Ident,
}

impl ResourceSpec {
    pub(super) fn parse(input: ItemStruct) -> syn::Result<Self> {
        let source_name = input.ident.to_string();
        let name = source_name.strip_suffix("Resource").ok_or_else(|| {
            syn::Error::new_spanned(
                &input.ident,
                "ApiResource requires a struct name ending in `Resource`",
            )
        })?;
        if name.is_empty() {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "ApiResource requires a non-empty resource name before `Resource`",
            ));
        }
        let name = format_ident!("{name}");
        let id = format_ident!("{name}Id");
        let Fields::Named(fields) = input.fields else {
            return Err(syn::Error::new_spanned(
                &input.ident,
                "ApiResource requires a struct with named fields",
            ));
        };
        let fields = fields
            .named
            .iter()
            .map(|field| ResourceField::resolve(field, &id))
            .collect::<syn::Result<Vec<_>>>()?;
        let display_field = ["name", "user", "username", "id"]
            .iter()
            .find_map(|name| {
                fields
                    .iter()
                    .find(|field| field.ident() == *name)
                    .map(|field| field.ident().clone())
            })
            .ok_or_else(|| {
                syn::Error::new_spanned(
                    &input.ident,
                    "ApiResource requires a `name`, `user`, `username`, or `id` field for Display",
                )
            })?;
        Ok(Self {
            name,
            fields,
            display_field,
        })
    }

    pub(super) fn emit(&self) -> TokenStream {
        let models = self.models();
        let resource = self.resource_impl();
        let asynchronous = self.runtime(
            "async",
            quote!(crate::client::r#async),
            format_ident!("Async{}Create", self.name),
        );
        let blocking = self.runtime(
            "blocking",
            quote!(crate::client::sync),
            format_ident!("Sync{}Create", self.name),
        );
        quote!(#models #resource #asynchronous #blocking)
    }

    fn required_fields(&self) -> Vec<&ResourceField> {
        self.fields
            .iter()
            .filter(|field| field.required())
            .collect()
    }

    fn state_names(&self) -> Vec<syn::Ident> {
        self.required_fields()
            .iter()
            .map(|field| format_ident!("{}_SET", field.ident().to_string().to_uppercase()))
            .collect()
    }

    fn models(&self) -> TokenStream {
        let name = &self.name;
        let id_name = format_ident!("{name}Id");
        let get_name = format_ident!("{name}Get");
        let post_name = format_ident!("{name}Post");
        let patch_name = format_ident!("{name}Patch");
        let draft_name = format_ident!("{name}CreateParams");
        let fields = self.model_fields();
        let ModelFields {
            resource,
            get,
            post,
            patch,
        } = fields;
        let CreateFields {
            draft, from_post, ..
        } = self.create_fields();
        let post_default = if self.required_fields().iter().all(|field| {
            !field.options.as_id && !is_id_type(field.post_type.as_ref().expect("required field"))
        }) {
            quote!(#[derive(Default)])
        } else {
            quote!()
        };
        quote! {
            crate::types::id::define_id!(#id_name, i32);
            impl crate::resources::ResourceId for #id_name {
                fn new(value: i32) -> Result<Self, crate::ApiError> { Self::new(value) }
                fn get(self) -> i32 { self.get() }
            }
            #[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq)]
            #[non_exhaustive]
            pub struct #name { #resource }
            #[derive(Default, Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq)]
            pub struct #get_name { #get }
            #[derive(serde::Serialize, serde::Deserialize, Clone, PartialEq)]
            #post_default
            pub struct #post_name { #post }
            #[doc(hidden)]
            #[derive(Default)]
            pub struct #draft_name { #draft }
            impl From<#post_name> for #draft_name {
                fn from(params: #post_name) -> Self { Self { #from_post } }
            }
            #[derive(Default, serde::Serialize, serde::Deserialize, Clone, PartialEq)]
            pub struct #patch_name { #patch }
        }
    }

    fn model_fields(&self) -> ModelFields {
        let mut generated = ModelFields::default();
        for field in &self.fields {
            let name = field.ident();
            let wire_name = &field.wire_ident;
            let ty = &field.model_type;
            let default = field.default_attribute();
            if !field.options.post_only {
                generated.resource.extend(quote!(#default pub #name: #ty,));
                if !field.options.skip_query {
                    let ty = &field.query_type;
                    generated.get.extend(quote!(pub #wire_name: Option<#ty>,));
                }
            }
            if let Some(ty) = &field.post_type {
                let skip = if field.options.post_optional {
                    quote!(#[serde(skip_serializing_if = "Option::is_none")])
                } else {
                    quote!()
                };
                generated.post.extend(quote!(#skip pub #wire_name: #ty,));
            }
            if let Some(ty) = &field.patch_type {
                generated.patch.extend(quote!(pub #wire_name: #ty,));
            }
        }
        generated
    }

    fn create_fields(&self) -> CreateFields {
        let mut generated = CreateFields::default();
        for field in &self.fields {
            let Some(ty) = &field.post_type else { continue };
            let name = &field.wire_ident;
            let inner = option_inner_type(ty).unwrap_or(ty);
            generated.draft.extend(quote!(#name: Option<#inner>,));
            if field.required() {
                generated
                    .from_post
                    .extend(quote!(#name: Some(params.#name),));
                generated.finish.extend(quote!(#name: builder.#name.ok_or(crate::ApiError::MissingRequiredField { field: stringify!(#name) })?,));
            } else {
                generated.from_post.extend(quote!(#name: params.#name,));
                generated.finish.extend(quote!(#name: builder.#name,));
            }
        }
        generated
    }

    fn resource_impl(&self) -> TokenStream {
        let name = &self.name;
        let id_name = format_ident!("{name}Id");
        let get_name = format_ident!("{name}Get");
        let post_name = format_ident!("{name}Post");
        let patch_name = format_ident!("{name}Patch");
        let draft_name = format_ident!("{name}CreateParams");
        let display = &self.display_field;
        let name_field = if name == "Group" {
            format_ident!("groupname")
        } else {
            format_ident!("name")
        };
        let plural = if name.to_string().ends_with('s') {
            format!("{name}es")
        } else {
            format!("{name}s")
        };
        let endpoint = format_ident!("{plural}");
        let item_endpoint = format_ident!("{plural}ById");
        let id_param = id_param_name(&name.to_string());
        let (name_endpoint, name_param) = if name == "Class" {
            (
                quote!(Some(crate::endpoints::Endpoint::ClassesByName)),
                "class_name",
            )
        } else {
            (quote!(None), "name")
        };
        let finish = self.create_fields().finish;
        let filters = self.get_filters();
        quote! {
            impl crate::client::GetID for #name { fn id(&self) -> Self::Id { self.id } }
            impl std::fmt::Display for #name { fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { write!(f, "{}", self.#display) } }
            impl crate::resources::sealed::Sealed for #name {}
            impl crate::resources::ApiResource for #name {
                type Id = #id_name;
                type GetParams = #get_name;
                type GetOutput = #name;
                type PostParams = #post_name;
                type PostBuilder = #draft_name;
                fn finish_post(builder: Self::PostBuilder) -> Result<Self::PostParams, crate::ApiError> { Ok(#post_name { #finish }) }
                type PostOutput = #name;
                type PatchParams = #patch_name;
                type PatchOutput = #name;
                type DeleteParams = ();
                type DeleteOutput = ();
                const NAME_FIELD: &'static str = stringify!(#name_field);
                const COLLECTION_ENDPOINT: crate::endpoints::Endpoint = crate::endpoints::Endpoint::#endpoint;
                const ITEM_ENDPOINT: Option<crate::endpoints::Endpoint> = Some(crate::endpoints::Endpoint::#item_endpoint);
                const ID_PARAM: &'static str = #id_param;
                const NAME_ITEM_ENDPOINT: Option<crate::endpoints::Endpoint> = #name_endpoint;
                const NAME_PARAM: &'static str = #name_param;
                fn endpoint(&self) -> crate::endpoints::Endpoint { Self::COLLECTION_ENDPOINT }
                fn build_params(filters: Vec<(String, crate::types::FilterOperator, String)>) -> Vec<crate::types::QueryFilter> {
                    filters.into_iter().map(|(key, operator, value)| crate::types::QueryFilter { key, operator, value }).collect()
                }
                fn filters_from_get(params: Self::GetParams) -> Vec<crate::types::QueryFilter> { let mut queries = vec![]; #filters queries }
            }
        }
    }

    fn get_filters(&self) -> TokenStream {
        self.fields.iter().filter(|field| !field.options.post_only && !field.options.skip_query).map(|field| {
            let name = &field.wire_ident; let key = field.query_key();
            quote! { if let Some(value) = params.#name { queries.push(crate::types::QueryFilter { key: #key.to_string(), value: value.to_string(), operator: crate::types::FilterOperator::Equals { is_negated: false } }); } }
        }).collect()
    }

    fn query_methods(&self) -> TokenStream {
        self.fields
            .iter()
            .filter(|field| !field.options.post_only && !field.options.skip_query)
            .map(|field| {
                let name = &field.wire_ident;
                let key = field.query_key();
                let lint = field.setter_lint_attribute();
                let wrapper = query_field_wrapper(&field.query_type, field.options.as_id);
                quote! { #lint pub fn #name(self) -> #wrapper { <#wrapper>::new(self, #key) } }
            })
            .collect()
    }

    fn create_methods(&self) -> TokenStream {
        self.fields.iter().filter_map(|field| field.post_type.as_ref().map(|ty| {
            let inner = option_inner_type(ty).unwrap_or(ty);
            let (arg, assign) = fluent_arg_and_assign(&quote!(Option<#inner>));
            let name = &field.wire_ident;
            quote! { pub fn #name(self, value: #arg) -> Self { self.edit_params(move |params| { params.#name = #assign; }) } }
        })).collect()
    }

    fn patch_methods(&self) -> TokenStream {
        self.fields.iter().filter_map(|field| field.patch_type.as_ref().map(|ty| {
            let (arg, assign) = fluent_arg_and_assign(&quote!(#ty)); let name = &field.wire_ident;
            quote! { pub fn #name(self, value: #arg) -> Self { self.edit_params(move |params| { params.#name = #assign; }) } }
        })).collect()
    }

    fn checked_methods(&self, checked: &syn::Ident) -> TokenStream {
        let required = self.required_fields();
        let states = self.state_names();
        self.fields.iter().filter_map(|field| field.post_type.as_ref().map(|ty| {
            let inner = option_inner_type(ty).unwrap_or(ty); let (arg, _) = fluent_arg_and_assign(&quote!(Option<#inner>));
            let name = &field.wire_ident; let lint = field.setter_lint_attribute();
            let next = required.iter().zip(&states).map(|(required, state)| if required.ident() == field.ident() { quote!(true) } else { quote!(#state) });
            quote! { #lint pub fn #name(self, value: #arg) -> #checked<#(#next),*> { #checked { inner: self.inner.#name(value) } } }
        })).collect()
    }

    fn runtime(&self, feature: &str, runtime: TokenStream, checked: syn::Ident) -> TokenStream {
        let name = &self.name;
        let states = self.state_names();
        let initial = states.iter().map(|_| quote!(false)).collect::<Vec<_>>();
        let complete = states.iter().map(|_| quote!(true)).collect::<Vec<_>>();
        let create = self.create_methods();
        let patch = self.patch_methods();
        let query = self.query_methods();
        let setters = self.checked_methods(&checked);
        let (asynchronous, wait) = if feature == "async" {
            (quote!(async), quote!(.await))
        } else {
            (quote!(), quote!())
        };
        quote! {
            #[cfg(feature = #feature)] impl #runtime::CreateOp<#name> { #create }
            #[cfg(feature = #feature)] pub struct #checked<#(const #states: bool),*> { inner: #runtime::CreateOp<#name> }
            #[cfg(feature = #feature)] impl<#(const #states: bool),*> #checked<#(#states),*> { #setters }
            #[cfg(feature = #feature)] impl #checked<#(#complete),*> {
                pub #asynchronous fn send(self) -> Result<#name, crate::ApiError> { self.inner.send()#wait }
            }
            #[cfg(feature = #feature)] impl #runtime::Resource<#name> {
                #[allow(deprecated)] pub fn create_checked(&self) -> #checked<#(#initial),*> { #checked { inner: self.create() } }
            }
            #[cfg(feature = #feature)] impl #runtime::UpdateOp<#name> { #patch }
            #[cfg(feature = #feature)] impl #runtime::QueryOp<#name> { #query }
            #[cfg(feature = #feature)] impl #runtime::Resource<#name> { #query }
        }
    }
}

#[derive(Default)]
struct ModelFields {
    resource: TokenStream,
    get: TokenStream,
    post: TokenStream,
    patch: TokenStream,
}
#[derive(Default)]
struct CreateFields {
    draft: TokenStream,
    from_post: TokenStream,
    finish: TokenStream,
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
