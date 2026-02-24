// #[derive(ApiResource)]
// pub struct Class {
//     #[api(read_only)]
//     pub id: i32,
//     pub name: String,
//     pub description: String,
//     pub namespace_id: i32,
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
    parse_macro_input, Data, DeriveInput, Fields, GenericArgument, Meta, PathArguments, Type,
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
pub fn api_resource_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let base_name = name.to_string();
    if !base_name.ends_with("Resource") {
        panic!("ApiResource only supports structs with names ending in 'Resource'");
    }
    let name = format_ident!("{}", base_name.trim_end_matches("Resource"));
    let plural_name = format_ident!("{}", pluralize(&name));

    let name_field = match base_name.trim_end_matches("Resource") {
        "User" => format_ident!("username"),
        "Group" => format_ident!("groupname"),
        _ => format_ident!("name"),
    };

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => &fields.named,
            _ => panic!("ApiResource only supports structs with named fields"),
        },
        _ => panic!("ApiResource only supports structs"),
    };

    let (main_fields, get_fields, post_fields, patch_fields) = process_fields(fields);

    let mut get_param_filters = proc_macro2::TokenStream::new();
    let mut create_sync_methods = proc_macro2::TokenStream::new();
    let mut create_async_methods = proc_macro2::TokenStream::new();
    let mut update_sync_methods = proc_macro2::TokenStream::new();
    let mut update_async_methods = proc_macro2::TokenStream::new();
    let mut query_sync_methods = proc_macro2::TokenStream::new();
    let mut query_async_methods = proc_macro2::TokenStream::new();

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
        let is_as_id = has_attribute(field, "as_id");

        let post_patch_field_ident = if is_as_id {
            format_ident!("{}_id", field_name)
        } else {
            field_ident.clone()
        };

        if !is_post_only {
            get_param_filters.extend(quote! {
                if let Some(value) = params.#post_patch_field_ident {
                    queries.push(crate::types::QueryFilter {
                        key: stringify!(#post_patch_field_ident).to_string(),
                        value: value.to_string(),
                        operator: crate::types::FilterOperator::Equals { is_negated: false },
                    });
                }
            });

            let method_ident = format_ident!("{}_eq", post_patch_field_ident);
            query_sync_methods.extend(quote! {
                pub fn #method_ident<V: ToString>(self, value: V) -> Self {
                    self.add_filter_equals(stringify!(#post_patch_field_ident), value)
                }
            });
            query_async_methods.extend(quote! {
                pub fn #method_ident<V: ToString>(self, value: V) -> Self {
                    self.add_filter_equals(stringify!(#post_patch_field_ident), value)
                }
            });

            if !is_as_id && is_string_type(field_ty) {
                let contains_method_ident = format_ident!("{}_contains", post_patch_field_ident);
                query_sync_methods.extend(quote! {
                    pub fn #contains_method_ident<V: ToString>(self, value: V) -> Self {
                        self.add_filter(
                            stringify!(#post_patch_field_ident),
                            crate::types::FilterOperator::Contains { is_negated: false },
                            value,
                        )
                    }
                });
                query_async_methods.extend(quote! {
                    pub fn #contains_method_ident<V: ToString>(self, value: V) -> Self {
                        self.add_filter(
                            stringify!(#post_patch_field_ident),
                            crate::types::FilterOperator::Contains { is_negated: false },
                            value,
                        )
                    }
                });
            }
        }

        if is_post_only || !is_read_only {
            let create_field_ty = if is_post_only {
                quote!(#field_ty)
            } else if is_as_id {
                if is_optional {
                    quote!(Option<i32>)
                } else {
                    quote!(i32)
                }
            } else if is_optional {
                quote!(Option<#field_ty>)
            } else {
                quote!(#field_ty)
            };
            let (arg_ty, assign_expr) = fluent_arg_and_assign(&create_field_ty);
            create_sync_methods.extend(quote! {
                pub fn #post_patch_field_ident(self, value: #arg_ty) -> Self {
                    self.edit_params(move |params| {
                        params.#post_patch_field_ident = #assign_expr;
                    })
                }
            });
            create_async_methods.extend(quote! {
                pub fn #post_patch_field_ident(self, value: #arg_ty) -> Self {
                    self.edit_params(move |params| {
                        params.#post_patch_field_ident = #assign_expr;
                    })
                }
            });
        }

        if !is_post_only && !is_read_only {
            let patch_field_ty = if is_as_id {
                if is_optional {
                    quote!(Option<i32>)
                } else {
                    quote!(i32)
                }
            } else {
                quote!(Option<#field_ty>)
            };
            let (arg_ty, assign_expr) = fluent_arg_and_assign(&patch_field_ty);
            update_sync_methods.extend(quote! {
                pub fn #post_patch_field_ident(self, value: #arg_ty) -> Self {
                    self.edit_params(move |params| {
                        params.#post_patch_field_ident = #assign_expr;
                    })
                }
            });
            update_async_methods.extend(quote! {
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
        .find(|&field| fields.iter().any(|f| f.ident.as_ref() == Some(&field)))
        .unwrap();

    // Generate the Display implementation
    let display_impl = quote! {
        impl std::fmt::Display for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{}", self.#display_field)
            }
        }
    };

    let expanded = quote! {
        #[derive(Default, Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, tabled::Tabled)]
        pub struct #name {
            #main_fields
        }

        impl crate::client::GetID for #name {
            fn id(&self) -> i32 {
                self.id
            }
        }

        #[derive(Default, Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq)]
        pub struct #get_name {
            #get_fields
        }

        #[derive(Default, Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq)]
        pub struct #post_name {
            #post_fields
        }

        #[derive(Default, Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq)]
        pub struct #patch_name {
            #patch_fields
        }

        #display_impl

        impl crate::resources::ApiResource for #name {
            type GetParams = #get_name;
            type GetOutput = #name;
            type PostParams = #post_name;
            type PostOutput = #name;
            type PatchParams = #patch_name;
            type PatchOutput = #name;
            type DeleteParams = ();
            type DeleteOutput = ();

            const NAME_FIELD: &'static str = stringify!(#name_field);

            fn endpoint(&self) -> crate::endpoints::Endpoint {
                crate::endpoints::Endpoint::#endpoint
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

        impl crate::client::sync::CreateOp<#name> {
            #create_sync_methods
        }

        impl crate::client::r#async::CreateOp<#name> {
            #create_async_methods
        }

        impl crate::client::sync::UpdateOp<#name> {
            #update_sync_methods
        }

        impl crate::client::r#async::UpdateOp<#name> {
            #update_async_methods
        }

        impl crate::client::sync::QueryOp<#name> {
            #query_sync_methods
        }

        impl crate::client::r#async::QueryOp<#name> {
            #query_async_methods
        }
    };

    TokenStream::from(expanded)
}

fn has_attribute(field: &syn::Field, attr_name: &str) -> bool {
    field.attrs.iter().any(|attr| {
        if attr.path().is_ident("api") {
            if let Meta::List(list) = &attr.meta {
                if let Ok(nested) =
                    list.parse_args_with(Punctuated::<Meta, syn::Token![,]>::parse_terminated)
                {
                    return nested
                        .iter()
                        .any(|meta| matches!(meta, Meta::Path(path) if path.is_ident(attr_name)));
                }
            }
        }
        false
    })
}

fn get_rename_value(field: &syn::Field) -> Option<String> {
    field.attrs.iter().find_map(|attr| {
        if attr.path().is_ident("api") {
            if let Meta::List(list) = &attr.meta {
                if let Ok(nested) =
                    list.parse_args_with(Punctuated::<Meta, syn::Token![,]>::parse_terminated)
                {
                    return nested.iter().find_map(|meta| {
                        if let Meta::NameValue(name_value) = meta {
                            if name_value.path.is_ident("table_rename") {
                                if let syn::Expr::Lit(expr_lit) = &name_value.value {
                                    if let syn::Lit::Str(lit) = &expr_lit.lit {
                                        return Some(lit.value());
                                    }
                                }
                            }
                        }
                        None
                    });
                }
            }
        }
        None
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

fn fluent_arg_and_assign(
    field_ty: &proc_macro2::TokenStream,
) -> (proc_macro2::TokenStream, proc_macro2::TokenStream) {
    let parsed_ty: Type = syn::parse2(field_ty.clone()).expect("generated field type should parse");

    if let Some(inner) = option_inner_type(&parsed_ty) {
        if is_string_type(inner) {
            (quote!(impl Into<String>), quote!(Some(value.into())))
        } else {
            (quote!(#inner), quote!(Some(value)))
        }
    } else if is_string_type(&parsed_ty) {
        (quote!(impl Into<String>), quote!(value.into()))
    } else {
        (quote!(#parsed_ty), quote!(value))
    }
}

fn process_fields(
    fields: &Punctuated<syn::Field, syn::Token![,]>,
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
        let is_as_id = has_attribute(field, "as_id");

        let rename = get_rename_value(field).unwrap_or_else(|| fieldname.clone());

        let id_field_name = if is_as_id {
            format!("{}_id", fieldname)
        } else {
            fieldname.clone()
        };
        let id_field_ident = syn::Ident::new(&id_field_name, proc_macro2::Span::call_site());

        if !is_post_only {
            let tabled_attr = if is_optional {
                quote!(
                    #[tabled(display = "crate::resources::tabled_display_option", rename = #rename)]
                    pub #name: Option<#ty>,
                )
            } else {
                quote!(
                    #[tabled(display = "crate::resources::tabled_display", rename = #rename)]
                    pub #name: #ty,
                )
            };

            main_fields.extend(quote! {
                #tabled_attr
            });

            let get_type = if is_as_id {
                quote!(Option<i32>)
            } else {
                quote!(Option<#ty>)
            };
            get_fields.extend(quote! { pub #id_field_ident: #get_type, });
        }

        if is_post_only {
            post_fields.extend(quote! { pub #id_field_ident: #ty, });
        } else if !is_read_only {
            if is_as_id {
                let id_type = if is_optional {
                    quote!(Option<i32>)
                } else {
                    quote!(i32)
                };
                patch_fields.extend(quote! { pub #id_field_ident: #id_type, });
                post_fields.extend(quote! { pub #id_field_ident: #id_type, });
            } else {
                patch_fields.extend(quote! { pub #id_field_ident: Option<#ty>, });
                let post_type = if is_optional {
                    quote!(Option<#ty>)
                } else {
                    quote!(#ty)
                };
                post_fields.extend(quote! { pub #id_field_ident: #post_type, });
            }
        }
    }

    (main_fields, get_fields, post_fields, patch_fields)
}
