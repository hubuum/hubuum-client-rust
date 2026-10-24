use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{GenericArgument, Meta, PathArguments, Type, punctuated::Punctuated};

#[derive(Clone, Debug, Default)]
pub(super) struct FieldOptions {
    pub(super) read_only: bool,
    pub(super) post_only: bool,
    pub(super) optional: bool,
    pub(super) response_optional: bool,
    pub(super) post_optional: bool,
    pub(super) as_id: bool,
    pub(super) skip_patch: bool,
    pub(super) skip_query: bool,
    pub(super) default: bool,
    pub(super) default_local: bool,
    pub(super) query_key: Option<String>,
}

impl FieldOptions {
    pub(super) fn parse(field: &syn::Field) -> syn::Result<Self> {
        let mut options = Self::default();
        for attr in &field.attrs {
            if !attr.path().is_ident("api") {
                continue;
            }
            let Meta::List(list) = &attr.meta else {
                return Err(syn::Error::new_spanned(
                    attr,
                    "expected `#[api(option, ...)]`",
                ));
            };
            let nested =
                list.parse_args_with(Punctuated::<Meta, syn::Token![,]>::parse_terminated)?;
            for meta in nested {
                options.apply(&meta)?;
            }
        }
        options.validate(field)?;
        Ok(options)
    }

    fn apply(&mut self, meta: &Meta) -> syn::Result<()> {
        if let Meta::NameValue(name_value) = &meta {
            if !name_value.path.is_ident("query_key") {
                return Err(syn::Error::new_spanned(
                    &name_value.path,
                    "unknown API field option",
                ));
            }
            if self.query_key.is_some() {
                return Err(syn::Error::new_spanned(
                    &name_value.path,
                    "duplicate API field option `query_key`",
                ));
            }
            let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(value),
                ..
            }) = &name_value.value
            else {
                return Err(syn::Error::new_spanned(
                    &name_value.value,
                    "`query_key` must be a string literal",
                ));
            };
            if value.value().is_empty() {
                return Err(syn::Error::new_spanned(
                    value,
                    "`query_key` cannot be empty",
                ));
            }
            self.query_key = Some(value.value());
            return Ok(());
        }
        let Meta::Path(path) = &meta else {
            return Err(syn::Error::new_spanned(
                meta,
                "API field options must be identifiers or `query_key = \"...\"`",
            ));
        };
        let Some(option) = path.get_ident() else {
            return Err(syn::Error::new_spanned(
                path,
                "API field options must be unqualified identifiers",
            ));
        };
        let option_name = option.to_string();
        let slot = match option_name.as_str() {
            "read_only" => &mut self.read_only,
            "post_only" => &mut self.post_only,
            "optional" => &mut self.optional,
            "response_optional" => &mut self.response_optional,
            "post_optional" => &mut self.post_optional,
            "as_id" => &mut self.as_id,
            "skip_patch" => &mut self.skip_patch,
            "skip_query" => &mut self.skip_query,
            "default" => &mut self.default,
            "default_local" => &mut self.default_local,
            _ => {
                return Err(syn::Error::new_spanned(
                    option,
                    format!("unknown API field option `{option_name}`"),
                ));
            }
        };
        if *slot {
            return Err(syn::Error::new_spanned(
                option,
                format!("duplicate API field option `{option_name}`"),
            ));
        }
        *slot = true;
        Ok(())
    }

    fn validate(&self, field: &syn::Field) -> syn::Result<()> {
        if self.read_only && self.post_only {
            return Err(syn::Error::new_spanned(
                field,
                "a field cannot be both `read_only` and `post_only`",
            ));
        }
        if self.post_only && (self.optional || self.post_optional) {
            return Err(syn::Error::new_spanned(
                field,
                "a `post_only` field cannot be optional",
            ));
        }
        if self.default && self.default_local {
            return Err(syn::Error::new_spanned(
                field,
                "a field cannot use both `default` and `default_local`",
            ));
        }
        if self.skip_query && self.query_key.is_some() {
            return Err(syn::Error::new_spanned(
                field,
                "a field cannot use both `skip_query` and `query_key`",
            ));
        }
        Ok(())
    }
}

pub(super) struct ResourceField {
    pub(super) syntax: syn::Field,
    pub(super) options: FieldOptions,
    pub(super) wire_ident: syn::Ident,
    pub(super) model_type: Type,
    pub(super) query_type: Type,
    pub(super) post_type: Option<Type>,
    pub(super) patch_type: Option<Type>,
}

impl ResourceField {
    pub(super) fn resolve(field: &syn::Field, id_name: &syn::Ident) -> syn::Result<Self> {
        let options = FieldOptions::parse(field)?;
        let name = field.ident.as_ref().expect("named fields were checked");
        let ty = &field.ty;
        let wire_ident = if options.as_id {
            format_ident!("{name}_id")
        } else {
            name.clone()
        };
        let query_type = if name == "id" {
            syn::parse_quote!(#id_name)
        } else if options.as_id {
            syn::parse_quote!(<#ty as crate::resources::ApiResource>::Id)
        } else {
            option_inner_type(ty).unwrap_or(ty).clone()
        };
        let model_type = if name == "id" {
            syn::parse_quote!(#id_name)
        } else if options.optional || options.response_optional {
            syn::parse_quote!(Option<#ty>)
        } else {
            ty.clone()
        };
        let writable_type: Type = if options.as_id {
            syn::parse_quote!(<#ty as crate::resources::ApiResource>::Id)
        } else {
            ty.clone()
        };
        let post_type = if options.post_only {
            Some(ty.clone())
        } else if options.read_only {
            None
        } else if options.optional || options.post_optional {
            Some(syn::parse_quote!(Option<#writable_type>))
        } else {
            Some(writable_type.clone())
        };
        let patch_type = if options.post_only || options.read_only || options.skip_patch {
            None
        } else {
            Some(syn::parse_quote!(Option<#writable_type>))
        };
        Ok(Self {
            syntax: field.clone(),
            options,
            wire_ident,
            model_type,
            query_type,
            post_type,
            patch_type,
        })
    }

    pub(super) fn ident(&self) -> &syn::Ident {
        self.syntax.ident.as_ref().expect("named field")
    }

    pub(super) fn required(&self) -> bool {
        self.post_type
            .as_ref()
            .is_some_and(|ty| option_inner_type(ty).is_none())
    }

    pub(super) fn query_key(&self) -> TokenStream {
        match &self.options.query_key {
            Some(key) => quote!(#key),
            None => {
                let name = &self.wire_ident;
                quote!(stringify!(#name))
            }
        }
    }

    pub(super) fn default_attribute(&self) -> TokenStream {
        if self.options.default_local {
            quote!(#[serde(default = "crate::types::default_local_identity_value")])
        } else if self.options.default {
            quote!(#[serde(default)])
        } else {
            quote!()
        }
    }

    pub(super) fn setter_lint_attribute(&self) -> TokenStream {
        let name = self.ident().to_string();
        if name.starts_with("from_") || name.starts_with("to_") {
            quote!(#[allow(clippy::wrong_self_convention)])
        } else {
            quote!()
        }
    }
}

pub(super) fn option_inner_type(ty: &Type) -> Option<&Type> {
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

pub(super) fn type_name_is(ty: &Type, expected: &str) -> bool {
    let ty = option_inner_type(ty).unwrap_or(ty);
    let Type::Path(type_path) = ty else {
        return false;
    };
    type_path
        .path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == expected)
}

pub(super) fn is_string_type(ty: &Type) -> bool {
    type_name_is(ty, "String")
}

pub(super) fn is_bool_type(ty: &Type) -> bool {
    type_name_is(ty, "bool")
}

pub(super) fn is_json_value_type(ty: &Type) -> bool {
    type_name_is(ty, "Value")
}

pub(super) fn is_numeric_or_datetime_type(ty: &Type) -> bool {
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

pub(super) fn is_id_type(ty: &Type) -> bool {
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

pub(super) fn query_field_wrapper(field_ty: &Type, is_as_id: bool) -> TokenStream {
    if is_as_id || is_numeric_or_datetime_type(field_ty) || is_id_type(field_ty) {
        quote!(crate::client::QueryNumericField<Self, #field_ty>)
    } else if is_string_type(field_ty) {
        quote!(crate::client::QueryTextField<Self>)
    } else if is_bool_type(field_ty) {
        quote!(crate::client::QueryBoolField<Self>)
    } else if is_json_value_type(field_ty) {
        quote!(crate::client::QueryJsonField<Self>)
    } else {
        quote!(crate::client::QueryValueField<Self, #field_ty>)
    }
}

pub(super) fn fluent_arg_and_assign(field_ty: &TokenStream) -> (TokenStream, TokenStream) {
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
