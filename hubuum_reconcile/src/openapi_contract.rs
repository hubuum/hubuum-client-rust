use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use syn::{Fields, GenericArgument, Item, ItemStruct, Meta, PathArguments, Type};

use crate::DynError;

const SNAPSHOT_PATH: &str = "openapi/operations.json";
const MODEL_CONTRACT_PATH: &str = "openapi/model-contract.json";

#[derive(Debug, Deserialize)]
struct Snapshot {
    schemas: BTreeMap<String, Schema>,
    operations: Vec<Operation>,
}

#[derive(Debug, Deserialize)]
struct Schema {
    #[serde(default)]
    properties: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    required: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
struct Operation {
    method: String,
    path: String,
    #[serde(default)]
    request_schema_refs: BTreeSet<String>,
    #[serde(default)]
    response_schema_refs: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
struct ModelContract {
    version: u32,
    models: Vec<ModelMapping>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Direction {
    Request,
    Response,
}

#[derive(Debug, Deserialize)]
struct ModelMapping {
    openapi_schema: String,
    rust_file: PathBuf,
    rust_type: String,
    direction: Direction,
    #[serde(default)]
    rust_only_fields: BTreeMap<String, String>,
    #[serde(default)]
    openapi_only_fields: BTreeMap<String, String>,
    #[serde(default)]
    requiredness_exceptions: BTreeMap<String, String>,
}

#[derive(Debug)]
struct RustField {
    rust_name: String,
    wire_name: String,
    optional: bool,
    serde_default: bool,
    skip_serializing: bool,
    skip_serializing_if: bool,
    skip_deserializing: bool,
    flatten: bool,
}

impl RustField {
    fn visible_in(&self, direction: Direction) -> bool {
        match direction {
            Direction::Request => !self.skip_serializing,
            Direction::Response => !self.skip_deserializing,
        }
    }

    fn required_in(&self, direction: Direction) -> bool {
        match direction {
            Direction::Request => !self.optional && !self.skip_serializing_if,
            Direction::Response => !self.optional && !self.serde_default,
        }
    }
}

pub(crate) fn check(root: &Path) -> Result<(), DynError> {
    let snapshot: Snapshot = read_json(&root.join(SNAPSHOT_PATH))?;
    let contract: ModelContract = read_json(&root.join(MODEL_CONTRACT_PATH))?;
    if contract.version != 1 {
        return Err(format!(
            "unsupported OpenAPI model contract version {}; expected 1",
            contract.version
        )
        .into());
    }
    if contract.models.is_empty() {
        return Err("OpenAPI model contract must map at least one Rust model".into());
    }

    let mut identities = BTreeSet::new();
    for mapping in &contract.models {
        let identity = (
            mapping.openapi_schema.as_str(),
            mapping.rust_file.as_path(),
            mapping.rust_type.as_str(),
            direction_name(mapping.direction),
        );
        if !identities.insert(identity) {
            return Err(format!(
                "duplicate OpenAPI model mapping for {} -> {}::{} ({})",
                mapping.openapi_schema,
                mapping.rust_file.display(),
                mapping.rust_type,
                direction_name(mapping.direction)
            )
            .into());
        }
        check_mapping(root, &snapshot, mapping)?;
    }

    println!(
        "OpenAPI property contract covers {} Rust model mappings",
        contract.models.len()
    );
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, DynError> {
    let source = fs::read_to_string(path)?;
    serde_json::from_str(&source)
        .map_err(|error| format!("failed to parse {}: {error}", path.display()).into())
}

fn check_mapping(root: &Path, snapshot: &Snapshot, mapping: &ModelMapping) -> Result<(), DynError> {
    let schema = snapshot
        .schemas
        .get(&mapping.openapi_schema)
        .ok_or_else(|| format!("unknown OpenAPI schema `{}`", mapping.openapi_schema))?;
    if schema.properties.is_empty() {
        return Err(format!(
            "OpenAPI schema `{}` is not an object with properties",
            mapping.openapi_schema
        )
        .into());
    }

    let referenced_by = snapshot
        .operations
        .iter()
        .filter(|operation| match mapping.direction {
            Direction::Request => operation
                .request_schema_refs
                .contains(&mapping.openapi_schema),
            Direction::Response => operation
                .response_schema_refs
                .contains(&mapping.openapi_schema),
        })
        .map(|operation| format!("{} {}", operation.method, operation.path))
        .collect::<Vec<_>>();
    if referenced_by.is_empty() {
        return Err(format!(
            "OpenAPI schema `{}` is not referenced by any {} operation",
            mapping.openapi_schema,
            direction_name(mapping.direction)
        )
        .into());
    }

    check_exception_reasons(mapping)?;

    let rust_path = root.join(&mapping.rust_file);
    let item = find_struct(&rust_path, &mapping.rust_type)?;
    let rust_fields = parse_fields(item)?;
    let visible_fields = rust_fields
        .iter()
        .filter(|field| field.visible_in(mapping.direction))
        .collect::<Vec<_>>();
    if visible_fields.iter().any(|field| field.flatten) {
        return Err(format!(
            "{}::{} uses #[serde(flatten)]; map the flattened wire model explicitly",
            mapping.rust_file.display(),
            mapping.rust_type
        )
        .into());
    }

    let by_wire = visible_fields
        .iter()
        .map(|field| (field.wire_name.as_str(), *field))
        .collect::<BTreeMap<_, _>>();
    if by_wire.len() != visible_fields.len() {
        return Err(format!(
            "{}::{} contains duplicate serialized field names",
            mapping.rust_file.display(),
            mapping.rust_type
        )
        .into());
    }

    let openapi_fields = schema.properties.keys().cloned().collect::<BTreeSet<_>>();
    let rust_wire_fields = by_wire
        .keys()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    let documented_rust_only = mapping
        .rust_only_fields
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let documented_openapi_only = mapping
        .openapi_only_fields
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();

    let unexpected_rust = rust_wire_fields
        .difference(&openapi_fields)
        .cloned()
        .collect::<BTreeSet<_>>();
    if unexpected_rust != documented_rust_only {
        return Err(format!(
            "{} -> {} Rust-only fields differ: actual {:?}, documented {:?}",
            mapping.openapi_schema, mapping.rust_type, unexpected_rust, documented_rust_only
        )
        .into());
    }
    let missing_rust = openapi_fields
        .difference(&rust_wire_fields)
        .cloned()
        .collect::<BTreeSet<_>>();
    if missing_rust != documented_openapi_only {
        return Err(format!(
            "{} -> {} OpenAPI-only fields differ: actual {:?}, documented {:?}",
            mapping.openapi_schema, mapping.rust_type, missing_rust, documented_openapi_only
        )
        .into());
    }

    for name in openapi_fields.intersection(&rust_wire_fields) {
        let field = by_wire[name.as_str()];
        let openapi_required = schema.required.contains(name);
        let rust_required = field.required_in(mapping.direction);
        let has_exception = mapping.requiredness_exceptions.contains_key(name);
        if openapi_required == rust_required && has_exception {
            return Err(format!(
                "stale requiredness exception for {}.{name}",
                mapping.openapi_schema
            )
            .into());
        }
        if openapi_required != rust_required && !has_exception {
            return Err(format!(
                "requiredness mismatch for {}.{name} -> {}::{} field `{}`: OpenAPI required={}, Rust required={}",
                mapping.openapi_schema,
                mapping.rust_file.display(),
                mapping.rust_type,
                field.rust_name,
                openapi_required,
                rust_required
            )
            .into());
        }
    }

    for name in mapping.requiredness_exceptions.keys() {
        if !openapi_fields.contains(name) || !rust_wire_fields.contains(name) {
            return Err(format!(
                "requiredness exception {}.{name} does not name a shared property",
                mapping.openapi_schema
            )
            .into());
        }
    }

    Ok(())
}

fn check_exception_reasons(mapping: &ModelMapping) -> Result<(), DynError> {
    for (kind, exceptions) in [
        ("Rust-only", &mapping.rust_only_fields),
        ("OpenAPI-only", &mapping.openapi_only_fields),
        ("requiredness", &mapping.requiredness_exceptions),
    ] {
        for (field, reason) in exceptions {
            if reason.trim().is_empty() {
                return Err(format!(
                    "{kind} exception {}.{field} must include a rationale",
                    mapping.openapi_schema
                )
                .into());
            }
        }
    }
    Ok(())
}

fn find_struct(path: &Path, name: &str) -> Result<ItemStruct, DynError> {
    let source = fs::read_to_string(path)?;
    let file = syn::parse_file(&source)
        .map_err(|error| format!("failed to parse {}: {error}", path.display()))?;
    file.items
        .into_iter()
        .find_map(|item| match item {
            Item::Struct(item) if item.ident == name => Some(item),
            _ => None,
        })
        .ok_or_else(|| format!("{} does not define struct `{name}`", path.display()).into())
}

fn parse_fields(item: ItemStruct) -> Result<Vec<RustField>, DynError> {
    let Fields::Named(fields) = item.fields else {
        return Err(format!("struct `{}` must use named fields", item.ident).into());
    };
    fields
        .named
        .into_iter()
        .map(|field| {
            let rust_name = field
                .ident
                .as_ref()
                .ok_or("named field is missing an identifier")?
                .to_string();
            let mut parsed = RustField {
                wire_name: rust_name.clone(),
                rust_name,
                optional: option_inner_type(&field.ty).is_some(),
                serde_default: false,
                skip_serializing: false,
                skip_serializing_if: false,
                skip_deserializing: false,
                flatten: false,
            };
            for attr in field.attrs {
                if !attr.path().is_ident("serde") {
                    continue;
                }
                let Meta::List(list) = attr.meta else {
                    continue;
                };
                list.parse_nested_meta(|meta| {
                    if meta.path.is_ident("rename") {
                        parsed.wire_name = meta.value()?.parse::<syn::LitStr>()?.value();
                    } else if meta.path.is_ident("default") {
                        parsed.serde_default = true;
                        if !meta.input.is_empty() {
                            let _ = meta.value()?.parse::<syn::Expr>()?;
                        }
                    } else if meta.path.is_ident("skip") {
                        parsed.skip_serializing = true;
                        parsed.skip_deserializing = true;
                    } else if meta.path.is_ident("skip_serializing") {
                        parsed.skip_serializing = true;
                    } else if meta.path.is_ident("skip_deserializing") {
                        parsed.skip_deserializing = true;
                    } else if meta.path.is_ident("skip_serializing_if") {
                        parsed.skip_serializing_if = true;
                        let _ = meta.value()?.parse::<syn::Expr>()?;
                    } else if meta.path.is_ident("flatten") {
                        parsed.flatten = true;
                    }
                    Ok(())
                })?;
            }
            Ok(parsed)
        })
        .collect()
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

const fn direction_name(direction: Direction) -> &'static str {
    match direction {
        Direction::Request => "request",
        Direction::Response => "response",
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, path::Path};

    use super::{Direction, ModelContract, Snapshot, parse_fields, read_json};

    #[test]
    fn parses_wire_names_optionality_and_directional_skips() {
        let item = syn::parse_quote! {
            struct Example {
                #[serde(rename = "ref")]
                ref_: Option<String>,
                #[serde(default)]
                count: usize,
                #[serde(skip_serializing)]
                response_only: String,
            }
        };
        let fields = parse_fields(item).unwrap();

        assert_eq!(fields[0].wire_name, "ref");
        assert!(!fields[0].required_in(Direction::Request));
        assert!(!fields[1].required_in(Direction::Response));
        assert!(!fields[2].visible_in(Direction::Request));
        assert!(fields[2].visible_in(Direction::Response));
    }

    #[test]
    fn historical_v008_omissions_remain_mapped() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("reconcile crate should live below the repository root");
        let snapshot: Snapshot = read_json(&root.join("openapi/operations.json")).unwrap();
        let contract: ModelContract = read_json(&root.join("openapi/model-contract.json")).unwrap();

        let mappings = contract
            .models
            .iter()
            .map(|mapping| (mapping.openapi_schema.as_str(), mapping.rust_type.as_str()))
            .collect::<BTreeSet<_>>();
        assert!(mappings.contains(&("NewHubuumClassRelation", "ClassRelationPost")));
        assert!(mappings.contains(&("RestoreTimestamps", "RestoreTimestamps")));
        assert!(mappings.contains(&("ExportTaskDetails", "ExportTaskDetails")));

        let class_relation = &snapshot.schemas["NewHubuumClassRelation"].properties;
        assert!(class_relation.contains_key("from_max_relations"));
        assert!(class_relation.contains_key("to_max_relations"));

        let timestamps = &snapshot.schemas["RestoreTimestamps"].properties;
        assert_eq!(
            timestamps
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["created_at", "updated_at"])
        );

        let export = &snapshot.schemas["ExportTaskDetails"].properties;
        for timing in [
            "total_duration_ms",
            "query_duration_ms",
            "hydration_duration_ms",
            "render_duration_ms",
        ] {
            assert!(export.contains_key(timing));
        }
    }
}
