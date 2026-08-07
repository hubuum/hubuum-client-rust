pub struct ClassResource {
    #[api(read_only)]
    pub id: i32,
    pub name: String,
    pub description: String,
    #[api(as_id, response_optional, skip_query)]
    pub collection: Collection,
    #[api(read_only, response_optional)]
    pub collection_id: CollectionId,
    #[api(optional)]
    pub json_schema: serde_json::Value,
    #[api(optional)]
    pub validate_schema: bool,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
    #[api(read_only)]
    pub revision: ResourceRevision,
}

pub struct ClassRelationResource {
    #[api(read_only)]
    pub id: i32,
    #[api(query_key = "from_classes")]
    pub from_hubuum_class_id: ClassId,
    #[api(query_key = "to_classes")]
    pub to_hubuum_class_id: ClassId,
    #[api(optional, skip_query)]
    pub forward_template_alias: String,
    #[api(optional, skip_query)]
    pub reverse_template_alias: String,
    #[api(optional, skip_patch, skip_query)]
    pub from_max_relations: ObjectRelationLimit,
    #[api(optional, skip_patch, skip_query)]
    pub to_max_relations: ObjectRelationLimit,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
    #[api(read_only)]
    pub revision: ResourceRevision,
}
