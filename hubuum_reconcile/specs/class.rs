pub struct ClassResource {
    #[api(read_only)]
    pub id: i32,
    pub name: String,
    pub description: String,
    #[api(as_id)]
    pub collection: Collection,
    #[api(optional)]
    pub json_schema: serde_json::Value,
    #[api(optional)]
    pub validate_schema: bool,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
}

pub struct ClassRelationResource {
    #[api(read_only)]
    pub id: i32,
    pub from_hubuum_class_id: ClassId,
    pub to_hubuum_class_id: ClassId,
    #[api(optional)]
    pub forward_template_alias: String,
    #[api(optional)]
    pub reverse_template_alias: String,
    #[api(read_only)]
    pub created_at: HubuumDateTime,
    #[api(read_only)]
    pub updated_at: HubuumDateTime,
}
