//! Blocking version of discover_fields; see docs/schema-evolution.md.

use std::{env, error::Error, time::Duration};

use hubuum_client::{
    ClassId, FieldDiscoveryOptions, FieldSampleLimit, SchemaProfilePreset, SchemaProfileRequest,
    Token, blocking::Client,
};

fn main() -> Result<(), Box<dyn Error>> {
    let class_id: ClassId = env::var("HUBUUM_CLASS_ID")?.parse()?;
    let client = Client::from_url(&env::var("HUBUUM_URL")?)?
        .login_with_token(Token::new(env::var("HUBUUM_TOKEN")?))?;

    let sample_limit = FieldSampleLimit::new(100)?;
    let options = FieldDiscoveryOptions::default()
        .with_sample_limit(sample_limit)
        .with_depth(6)?
        .with_containers(true);
    let fields = client.class_fields(class_id, &options)?;
    // JSON preserves structured paths and previews that Debug intentionally redacts.
    println!(
        "Field inventory:\n{}",
        serde_json::to_string_pretty(&fields)?
    );

    let schema = client.class_schema(class_id);
    let task = schema
        .profile(SchemaProfileRequest::new(
            SchemaProfilePreset::Balanced,
            sample_limit,
        ))
        .send()?;
    // Retain this ID before waiting so a polling timeout can be resumed.
    println!("HUBUUM_PROFILE_TASK_ID={}", task.id);
    client
        .tasks()
        .wait(task.id)
        .timeout(Some(Duration::from_secs(120)))
        .send()?;
    let report = schema.profile_report(task.id)?;
    println!(
        "Schema suggestion:\n{}",
        serde_json::to_string_pretty(&report)?
    );
    // Review the schema, findings, sample_valid, and truncation before activation.
    Ok(())
}
