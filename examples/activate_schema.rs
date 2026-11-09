//! Stage a reviewed suggestion, inspect whole-class impact, and activate it.
//! Running this example changes the class policy; see docs/schema-evolution.md.

use std::{env, error::Error, time::Duration};

use hubuum_client::{
    ClassId, Client, SchemaActivationPolicy, SchemaActivationRequest, SchemaImpactReadiness,
    SchemaWorkStatus, TaskId, Token,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let class_id: ClassId = env::var("HUBUUM_CLASS_ID")?.parse()?;
    let task_id: TaskId = env::var("HUBUUM_PROFILE_TASK_ID")?.parse()?;
    let client = Client::from_url(&env::var("HUBUUM_URL")?)?
        .login_with_token(Token::new(env::var("HUBUUM_TOKEN")?))
        .await?;

    let schema = client.class_schema(class_id);
    // Fetch the retained report that was reviewed after running discover_fields.
    let report = schema.profile_report(task_id).await?;
    let active = schema.get().await?.active;
    let staged = schema.stage(report.stage_request(true)?).await?;
    println!("Staged schema revision: {}", staged.revision);

    let analysis = schema.impact(staged.revision).await?;
    println!("Impact task: {}", analysis.task_id);
    client
        .tasks()
        .wait(analysis.task_id)
        .timeout(Some(Duration::from_secs(120)))
        .send()
        .await?;
    let impact = schema.work(analysis.task_id).await?;
    println!(
        "Whole-class impact:\n{}",
        serde_json::to_string_pretty(&impact)?
    );
    if impact.status != SchemaWorkStatus::Complete
        || impact.readiness != Some(SchemaImpactReadiness::Compatible)
    {
        return Err("impact is not complete and compatible; the revision remains staged".into());
    }

    // The server rechecks the active revision and population at activation time.
    // A conflict requires fresh review and impact analysis, not a blind retry.
    let activated = schema
        .activate(
            staged.revision,
            SchemaActivationRequest {
                expected_active_revision: active.revision,
                policy: SchemaActivationPolicy::RejectIncompatible,
                impact_task_id: Some(analysis.task_id),
            },
        )
        .await?;
    println!(
        "Activation result:\n{}",
        serde_json::to_string_pretty(&activated)?
    );
    Ok(())
}
