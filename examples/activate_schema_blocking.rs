//! Blocking version of activate_schema; running it changes the class policy.
//! See docs/schema-evolution.md for environment variables and run commands.

use std::{env, error::Error, time::Duration};

use hubuum_client::{
    ClassId, SchemaActivationPolicy, SchemaActivationRequest, SchemaImpactReadiness,
    SchemaWorkStatus, TaskId, Token, blocking::Client,
};

fn main() -> Result<(), Box<dyn Error>> {
    let class_id: ClassId = env::var("HUBUUM_CLASS_ID")?.parse()?;
    let task_id: TaskId = env::var("HUBUUM_PROFILE_TASK_ID")?.parse()?;
    let client = Client::from_url(&env::var("HUBUUM_URL")?)?
        .login_with_token(Token::new(env::var("HUBUUM_TOKEN")?))?;

    let schema = client.class_schema(class_id);
    // Fetch the retained report that was reviewed after running discover_fields_blocking.
    let report = schema.profile_report(task_id)?;
    let active = schema.get()?.active;
    let staged = schema.stage(report.stage_request(true)?)?;
    println!("Staged schema revision: {}", staged.revision);

    let analysis = schema.impact(staged.revision)?;
    println!("Impact task: {}", analysis.task_id);
    client
        .tasks()
        .wait(analysis.task_id)
        .timeout(Some(Duration::from_secs(120)))
        .send()?;
    let impact = schema.work(analysis.task_id)?;
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
    let activated = schema.activate(
        staged.revision,
        SchemaActivationRequest {
            expected_active_revision: active.revision,
            policy: SchemaActivationPolicy::RejectIncompatible,
            impact_task_id: Some(analysis.task_id),
        },
    )?;
    println!(
        "Activation result:\n{}",
        serde_json::to_string_pretty(&activated)?
    );
    Ok(())
}
