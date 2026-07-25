use serde::{Deserialize, Serialize};

use super::{PrincipalId, TaskId};

/// A durable principal identity resolved for provenance responses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenancePrincipal {
    pub principal_id: PrincipalId,
    #[serde(default)]
    pub name: Option<String>,
}

/// The immediate actor that performed a mutation.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenanceActor {
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub principal: Option<ProvenancePrincipal>,
}

/// Shared root-task provenance returned by audit, history, and task APIs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Provenance {
    pub actor: ProvenanceActor,
    #[serde(default)]
    pub initiator: Option<ProvenancePrincipal>,
    #[serde(default)]
    pub task_id: Option<TaskId>,
}
