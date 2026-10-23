use hubuum_client::{ClassId, HistoricalEndpointContext, HistoricalRelationValue};

fn class_id(value: HistoricalRelationValue) -> Option<ClassId> {
    match value {
        HistoricalRelationValue::Object {
            to: HistoricalEndpointContext::Available { snapshot }, ..
        } => Some(snapshot.id),
        _ => None,
    }
}

fn main() {}
