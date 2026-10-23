use hubuum_client::{ClassId, HistoricalEndpointContext, HistoricalRelationValue};

fn class_id(value: HistoricalRelationValue) -> ClassId {
    match value {
        HistoricalRelationValue::Object {
            to: HistoricalEndpointContext::Available { snapshot }, ..
        } => snapshot.id,
        _ => unreachable!(),
    }
}

fn main() {}
