use hubuum_client::{
    Authenticated, ClassId, EventSinkId, PrincipalId, RemoteTargetId, TaskId, blocking,
};

fn borrowed_id_contract(client: &blocking::Client<Authenticated>) {
    let class_id = ClassId::new(7).unwrap();
    let principal_id = PrincipalId::new(8).unwrap();
    let task_id = TaskId::new(9).unwrap();
    let remote_target_id = RemoteTargetId::new(10).unwrap();
    let event_sink_id = EventSinkId::new(11).unwrap();

    let _ = client.objects(&class_id);
    let _ = client.classes().get(&class_id);
    let _ = client.principal_settings(&principal_id);
    let _ = client.tasks().get(&task_id);
    let _ = client.remote_targets().get(&remote_target_id);
    let _ = client.event_sinks().get(&event_sink_id);

    let _: i32 = remote_target_id.into();
    let _: i32 = event_sink_id.into();
}

fn main() {}
