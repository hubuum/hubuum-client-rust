use hubuum_client::{
    Authenticated, ClassId, EventSinkId, PrincipalId, RemoteTargetId, TaskId, blocking,
};

fn borrowed_id_contract(client: &blocking::Client<Authenticated>) {
    let class_id = ClassId::new(7);
    let principal_id = PrincipalId::new(8);
    let task_id = TaskId::new(9);
    let remote_target_id = RemoteTargetId::new(10);
    let event_sink_id = EventSinkId::new(11);

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
