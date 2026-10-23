use hubuum_client::ClassId;

fn main() {
    let _ = ClassId::from(0);
    let _ = ClassId::default();
    let _ = ClassId(1);
}
