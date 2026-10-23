use hubuum_client::ClassId;

fn main() {
    let _ = ClassId::from(0);
    let _ = ClassId::default();
    let mut id = ClassId::new(1).unwrap();
    id.0 = 0;
}
