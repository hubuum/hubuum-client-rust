use hubuum_client::{ClassId, ObjectId};
use hubuum_client::{
    ApiError, Authenticated, BaseUrl, Client, RelatedObjectFilter, StructuredClassSelector,
    Token, blocking,
};

fn filters(
    blocking: &blocking::Client<Authenticated>,
    asynchronous: &Client<Authenticated>,
) -> Result<(), ApiError> {
    let group = RelatedObjectFilter::new("room", StructuredClassSelector::Id { id: ClassId::new(7).unwrap() })?
        .max_depth(2)?.name().ieq("Room A").id().eq(ObjectId::new(19).unwrap());
    let _ = blocking.objects(ClassId::new(1).unwrap()).related(group.clone())?.query().related(
        RelatedObjectFilter::new("owner", StructuredClassSelector::Name { name: "Person".into() })?,
    )?;
    let _ = asynchronous.objects(ClassId::new(1).unwrap()).related(group.clone())?.query();
    let _ = blocking.class_by_name("Hosts").objects().query().related(group.clone())?;
    let _ = asynchronous.class_by_name("Hosts").objects().query().related(group)?;
    Ok(())
}

fn main() {
    let url = BaseUrl::new("https://example.invalid").unwrap();
    let blocking = blocking::Client::try_new(url.clone()).unwrap().authenticate(Token::new("token"));
    let asynchronous = Client::try_new(url).unwrap().authenticate(Token::new("token"));
    filters(&blocking, &asynchronous).unwrap();
}
