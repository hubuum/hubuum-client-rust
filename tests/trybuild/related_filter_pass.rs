use hubuum_client::{
    ApiError, Authenticated, BaseUrl, Client, RelatedObjectFilter, StructuredClassSelector,
    Token, blocking,
};

fn filters(
    blocking: &blocking::Client<Authenticated>,
    asynchronous: &Client<Authenticated>,
) -> Result<(), ApiError> {
    let group = RelatedObjectFilter::new("room", StructuredClassSelector::Id { id: 7.into() })?
        .max_depth(2)?.name().ieq("Room A").id().eq(19.into());
    let _ = blocking.objects(1).related(group.clone())?.query().related(
        RelatedObjectFilter::new("owner", StructuredClassSelector::Name { name: "Person".into() })?,
    )?;
    let _ = asynchronous.objects(1).related(group.clone())?.query();
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
