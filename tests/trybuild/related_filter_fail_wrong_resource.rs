use hubuum_client::{ClassId};
use hubuum_client::{BaseUrl, RelatedObjectFilter, StructuredClassSelector, Token, blocking};

fn main() {
    let client = blocking::Client::try_new(BaseUrl::new("https://example.invalid").unwrap())
        .unwrap().authenticate(Token::new("token"));
    let group = RelatedObjectFilter::new("room", StructuredClassSelector::Id { id: ClassId::new(7).unwrap() }).unwrap();
    let _ = client.classes().related(group);
}
