use traitgate::prelude::*;

#[derive(Debug)]
struct User {
    id: u32,
    is_admin: bool,
}

#[derive(Debug)]
struct Document {
    owner_id: u32,
}

struct View;

struct DocumentAuthorizer;

impl Authorizer<User, View, Document> for DocumentAuthorizer {
    fn check(user: &User, _action: &View, doc: &Document) -> AuthorizationDecision<(), ()> {
        if user.is_admin || user.id == doc.owner_id {
            AuthorizationDecision::allowed()
        } else {
            AuthorizationDecision::forbidden()
        }
    }
}

fn main() {
    let alice = User {
        id: 1,
        is_admin: false,
    };
    let bob = User {
        id: 2,
        is_admin: false,
    };
    let admin = User {
        id: 0,
        is_admin: true,
    };

    let doc = Document { owner_id: 1 };

    let alice_dec = DocumentAuthorizer::check(&alice, &View, &doc);
    assert!(alice_dec.is_allowed());
    println!("Alice view: {:?}", alice_dec);

    let bob_dec = DocumentAuthorizer::check(&bob, &View, &doc);
    assert!(bob_dec.is_forbidden());
    println!("Bob view: {:?}", bob_dec);

    let admin_dec = DocumentAuthorizer::check(&admin, &View, &doc);
    assert!(admin_dec.is_allowed());
    println!("Admin view: {:?}", admin_dec);
}
