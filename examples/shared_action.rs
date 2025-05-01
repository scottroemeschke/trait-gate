//! One generic `Delete` action reused for multiple resources.

use traitgate::prelude::*;

struct User {
    id: u64,
    is_admin: bool,
}

#[allow(dead_code)]
struct Post {
    id: u64,
    author: u64,
}
#[allow(dead_code)]
struct Comment {
    id: u64,
    author: u64,
}

struct Delete;

struct AuthorizerImpl;

impl Authorizer<User, Delete, Post> for AuthorizerImpl {
    fn check(u: &User, _: &Delete, p: &Post) -> AuthorizationDecision {
        if u.is_admin || u.id == p.author {
            AuthorizationDecision::allowed()
        } else {
            AuthorizationDecision::forbidden()
        }
    }
}

impl Authorizer<User, Delete, Comment> for AuthorizerImpl {
    fn check(u: &User, _: &Delete, c: &Comment) -> AuthorizationDecision {
        if u.is_admin || u.id == c.author {
            AuthorizationDecision::allowed()
        } else {
            AuthorizationDecision::forbidden()
        }
    }
}

fn main() {
    let admin = User {
        id: 0,
        is_admin: true,
    };
    let alice = User {
        id: 1,
        is_admin: false,
    };

    let post = Post { id: 10, author: 1 };
    let comment = Comment { id: 99, author: 2 };

    assert!(AuthorizerImpl::check(&admin, &Delete, &post).is_allowed());
    assert!(AuthorizerImpl::check(&alice, &Delete, &comment).is_forbidden());
}
