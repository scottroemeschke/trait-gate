use traitgate::prelude::*;

struct User {
    is_admin: bool,
}
struct Resource;
struct View;

struct MyAuth;
impl Authorizer<User, View, Resource> for MyAuth {
    fn check(u: &User, _: &View, _: &Resource) -> AuthorizationDecision {
        if u.is_admin {
            AuthorizationDecision::allowed()
        } else {
            AuthorizationDecision::forbidden()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_allowed() {
        let dec = MyAuth::check(&User { is_admin: true }, &View, &Resource);
        assert!(dec.is_allowed());
    }

    #[test]
    fn non_admin_forbidden() {
        let dec = MyAuth::check(&User { is_admin: false }, &View, &Resource);
        assert!(dec.is_forbidden());
    }
}

fn main() {
    MyAuth::check(&User { is_admin: true }, &View, &Resource);
}
