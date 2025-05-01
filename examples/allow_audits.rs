use traitgate::prelude::*;

#[derive(Debug, PartialEq)]
struct AuditInfo {
    method: &'static str,
    role: &'static str,
}

#[derive(Debug, PartialEq)]
enum UploadDenied {
    TooLarge,
}

struct User {
    role: &'static str,
}
struct Upload {
    size_mb: u32,
}
struct Server; // dummy resource

struct UploadAuthorizer;

impl Authorizer<User, Upload, Server, AuditInfo, UploadDenied> for UploadAuthorizer {
    fn check(
        user: &User,
        action: &Upload,
        _srv: &Server,
    ) -> AuthorizationDecision<AuditInfo, UploadDenied> {
        if action.size_mb > 100 {
            AuthorizationDecision::forbidden_with(UploadDenied::TooLarge)
        } else {
            AuthorizationDecision::allowed_with(AuditInfo {
                method: "standard",
                role: user.role,
            })
        }
    }
}

fn main() {
    let user = User { role: "admin" };
    let server = Server;
    let ok = Upload { size_mb: 10 };

    UploadAuthorizer::check(&user, &ok, &server)
        .inspect_allowed(|audit| println!("UPLOAD ALLOWED: {:?}", audit))
        .expect_allowed("should pass");
}
