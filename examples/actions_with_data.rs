use traitgate::prelude::*;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Plan {
    Free,
    Pro,
}

#[allow(dead_code)]
#[derive(Debug)]
struct User {
    id: u64,
    plan: Plan,
}

#[derive(Debug)]
struct UsageContext {
    used_mb: u32,
}

#[derive(Debug)]
struct Upload {
    size_mb: u32,
}

#[derive(Debug, PartialEq, Eq)]
enum UploadForbiddenReason {
    FileTooLarge { requested: u32, max_allowed: u32 },
    MonthlyQuotaExceeded { used: u32, limit: u32 },
}

struct App;

struct UploadAuthorizer;

impl
    AuthorizerWithContext<
        User,
        Upload,
        App,
        UsageContext,
        (), // no need for allow‐reason data
        UploadForbiddenReason,
    > for UploadAuthorizer
{
    fn check_with_context(
        user: &User,
        action: &Upload,
        _app: &App,
        ctx: &UsageContext,
    ) -> AuthorizationDecision<(), UploadForbiddenReason> {
        // Determine per‐file max by plan
        let max_file = match user.plan {
            Plan::Free => 10,
            Plan::Pro => 500,
        };
        if action.size_mb > max_file {
            return AuthorizationDecision::forbidden_with(UploadForbiddenReason::FileTooLarge {
                requested: action.size_mb,
                max_allowed: max_file,
            });
        }

        // Determine monthly quota by plan
        let monthly_limit = match user.plan {
            Plan::Free => 500,
            Plan::Pro => 5_000,
        };
        if ctx.used_mb + action.size_mb > monthly_limit {
            return AuthorizationDecision::forbidden_with(
                UploadForbiddenReason::MonthlyQuotaExceeded {
                    used: ctx.used_mb,
                    limit: monthly_limit,
                },
            );
        }

        AuthorizationDecision::allowed()
    }
}

fn main() {
    let user = User {
        id: 1,
        plan: Plan::Free,
    };
    let pro_user = User {
        id: 2,
        plan: Plan::Pro,
    };

    let ctx_almost_full = UsageContext { used_mb: 495 };
    let ctx_empty = UsageContext { used_mb: 0 };

    let small_upload = Upload { size_mb: 5 };
    let big_upload = Upload { size_mb: 50 };
    let huge_upload = Upload { size_mb: 200 };

    // Free user, small file within limits => allowed
    let d1 = UploadAuthorizer::check_with_context(&user, &small_upload, &App, &ctx_almost_full);
    assert!(d1.is_allowed());
    println!("Free small upload allowed");

    // Free user, file too large for plan
    let d2 = UploadAuthorizer::check_with_context(&user, &big_upload, &App, &ctx_empty);
    let d2 = d2.inspect_forbidden(|r| println!("Denied: {:?}", r));
    assert!(d2.is_forbidden());

    // Free user, uploading small file would exceed monthly quota
    let plus = Upload { size_mb: 10 };
    let d3 = UploadAuthorizer::check_with_context(&user, &plus, &App, &ctx_almost_full);
    let d3 = d3.inspect_forbidden(|r| println!("Denied: {:?}", r));
    assert!(d3.is_forbidden());

    // Pro user, large uploads are fine
    let d4 = UploadAuthorizer::check_with_context(&pro_user, &huge_upload, &App, &ctx_empty);
    assert!(d4.is_allowed());
    println!("Pro huge upload allowed");
}
