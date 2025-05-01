use traitgate::prelude::*;

#[derive(Debug)]
enum Env {
    Dev,
    Prod,
}

#[derive(Debug)]
struct AppCtx {
    env: Env,
    tenant_id: u32,
}

#[allow(dead_code)]
struct User {
    id: u32,
}

struct FeatureA;
struct FeatureB;

struct AResource;
struct BResource;

struct AAuth;
impl AuthorizerWithContext<User, FeatureA, AResource, AppCtx> for AAuth {
    fn check_with_context(
        _u: &User,
        _a: &FeatureA,
        _r: &AResource,
        ctx: &AppCtx,
    ) -> AuthorizationDecision {
        match ctx.env {
            Env::Dev => AuthorizationDecision::allowed(),
            Env::Prod => AuthorizationDecision::forbidden(),
        }
    }
}

struct BAuth;
impl AuthorizerWithContext<User, FeatureB, BResource, AppCtx> for BAuth {
    fn check_with_context(
        _u: &User,
        _a: &FeatureB,
        _r: &BResource,
        ctx: &AppCtx,
    ) -> AuthorizationDecision {
        if ctx.tenant_id == 1 {
            AuthorizationDecision::allowed()
        } else {
            AuthorizationDecision::forbidden()
        }
    }
}

fn main() {
    let ctx_dev = AppCtx {
        env: Env::Dev,
        tenant_id: 2,
    };
    let ctx_prod = AppCtx {
        env: Env::Prod,
        tenant_id: 1,
    };

    let user = User { id: 7 };

    assert!(AAuth::check_with_context(&user, &FeatureA, &AResource, &ctx_dev).is_allowed());
    assert!(AAuth::check_with_context(&user, &FeatureA, &AResource, &ctx_prod).is_forbidden());

    assert!(BAuth::check_with_context(&user, &FeatureB, &BResource, &ctx_prod).is_allowed());
    assert!(BAuth::check_with_context(&user, &FeatureB, &BResource, &ctx_dev).is_forbidden());
}
