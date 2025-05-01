use crate::decision::AuthorizationDecision;

/// An authorization check.
///
/// # Type parameters
/// - `Actor`: Type for who would perform the action (e.g. `User`).
/// - `Action`: Type for what would be performed (e.g. `DeletePost`).
/// - `Resource`: Type for the target of the action (e.g. `Post`).
/// - `AllowReason`: (Optional) Type of the allowed reason returned on an `Allowed` decision. Defaults to `()`.
/// - `ForbiddenReason`: (Optional) Type of forbidden reason returned on a `Forbidden` decision. Defaults to `()`.
pub trait Authorizer<Actor, Action, Resource, AllowReason = (), ForbiddenReason = ()> {
    /// Perform the authorization check.
    ///
    /// - `actor`:   Reference to who would perform the action on the resource
    /// - `action`:  Reference to what would be performed by the actor on the resource
    /// - `resource`: Reference to the target of the action performed by the actor
    ///
    /// Returns an [`AuthorizationDecision`] that will be either allowed or forbidden and carrying
    /// optional reason data.
    fn check(
        actor: &Actor,
        action: &Action,
        resource: &Resource,
    ) -> AuthorizationDecision<AllowReason, ForbiddenReason>;
}

/// An authorization check with extra context.
///
/// # Type parameters
/// - `Actor`:       Type for who would perform the action (e.g. `User`).
/// - `Action`:      Type for what would be performed (e.g. `DeletePost`).
/// - `Resource`:    Type for the target of the action (e.g. `Post`).
/// - `Context`:     Type for any additional data needed to make the decision
/// - `AllowReason`: (Optional) Type of the allowed reason returned on an `Allowed` decision. Defaults to `()`.
/// - `ForbiddenReason`: (Optional) Type of forbidden reason returned on a `Forbidden` decision. Defaults to `()`.
pub trait AuthorizerWithContext<
    Actor,
    Action,
    Resource,
    Context,
    AllowReason = (),
    ForbiddenReason = (),
>
{
    /// Perform the authorization check given extra context.
    ///
    /// - `actor`:    Reference to who would perform the action on the resource
    /// - `action`:   Reference to what would be performed by the actor
    /// - `resource`: Reference to the target of the action
    /// - `context`:  Reference to the extra data needed for this check
    ///
    /// Returns an [`AuthorizationDecision`] that will be either allowed or forbidden and carrying
    /// optional reason data.
    fn check(
        actor: &Actor,
        action: &Action,
        resource: &Resource,
        context: &Context,
    ) -> AuthorizationDecision<AllowReason, ForbiddenReason>;
}
