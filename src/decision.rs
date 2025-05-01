use std::fmt::{Debug, Display, Formatter};

/// # `AuthorizationDecision`
///
/// Output type for authorizers.
///
/// It is an enum designating whether an action is permitted
/// (`Allowed`) or denied (`Forbidden`).  Both variants of the enum may carry a
/// user-defined and accessible “reason” payload for logic branching, API error messages,
/// metrics and analytics, etc.
///
/// Both reason types default to unit, and you can have both typed, just one, or neither. Often
/// forbidden reasons are used heavily, but allowed reasons are not unless there's particular
/// compliance or audit/logging required for sensitive resources.
///
/// They are simple enums with no references to the inputs of the authorizer or anything like this,
/// so feel free to store and pass them around if needed, pass them down from middleware to
/// core logic, create them for unit tests, etc.
///
/// ## Constructors
/// | Method                               | Description                                    |
/// |--------------------------------------|------------------------------------------------|
/// | `allowed()` / `forbidden()`          | Create a decision without a reason.    |
/// | `allowed_with(reason)` / `forbidden_with(reason)` | Create a decision with an attached reason. |
///
/// ## Utilities
/// Predicates: `is_allowed()`, `is_forbidden()`
/// Result conversion:
///   `into_result()` → `Result<AllowedReason, ForbiddenReason>`
///   `ok_or(err)` / `ok_or_else(f)` → convert to `Result<(), E>`
/// Assertions / unwraps: `expect_allowed(msg)`, `expect_forbidden(msg)`,
///   `unwrap_allowed()`, `unwrap_forbidden()`
/// Inspection: `inspect_allowed(|r| …)`, `inspect_forbidden(|r| …)`
///   (executes the closure for side effects, returns `self` unchanged)
///
/// ## Examples
///
/// ### 1 – Minimal check without reasons
/// ```rust
/// use traitgate::AuthorizationDecision;
///
/// let dec: AuthorizationDecision<(), ()> = AuthorizationDecision::allowed();
/// assert!(dec.is_allowed());
/// ```
///
/// ### 2 – Custom deny reason
/// ```rust
/// use traitgate::AuthorizationDecision;
///
/// #[derive(Debug, PartialEq)]
/// enum PostDeny { NotAuthor, RateLimited }
///
/// let denied = AuthorizationDecision::<(), PostDeny>::forbidden_with(PostDeny::RateLimited);
/// assert_eq!(denied.into_result(), Err(PostDeny::RateLimited));
/// ```
///
/// ### 3 – Logging an allow reason
/// ```rust
/// use traitgate::AuthorizationDecision;
///
/// let decision = AuthorizationDecision::<&str, ()>::allowed_with("scope=admin");
/// decision
///     .inspect_allowed(|r| println!("granted via {}", r))
///     .expect_allowed("expected to be allowed");
/// ```
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthorizationDecision<AllowedReason = (), ForbiddenReason = ()> {
    /// The authorization is allowed, with an optional reason.
    Allowed { reason: AllowedReason },
    /// The authorization is forbidden, with an optional reason.
    Forbidden { reason: ForbiddenReason },
}

impl<A, F> Display for AuthorizationDecision<A, F>
where
    A: Display,
    F: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorizationDecision::Allowed { reason } => write!(f, "Allowed({})", reason),
            AuthorizationDecision::Forbidden { reason } => write!(f, "Forbidden({})", reason),
        }
    }
}
impl<F> AuthorizationDecision<(), F> {
    /// Create an `Allowed` decision when you don’t need a reason.
    ///
    /// ```rust
    /// use traitgate::prelude::*;
    /// let ok = AuthorizationDecision::<(),()>::allowed();
    /// assert!(ok.is_allowed());
    /// ```
    pub fn allowed() -> Self {
        Self::Allowed { reason: () }
    }
}

impl<A> AuthorizationDecision<A, ()> {
    /// Create a `Forbidden` decision when you don’t need a reason.
    ///
    /// ```rust
    /// use traitgate::prelude::*;
    /// let no = AuthorizationDecision::<(),()>::forbidden();
    /// assert!(no.is_forbidden());
    /// ```
    pub fn forbidden() -> Self {
        Self::Forbidden { reason: () }
    }
}

impl<A, F> AuthorizationDecision<A, F> {
    /// Create `Allowed { reason }` with your custom allow-reason.
    ///
    /// ```rust
    /// use traitgate::prelude::*;
    /// struct NewPostAllowed { is_author: bool }
    /// AuthorizationDecision::<NewPostAllowed, ()>::allowed_with(NewPostAllowed { is_author: true });
    /// ```
    pub fn allowed_with(reason: A) -> Self {
        AuthorizationDecision::Allowed { reason }
    }

    /// Create `Forbidden { reason }` with your custom deny-reason.
    ///
    /// ```rust
    /// use traitgate::prelude::*;
    /// enum OrderModifyForbiddenReason {
    ///   OrderIsHaunted,
    ///   NotOwner
    /// }
    /// let dec = AuthorizationDecision::<(), OrderModifyForbiddenReason>::forbidden_with(OrderModifyForbiddenReason::NotOwner);
    /// ```
    pub fn forbidden_with(reason: F) -> Self {
        AuthorizationDecision::Forbidden { reason }
    }

    /// Return true if the decision is `Allowed`
    pub fn is_allowed(&self) -> bool {
        matches!(self, AuthorizationDecision::Allowed { .. })
    }

    /// Return true if the decision is `Forbidden`
    pub fn is_forbidden(&self) -> bool {
        matches!(self, AuthorizationDecision::Forbidden { .. })
    }

    /// Convert into `Result<(), E>`, using `err` when forbidden.
    ///
    /// ```rust
    /// use traitgate::prelude::*;
    /// let dec = AuthorizationDecision::<(),()>::allowed();
    /// let res: Result<(), &str> = dec.ok_or("access denied");
    /// ```
    pub fn ok_or<E>(self, err: E) -> Result<(), E> {
        match self {
            AuthorizationDecision::Allowed { reason: _ } => Ok(()),
            AuthorizationDecision::Forbidden { reason: _ } => Err(err),
        }
    }

    /// Like `ok_or`, but builds the error from the forbidden reason.
    pub fn ok_or_else<E, G>(self, err_fn: G) -> Result<(), E>
    where
        G: FnOnce(F) -> E,
    {
        match self {
            AuthorizationDecision::Allowed { reason: _ } => Ok(()),
            AuthorizationDecision::Forbidden { reason } => Err(err_fn(reason)),
        }
    }

    /// Convert into `Result<AllowedReason, ForbiddenReason>`.
    pub fn into_result(self) -> Result<A, F> {
        match self {
            AuthorizationDecision::Allowed { reason } => Ok(reason),
            AuthorizationDecision::Forbidden { reason } => Err(reason),
        }
    }

    /// Panic with `msg` if forbidden; otherwise return the allowed reason.
    ///
    /// ```rust
    /// // panics if decision is forbidden
    /// use traitgate::prelude::*;
    /// let dec = AuthorizationDecision::<(),()>::allowed();
    /// let reason = dec.expect_allowed("must be allowed");
    /// ```
    pub fn expect_allowed(self, msg: &str) -> A {
        match self {
            AuthorizationDecision::Allowed { reason } => reason,
            AuthorizationDecision::Forbidden { reason: _ } => {
                panic!("{}", msg)
            }
        }
    }

    /// Panic with `msg` if allowed; otherwise return the forbidden reason.
    ///
    /// ```rust
    /// // panics if decision is forbidden
    /// use traitgate::prelude::*;
    /// let dec = AuthorizationDecision::<(),()>::forbidden();
    /// let reason = dec.expect_forbidden("must be forbidden");
    /// ```
    pub fn expect_forbidden(self, msg: &str) -> F {
        match self {
            AuthorizationDecision::Forbidden { reason } => reason,
            AuthorizationDecision::Allowed { reason: _ } => {
                panic!("{}", msg)
            }
        }
    }

    /// Panic if allowed; otherwise return the forbidden reason.
    ///
    /// ```rust
    /// // panics if decision is allowed
    /// use traitgate::prelude::*;
    /// let dec = AuthorizationDecision::<(),()>::forbidden();
    /// let reason = dec.unwrap_forbidden();
    /// ```
    pub fn unwrap_forbidden(self) -> F {
        match self {
            AuthorizationDecision::Allowed { reason: _ } => {
                panic!("tried to unwrap authorization decision as forbidden but it was allowed")
            }
            AuthorizationDecision::Forbidden { reason } => reason,
        }
    }

    /// Panic if forbidden; otherwise return the allowed reason.
    ///
    /// ```rust
    /// // panics if decision is forbidden
    /// use traitgate::prelude::*;
    /// let dec = AuthorizationDecision::<(),()>::allowed();
    /// let reason = dec.unwrap_allowed();
    /// ```
    pub fn unwrap_allowed(self) -> A {
        match self {
            AuthorizationDecision::Allowed { reason } => reason,
            AuthorizationDecision::Forbidden { reason: _ } => {
                panic!("tried to unwrap authorization decision as allowed but it was forbidden")
            }
        }
    }

    /// If this decision is `Forbidden`, runs `inspect_fn(&reason)`as a side‐effect,
    /// then returns the original decision unchanged.
    ///
    /// # Example
    ///
    /// ```
    /// # use traitgate::AuthorizationDecision;
    /// let dec = AuthorizationDecision::<(), &str>::forbidden_with("not owner");
    /// dec.inspect_forbidden(|reason| println!("Denied because {}", reason));
    pub fn inspect_forbidden<G: FnOnce(&F)>(self, inspect_fn: G) -> Self {
        if let AuthorizationDecision::Forbidden { ref reason } = self {
            inspect_fn(reason);
        }

        self
    }

    /// If this decision is `Forbidden`, runs `inspect_fn(&reason)` for a side‐effect,
    /// then returns the original decision unchanged.
    ///
    /// # Example
    ///
    /// ```
    /// # use traitgate::AuthorizationDecision;
    /// let dec = AuthorizationDecision::<&str,()>::allowed_with("admin");
    /// dec.inspect_allowed(|reason| println!("Granted because {}", reason));
    /// ```
    pub fn inspect_allowed<G: FnOnce(&A)>(self, inspect_fn: G) -> Self {
        if let AuthorizationDecision::Allowed { ref reason } = self {
            inspect_fn(reason);
        }

        self
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[allow(clippy::unit_cmp)]
    #[test]
    fn basic_allowed_and_forbidden() {
        // Unit‐reason allowed
        let ok: AuthorizationDecision<(), ()> = AuthorizationDecision::allowed();
        assert!(ok.is_allowed());
        assert!(!ok.is_forbidden());
        assert_eq!(ok.into_result(), Ok(()));
        assert_eq!(ok.ok_or("err"), Ok(()));
        assert_eq!(ok.ok_or_else(|_| "err"), Ok(()));
        assert_eq!(ok.unwrap_allowed(), ());

        // Unit‐reason forbidden
        let no: AuthorizationDecision<(), ()> = AuthorizationDecision::forbidden();
        assert!(!no.is_allowed());
        assert!(no.is_forbidden());
        assert_eq!(no.into_result(), Err(()));
        assert_eq!(no.ok_or("err"), Err("err"));
        assert_eq!(no.ok_or_else(|_| "err"), Err("err"));
        assert_eq!(no.unwrap_forbidden(), ());
    }

    #[test]
    fn custom_reason_constructors_and_unwraps() {
        // Allowed with custom reason – need to specify forbidden‐reason type for inference
        let allow_r: AuthorizationDecision<i32, ()> = AuthorizationDecision::allowed_with(42);
        // Alternatively:
        // let allow_r = AuthorizationDecision::<i32, ()>::allowed_with(42);

        assert!(allow_r.is_allowed());
        assert_eq!(allow_r.into_result(), Ok(42));
        assert_eq!(allow_r.unwrap_allowed(), 42);

        // Forbidden with custom reason – specify allow‐reason type
        let forbid_r: AuthorizationDecision<(), &str> =
            AuthorizationDecision::forbidden_with("nope");
        // Or use turbofish:
        // let forbid_r = AuthorizationDecision::<(), &str>::forbidden_with("nope");

        assert!(forbid_r.is_forbidden());
        assert_eq!(forbid_r.into_result(), Err("nope"));
        assert_eq!(forbid_r.unwrap_forbidden(), "nope");
    }

    #[test]
    fn expect_methods_return_reason() {
        let a: AuthorizationDecision<&str, &str> = AuthorizationDecision::allowed_with("yes");
        assert_eq!(a.expect_allowed("fail"), "yes");

        let f: AuthorizationDecision<&str, &str> = AuthorizationDecision::forbidden_with("denied");
        assert_eq!(f.expect_forbidden("fail"), "denied");
    }

    #[test]
    #[should_panic(expected = "must be allowed")]
    fn expect_allowed_panics_when_forbidden() {
        let dec: AuthorizationDecision = AuthorizationDecision::forbidden();
        dec.expect_allowed("must be allowed");
    }

    #[test]
    #[should_panic(expected = "must be forbidden")]
    fn expect_forbidden_panics_when_allowed() {
        let dec: AuthorizationDecision<&str> = AuthorizationDecision::allowed_with("x");
        dec.expect_forbidden("must be forbidden");
    }

    #[test]
    fn inspect_allowed_and_forbidden_call_closure() {
        // inspect_allowed
        let flag_allowed = Cell::new(false);
        let dec_allowed: AuthorizationDecision<&str, ()> =
            AuthorizationDecision::allowed_with("admin").inspect_allowed(|reason| {
                assert_eq!(reason, &"admin");
                flag_allowed.set(true);
            });
        assert!(flag_allowed.get());
        assert!(dec_allowed.is_allowed());

        // inspect_forbidden
        let flag_forbidden = Cell::new(false);
        let dec_forbidden: AuthorizationDecision<(), &str> =
            AuthorizationDecision::forbidden_with("denied").inspect_forbidden(|reason| {
                assert_eq!(reason, &"denied");
                flag_forbidden.set(true);
            });
        assert!(flag_forbidden.get());
        assert!(dec_forbidden.is_forbidden());
    }
}
