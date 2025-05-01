# TraitGate

A zero-dependency authorization mini-library powered by stateless traits and an ergonomic `AuthorizationDecision` enum.

## Getting Started

Add to your `Cargo.toml`:

```toml
[dependencies]
traitgate = "0.1"
```

In your code:

```rust
use traitgate::prelude::*;

struct User { id: u64, is_admin: bool }      // actor
struct Order { user_id: u64, num_books: u64 } // resource
struct View;
struct Edit; // actions

struct OrderAuthorizer;

impl Authorizer<User, View, Order> for OrderAuthorizer {
    fn check(user: &User, _: &View, order: &Order) -> AuthorizationDecision {
        if user.id == order.user_id || user.is_admin {
            AuthorizationDecision::allowed()
        } else {
            AuthorizationDecision::forbidden()
        }
    }
}
```

## Core Concepts

1. **Inputs**  
   Authorizers are stateless functions over:
    - Actor (who is doing the action)
    - Action (what they’re trying to do)
    - Resource (what they’re doing it to)
    - Context (optional, any additional information needed like request metadata, application environment, etc.)

2. **Traits**  
   TraitGate provides two traits:
    - `Authorizer`
    - `AuthorizerWithContext`

3. **Decisions**  
   Authorizers return an `AuthorizationDecision<AllowReason, ForbidReason>. Allow and forbid reason are both optional, 
defaulting to unit`:
    - `Allowed { reason }`
    - `Forbidden { reason }`
    - Includes methods like:
        - Constructors: `allowed()`, `forbidden()`, `allowed_with()`, `forbidden_with()`
        - Transformation and Combinators: `into_result()`, `ok_or()`, `ok_or_else()`
        - Side effects: `inspect_allowed()`, `inspect_forbidden()` 
        - Unwrapping: `expect_allowed()`, `unwrap_forbidden()`

## Features

- Zero dependencies
- Compile-time safety: Missing or duplicate authorizers are compile errors
- Simple: No macros, no async, no runtime configuration, no authorizer composition, sub-authorizers, or similar patterns
- Optional context support for things like rate limits, tenancy, etc.
- Optional user-defined reasons for allowed/forbidden decisions
- Flexible organization: Unopinionated in how to organize your authorizer inputs or authorizers, eg. one central authorizer for your application or one per resource

## Getting Started

 Add to your Cargo.toml:
```toml
[dependencies]
traitgate = "0.1"
 ```

 In your code:
```rust
use traitgate::prelude::*;
// Define your types:
struct User { id: u64, is_admin: bool }  //actor
struct Order  { user_id: u64, num_books: u64 } //resource
struct View; struct Edit; //actions
// Implement authorization checks:
struct OrderAuthorizer;
impl Authorizer<User, View, Order> for OrderAuthorizer {
    fn check(user: &User, _: &View, order: &Order) -> AuthorizationDecision {
        if (user.id == order.user_id || user.is_admin) {
          return AuthorizationDecision::allowed();
        }
        AuthorizationDecision::forbidden()
    }
}
```

## Full Example

```rust
use traitgate::prelude::*;

#[derive(Debug)]
struct User {
   id: u64,
   is_admin: bool,
   is_pro: bool,
}

#[derive(Debug)]
struct Post {
   author_id: u64,
   content: String,
}

struct RateLimitContext {
   remaining_requests: u32,
}

struct View;
struct Edit;
struct Delete {
   delete_forks: bool
}

#[derive(Debug, PartialEq)]
enum EditPostDenied {
   NotAuthor,
   RateLimited { used: u32, limit: u32 },
}

struct PostAuthorizer;

impl Authorizer<User, View, Post> for PostAuthorizer {
   fn check(_: &User, _: &View, _: &Post) -> AuthorizationDecision<(), ()> {
      AuthorizationDecision::allowed()
   }
}
impl AuthorizerWithContext<
   User,
   Edit,
   Post,
   RateLimitContext,
   (),
   EditPostDenied,
> for PostAuthorizer
{
   fn check(
      user: &User,
      _: &Edit,
      post: &Post,
      ctx: &RateLimitContext,
   ) -> AuthorizationDecision<(), EditPostDenied> {
      if !user.is_admin && user.id != post.author_id {
         return AuthorizationDecision::forbidden_with(EditPostDenied::NotAuthor);
      }
      if ctx.remaining_requests == 0 {
         return AuthorizationDecision::forbidden_with(EditPostDenied::RateLimited {
            used: 0,
            limit: 5,
         });
      }
      AuthorizationDecision::allowed()
   }
}

impl Authorizer<User, Delete, Post> for PostAuthorizer {
   fn check(
      user: &User,
      action: &Delete,
      post: &Post,
   ) -> AuthorizationDecision<(), String> {
      if user.is_admin {
         return AuthorizationDecision::allowed();
      }

      if user.id != post.author_id {
         return AuthorizationDecision::forbidden_with("You are not the author".into());
      }

      if action.delete_forks && !user.is_pro {
         return AuthorizationDecision::forbidden_with(
            "Deleting forks requires a Pro subscription".into(),
         );
      }

      AuthorizationDecision::allowed()
   }
}

fn main() -> Result<(), String> {
   let author_regular = User { id: 1, is_admin: false, is_pro: false };
   let author_pro     = User { id: 2, is_admin: false, is_pro: true  };
   let stranger       = User { id: 3, is_admin: false, is_pro: true  };
   let admin          = User { id: 4, is_admin: true,  is_pro: false };

   let post = Post { author_id: 1, content: "Hello".into() };
   let ctx  = RateLimitContext { remaining_requests: 1 };

   PostAuthorizer::check(&author_regular, &Edit, &post, &ctx)
           .expect_allowed("author should be able to edit");

   let normal_delete = Delete { delete_forks: false };
   PostAuthorizer::check(&author_regular, &normal_delete, &post)
           .expect_allowed("author can delete own post");

   let fork_delete = Delete { delete_forks: true };
   let reason = PostAuthorizer::check(&author_regular, &fork_delete, &post)
           .expect_forbidden("should have required Pro");
   assert_eq!(reason, "Deleting forks requires a Pro subscription");

   PostAuthorizer::check(&author_pro, &fork_delete, &post)
           .expect_allowed("Pro author can delete forks");

   assert!(PostAuthorizer::check(&stranger, &normal_delete, &post).is_forbidden());

   PostAuthorizer::check(&admin, &fork_delete, &post)
           .expect_allowed("admin bypasses rules");

   Ok(())
}
```

## Contributing

Contributions and PRs welcome!

### License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as 
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
