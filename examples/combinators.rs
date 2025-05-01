use std::fmt::Debug;
use traitgate::prelude::*;

#[derive(Debug)]
struct User {
    id: u64,
    is_suspended: bool,
    tweets_this_hour: u8,
    tweet_limit: u8,
}

#[derive(Debug)]
struct Tweet {
    id: u64,
    author_id: u64,
    content: String,
}

struct PostTweet {
    content: String,
}
struct DeleteTweet;
struct LikeTweet;

#[derive(Debug, PartialEq)]
enum PostTweetDenied {
    Suspended,
}

#[derive(Debug, PartialEq)]
enum DeleteTweetDenied {
    NotAuthor,
}

struct TweetAuthorizer;

impl Authorizer<User, PostTweet, (), (), PostTweetDenied> for TweetAuthorizer {
    fn check(
        user: &User,
        _post_action: &PostTweet,
        _: &(),
    ) -> AuthorizationDecision<(), PostTweetDenied> {
        if user.is_suspended {
            return AuthorizationDecision::forbidden_with(PostTweetDenied::Suspended);
        }
        AuthorizationDecision::allowed()
    }
}

impl Authorizer<User, DeleteTweet, Tweet, (), DeleteTweetDenied> for TweetAuthorizer {
    fn check(
        user: &User,
        _: &DeleteTweet,
        tweet: &Tweet,
    ) -> AuthorizationDecision<(), DeleteTweetDenied> {
        if user.id == tweet.author_id {
            AuthorizationDecision::allowed()
        } else {
            AuthorizationDecision::forbidden_with(DeleteTweetDenied::NotAuthor)
        }
    }
}

impl Authorizer<User, LikeTweet, Tweet> for TweetAuthorizer {
    fn check(_: &User, _: &LikeTweet, _: &Tweet) -> AuthorizationDecision {
        AuthorizationDecision::allowed()
    }
}

fn main() -> Result<(), String> {
    let user = User {
        id: 1,
        is_suspended: false,
        tweets_this_hour: 5,
        tweet_limit: 5,
    };

    let post = PostTweet {
        content: "Hello, world!".into(),
    };

    TweetAuthorizer::check(&user, &post, &())
        .inspect_forbidden(|r| println!("Post denied: {:?}", r))
        .ok_or("failed to post")?;

    let other_tweet = Tweet {
        id: 42,
        author_id: 2,
        content: "Hi".into(),
    };
    let del_reason = TweetAuthorizer::check(&user, &DeleteTweet, &other_tweet)
        .into_result()
        .unwrap_err();
    println!("Delete failed because: {:?}", del_reason);

    TweetAuthorizer::check(&user, &LikeTweet, &other_tweet)
        .expect_allowed("should be able to like");
    println!("Like succeeded");

    Ok(())
}
