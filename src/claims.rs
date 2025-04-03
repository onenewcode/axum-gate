//! Payloads that can be used in combination with `axum-gate`.
use chrono::{TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashSet;

/// Registered/reserved claims by IANA/JWT spec, see
/// [auth0](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-token-claims) for more
/// information.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[skip_serializing_none]
pub struct RegisteredClaims {
    /// Issuer of the JWT
    #[serde(rename = "iss")]
    pub issuer: Option<HashSet<String>>,
    /// Subject of the JWT (the user)
    #[serde(rename = "sub")]
    pub subject: Option<String>,
    /// Recipient for which the JWT is intended
    #[serde(rename = "aud")]
    pub audience: Option<HashSet<String>>,
    /// Time after which the JWT expires
    #[serde(rename = "exp")]
    pub expiration_time: Option<u64>,
    /// Time before which the JWT must not be accepted for processing
    #[serde(rename = "nbf")]
    pub not_before_time: Option<u64>,
    /// Time at which the JWT was issued; can be used to determine age of the JWT
    #[serde(rename = "iat")]
    pub issued_at_time: Option<u64>,
    /// Unique identifier; can be used to prevent the JWT from being replayed (allows a token to be used only once)
    #[serde(rename = "jti")]
    pub jwt_id: Option<String>,
}

impl Default for RegisteredClaims {
    /// Initializes the claims with `expiration_time` set to 1 week.
    fn default() -> Self {
        Self {
            issuer: None,
            subject: None,
            audience: None,
            expiration_time: Some((Utc::now() + TimeDelta::weeks(1)).timestamp() as u64),
            not_before_time: None,
            issued_at_time: None,
            jwt_id: None,
        }
    }
}

/// Default claims for the use with `axum-gate`s [JsonWebToken](crate::codecs::JsonWebToken) codec.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct JwtClaims<CustomClaims> {
    /// The registered claims of a JWT.
    #[serde(flatten)]
    pub registered_claims: RegisteredClaims,
    /// Your custom claims that are added to the JWT.
    #[serde(flatten)]
    pub custom_claims: CustomClaims,
}

impl<CustomClaims> JwtClaims<CustomClaims> {
    /// Creates a new claim with default registered claims and the given custom claims.
    pub fn new(custom_claims: CustomClaims) -> Self {
        Self {
            registered_claims: RegisteredClaims::default(),
            custom_claims,
        }
    }

    /// Creates new claims with the given registered claims.
    pub fn new_with_registered(
        custom_claims: CustomClaims,
        registered_claims: RegisteredClaims,
    ) -> Self {
        Self {
            custom_claims,
            registered_claims,
        }
    }
}
