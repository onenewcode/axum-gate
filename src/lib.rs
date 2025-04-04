//! Fully customizable role based JWT auth for axum.
//!
//! # Examples
//!
//! These examples aim to give you a basic overview about the possibilities that [axum-gate](crate) offers.
//!
//! ## Required preparations to protect your application
//!
//! To protect your application with `axum-gate` you need to use storages that implement
//! [CredentialsStorageService](crate::storage::CredentialsStorageService) and
//! [PassportStorageService](crate::storage::PassportStorageService). For modularity and separation
//! of concerns they have been
//! split into two. It is still possible to implement both on the same storage if it is responsible
//! for [`Passport`](crate::passport::Passport) as well as the
//! [`Credentials`](crate::credentials::Credentials) of a user.
//!
//! In case of the pre-defined [PassportMemoryStorage](crate::storage::PassportMemoryStorage)
//! and [CredentialsMemoryStorage](crate::storage::CredentialsMemoryStorage)
//! where both of them use the memory for storage, the following
//! steps are required during the setup of your app.
//!
//! ```
//! # use axum_gate::credentials::Credentials;
//! # use axum_gate::passport::BasicPassport;
//! # use axum_gate::roles::BasicRole;
//! # use axum_gate::secrets::Argon2Hasher;
//! # use axum_gate::storage::{CredentialsMemoryStorage, PassportMemoryStorage};
//! # use std::sync::Arc;
//! # async fn example_storage() {
//! // We create a hasher that protects the secret in the persistent storage.
//! let hasher = Arc::new(Argon2Hasher::default());
//! // We first need to create the credentials. (Demonstration purpose only)
//! let user_creds = Credentials::new(
//!     "user@example.com".to_string(),
//!     "user_password".to_string().as_bytes(),
//! )
//! .hash_secret(&*hasher) // The secret should always be hashed when persisting.
//! .unwrap();
//! // Then a credentials storage is created.
//! let creds_storage = Arc::new(CredentialsMemoryStorage::from(vec![
//!     user_creds.clone(),
//! ]));
//! // Same for the passport which provides details about the user.
//! // The ID is used to create a connection between the storage entries.
//! let user_passport = BasicPassport::new(&user_creds.id, &["user"], &[BasicRole::User])
//!     .expect("Creating passport failed.");
//! let passport_storage = Arc::new(PassportMemoryStorage::from(vec![
//!     user_passport,
//! ]));
//! # }
//! ```
//!
//! ## Protecting your application
//!
//! The actual protection of your application is pretty simple.
//!
//! You have two options:
//! 1. Limit access a specific role,
//! 2. Enable access to a specific role and all its
//! [subordinates](crate::roles::AccessHierarchy::subordinate), or
//! 3. Limit access to a specific group.
//!
//! ## Using `Passport` details in your route handler
//!
//! `axum-gate` provides two [Extension](axum::extract::Extension)s to the handler.
//! The first one contains the [RegisteredClaims](crate::jwt::RegisteredClaims), the second
//! your custom claims. In this pre-defined case it is the
//! [`BasicPassport`](crate::passport::BasicPassport).
//! You can use them like any other extension:
//! ```
//! # use axum::extract::Extension;
//! # use axum_gate::passport::BasicPassport;
//! async fn reporter(Extension(user): Extension<BasicPassport>) -> Result<String, ()> {
//!     Ok(format!(
//!         "Hello {}, your roles are {:?} and you are member of groups {:?}!",
//!         user.id, user.roles, user.groups
//!     ))
//! }
//! ```
//!
//! # Further examples
//! - A pre-defined implementation of [SecretsHashingService](crate::secrets::SecretsHashingService)
//! can be found at [Argon2Hasher](crate::secrets::Argon2Hasher) that is used to hash credentials
//! before persisting it using [CredentialsStorageService](crate::storage::CredentialsStorageService)
//! - An example for a [CredentialsStorageService](crate::storage::CredentialsStorageService) /
//! [CredentialsVerifierService](crate::credentials::CredentialsVerifierService) used for
//! authentication can be found at [CredentialsMemoryStorage](crate::storage::CredentialsMemoryStorage)
#![deny(missing_docs)]

mod access_hierarchy;
pub mod codecs;
pub mod credentials;
mod errors;
pub mod gate;
pub mod jwt;
pub mod passport;
pub mod roles;
pub mod route_handlers;
pub mod secrets;
pub mod storage;

pub use access_hierarchy::AccessHierarchy;
pub use errors::Error;
pub use jsonwebtoken;
