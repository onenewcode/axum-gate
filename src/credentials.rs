//! Credentials definitions used for API, or storage.
use serde::{Deserialize, Serialize};

/// The credentials contain login data such as eg. user id and password.
///
/// These values are plain values. If you need to store the password in a storage, you will be
/// required to put it in a [Secret].
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credentials<Id> {
    /// The identification of the user, eg. a username.
    pub id: Id,
    /// The secret of the user, eg. a password.
    pub secret: String,
}

impl<Id> Credentials<Id> {
    /// Creates a new instance with the given id and secret.
    pub fn new(id: &Id, secret: &str) -> Self
    where
        Id: ToOwned<Owned = Id>,
    {
        Self {
            id: id.to_owned(),
            secret: secret.to_string(),
        }
    }
}
