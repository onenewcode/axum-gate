use serde::{Deserialize, Serialize};

/// Defines credentials for a simple login based on an `id` and a `secret`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credentials<Id> {
    /// The identification of the user, eg. a username.
    pub id: Id,
    /// The secret of the user, eg. a password.
    pub secret: String,
}

impl<Id> Credentials<Id>
where
    Id: Clone,
{
    /// Creates a new ticket with the given id and secret.
    pub fn new(id: &Id, secret: &str) -> Self {
        Self {
            id: id.clone(),
            secret: secret.to_string(),
        }
    }
}
