use serde::{Deserialize, Serialize};
#[cfg(feature = "storage-surrealdb")]
use surrealdb::RecordId;

/// Thin wrapper for a unique identifier for a [Passport](super::Passport).
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Hash)]
#[serde(transparent)]
pub struct PassportId(String);

impl From<&str> for PassportId {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl std::fmt::Display for PassportId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(feature = "storage-surrealdb")]
impl From<RecordId> for PassportId {
    fn from(value: RecordId) -> Self {
        Self(value.key().to_string())
    }
}
