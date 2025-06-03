use serde::{Deserialize, Serialize};

/// Basic group definitions.
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub struct Group(String);

impl Group {
    /// Creates a new instance with the given group name.
    pub fn new(group: &str) -> Self {
        Self(group.to_string())
    }

    /// Returns the group name.
    pub fn name(&self) -> &str {
        &self.0
    }
}
