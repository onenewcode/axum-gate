use serde::{Deserialize, Serialize};
use std::hash::Hash;

/// Basic group definitions.
#[derive(Hash, Eq, PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub struct BasicGroup(String);

impl BasicGroup {
    /// Creates a new instance with the given group name.
    pub fn new(group: &str) -> Self {
        Self(group.to_string())
    }

    /// Returns the group name.
    pub fn name(&self) -> &str {
        &self.0
    }
}
