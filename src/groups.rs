use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::hash::Hash;

use crate::CommaSeparatedValue;

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

impl CommaSeparatedValue for HashSet<BasicGroup> {
    fn from_csv(value: &str) -> Result<Self, String> {
        let value: Vec<&str> = value.split(',').collect();
        let mut result = HashSet::new();
        for v in value {
            result.insert(BasicGroup::new(v));
        }
        Ok(result)
    }

    fn into_csv(self) -> String {
        self.into_iter()
            .map(|g| g.name().to_string())
            .collect::<Vec<String>>()
            .join(",")
    }
}
