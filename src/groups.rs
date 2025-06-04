use crate::utils::CommaSeparatedValue;

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

impl CommaSeparatedValue for Vec<Group> {
    fn from_csv(value: &str) -> Result<Self, String> {
        Ok(value
            .split(',')
            .collect::<Vec<&str>>()
            .iter()
            .map(|g| Group::new(g))
            .collect())
    }

    fn into_csv(self) -> String {
        self.into_iter()
            .map(|g| g.name().to_string())
            .collect::<Vec<String>>()
            .join(",")
    }
}
