use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

/// State of a [Gate](super::Gate) instance.
#[derive(Clone, Debug)]
pub struct GateState {
    /// Defines the point in time where a login will be invalidated.
    not_before_time: Arc<RwLock<DateTime<Utc>>>,
}

impl GateState {
    /// Creates a new state.
    pub fn new(not_before_time: DateTime<Utc>) -> Self {
        Self {
            not_before_time: Arc::new(RwLock::new(not_before_time)),
        }
    }
}

impl GateState {
    /// Checks whether the timstamp indicates that a login needs to be invalidated.
    pub async fn needs_invalidation(&self, timestamp: DateTime<Utc>) -> bool {
        let read = self.not_before_time.read().await;
        *read == timestamp
    }
}
