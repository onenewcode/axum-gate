use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

/// State of a [Gate](super::Gate) instance. Used internally for identifying whether a login has
/// invalidated.
#[derive(Clone, Debug)]
pub struct GateState {
    /// Defines the point in time where a login will be invalidated.
    not_before_time: Arc<RwLock<DateTime<Utc>>>,
}

impl Default for GateState {
    fn default() -> Self {
        Self {
            not_before_time: Arc::new(RwLock::new(Utc::now())),
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
