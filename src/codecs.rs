//! En- and decoding payload interfaces.
use crate::Error;
use serde::{Serialize, de::DeserializeOwned};

/// Methods for encoding and decoding payload.
pub trait CodecService
where
    Self: Clone,
    Self::Payload: Serialize + DeserializeOwned,
{
    /// The payload that can be encoded.
    type Payload;

    /// Encodes the given payload.
    fn encode(&self, payload: &Self::Payload) -> Result<Vec<u8>, Error>;
    /// Decodoes the given payload.
    fn decode(&self, encoded_value: &[u8]) -> Result<Self::Payload, Error>;
}
