//! Encoding/decoding abstraction for JWTs or alternative token / credential formats.
//!
//! The [`Codec`] trait defines a minimal interface for transforming a strongly-typed
//! payload (`Self::Payload`) into an opaque byte vector and back again. It is used
//! throughout the crate wherever pluggable token formats are desirable (e.g. JWT,
//! custom signed blobs, encrypted envelopes, detached signatures).
//!
//! # Design Goals
//! - Small surface area: only `encode` and `decode`.
//! - Payload associated type must implement `Serialize` + `DeserializeOwned` (serde-based).
//! - Clone required to allow cheap cloning of lightweight codec configurations (keys, etc.).
//!
//! # Typical Implementation (JWT Example)
//! The provided `JsonWebToken` implements this trait for `JwtClaims<T>` payloads. You can
//! supply your own implementation to:
//! - Use a different signing / encryption algorithm
//! - Add envelope encryption before signing
//! - Delegate to a remote signing service / HSM
//!
//! # Error Semantics
//! - `Ok(Vec<u8>)` / `Ok(Payload)` for normal success
//! - `Err(Error::Infrastructure(..))` (or other error variants) for malformed tokens,
//!   signature failures, expired tokens (depending on implementation), serialization issues,
//!   or cryptographic backend errors
//!
//! # Security Considerations
//! - Implementations MUST validate integrity / authenticity in `decode` (e.g. verify
//!   signatures / MACs) before returning a payload.
//! - Avoid producing distinguishable error messages that leak sensitive validation details
//!   if the higher layer aims for uniform failure responses.
//! - Ensure keys / secrets are held in memory securely (consider zeroing where appropriate).
//!
//! # Streaming vs In-Memory
//! This trait intentionally uses an in-memory `Vec<u8>` to keep the interface simple.
//! If you require streaming (very large claims / payloads), introduce a separate
//! streaming codec trait rather than expanding this one.
//!
//! # Example (Pseudo Custom Codec)
//! ```rust,no_run
//! use axum_gate::advanced::Codec;
//! use serde::{Serialize, Deserialize};
//!
//! #[derive(Clone)]
//! struct MyCodec;
//!
//! #[derive(Serialize, Deserialize, Clone)]
//! struct MyPayload {
//!     value: String,
//! }
//!
//! impl Codec for MyCodec {
//!     type Payload = MyPayload;
//!
//!     fn encode(&self, payload: &Self::Payload) -> axum_gate::errors::Result<Vec<u8>> {
//!         let mut data = bincode::serialize(payload)
//!             .map_err(|e| axum_gate::errors::Error::Infrastructure(
//!                 axum_gate::errors::InfrastructureError::Other(format!("serialize: {e}"))
//!             ))?;
//!         // Optionally: encrypt / sign here
//!         Ok(std::mem::take(&mut data))
//!     }
//!
//!     fn decode(&self, encoded: &[u8]) -> axum_gate::errors::Result<Self::Payload> {
//!         // Optionally: verify / decrypt first
//!         let v = bincode::deserialize(encoded)
//!             .map_err(|e| axum_gate::errors::Error::Infrastructure(
//!                 axum_gate::errors::InfrastructureError::Other(format!("deserialize: {e}"))
//!             ))?;
//!         Ok(v)
//!     }
//! }
//! ```
//!
//! # Backward Compatibility
//! Keep custom codecs liberal in what they accept (where safe) and strict in what they
//! produce to ease migrations (e.g. version tagging in headers / envelopes).
use crate::errors::Result;
use serde::{Serialize, de::DeserializeOwned};

/// A pluggable payload encoder/decoder.
///
/// See the module-level documentation for detailed guidance and examples.
pub trait Codec
where
    Self: Clone,
    Self::Payload: Serialize + DeserializeOwned,
{
    /// Type of the payload being encoded/decoded.
    type Payload;

    /// Encode a payload into an opaque, implementation-defined byte vector.
    ///
    /// Implementations MUST:
    /// - Serialize + sign / encrypt (where applicable)
    /// - Return an error if encoding or cryptographic operations fail
    fn encode(&self, payload: &Self::Payload) -> Result<Vec<u8>>;

    /// Decode a previously encoded payload.
    ///
    /// Implementations MUST:
    /// - Fully validate integrity/authenticity (e.g. signature/MAC) before returning
    /// - Reject malformed or tampered data with an appropriate error
    fn decode(&self, encoded_value: &[u8]) -> Result<Self::Payload>;
}
