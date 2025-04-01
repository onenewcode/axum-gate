//! Implementors of the [CodecService] for en- and decoding payload.
use crate::Error;
use crate::services::CodecService;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Serialize, de::DeserializeOwned};
use std::marker::PhantomData;

/// A symmetric key, having the same value for en- and decoding.
#[derive(Clone)]
pub struct Symmetric<P> {
    enc_key: EncodingKey,
    dec_key: DecodingKey,
    phantom_payload: PhantomData<P>,
}

impl<P> Default for Symmetric<P> {
    /// Creates a random key and uses it for en- and decoding.
    fn default() -> Self {
        use rand::{Rng, distr::Alphanumeric, rng};

        let authentication_secret: String = rng()
            .sample_iter(&Alphanumeric)
            .take(60)
            .map(char::from)
            .collect();
        Self {
            enc_key: EncodingKey::from_secret(authentication_secret.as_bytes()),
            dec_key: DecodingKey::from_secret(authentication_secret.as_bytes()),
            phantom_payload: PhantomData,
        }
    }
}

impl<P> CodecService for Symmetric<P>
where
    P: Serialize + DeserializeOwned + Clone,
{
    type Payload = P;
    fn encode(&self, payload: &Self::Payload) -> Result<Vec<u8>, Error> {
        let web_token = jsonwebtoken::encode(&Header::default(), payload, &self.enc_key)
            .map_err(|e| Error::Codec(format!("{e}")))?;
        Ok(web_token.as_bytes().to_vec())
    }
    fn decode(&self, encoded_value: &[u8]) -> Result<Self::Payload, Error> {
        let claims = jsonwebtoken::decode::<Self::Payload>(
            &String::from_utf8_lossy(encoded_value),
            &self.dec_key,
            &Validation::default(),
        )
        .map_err(|e| Error::Codec(format!("{e}")))?;

        Ok(claims.claims)
    }
}
