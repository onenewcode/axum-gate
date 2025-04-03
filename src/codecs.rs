//! Implementors of the [CodecService] for en- and decoding payload.
use crate::Error;
use crate::jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Serialize, de::DeserializeOwned};
use std::marker::PhantomData;

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

/// Options to configure the [JsonWebToken] codec.
pub struct JsonWebTokenOptions {
    /// Key for encoding.
    pub enc_key: EncodingKey,
    /// Key for decoding.
    pub dec_key: DecodingKey,
    /// The header used for encoding.
    pub header: Option<Header>,
    /// Validation options.
    pub validation: Option<Validation>,
}

impl Default for JsonWebTokenOptions {
    /// Creates a random, alphanumeric 60 char key and uses it for en- and decoding (symmetric).
    /// [Header] and [Validation] are set with its default values.
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
            header: Some(Header::default()),
            validation: Some(Validation::default()),
        }
    }
}

/// Encrypts using the given keys as JWT using [jsonwebtoken].
#[derive(Clone)]
pub struct JsonWebToken<P> {
    /// Key for encoding.
    enc_key: EncodingKey,
    /// Key for decoding.
    dec_key: DecodingKey,
    /// The header used for encoding.
    pub header: Header,
    /// Validation options for the JWT.
    pub validation: Validation,
    phantom_payload: PhantomData<P>,
}

impl<P> JsonWebToken<P> {
    /// Creates a new instance with the given encoding and decoding keys.
    pub fn new_with_options(options: JsonWebTokenOptions) -> Self {
        let JsonWebTokenOptions {
            enc_key,
            dec_key,
            header,
            validation,
        } = options;
        Self {
            enc_key,
            dec_key,
            header: header.unwrap_or(Header::default()),
            validation: validation.unwrap_or(Validation::default()),
            phantom_payload: PhantomData,
        }
    }
}

impl<P> Default for JsonWebToken<P> {
    fn default() -> Self {
        Self::new_with_options(JsonWebTokenOptions::default())
    }
}

impl<P> CodecService for JsonWebToken<P>
where
    P: Serialize + DeserializeOwned + Clone,
{
    type Payload = P;
    fn encode(&self, payload: &Self::Payload) -> Result<Vec<u8>, Error> {
        let web_token = jsonwebtoken::encode(&self.header, payload, &self.enc_key)
            .map_err(|e| Error::Codec(format!("{e}")))?;
        Ok(web_token.as_bytes().to_vec())
    }
    /// Decodes the given value.
    ///
    /// # Errors
    /// Returns an error if the header stored in [JsonWebToken] does not match the decoded value.
    /// The header can be retrieved from [JsonWebToken::header].
    fn decode(&self, encoded_value: &[u8]) -> Result<Self::Payload, Error> {
        let claims = jsonwebtoken::decode::<Self::Payload>(
            &String::from_utf8_lossy(encoded_value),
            &self.dec_key,
            &self.validation,
        )
        .map_err(|e| Error::Codec(format!("{e}")))?;

        if self.header != claims.header {
            return Err(Error::Codec(format!(
                "Header of the decoded value does not match the one used for encoding."
            )));
        }

        Ok(claims.claims)
    }
}
