//! Different hashing algorithms, mostly used for credentials.
use crate::Error;
use crate::services::SecretsHashingService;
use argon2::{
    Argon2, PasswordHash, PasswordVerifier,
    password_hash::{Encoding, PasswordHasher, SaltString, rand_core::OsRng},
};

/// Hashes values using [argon2].
pub struct Argon2Hasher;

impl Default for Argon2Hasher {
    fn default() -> Self {
        Self {}
    }
}

impl SecretsHashingService for Argon2Hasher {
    fn hash_secret(&self, plain_value: &[u8]) -> Result<Vec<u8>, crate::Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        Ok(argon2
            .hash_password(plain_value, &salt)
            .map_err(|e| Error::Hashing(format!("Could not hash secret: {e}")))?
            .to_string()
            .as_bytes()
            .to_vec())
    }
    fn verify_secret(&self, plain_value: &[u8], hashed_value: &[u8]) -> Result<bool, crate::Error> {
        let string_value = String::from_utf8(hashed_value.to_vec())
            .map_err(|e| crate::Error::Hashing(format!("{e}")))?;
        let hash = PasswordHash::parse(&string_value, Encoding::B64)
            .map_err(|e| crate::Error::Hashing(format!("{e}")))?;
        Ok(Argon2::default()
            .verify_password(plain_value, &hash)
            .is_ok())
    }
}
