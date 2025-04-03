//! Secrets hashing, verification models.
use crate::Error;
use argon2::password_hash::{Encoding, PasswordHasher, SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use tracing::debug;

/// Responsible for hashing a plain value secret.
pub trait SecretsHashingService {
    /// Hashes the given plain value.
    fn hash_secret(&self, plain_value: &[u8]) -> Result<Vec<u8>, Error>;
    /// Verifies that `plain_value` matches the `hashed_value` by using the implementors hashing,
    /// function. Returns `true` if equal.
    fn verify_secret(&self, plain_value: &[u8], hashed_value: &[u8]) -> Result<bool, Error>;
}

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
        debug!("Created string value from hashed_value: {string_value}");
        let hash = PasswordHash::parse(&string_value, Encoding::B64)
            .map_err(|e| crate::Error::Hashing(format!("{e}")))?;
        Ok(Argon2::default()
            .verify_password(plain_value, &hash)
            .is_ok())
    }
}

#[test]
fn secrets_hasher_service() {
    let secret = b"something";
    let hasher = Argon2Hasher::default();
    let hashed_secret = hasher.hash_secret(secret).unwrap();
    assert_eq!(true, hasher.verify_secret(secret, &hashed_secret).unwrap());
    assert_eq!(
        false,
        hasher
            .verify_secret(b"somethingwrong", &hashed_secret)
            .unwrap()
    );
}
