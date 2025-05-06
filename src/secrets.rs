//! Secrets hashing, verification models.
use crate::Error;
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHash, PasswordVerifier};

/// Responsible for hashing a plain value secret.
pub trait SecretsHashingService {
    /// Hashes the given plain value.
    fn hash_secret(&self, plain_value: &str) -> Result<String, Error>;
    /// Verifies that `plain_value` matches the `hashed_value` by using the implementors hashing,
    /// function. Returns `true` if equal.
    fn verify_secret(&self, plain_value: &str, hashed_value: &str) -> Result<bool, Error>;
}

/// Hashes values using [argon2].
pub struct Argon2Hasher;

impl Default for Argon2Hasher {
    fn default() -> Self {
        Self {}
    }
}

impl SecretsHashingService for Argon2Hasher {
    fn hash_secret(&self, plain_value: &str) -> Result<String, crate::Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        Ok(argon2
            .hash_password(plain_value.as_bytes(), &salt)
            .map_err(|e| Error::Hashing(format!("Could not hash secret: {e}")))?
            .to_string())
    }
    fn verify_secret(&self, plain_value: &str, hashed_value: &str) -> Result<bool, crate::Error> {
        let hash = PasswordHash::new(&hashed_value).map_err(|e| {
            crate::Error::Hashing(format!(
                "Could not create password hash from hashed value string: {e}"
            ))
        })?;
        Ok(Argon2::default()
            .verify_password(plain_value.as_bytes(), &hash)
            .is_ok())
    }
}

#[test]
fn argon2hasher() {
    let secret = "something";
    let hasher = Argon2Hasher::default();
    let hashed_secret = hasher.hash_secret(secret).unwrap();
    assert_eq!(true, hasher.verify_secret(secret, &hashed_secret).unwrap());
    assert_eq!(
        false,
        hasher
            .verify_secret("somethingwrong", &hashed_secret)
            .unwrap()
    );
}
