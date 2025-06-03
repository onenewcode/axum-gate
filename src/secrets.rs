//! Secrets hashing, verification models.
use crate::Error;
use crate::services::SecretsHashingService;

use anyhow::Result;
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHash, PasswordVerifier};

/// A hashed secret.
pub type HashedSecret = String;

/// The result of a secret verification.
#[derive(Eq, PartialEq, Debug)]
pub enum VerificationResult {
    /// The verification was successful.
    Ok,
    /// The verification failed.
    Unauthorized,
}

impl From<bool> for VerificationResult {
    fn from(value: bool) -> Self {
        if value { Self::Ok } else { Self::Unauthorized }
    }
}

/// Hashes values using [argon2].
pub struct Argon2Hasher;

impl Default for Argon2Hasher {
    fn default() -> Self {
        Self {}
    }
}

impl SecretsHashingService for Argon2Hasher {
    fn hash_secret(&self, plain_value: &str) -> Result<HashedSecret> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        Ok(argon2
            .hash_password(plain_value.as_bytes(), &salt)
            .map_err(|e| Error::Hashing(format!("Could not hash secret: {e}")))?
            .to_string())
    }
    fn verify_secret(&self, plain_value: &str, hashed_value: &str) -> Result<VerificationResult> {
        let hash = PasswordHash::new(&hashed_value).map_err(|e| {
            crate::Error::Hashing(format!(
                "Could not create password hash from hashed value string: {e}"
            ))
        })?;
        Ok(VerificationResult::from(
            Argon2::default()
                .verify_password(plain_value.as_bytes(), &hash)
                .is_ok(),
        ))
    }
}

#[test]
fn argon2hasher() {
    let secret = "something";
    let hasher = Argon2Hasher::default();
    let hashed_secret = hasher.hash_secret(secret).unwrap();
    assert_eq!(
        VerificationResult::Ok,
        hasher.verify_secret(secret, &hashed_secret).unwrap()
    );
    assert_eq!(
        VerificationResult::Unauthorized,
        hasher
            .verify_secret("somethingwrong", &hashed_secret)
            .unwrap()
    );
}
