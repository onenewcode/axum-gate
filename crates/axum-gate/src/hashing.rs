//! Value hashing implementations.
use crate::Error;
use crate::services::HashingService;

use anyhow::Result;
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHash, PasswordVerifier};

/// A hashed value.
pub type HashedValue = String;

/// The verification result of a hashed value.
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
#[derive(Default)]
pub struct Argon2Hasher;

impl HashingService for Argon2Hasher {
    fn hash_value(&self, plain_value: &str) -> Result<HashedValue> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        Ok(argon2
            .hash_password(plain_value.as_bytes(), &salt)
            .map_err(|e| Error::Hashing(format!("Could not hash secret: {e}")))?
            .to_string())
    }
    fn verify_value(&self, plain_value: &str, hashed_value: &str) -> Result<VerificationResult> {
        let hash = PasswordHash::new(hashed_value).map_err(|e| {
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
    let hasher = Argon2Hasher;
    let hashed_secret = hasher.hash_value(secret).unwrap();
    assert_eq!(
        VerificationResult::Ok,
        hasher.verify_value(secret, &hashed_secret).unwrap()
    );
    assert_eq!(
        VerificationResult::Unauthorized,
        hasher
            .verify_value("somethingwrong", &hashed_secret)
            .unwrap()
    );
}
