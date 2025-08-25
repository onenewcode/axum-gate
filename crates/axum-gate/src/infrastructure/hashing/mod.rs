//! Value hashing implementations.
use crate::domain::values::VerificationResult;
use crate::errors::{Error, HashingOperation, PortError};
use crate::ports::auth::HashingService;

use crate::errors::Result;
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use argon2::{Argon2, PasswordHash, PasswordVerifier};

/// A hashed value.
pub type HashedValue = String;

/// Hashes values using [argon2].
#[derive(Default)]
pub struct Argon2Hasher;

impl HashingService for Argon2Hasher {
    fn hash_value(&self, plain_value: &str) -> Result<HashedValue> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        Ok(argon2
            .hash_password(plain_value.as_bytes(), &salt)
            .map_err(|e| {
                Error::Port(PortError::Hashing {
                    operation: HashingOperation::Hash,
                    message: format!("Could not hash secret: {e}"),
                    algorithm: Some("Argon2".to_string()),
                })
            })?
            .to_string())
    }
    fn verify_value(&self, plain_value: &str, hashed_value: &str) -> Result<VerificationResult> {
        let hash = PasswordHash::new(hashed_value).map_err(|e| {
            crate::errors::Error::Port(PortError::Hashing {
                operation: HashingOperation::Verify,
                message: format!("Could not create password hash from hashed value string: {e}"),
                algorithm: Some("Argon2".to_string()),
            })
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
