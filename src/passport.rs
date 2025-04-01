//! A [Passport] identifies a user.
pub use self::standard_passport::StandardPassport;
use crate::Error;
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
};
use serde::{Serialize, de::DeserializeOwned};

mod standard_passport;

/// Defines a `Passport` of a user. This is also known as account.
pub trait Passport {
    /// The unique identifier type of the passport.
    type Id;
    /// The services that this passport is able to access. Serde is required to store the services
    /// in JWT.
    type Services: Serialize + DeserializeOwned;

    /// Returns the unique identifier of the passport.
    fn id(&self) -> &Self::Id;

    /// Returns the services this passport is valid for.
    fn services(&self) -> &[Self::Services];

    /// Checks if the given password is correct.
    fn verify_password(&self, password: &str) -> Result<bool, Error>;

    /// Verfies the `old_password` and rejects if it does not match. Replaces it
    /// by `new_password` otherwise.
    ///
    /// Always returns the current password. This means, if rejected the old, otherwise the new
    /// one.
    fn change_password(&mut self, old_password: &str, new_password: &str) -> Result<(), Error>;

    /// Hashes the password using `[argon2]`.
    fn hash_password(password: &str) -> Result<String, Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        Ok(argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| Error::Passport(format!("Could not hash password: {e}")))?
            .to_string())
    }
}
