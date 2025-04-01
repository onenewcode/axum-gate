//! Passports are the identification card for a user. Traditionally known as `Account`.
use super::Passport;
use crate::Error;
use crate::Role;
use argon2::{
    Argon2,
    password_hash::{
        Encoding, PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
    },
};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

/// Defines a passport of a user.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StandardPassport {
    /// The unique id of the passport. For example username, email or some string of your choice.
    pub id: String,
    /// Password to login to the service. Resides encoded in memory.
    password: String,
    /// A list of scopes that the user can access.
    services: Vec<String>,
    /// Type of this passport.
    pub account_type: Role,
    /// Wether the passport is disabled.
    pub disabled: bool,
    /// Whether the passport has been confirmed. This is useful in combination
    /// with for example E-Mail verficiation.
    pub confirmed: bool,
    /// Determines when this passport expires.
    pub expires_at: DateTime<Utc>,
}

impl StandardPassport {
    /// Creates a new passport with [StandardPassport::disabled] and [StandardPassport::confirmed] set to `false`.
    pub fn new(
        id: &str,
        password: &str,
        services: &[&str],
        account_type: Role,
    ) -> Result<Self, Error> {
        Ok(Self {
            id: id.to_string(),
            password: Self::hash_password(password)?,
            services: services
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<String>>(),
            account_type,
            disabled: false,  // always activate
            confirmed: false, // always require user to confirm it
            expires_at: chrono::Utc::now()
                + TimeDelta::try_weeks(104).ok_or(Error::Passport(format!(
                    "Internal server error. Could not create TimeDelta with \
                     two years."
                )))?,
        })
    }
}

impl Passport for StandardPassport {
    type Id = String;
    type Services = String;

    fn id(&self) -> &Self::Id {
        &self.id
    }

    fn services(&self) -> &[String] {
        &self.services
    }

    fn change_password(&mut self, old_password: &str, new_password: &str) -> Result<(), Error> {
        if self.verify_password(old_password)? {
            self.password = Self::hash_password(new_password)?;
            Ok(())
        } else {
            Err(Error::Passport(format!("Passwords do not match.")))
        }
    }

    fn verify_password(&self, password: &str) -> Result<bool, Error> {
        let hash = PasswordHash::parse(&self.password, Encoding::B64)
            .map_err(|e| Error::Passport(format!("{e}")))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok())
    }

    /// Hashes the password using `[argon2]`.
    fn hash_password(password: &str) -> Result<String, Error> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        Ok(argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| Error::Passport(format!("{e}")))?
            .to_string())
    }
}
