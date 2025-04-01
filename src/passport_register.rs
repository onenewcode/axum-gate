//! A [PassportRegister] is a data structure that has access to all the registered users ([Passport]s).
use super::passport::Passport;
use crate::Credentials;
use crate::Error;
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use tracing::debug;

/// The passport register contains a collection of passports that are
/// known to your application.
///
/// `ID` is the unique identifier type for a [Passport].
pub trait PassportRegister<P>
where
    P: Passport + Clone,
{
    /// Returns the passport for the given `passport_id`.
    fn passport(&self, passport_id: &P::Id) -> Result<Option<P>, Error>;
    /// Stores the given passport in the register returning its ID for further usage.
    fn set_passport(&mut self, passport: P) -> Result<P::Id, Error>;
    /// Verifies if the given [Credentials] is valid.
    /// Return scenarios should be the following:
    /// - If valid, a copy of the corresponding passport is returned.
    /// - If no corresponding [Passport] is found, the return value should be `Ok(None)`.
    /// - In all other cases, it should return `Err(_)`.
    fn verify_credentials(&self, credentials: &Credentials<P::Id>) -> Result<Option<P>, Error>;
}

/// A [MemoryPassportRegister] is a data structure where all [Passport]s are stored in memory.
pub struct MemoryPassportRegister<P>
where
    P: Passport + Clone,
    <P as Passport>::Id: Eq + Hash,
{
    passports: HashMap<<P as Passport>::Id, P>,
}

impl<P> From<Vec<P>> for MemoryPassportRegister<P>
where
    P: Passport + Clone,
    <P as Passport>::Id: Eq + Hash + Clone,
{
    fn from(value: Vec<P>) -> Self {
        let mut passports = HashMap::new();
        for val in value {
            let id = val.id().clone();
            passports.insert(id, val);
        }
        Self { passports }
    }
}

impl<P> PassportRegister<P> for MemoryPassportRegister<P>
where
    P: Passport + Clone,
    <P as Passport>::Id: Eq + Hash + Clone + Display,
{
    fn passport(&self, passport_id: &<P as Passport>::Id) -> Result<Option<P>, Error> {
        Ok(self.passports.get(passport_id).cloned())
    }
    fn set_passport(&mut self, passport: P) -> Result<P::Id, Error> {
        let id = passport.id().clone();
        self.passports.insert(id.clone(), passport);
        Ok(id)
    }
    fn verify_credentials(&self, credentials: &Credentials<P::Id>) -> Result<Option<P>, Error> {
        let Some(passport) = self.passport(&credentials.id)? else {
            debug!("User with id {} not found.", credentials.id);
            return Ok(None);
        };
        if passport.verify_password(&credentials.secret)? {
            Ok(Some(passport))
        } else {
            Err(Error::PassportRegister(format!("Invalid credentials.")))
        }
    }
}
