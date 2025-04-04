//! A [PassportStorage] is a data structure that has access to all the registered users ([Passport]s).
use crate::Error;
use crate::passport::Passport;
use crate::storage::PassportStorageService;
use std::collections::HashMap;
use std::fmt::Display;
use std::hash::Hash;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A [PassportMemoryStorage] is a data structure where all [Passport]s are stored in memory.
#[derive(Clone)]
pub struct PassportMemoryStorage<P>
where
    P: Passport + Clone,
    <P as Passport>::Id: Eq + Hash,
{
    passports: Arc<RwLock<HashMap<<P as Passport>::Id, P>>>,
}

impl<P> From<Vec<P>> for PassportMemoryStorage<P>
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
        let passports = Arc::new(RwLock::new(passports));
        Self { passports }
    }
}

impl<P> PassportStorageService<P> for PassportMemoryStorage<P>
where
    P: Passport + Clone,
    <P as Passport>::Id: Eq + Hash + Clone + Display,
{
    async fn passport(&self, passport_id: &<P as Passport>::Id) -> Result<Option<P>, Error> {
        let read = self.passports.read().await;
        Ok(read.get(passport_id).cloned())
    }
    async fn store_passport(&mut self, passport: P) -> Result<P::Id, Error> {
        let id = passport.id().clone();
        let mut write = self.passports.write().await;
        write.insert(id.clone(), passport);
        Ok(id)
    }
    async fn remove_passport(&self, passport_id: &<P as Passport>::Id) -> Result<bool, Error> {
        let mut write = self.passports.write().await;
        if !write.contains_key(passport_id) {
            return Ok(false);
        }
        Ok(write.remove(passport_id).is_some())
    }
}
