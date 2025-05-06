//! Storage implementations that use surrealdb as backend.

use crate::Error;
use crate::credentials::{Credentials, CredentialsVerifierService};
use crate::passport::BasicPassport;
use crate::secrets::SecretsHashingService;
use crate::storage::CredentialsStorageService;
use crate::storage::PassportStorageService;

use std::default::Default;
use std::fmt::Display;
use std::str::FromStr;

use serde::Serialize;
use surrealdb::{Connection, RecordId, Surreal};
use tracing::debug;

/// Table names that are used within the database.
#[derive(Clone, Debug)]
pub struct TableNames {
    /// Where passports are being stored.
    pub passports: String,
    /// Where credentials are stored.
    pub credentials: String,
}

impl Default for TableNames {
    fn default() -> Self {
        Self {
            passports: "passports".to_string(),
            credentials: "credentials".to_string(),
        }
    }
}

/// Configurations to use with the [surrealdb] database.
#[derive(Clone, Debug)]
pub struct DatabaseScope {
    /// The table names of the database.
    pub table_names: TableNames,
    /// Namespace where data is stored.
    pub namespace: String,
    /// Database name where data is stored.
    pub database: String,
}

impl Default for DatabaseScope {
    fn default() -> Self {
        Self {
            table_names: TableNames::default(),
            namespace: "axum-gate".to_string(),
            database: "axum-gate".to_string(),
        }
    }
}

/// A storage that uses [surrealdb] as backend.
#[derive(Clone)]
pub struct SurrealDbStorage<S, Hasher>
where
    S: Connection,
    Hasher: SecretsHashingService,
{
    db: Surreal<S>,
    hasher: Hasher,
    scope_settings: DatabaseScope,
}

impl<S, Hasher> SurrealDbStorage<S, Hasher>
where
    S: Connection,
    Hasher: SecretsHashingService,
{
    /// Creates a new instance.
    pub fn new(db: Surreal<S>, hasher: Hasher, scope_settings: DatabaseScope) -> Self {
        Self {
            db,
            hasher,
            scope_settings,
        }
    }

    /// Sets the correct namespace and database to use.
    async fn use_ns_db(&self) -> Result<(), Error> {
        self.db
            .use_ns(&self.scope_settings.namespace)
            .use_db(&self.scope_settings.database)
            .await
            .map_err(|e| Error::Storage(e.to_string()))
    }
}

impl<Id, S, Hasher> PassportStorageService<BasicPassport<Id>> for SurrealDbStorage<S, Hasher>
where
    Id: Clone + Display + FromStr,
    <Id as FromStr>::Err: Display,
    Hasher: SecretsHashingService,
    S: Connection,
{
    async fn passport(&self, passport_id: &Id) -> Result<Option<BasicPassport<Id>>, Error> {
        self.use_ns_db().await?;
        let Some(db_passport): Option<BasicPassport<RecordId>> = self
            .db
            .select(RecordId::from_table_key(
                &self.scope_settings.table_names.passports,
                passport_id.to_string(),
            ))
            .await
            .map_err(|e| Error::PassportStorage(e.to_string()))?
        else {
            debug!("Could not find passport with id {passport_id} in database.");
            return Ok(None);
        };
        let id = db_passport.id.key().to_string();
        let id = id.trim_start_matches("⟨").trim_end_matches("⟩");
        Ok(Some(BasicPassport {
            id: Id::from_str(id).map_err(|e| {
                Error::Passport(format!("Could not convert id {id} from RecordId: {e}"))
            })?,
            groups: db_passport.groups,
            roles: db_passport.roles,
            disabled: db_passport.disabled,
            email_verified: db_passport.email_verified,
            expires_at: db_passport.expires_at,
        }))
    }

    async fn store_passport(&self, passport: &BasicPassport<Id>) -> Result<Option<Id>, Error> {
        self.use_ns_db().await?;
        let record_id = RecordId::from_table_key(
            &self.scope_settings.table_names.passports,
            passport.id.to_string(),
        );
        let db_passport = BasicPassport {
            id: None::<()>,
            groups: passport.groups.clone(),
            roles: passport.roles.clone(),
            disabled: passport.disabled,
            email_verified: passport.email_verified,
            expires_at: passport.expires_at,
        };

        let Some(db_passport): Option<BasicPassport<RecordId>> = self
            .db
            .insert(record_id)
            .content(db_passport)
            .await
            .map_err(|e| Error::PassportStorage(format!("Could not insert passport: {e}")))?
        else {
            debug!(
                "Inserting passport {} returned None. Maybe it is already available in the database?",
                passport.id
            );
            return Ok(None);
        };
        let id = db_passport.id.key().to_string();
        let id = id.trim_start_matches("⟨").trim_end_matches("⟩");
        Ok(Some(Id::from_str(id).map_err(|e| {
            Error::PassportStorage(format!("Could not convert id {id} from_str: {e}"))
        })?))
    }

    async fn remove_passport(&self, passport_id: &Id) -> Result<bool, Error> {
        self.use_ns_db().await?;
        let p: Option<BasicPassport<RecordId>> = self
            .db
            .delete(RecordId::from_table_key(
                &self.scope_settings.table_names.passports,
                passport_id.to_string(),
            ))
            .await
            .map_err(|e| Error::PassportStorage(e.to_string()))?;
        Ok(p.is_some())
    }
}

impl<Id, S, Hasher> CredentialsStorageService<Id> for SurrealDbStorage<S, Hasher>
where
    Id: Clone + Display + Serialize + 'static,
    Hasher: SecretsHashingService,
    S: Connection,
{
    async fn store_credentials(&self, credentials: Credentials<Id>) -> Result<bool, crate::Error> {
        self.use_ns_db().await?;

        let record_id = RecordId::from_table_key(
            &self.scope_settings.table_names.credentials,
            &credentials.id.to_string(),
        );
        let secret = self
            .hasher
            .hash_secret(&credentials.secret)
            .map_err(|e| Error::CredentialsStorage(e.to_string()))?;
        let db_credentials = Credentials::new(record_id, &secret);

        let result: Option<Credentials<RecordId>> = self
            .db
            .insert(&db_credentials.id)
            .content(db_credentials)
            .await
            .map_err(|e| Error::CredentialsStorage(e.to_string()))?;
        Ok(result.is_some())
    }

    async fn remove_credentials(&self, id: &Id) -> Result<bool, crate::Error> {
        self.use_ns_db().await?;
        let record_id = RecordId::from_table_key(
            &self.scope_settings.table_names.credentials,
            &id.to_string(),
        );
        let result: Option<Credentials<RecordId>> = self
            .db
            .delete(record_id)
            .await
            .map_err(|e| Error::CredentialsStorage(e.to_string()))?;
        Ok(result.is_some())
    }

    async fn update_credentials(&self, credentials: Credentials<Id>) -> Result<(), crate::Error> {
        self.use_ns_db().await?;
        let record_id = RecordId::from_table_key(
            &self.scope_settings.table_names.credentials,
            &credentials.id.to_string(),
        );
        let secret = self
            .hasher
            .hash_secret(&credentials.secret)
            .map_err(|e| Error::CredentialsStorage(e.to_string()))?;
        let db_credentials = Credentials::new(record_id, &secret);
        let _: Option<Credentials<RecordId>> = self
            .db
            .update(&db_credentials.id)
            .content(db_credentials)
            .await
            .map_err(|e| Error::CredentialsStorage(e.to_string()))?;
        Ok(())
    }
}

impl<Id, S, Hasher> CredentialsVerifierService<Id> for SurrealDbStorage<S, Hasher>
where
    Id: Display + Serialize,
    S: Connection,
    Hasher: SecretsHashingService,
{
    async fn verify_credentials(&self, credentials: &Credentials<Id>) -> Result<bool, Error> {
        self.use_ns_db().await?;
        let record_id = RecordId::from_table_key(
            &self.scope_settings.table_names.credentials,
            &credentials.id.to_string(),
        );
        let Some(db_credentials): Option<Credentials<RecordId>> =
            self.db
                .select(record_id)
                .await
                .map_err(|e| Error::CredentialsStorage(e.to_string()))?
        else {
            return Ok(false);
        };
        self.hasher
            .verify_secret(&credentials.secret, &db_credentials.secret)
    }
}

#[test]
fn credentials_storage() {
    tokio_test::block_on(async move {
        use crate::secrets::Argon2Hasher;
        use surrealdb::engine::local::Mem;

        // create a storage
        let db = Surreal::new::<Mem>(())
            .await
            .expect("Could not create in memory database.");
        let creds_storage =
            SurrealDbStorage::new(db, Argon2Hasher::default(), DatabaseScope::default());

        let creds = Credentials::new("admin@example.com", "admin_password");

        creds_storage.store_credentials(creds).await.unwrap();

        let creds_to_verify = Credentials::new("admin@example.com", "admin_password");
        let wrong_creds = Credentials::new("admin@example.com", "admin_passwordwrong");
        assert_eq!(
            false,
            creds_storage
                .verify_credentials(&wrong_creds)
                .await
                .unwrap()
        );
        assert_eq!(
            true,
            creds_storage
                .verify_credentials(&creds_to_verify)
                .await
                .unwrap()
        );
    })
}

#[test]
fn passport_storage() {
    tokio_test::block_on(async move {
        use crate::passport::Passport;
        use crate::roles::BasicRole;
        use crate::secrets::Argon2Hasher;
        use surrealdb::engine::local::Mem;
        use uuid::Uuid;

        let db = Surreal::new::<Mem>(())
            .await
            .expect("Could not create in memory database.");
        let hasher = Argon2Hasher::default();
        let passport_storage = SurrealDbStorage::new(db, hasher, DatabaseScope::default());

        let id = Uuid::new_v4();
        let passport = BasicPassport::new(&id, &["admin", "audio"], &[BasicRole::Admin]).unwrap();
        passport_storage.store_passport(&passport).await.unwrap();

        let Some(db_passport) = passport_storage.passport(&id).await.unwrap() else {
            panic!("Passport not found in storage.");
        };

        assert_eq!(passport.id(), db_passport.id());

        if !passport_storage
            .remove_passport(passport.id())
            .await
            .unwrap()
        {
            panic!("Removing passport was not successful.");
        };

        if passport_storage
            .passport(passport.id())
            .await
            .unwrap()
            .is_some()
        {
            panic!("Passport is still available althoug it should not.");
        };
    })
}
