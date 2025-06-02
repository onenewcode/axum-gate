//! Storage implementations that use surrealdb as backend.

use super::TableNames;
use crate::AccessHierarchy;
use crate::Account;
use crate::Error;
use crate::credentials::{Credentials, CredentialsVerifierService};
use crate::secrets::SecretsHashingService;
use crate::storage::CredentialsStorageService;
use crate::storage::PassportStorageService;

use std::default::Default;
use std::fmt::Display;
use std::str::FromStr;

use serde::Serialize;
use serde::de::DeserializeOwned;
use surrealdb::{Connection, RecordId, Surreal};
use tracing::debug;

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

impl<Id, R, S, Hasher> PassportStorageService<Account<Id, R>> for SurrealDbStorage<S, Hasher>
where
    Id: Clone + Display + FromStr,
    <Id as FromStr>::Err: Display,
    R: AccessHierarchy + std::hash::Hash + Eq + DeserializeOwned + Serialize + 'static,
    Hasher: SecretsHashingService,
    S: Connection,
{
    async fn passport(&self, passport_id: &Id) -> Result<Option<Account<Id, R>>, Error> {
        self.use_ns_db().await?;
        let Some(db_passport): Option<Account<RecordId, R>> = self
            .db
            .select(RecordId::from_table_key(
                &self.scope_settings.table_names.accounts,
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
        Ok(Some(Account {
            id: Id::from_str(id).map_err(|e| {
                Error::Passport(format!("Could not convert id {id} from RecordId: {e}"))
            })?,
            username: db_passport.username,
            groups: db_passport.groups,
            roles: db_passport.roles,
        }))
    }

    async fn store_passport(&self, passport: &Account<Id, R>) -> Result<Option<Id>, Error> {
        self.use_ns_db().await?;
        let record_id = RecordId::from_table_key(
            &self.scope_settings.table_names.accounts,
            passport.id.to_string(),
        );
        let db_passport = Account {
            id: None::<()>,
            username: passport.username.clone(),
            groups: passport.groups.clone(),
            roles: passport.roles.clone(),
        };

        let Some(db_passport): Option<Account<RecordId, R>> = self
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

    async fn remove_passport(&self, passport_id: &Id) -> Result<Option<Account<Id, R>>, Error> {
        self.use_ns_db().await?;
        let p: Option<Account<RecordId, R>> = self
            .db
            .delete(RecordId::from_table_key(
                &self.scope_settings.table_names.accounts,
                passport_id.to_string(),
            ))
            .await
            .map_err(|e| Error::PassportStorage(e.to_string()))?;
        let p = p.map(|acc| Account {
            id: passport_id.clone(),
            username: acc.username,
            roles: acc.roles,
            groups: acc.groups,
        });
        Ok(p)
    }
}

impl<Id, S, Hasher> CredentialsStorageService<Id> for SurrealDbStorage<S, Hasher>
where
    Id: Clone + Display + Serialize + FromStr + 'static,
    <Id as FromStr>::Err: Display,
    Hasher: SecretsHashingService,
    S: Connection,
{
    async fn store_credentials(
        &self,
        credentials: Credentials<Id>,
    ) -> Result<Credentials<Id>, crate::Error> {
        self.use_ns_db().await?;

        let record_id = RecordId::from_table_key(
            &self.scope_settings.table_names.credentials,
            &credentials.id.to_string(),
        );
        let secret = self
            .hasher
            .hash_secret(&credentials.secret)
            .map_err(|e| Error::CredentialsStorage(e.to_string()))?;
        let db_credentials = Credentials::new(&record_id, &secret);

        let Some(result): Option<Credentials<RecordId>> = self
            .db
            .insert(&db_credentials.id)
            .content(db_credentials)
            .await
            .map_err(|e| Error::CredentialsStorage(e.to_string()))?
        else {
            return Err(Error::CredentialsStorage(
                "Insertion of credentials returned None due to an unknown reason.".to_string(),
            ));
        };
        let id = result.id.key().to_string();
        let id = id.trim_start_matches("⟨").trim_end_matches("⟩");
        Ok(Credentials::new(
            &Id::from_str(id).map_err(|e| Error::CredentialsStorage(e.to_string()))?,
            &result.secret,
        ))
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
        let db_credentials = Credentials::new(&record_id, &secret);
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
        let query = format!(
            "crypto::argon2::compare((SELECT secret from only $record_id).secret, type::string($request_secret))"
        );

        let mut response = self
            .db
            .query(query)
            .bind(("record_id", record_id))
            .bind(("request_secret", credentials.secret.clone()))
            .await
            .map_err(|e| Error::CredentialsStorage(e.to_string()))?;
        let result: Option<bool> = response
            .take(0)
            .map_err(|e| Error::CredentialsStorage(e.to_string()))?;
        Ok(result.unwrap_or(false))
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

        let creds = Credentials::new(&"admin@example.com".to_string(), "admin_password");

        creds_storage.store_credentials(creds).await.unwrap();

        let creds_to_verify = Credentials::new(&"admin@example.com", "admin_password");
        let wrong_creds = Credentials::new(&"admin@example.com", "admin_passwordwrong");
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
        use crate::roles::Role;
        use crate::secrets::Argon2Hasher;
        use surrealdb::engine::local::Mem;
        use uuid::Uuid;

        let db = Surreal::new::<Mem>(())
            .await
            .expect("Could not create in memory database.");
        let hasher = Argon2Hasher::default();
        let passport_storage = SurrealDbStorage::new(db, hasher, DatabaseScope::default());

        let id = Uuid::new_v4();
        let passport = Account::new(
            &id,
            "mymail@accountid-example.com",
            &["admin", "audio"],
            &[Role::Admin],
        );
        passport_storage.store_passport(&passport).await.unwrap();

        let Some(db_passport): Option<Account<Uuid, Role>> =
            passport_storage.passport(&id).await.unwrap()
        else {
            panic!("Passport not found in storage.");
        };

        assert_eq!(passport.id(), db_passport.id());

        let account: Option<Account<Uuid, Role>> = passport_storage
            .remove_passport(passport.id())
            .await
            .unwrap();
        if !account.is_some() {
            panic!("Removing passport was not successful.");
        };

        let passport: Option<Account<Uuid, Role>> =
            passport_storage.passport(passport.id()).await.unwrap();
        if passport.is_some() {
            panic!("Passport is still available althoug it should not.");
        };
    })
}
