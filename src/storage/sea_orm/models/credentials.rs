//! Credentials model to be used with [sea-orm].

use crate::secrets::Secret;

use sea_orm::{ActiveValue, entity::prelude::*};

/// Credentials model for the use with [sea-orm].
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "axum-gate-credentials")]
pub struct Model {
    /// Primary key for storing in a database table.
    #[sea_orm(primary_key)]
    pub id: i32,
    /// The unique identifier, eg username.
    pub account_id: Uuid,
    /// The actual secret.
    pub secret: String,
}

/// Relation definition for [Credentials](Model).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl From<Secret> for ActiveModel {
    fn from(value: Secret) -> Self {
        Self {
            id: ActiveValue::NotSet,
            account_id: ActiveValue::Set(value.account_id),
            secret: ActiveValue::Set(value.secret),
        }
    }
}
