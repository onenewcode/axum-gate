//! Credentials model to be used with [sea-orm].

use crate::credentials::Credentials;

use std::fmt::Display;

use sea_orm::{ActiveValue, entity::prelude::*};

/// Credentials model for the use with [sea-orm].
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "axum-gate-credentials")]
pub struct Model {
    /// Primary key for storing in a database table.
    #[sea_orm(primary_key)]
    pub id: i32,
    /// The unique identifier, eg username.
    pub username: String,
    /// The actual secret.
    pub secret: String,
}

/// Relation definition for [Credentials](Model).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl<Id> From<Credentials<Id>> for ActiveModel
where
    Id: Display,
{
    fn from(value: Credentials<Id>) -> Self {
        Self {
            id: ActiveValue::NotSet,
            username: ActiveValue::Set(value.username),
            secret: ActiveValue::Set(value.secret),
        }
    }
}
