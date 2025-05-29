//! Passport model to be used with [sea-orm].

use crate::Account;
use crate::CommaSeparatedValue;

use std::collections::HashSet;

use sea_orm::ActiveValue;
use sea_orm::entity::prelude::*;

/// Basic passport model for the use with [sea-orm].
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "axum-gate-accounts")]
pub struct Model {
    /// Primary key for storing in a database table.
    #[sea_orm(primary_key)]
    pub id: i32,
    /// The account id, eg an email address or a username.
    pub username: String,
    /// The groups this passport belongs to.
    pub groups: String,
    /// The roles this passport has.
    pub roles: String,
}

/// Relation definition for a [Passport](Model).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl<R> From<Account<i32, R>> for ActiveModel
where
    R: Eq + std::hash::Hash,
    HashSet<R>: CommaSeparatedValue,
{
    fn from(value: Account<i32, R>) -> Self {
        Self {
            id: ActiveValue::Set(value.id),
            username: ActiveValue::Set(value.username),
            groups: ActiveValue::Set(value.groups.into_csv()),
            roles: ActiveValue::Set(value.roles.into_csv()),
        }
    }
}
