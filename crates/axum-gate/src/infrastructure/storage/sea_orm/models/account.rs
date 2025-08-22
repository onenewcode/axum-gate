//! Passport model to be used with [sea-orm].

use crate::Account;
use crate::domain::traits::{AccessHierarchy, CommaSeparatedValue};

use sea_orm::ActiveValue;
use sea_orm::entity::prelude::*;

/// Basic passport model for the use with [sea-orm].
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "axum-gate-accounts")]
pub struct Model {
    /// Primary key for storing in a database table.
    #[sea_orm(primary_key)]
    pub id: i32,
    /// The unique account id.
    pub account_id: Uuid,
    /// The user id, eg an email address or a username.
    pub user_id: String,
    /// The groups this passport belongs to.
    pub groups: String,
    /// The roles this passport has.
    pub roles: String,
}

/// Relation definition for a [Passport](Model).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl<R, G> From<Account<R, G>> for ActiveModel
where
    R: AccessHierarchy + Eq,
    Vec<R>: CommaSeparatedValue,
    G: Eq,
    Vec<G>: CommaSeparatedValue,
{
    fn from(value: Account<R, G>) -> Self {
        Self {
            id: ActiveValue::NotSet,
            account_id: ActiveValue::Set(value.account_id),
            user_id: ActiveValue::Set(value.user_id),
            groups: ActiveValue::Set(value.groups.into_csv()),
            roles: ActiveValue::Set(value.roles.into_csv()),
        }
    }
}
