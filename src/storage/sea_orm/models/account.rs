//! Passport model to be used with [sea-orm].

use crate::Account;
use crate::CommaSeparatedValue;

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
    pub account_id: String,
    /// The groups this passport belongs to.
    pub groups: String,
    /// The roles this passport has.
    pub roles: String,
    /// Whether the passport is disabled.
    pub disabled: bool,
    /// Expiration time of the passport.
    pub expires_at: DateTimeUtc,
}

/// Relation definition for a [Passport](Model).
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

impl From<Account<i32, String>> for ActiveModel {
    fn from(value: Account<i32, String>) -> Self {
        Self {
            id: ActiveValue::Set(value.id),
            account_id: ActiveValue::Set(value.account_id),
            groups: ActiveValue::Set(value.groups.into_csv()),
            roles: ActiveValue::Set(value.roles.into_csv()),
            disabled: ActiveValue::Set(value.disabled),
            expires_at: ActiveValue::Set(value.expires_at),
        }
    }
}
