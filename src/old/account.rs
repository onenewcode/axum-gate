/*
#[cfg(feature = "storage-seaorm")]
impl<R> TryFrom<crate::storage::sea_orm::models::account::Model> for Account<i32, R>
where
    R: Eq + std::hash::Hash + std::fmt::Display + Clone,
    HashSet<R>: CommaSeparatedValue,
{
    type Error = String;

    fn try_from(
        value: crate::storage::sea_orm::models::account::Model,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            username: value.username,
            groups: HashSet::<Group>::from_csv(&value.groups)?,
            roles: HashSet::<R>::from_csv(&value.roles)?,
        })
    }
}
 */
