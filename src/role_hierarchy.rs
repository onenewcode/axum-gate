//! Available roles for your application.

/// Hierarchy of roles. Used for walking up and down the hierarchy of roles
/// for authorization.
pub trait RoleHierarchy
where
    Self: Copy,
{
    /// Returns the role that is one level above `self`.
    fn supervisor(&self) -> Option<Self>;
    /// Returns the role one level below `self`.
    fn subordinate(&self) -> Option<Self>;
}
