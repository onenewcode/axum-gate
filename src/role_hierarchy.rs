/// Hierarchy of roles. Used to check whether a user is authorized to access specific
/// resources.
pub trait RoleHierarchy
where
    Self: Copy,
{
    /// Returns the role that is one level above `self`.
    fn supervisor(&self) -> Option<Self>;
    /// Returns the role one level below `self`.
    fn subordinate(&self) -> Option<Self>;
}
