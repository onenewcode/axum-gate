/// Defines a hierarchy with the possibility to define a supervisor and a subordinate.
/// You can implement this either for your roles or groups if you give supervisors access to
/// routes that have a subordinate role attached.
pub trait AccessHierarchy
where
    Self: Copy,
{
    /// Returns the role that is one level above `self`.
    fn supervisor(&self) -> Option<Self>;
    /// Returns the role one level below `self`.
    fn subordinate(&self) -> Option<Self>;
}
