//! Utility functions and traits that do not have a specific domain.

/// Conversion between a model and its CSV representation.
pub trait CommaSeparatedValue
where
    Self: Sized,
{
    /// Converts `self` into a comma separated value.
    fn into_csv(self) -> String;
    /// Converts the given slice into the model.
    fn from_csv(value: &str) -> Result<Self, String>;
}

/// Defines a hierarchy with the possibility to define a supervisor and a subordinate.
/// You can implement this for your roles if you give supervisors access to
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
