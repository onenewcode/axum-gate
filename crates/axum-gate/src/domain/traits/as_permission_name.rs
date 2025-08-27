/// Trait for types that can be converted to permission names.
///
/// This trait allows permission enums to define their string representation
/// for use with PermissionId. Typically implemented by nested permission enums
/// that provide structured permission definitions.
pub trait AsPermissionName {
    /// Convert the permission to its string representation.
    fn as_permission_name(&self) -> String;
}
