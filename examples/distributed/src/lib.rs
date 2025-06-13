use num_enum::{IntoPrimitive, TryFromPrimitive};

/// Provides custom permissions for fine-grained access support.
#[derive(Debug, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(u32)]
#[non_exhaustive]
pub enum AdditionalPermission {
    ReadRepository,
    WriteRepository,
    ReadApi,
    WriteApi,
}
