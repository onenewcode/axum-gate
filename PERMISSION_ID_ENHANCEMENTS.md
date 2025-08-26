# PermissionId Enhancements: AsPermissionName Trait

This document describes the enhancements made to the `PermissionId` type to support nested enum permission definitions through the new `AsPermissionName` trait.

## Overview

The `PermissionId` has been enhanced to work seamlessly with structured permission enums, allowing for type-safe permission definitions while maintaining the same deterministic, zero-synchronization properties.

## New Features

### AsPermissionName Trait

A new trait `AsPermissionName` has been added to enable custom types to define their string representation for permission ID generation:

```rust
pub trait AsPermissionName {
    /// Convert the permission to its string representation.
    fn as_permission_name(&self) -> String;
}
```

### Enhanced PermissionId Methods

#### From Trait Implementation

Direct conversion from permission enums to PermissionId using the `From` trait:

```rust
impl<T: AsPermissionName> From<&T> for PermissionId
```

This provides a consistent API alongside the existing `From<&str>` and `From<String>` implementations.

## Usage Examples

### Basic Enum Implementation

```rust
use axum_gate::{AsPermissionName, PermissionId};

#[derive(Debug)]
enum AppPermission {
    Read,
    Write,
    Delete,
}

impl AsPermissionName for AppPermission {
    fn as_permission_name(&self) -> String {
        format!("app:{:?}", self).to_lowercase()
    }
}

// Usage
let read_perm = AppPermission::Read;
let permission_id = PermissionId::from(&read_perm);
```

### Nested Enum Structure (Distributed Example)

```rust
use axum_gate::{AsPermissionName, PermissionId};
use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

#[derive(Debug, Clone, Serialize, Deserialize, Display, EnumString)]
pub enum AppPermissions {
    Repository(RepositoryPermission),
    Api(ApiPermission),
    System(SystemPermission),
}

#[derive(Debug, Clone, Serialize, Deserialize, Display, EnumString)]
pub enum RepositoryPermission {
    Read,
    Write,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize, Display, EnumString)]
pub enum ApiPermission {
    Read,
    Write,
}

#[derive(Debug, Clone, Serialize, Deserialize, Display, EnumString)]
pub enum SystemPermission {
    Admin,
}

impl AsPermissionName for AppPermissions {
    fn as_permission_name(&self) -> String {
        match self {
            AppPermissions::Repository(perm) => format!("repository:{}", perm).to_lowercase(),
            AppPermissions::Api(perm) => format!("api:{}", perm).to_lowercase(),
            AppPermissions::System(perm) => format!("system:{}", perm).to_lowercase(),
        }
    }
}

// Usage
let repo_read = AppPermissions::Repository(RepositoryPermission::Read);
let api_write = AppPermissions::Api(ApiPermission::Write);

// All these methods produce the same result:
let id1 = PermissionId::from(repo_read.as_permission_name().as_str());
let id2 = PermissionId::from(&repo_read);

assert_eq!(id1, id2);
```

## Benefits

### 1. Type Safety
- Compile-time validation of permission names
- IntelliSense/autocomplete support
- Refactoring safety

### 2. Zero-Synchronization Maintained
- Same deterministic behavior as string-based permissions
- No coordination required between distributed nodes
- Identical permission IDs across all systems

### 3. Enhanced Developer Experience
- Clean, structured permission definitions
- Easier permission categorization
- Support for permission enumeration and iteration

### 4. Backward Compatibility
- Existing string-based permissions continue to work
- No breaking changes to existing APIs
- Gradual migration path available

## Migration Guide

### From String-Based Permissions

**Before:**
```rust
let permission_id = PermissionId::from_name("repository:read");
// or
let permission_id = PermissionId::from("repository:read");
```

**After:**
```rust
// Define your enum structure
#[derive(Debug)]
enum AppPermission {
    Repository(RepoPermission),
}

#[derive(Debug)]
enum RepoPermission {
    Read,
}

impl AsPermissionName for AppPermission {
    fn as_permission_name(&self) -> String {
        match self {
            AppPermission::Repository(perm) => format!("repository:{:?}", perm).to_lowercase(),
        }
    }
}

// Use the consistent From trait approach
let repo_read = AppPermission::Repository(RepoPermission::Read);
let permission_id = PermissionId::from(&repo_read);
```

### Integration with Permissions Struct

The enhanced `PermissionId` works seamlessly with the existing `Permissions` struct:

```rust
use axum_gate::Permissions;

let mut permissions = Permissions::new();
let repo_read = AppPermission::Repository(RepoPermission::Read);

// Direct enum support using From trait
permissions.grant(&repo_read);  // Uses From<&T> for PermissionId
permissions.has(&repo_read);    // Uses From<&T> for PermissionId
```

## Testing

The enhancements include comprehensive tests covering:

- Basic enum conversion
- Nested enum structures
- Deterministic ID generation
- Trait implementations
- Integration with existing APIs

Run the tests with:
```bash
cargo test permission_id
```

## Performance

The trait-based approach has minimal overhead:
- Single trait method call for string conversion
- Same SHA-256 hashing as string-based permissions  
- No additional memory allocations beyond string conversion
- Consistent `From` trait usage across all types (strings, enums, u32)

## Examples

See the `distributed` example for a complete implementation showing:
- Nested enum permission structures
- Integration with distributed systems
- Zero-synchronization across multiple nodes
- Performance benchmarking

```bash
cd examples/distributed
cargo run --bin demo
```

This will demonstrate the consistent `From` trait approach for both strings and enums, showing that they produce identical results while providing better type safety and developer experience.

## API Consistency

The enhanced `PermissionId` now provides a consistent API using the `From` trait for all conversion types:

- `PermissionId::from("string")` - from string literals
- `PermissionId::from(&string_var)` - from string variables
- `PermissionId::from(&permission_enum)` - from enums implementing `AsPermissionName`
- `PermissionId::from(u32_value)` - from raw u32 values

This eliminates the need for multiple different methods and provides a more idiomatic Rust experience.