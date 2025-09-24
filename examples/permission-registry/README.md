# Permission Mapping Registry Example

This example demonstrates the optional **permission mapping registry pattern** in axum-gate, which enables reverse lookup from permission IDs back to their normalized string representations.

## Overview

The axum-gate permission system uses a high-performance bitmap-based storage approach where permission strings are hashed to 64-bit IDs. While this provides excellent performance for permission checking, it means the original permission strings cannot be recovered from the stored IDs.

The permission mapping registry provides an optional solution that allows you to:

- Store mappings between permission IDs and their normalized strings
- Perform reverse lookups for debugging and logging
- Build administrative interfaces with human-readable permission names
- Generate audit trails with meaningful permission descriptions

## Key Features

- **Optional**: Works alongside the existing bitmap system without replacing it
- **Performance**: The registry doesn't impact the core permission checking performance
- **Flexible**: Store original formatting, normalized strings, and computed IDs
- **Thread-safe**: Built with async/await and safe concurrency patterns
- **Validation**: Ensures consistency between strings and IDs

## Running the Example

```bash
# From the axum-gate root directory
cargo run -p permission-registry-example
```

## What the Example Demonstrates

### 1. Basic Registry Operations

- Creating permission mappings from strings
- Storing mappings in the repository
- Reverse lookup by permission ID
- Forward lookup by permission string (with normalization)
- Listing all stored mappings

### 2. Integration with Permissions

- Granting permissions using the bitmap system
- Storing corresponding mappings for reverse lookup
- Retrieving human-readable names for granted permissions

### 3. Account Integration

- Creating accounts with meaningful permission names
- Storing both the functional permissions and their descriptions
- Displaying account permissions with readable names

### 4. Repository Operations

- Removing mappings by ID or string
- Checking for mapping existence
- Bulk operations and cleanup

## Core Types

### `PermissionMapping`

The domain value object that represents a mapping:

```rust
use axum_gate::auth::PermissionMapping;

// Create from string (most common)
let mapping = PermissionMapping::from("read:api");

// Access components
println!("Normalized: {}", mapping.normalized_string()); // "read:api"
println!("ID: {}", mapping.id_as_u64());               // 4432869890453236604
```

### `PermissionMappingRepository`

The repository trait for storing and retrieving mappings:

```rust
use axum_gate::advanced::PermissionMappingRepository;
use axum_gate::storage::MemoryPermissionMappingRepository;

let repo = MemoryPermissionMappingRepository::default();

// Store a mapping
let mapping = PermissionMapping::from("write:file");
repo.store_mapping(mapping.clone()).await?;

// Query by ID
let found = repo.query_mapping_by_id(mapping.permission_id()).await?;

// Query by string (with normalization)
let found = repo.query_mapping_by_string("WRITE:FILE").await?; // Case insensitive
```

## Usage Patterns

### Service Layer Integration

```rust
async fn grant_permission_with_registry<R>(
    permissions: &mut Permissions,
    registry: &R,
    permission_str: &str,
) -> Result<()>
where
    R: PermissionMappingRepository,
{
    let mapping = PermissionMapping::from(permission_str);

    // Grant the permission (primary operation)
    permissions.grant(mapping.normalized_string());

    // Store the mapping for reverse lookup (optional)
    if let Err(e) = registry.store_mapping(mapping).await {
        // Log but don't fail the permission grant
        tracing::warn!("Failed to store permission mapping: {}", e);
    }

    Ok(())
}
```

### Debugging and Logging

```rust
// Log granted permissions with human-readable names
for permission_id in account.permissions.iter() {
    let id = PermissionId::from_u64(permission_id);
    match registry.query_mapping_by_id(id).await {
        Ok(Some(mapping)) => {
            info!("User has permission: {}", mapping.normalized_string());
        }
        Ok(None) => {
            warn!("Unknown permission ID: {}", permission_id);
        }
        Err(e) => {
            error!("Failed to lookup permission {}: {}", permission_id, e);
        }
    }
}
```

## Available Implementations

### In-Memory (`MemoryPermissionMappingRepository`)

Perfect for development, testing, and small applications:

```rust
use axum_gate::storage::MemoryPermissionMappingRepository;

let repo = MemoryPermissionMappingRepository::default();
```

### Production Implementations

For production use, you would typically implement the `PermissionMappingRepository` trait for your chosen database:

- SQL databases (PostgreSQL, MySQL, SQLite)
- NoSQL databases (MongoDB, DynamoDB)
- Key-value stores (Redis, etcd)

## Performance Considerations

- The registry is designed for **optional** use - core permission checking doesn't depend on it
- Lookups are O(1) for the in-memory implementation
- Consider caching strategies for frequently accessed mappings
- The registry can be populated asynchronously without blocking permission grants

## Error Handling

The example demonstrates proper error handling patterns:

- Registry failures don't prevent permission operations
- Validation ensures mapping consistency
- Graceful degradation when mappings aren't found

## When to Use

Consider using the permission mapping registry when you need:

- **Debugging**: Understanding what permissions are actually granted
- **Administrative UIs**: Showing human-readable permission lists
- **Audit Trails**: Recording permission changes with meaningful names
- **Reporting**: Generating permission reports and analytics
- **Development**: Easier debugging during development

The registry is **optional** - you can use axum-gate's high-performance permission system without it and add the registry later when needed.