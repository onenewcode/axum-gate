# `axum-gate` Distributed System Example with Nested Enum Permissions

This example demonstrates how to use `axum-gate` within a distributed system where all nodes share the same secret for encryption, featuring a type-safe nested enum permission system with strum serialization.

## Features

- **Zero-Sync Permissions**: No coordination required between distributed nodes
- **Type-Safe Nested Enums**: Organized permission structure with compile-time safety
- **Strum Integration**: Automatic serialization/deserialization support
- **Performance Optimized**: High-performance permission checking with roaring bitmaps
- **Collision Resistant**: SHA-256 based deterministic permission IDs

## Architecture

The example consists of three components:

1. **Auth Node** (`auth_node.rs`) - Issues JWT tokens with permission bitmaps
2. **Consumer Node** (`consumer_node.rs`) - Validates permissions without coordination
3. **Demo** (`demo.rs`) - Demonstrates the zero-sync permission system

## Permission Structure

The permissions are organized using nested enums for better type safety and categorization:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Display, EnumString, EnumIter)]
pub enum AppPermissions {
    Repository(RepositoryPermission),
    Api(ApiPermission),
    System(SystemPermission),
}

#[derive(Debug, Clone, Serialize, Deserialize, Display, EnumString, EnumIter)]
pub enum RepositoryPermission {
    Read,
    Write,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize, Display, EnumString, EnumIter)]
pub enum ApiPermission {
    Read,
    Write,
}

#[derive(Debug, Clone, Serialize, Deserialize, Display, EnumString, EnumIter)]
pub enum SystemPermission {
    Admin,
}
```

## Usage Examples

### Granting Permissions

```rust
use distributed::{AppPermissions, RepositoryPermission, ApiPermission, PermissionHelper};

let mut user_permissions = RoaringBitmap::new();

// Grant specific permission
PermissionHelper::grant_permission(
    &mut user_permissions,
    &AppPermissions::Repository(RepositoryPermission::Read)
);

// Grant category permissions
PermissionHelper::grant_repository_access(&mut user_permissions); // read + write
PermissionHelper::grant_api_access(&mut user_permissions); // read + write
PermissionHelper::grant_admin_access(&mut user_permissions); // all permissions
```

### Checking Permissions

```rust
// Direct permission check
let can_read = PermissionHelper::has_permission(
    &user.permissions,
    &AppPermissions::Repository(RepositoryPermission::Read)
);

// Helper methods
let can_access_repo = PermissionHelper::can_access_repository(&user.permissions);
let can_modify_repo = PermissionHelper::can_modify_repository(&user.permissions);
let is_admin = PermissionHelper::is_admin(&user.permissions);
```

### Using with Axum Gates

```rust
use axum_gate::{Gate, PermissionId};

let app = Router::new()
    .route("/api/data", get(get_data))
    .layer(
        Gate::new_cookie(issuer, jwt_codec)
            .grant_permission(PermissionId::from(
                AppPermissions::Api(ApiPermission::Read).as_str()
            ))
    );
```

### Serialization with Strum

```rust
// Convert to string
let perm = AppPermissions::Repository(RepositoryPermission::Read);
let as_string = perm.to_string(); // "repository(read)"

// Parse from string
let from_string = AppPermissions::from_str("repository(read)").unwrap();

// JSON serialization
let json = serde_json::to_string(&perm).unwrap();
let deserialized: AppPermissions = serde_json::from_str(&json).unwrap();
```

### Iteration Support

```rust
// Iterate over permission categories
for perm in AppPermissions::all_repository() {
    println!("Repository permission: {}", perm.as_str());
}

for perm in RepositoryPermission::iter() {
    println!("Repository action: {}", perm);
}
```

## Running the Example

### Prerequisites

Create a `.env` file in the distributed example directory:

```env
AXUM_GATE_SHARED_SECRET=your-super-secret-key-here-make-it-long-and-random
```

### Demo

Run the comprehensive demo to see the nested enum permission system in action:

```bash
cargo run --bin demo
```

### Auth Node

Start the authentication server:

```bash
cargo run --bin auth_node
```

The auth node runs on `http://127.0.0.1:3000` and provides:
- `POST /login` - Authenticate and receive JWT with permission bitmap
- `GET /logout` - Clear authentication cookie

Pre-configured users:
- `admin@example.com` / `admin_password` - Full admin permissions
- `reporter@example.com` / `reporter_password` - Repository read/write access
- `user@example.com` / `user_password` - API read access only

### Consumer Node

Start the consumer server:

```bash
cargo run --bin consumer_node
```

The consumer node runs on `http://127.0.0.1:3001` and provides:
- `/` - Public endpoint
- `/permissions` - Shows user's permission analysis (requires API read)
- `/user` - User-only endpoint
- `/reporter` - Reporter-only endpoint
- `/admin` - Admin-only endpoint
- `/secret-admin-group` - Admin group-only endpoint

## Key Benefits

✓ **Zero Coordination**: No synchronization required between nodes
✓ **Type Safety**: Compile-time validation of permission usage
✓ **High Performance**: Optimized bitmap operations
✓ **Deterministic**: Same permission always generates same ID
✓ **Collision Resistant**: SHA-256 based permission IDs
✓ **Serializable**: Full strum integration for easy persistence
✓ **Organized**: Logical permission categorization
✓ **Iterator Support**: Easy bulk operations on permission sets

## Architecture Advantages

### Traditional Distributed Auth
- Requires permission synchronization across nodes
- Network calls for permission updates
- Complex deployment coordination
- Risk of permission inconsistencies

### Axum-Gate Zero-Sync with Nested Enums
- No synchronization required
- Zero network overhead for permission checks
- Instant deployment across all nodes
- Type-safe permission management
- Automatic serialization support
- Organized permission structure

## Testing

Run the test suite:

```bash
cargo test
```

The tests verify:
- Deterministic permission ID generation
- Enum serialization/deserialization
- Permission checking logic
- Helper function behavior
- Category-based permission operations
