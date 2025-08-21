# Permission Validation Example

This example demonstrates the comprehensive permission validation capabilities provided by `axum-gate`. It showcases how to validate variable permission strings for duplicates and hash collisions, both at application startup and during runtime.

## Overview

The validation system in `axum-gate` provides runtime validation capabilities that complement the compile-time validation offered by the `validate_permissions!` macro. This is particularly useful when dealing with:

- Dynamic permission strings loaded from configuration files
- Permissions generated at runtime
- Distributed systems where permissions may change
- Permission sets that need validation during application lifecycle events

## Features Demonstrated

### 1. Static Permission Validation
```rust
use axum_gate::permissions::validation::ApplicationValidator;

let permissions = [
    "user:read:profile",
    "user:write:profile", 
    "admin:manage:system"
];

ApplicationValidator::new()
    .add_permissions(permissions)
    .validate()?;
```

### 2. Application-Level Validation
```rust
use axum_gate::permissions::validation::ApplicationValidator;

let validator = ApplicationValidator::new()
    .add_permissions(["user:read", "user:write"])
    .add_permission("admin:delete")
    .validate()?;
```

### 3. Detailed Collision Checking
```rust
use axum_gate::permissions::validation::PermissionCollisionChecker;

let mut checker = PermissionCollisionChecker::new(permissions);
let report = checker.validate()?;

if !report.is_valid() {
    println!("Issues found: {}", report.summary());
    report.log_results();
}
```

### 4. Runtime Validation
Validate permissions during application events like:
- Feature additions
- Configuration updates
- Permission cleanup operations
- Service deployment

### 5. Error Handling Patterns
- Strict validation with immediate failure
- Graceful degradation with fallback permissions
- Recovery mechanisms for common issues
- Detailed reporting for debugging

## Running the Example

```bash
cargo run --bin permission-validation-example
```

## Key Benefits

1. **Fail-Fast**: Catches permission issues at startup rather than runtime
2. **Comprehensive**: Checks both duplicate strings and hash collisions  
3. **Detailed Reporting**: Provides clear information about validation issues
4. **Flexible**: Handles permissions from multiple sources
5. **Zero Runtime Overhead**: Validation only runs when explicitly called
6. **Integration-Friendly**: Works seamlessly with existing `axum-gate` infrastructure

## Validation Types

### Duplicate String Detection
Identifies when the same permission string appears multiple times in your permission set.

### Hash Collision Detection
Detects when different permission strings hash to the same u32 value, which could cause authorization issues.

### Conflict Analysis
Provides detailed analysis of which permissions conflict and how they're distributed across hash IDs.

## Error Handling Approaches

The example demonstrates several error handling patterns:

1. **Strict Validation**: Fail immediately on any issues
2. **Detailed Reporting**: Get comprehensive information about problems
3. **Recovery Mechanisms**: Automatic deduplication and cleanup
4. **Graceful Degradation**: Fallback to safe permission sets when issues are detected

## Production Usage

In production applications, you would typically:

1. **Startup Validation**: Use `ApplicationValidator` during application initialization
2. **Runtime Updates**: Use `PermissionCollisionChecker` when permissions change
3. **Detailed Analysis**: Use validation reports for debugging and monitoring
4. **Error Recovery**: Implement fallback mechanisms for permission issues
5. **Collision Monitoring**: Monitor for hash collisions in distributed systems

Example production integration:

```rust
// Application startup
ApplicationValidator::new()
    .add_permissions(load_config_permissions()?)
    .add_permissions(load_database_permissions().await?)
    .validate()
    .context("Failed to validate permissions at startup")?;

// Runtime permission updates
fn update_user_permissions(new_permissions: Vec<String>) -> Result<()> {
    let mut checker = PermissionCollisionChecker::new(new_permissions);
    let report = checker.validate()?;
    
    if !report.is_valid() {
        warn!("Permission issues detected: {}", report.summary());
        report.log_results();
        // Handle according to your application's requirements
    }
    
    Ok(())
}
```

## Integration with axum-gate

This validation system works seamlessly with the existing `axum-gate` permission system:

- Uses the same `PermissionId::from_name()` hashing algorithm
- Compatible with `RoaringBitmap` permission storage
- Integrates with the zero-synchronization distributed permission model
- Complements compile-time validation macros

## Performance Considerations

- **Timing**: Designed for startup and configuration changes, not request-time validation
- **Complexity**: O(n) for both duplicate and collision detection
- **Memory**: Linear scaling with permission count during validation
- **Runtime**: Zero overhead once validation completes
- **Scalability**: Handles thousands of permissions efficiently

## API Overview

The validation system provides three main interfaces:

1. **`ApplicationValidator`** - High-level interface for application startup
2. **`PermissionCollisionChecker`** - Lower-level interface with detailed reporting  
3. **`ValidationReport`** - Comprehensive validation results and analysis

This clean, focused API ensures your variable permission strings don't cause security issues due to unexpected collisions while maintaining the zero-synchronization benefits of the deterministic hashing system.