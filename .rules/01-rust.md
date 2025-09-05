
---
description: Enforces best practices for Rust development, focusing on context-aware code generation, modern patterns, and maintainable architecture. Provides comprehensive guidelines for writing clean, efficient, and secure Rust code with proper context.
globs: **/*.{rs,toml}
---
# Rust Best Practices

You are an expert in Rust programming and related technologies.
You understand modern Rust development practices, architectural patterns, and the importance of providing complete context in code generation.

### Context-Aware Code Generation
- Always provide complete module context including imports and module declarations
- Include relevant configuration files (Cargo.toml, Cargo.lock) when generating projects
- Generate complete function signatures with proper parameters, return types, and lifetimes
- Include comprehensive documentation comments explaining the purpose, parameters, and return values
- Provide context about the module's role in the larger system architecture
- Follow proper module organization and crate structure

### Code Style and Structure
- Follow Rust style guide and clean code principles
- Structure code in logical modules following domain-driven design
- Implement proper separation of concerns (handlers, services, repositories)
- Use modern Rust features (async/await, const generics, pattern matching) appropriately
- Maintain consistent code formatting using rustfmt
- Use proper trait design and composition
- Implement proper error handling with custom error types
- Use proper logging with structured data

### Type System and Ownership
- Use proper type definitions and traits
- Implement proper ownership patterns
- Use proper borrowing and lifetimes
- Implement proper smart pointers
- Use proper type conversions
- Implement proper generics and associated types
- Use proper type safety patterns
- Implement proper trait bounds

### Testing and Quality
- Write comprehensive unit tests with proper test context
- Include integration tests for critical paths
- Use proper test organization with test modules
- Implement proper test helpers and utilities
- Include performance tests for critical components
- Maintain high test coverage for core business logic
- Use proper test data factories
- Implement proper test doubles
- Use proper test organization with test attributes

### Security and Performance
- Implement proper input validation and sanitization
- Use secure authentication and token management
- Configure proper CORS and CSRF protection
- Implement rate limiting and request validation
- Use proper caching strategies
- Optimize memory usage and allocations
- Implement proper error handling and logging
- Use proper data validation and sanitization
- Implement proper access control

### API Design
- Follow RESTful principles with proper HTTP methods
- Use proper status codes and error responses
- Implement proper versioning strategies
- Document APIs using OpenAPI/Swagger
- Include proper request/response validation
- Implement proper pagination and filtering
- Use proper serialization and deserialization
- Implement proper rate limiting
- Use proper API authentication

### Concurrency and Parallelism
- Use proper async/await patterns
- Implement proper thread management
- Use proper synchronization primitives
- Implement proper message passing
- Use proper thread pools
- Implement proper error handling in async code
- Use proper resource cleanup
- Implement proper backpressure
- Use proper concurrent data structures

### Build and Deployment
- Use proper Cargo features and dependencies
- Implement proper CI/CD pipelines
- Use Docker for containerization
- Configure proper environment variables
- Implement proper logging and monitoring
- Use proper deployment strategies
- Implement proper backup strategies
- Use proper monitoring tools
- Implement proper error tracking

### Examples

```rust
//! User service module for handling user-related operations.
//! Provides methods for user management and authentication.

use std::error::Error;
use std::fmt;
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use tracing::{info, error};

/// Custom error type for user service operations.
#[derive(Debug)]
pub struct UserServiceError {
    message: String,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl fmt::Display for UserServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UserServiceError: {}", self.message)
    }
}

impl Error for UserServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as &dyn Error)
    }
}

/// User service for handling user-related operations.
#[derive(Debug)]
pub struct UserService {
    api_client: Arc<dyn ApiClient>,
    cache: Arc<Mutex<dyn Cache>>,
}

impl UserService {
    /// Creates a new UserService instance.
    pub fn new(api_client: Arc<dyn ApiClient>, cache: Arc<Mutex<dyn Cache>>) -> Self {
        Self { api_client, cache }
    }

    /// Finds a user by their email address.
    ///
    /// # Arguments
    ///
    /// * `email` - The email address to search for
    ///
    /// # Returns
    ///
    /// Returns a Result containing the user if found, or an error if the operation fails.
    pub async fn find_user_by_email(&self, email: &str) -> Result<Option<User>, UserServiceError> {
        // Check cache first
        if let Some(cached_user) = self.check_cache(email).await? {
            return Ok(Some(cached_user));
        }

        // Fetch from API
        match self.api_client.get_user(email).await {
            Ok(Some(user)) => {
                // Cache the result
                if let Err(e) = self.cache_user(&user).await {
                    error!("Failed to cache user: {}", e);
                }
                Ok(Some(user))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(UserServiceError {
                message: format!("Failed to find user by email: {}", e),
                source: Some(Box::new(e)),
            }),
        }
    }

    async fn check_cache(&self, email: &str) -> Result<Option<User>, UserServiceError> {
        let mut cache = self.cache.lock().await;
        match cache.get(&format!("user:{}", email)).await {
            Ok(Some(data)) => {
                info!("Cache hit for user: {}", email);
                serde_json::from_str(&data).map_err(|e| UserServiceError {
                    message: format!("Failed to deserialize cached user: {}", e),
                    source: Some(Box::new(e)),
                })
            }
            Ok(None) => Ok(None),
            Err(e) => Err(UserServiceError {
                message: format!("Cache error: {}", e),
                source: Some(Box::new(e)),
            }),
        }
    }

    async fn cache_user(&self, user: &User) -> Result<(), UserServiceError> {
        let mut cache = self.cache.lock().await;
        let data = serde_json::to_string(user).map_err(|e| UserServiceError {
            message: format!("Failed to serialize user: {}", e),
            source: Some(Box::new(e)),
        })?;

        cache.set(&format!("user:{}", user.email), &data).await.map_err(|e| UserServiceError {
            message: format!("Failed to cache user: {}", e),
            source: Some(Box::new(e)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use mockall::predicate::*;
    use mockall::mock;

    mock! {
        pub ApiClient {
            fn get_user(&self, email: &str) -> Result<Option<User>, Box<dyn Error + Send + Sync>>;
        }
    }

    mock! {
        pub Cache {
            fn get(&mut self, key: &str) -> Result<Option<String>, Box<dyn Error + Send + Sync>>;
            fn set(&mut self, key: &str, value: &str) -> Result<(), Box<dyn Error + Send + Sync>>;
        }
    }

    #[tokio::test]
    async fn test_find_user_by_email_cache_hit() {
        // Setup
        let mut mock_api = MockApiClient::new();
        let mut mock_cache = MockCache::new();

        let user = User {
            id: 1,
            email: "test@example.com".to_string(),
        };

        mock_cache.expect_get()
            .with(eq("user:test@example.com"))
            .returning(move |_| Ok(Some(serde_json::to_string(&user).unwrap())));

        let service = UserService::new(
            Arc::new(mock_api),
            Arc::new(Mutex::new(mock_cache)),
        );

        // Execute
        let result = service.find_user_by_email("test@example.com").await;

        // Verify
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(user));
    }

    #[tokio::test]
    async fn test_find_user_by_email_api_success() {
        // Setup
        let mut mock_api = MockApiClient::new();
        let mut mock_cache = MockCache::new();

        let user = User {
            id: 1,
            email: "test@example.com".to_string(),
        };

        mock_cache.expect_get()
            .with(eq("user:test@example.com"))
            .returning(|_| Ok(None));

        mock_api.expect_get_user()
            .with(eq("test@example.com"))
            .returning(move |_| Ok(Some(user.clone())));

        mock_cache.expect_set()
            .with(eq("user:test@example.com"), eq(serde_json::to_string(&user).unwrap()))
            .returning(|_, _| Ok(()));

        let service = UserService::new(
            Arc::new(mock_api),
            Arc::new(Mutex::new(mock_cache)),
        );

        // Execute
        let result = service.find_user_by_email("test@example.com").await;

        // Verify
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(user));
    }
}
