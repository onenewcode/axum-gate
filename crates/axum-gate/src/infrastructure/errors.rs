//! Infrastructure layer error types for external system integration failures.
//!
//! This module contains error types that represent failures in external systems,
//! databases, web servers, and other infrastructure components.
//!
//! All infrastructure errors implement `UserFriendlyError` to provide appropriate
//! messaging for end users, developers, and support teams while maintaining
//! security and consistency.

use crate::errors::{ErrorSeverity, UserFriendlyError};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use thiserror::Error;

/// Infrastructure layer errors for external system integration failures.
///
/// These errors represent failures in external systems, databases, web servers,
/// and other infrastructure components.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InfrastructureError {
    /// Database operation error
    #[error("Database error: {operation} failed - {message}")]
    Database {
        /// The database operation that failed
        operation: DatabaseOperation,
        /// Description of the failure
        message: String,
        /// The table or collection involved
        table: Option<String>,
        /// The record ID if applicable
        record_id: Option<String>,
    },

    /// JWT token processing error
    #[error("JWT error: {operation} - {message}")]
    Jwt {
        /// The JWT operation that failed
        operation: JwtOperation,
        /// Description of the failure
        message: String,
        /// The token that caused the error (truncated for security)
        token_preview: Option<String>,
    },

    /// Network connectivity error
    #[error("Network error: {operation} - {message}")]
    Network {
        /// The network operation that failed
        operation: NetworkOperation,
        /// Description of the network failure
        message: String,
        /// The remote endpoint involved
        endpoint: Option<String>,
        /// HTTP status code if applicable
        status_code: Option<u16>,
    },

    /// External service integration error
    #[error("Service error: {service} - {message}")]
    ExternalService {
        /// The external service that failed
        service: String,
        /// Description of the service failure
        message: String,
        /// The operation being performed
        operation: Option<String>,
        /// Response code from the external service
        response_code: Option<String>,
    },

    /// File system operation error
    #[error("Filesystem error: {operation} - {message}")]
    FileSystem {
        /// The file system operation that failed
        operation: FileSystemOperation,
        /// Description of the failure
        message: String,
        /// The file path involved
        path: Option<String>,
        /// File permissions if relevant
        permissions: Option<String>,
    },

    /// Configuration loading or parsing error
    #[error("Configuration error: {component} - {message}")]
    Configuration {
        /// The configuration component that failed
        component: String,
        /// Description of the configuration failure
        message: String,
        /// The configuration key or section
        config_key: Option<String>,
        /// Expected format or type
        expected_format: Option<String>,
    },
}

/// Database operation types
#[derive(Debug, Clone)]
pub enum DatabaseOperation {
    /// Database connection operation
    Connect,
    /// Database query operation
    Query,
    /// Database insert operation
    Insert,
    /// Database update operation
    Update,
    /// Database delete operation
    Delete,
    /// Database migration operation
    Migration,
    /// Database backup operation
    Backup,
    /// Database transaction operation
    Transaction,
}

impl fmt::Display for DatabaseOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DatabaseOperation::Connect => write!(f, "connect"),
            DatabaseOperation::Query => write!(f, "query"),
            DatabaseOperation::Insert => write!(f, "insert"),
            DatabaseOperation::Update => write!(f, "update"),
            DatabaseOperation::Delete => write!(f, "delete"),
            DatabaseOperation::Migration => write!(f, "migration"),
            DatabaseOperation::Backup => write!(f, "backup"),
            DatabaseOperation::Transaction => write!(f, "transaction"),
        }
    }
}

/// JWT operation types
#[derive(Debug, Clone)]
pub enum JwtOperation {
    /// JWT encode operation
    Encode,
    /// JWT decode operation
    Decode,
    /// JWT validation operation
    Validate,
    /// JWT refresh operation
    Refresh,
    /// JWT revocation operation
    Revoke,
}

impl fmt::Display for JwtOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JwtOperation::Encode => write!(f, "encode"),
            JwtOperation::Decode => write!(f, "decode"),
            JwtOperation::Validate => write!(f, "validate"),
            JwtOperation::Refresh => write!(f, "refresh"),
            JwtOperation::Revoke => write!(f, "revoke"),
        }
    }
}

/// Network operation types
#[derive(Debug, Clone)]
pub enum NetworkOperation {
    /// HTTP request operation
    HttpRequest,
    /// DNS resolution operation
    DnsResolution,
    /// Socket connection operation
    SocketConnect,
    /// Data transfer operation
    DataTransfer,
    /// SSL/TLS handshake operation
    SslHandshake,
}

impl fmt::Display for NetworkOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkOperation::HttpRequest => write!(f, "http_request"),
            NetworkOperation::DnsResolution => write!(f, "dns_resolution"),
            NetworkOperation::SocketConnect => write!(f, "socket_connect"),
            NetworkOperation::DataTransfer => write!(f, "data_transfer"),
            NetworkOperation::SslHandshake => write!(f, "ssl_handshake"),
        }
    }
}

/// File system operation types
#[derive(Debug, Clone)]
pub enum FileSystemOperation {
    /// File read operation
    Read,
    /// File write operation
    Write,
    /// File delete operation
    Delete,
    /// Directory create operation
    CreateDir,
    /// File permission change operation
    ChangePermissions,
    /// File move operation
    Move,
    /// File copy operation
    Copy,
}

impl fmt::Display for FileSystemOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileSystemOperation::Read => write!(f, "read"),
            FileSystemOperation::Write => write!(f, "write"),
            FileSystemOperation::Delete => write!(f, "delete"),
            FileSystemOperation::CreateDir => write!(f, "create_directory"),
            FileSystemOperation::ChangePermissions => write!(f, "change_permissions"),
            FileSystemOperation::Move => write!(f, "move"),
            FileSystemOperation::Copy => write!(f, "copy"),
        }
    }
}

impl InfrastructureError {
    /// Create a database error
    pub fn database(operation: DatabaseOperation, message: impl Into<String>) -> Self {
        InfrastructureError::Database {
            operation,
            message: message.into(),
            table: None,
            record_id: None,
        }
    }

    /// Create a database error with table context
    pub fn database_with_context(
        operation: DatabaseOperation,
        message: impl Into<String>,
        table: Option<String>,
        record_id: Option<String>,
    ) -> Self {
        InfrastructureError::Database {
            operation,
            message: message.into(),
            table,
            record_id,
        }
    }

    /// Create a JWT error
    pub fn jwt(operation: JwtOperation, message: impl Into<String>) -> Self {
        InfrastructureError::Jwt {
            operation,
            message: message.into(),
            token_preview: None,
        }
    }

    /// Create a JWT error with token preview
    pub fn jwt_with_preview(
        operation: JwtOperation,
        message: impl Into<String>,
        token_preview: Option<String>,
    ) -> Self {
        InfrastructureError::Jwt {
            operation,
            message: message.into(),
            token_preview,
        }
    }

    /// Create a network error
    pub fn network(
        operation: NetworkOperation,
        message: impl Into<String>,
        endpoint: Option<String>,
        status_code: Option<u16>,
    ) -> Self {
        InfrastructureError::Network {
            operation,
            message: message.into(),
            endpoint,
            status_code,
        }
    }

    /// Create an external service error
    pub fn external_service(
        service: impl Into<String>,
        message: impl Into<String>,
        operation: Option<String>,
        response_code: Option<String>,
    ) -> Self {
        InfrastructureError::ExternalService {
            service: service.into(),
            message: message.into(),
            operation,
            response_code,
        }
    }

    /// Create a file system error
    pub fn file_system(
        operation: FileSystemOperation,
        message: impl Into<String>,
        path: Option<String>,
        permissions: Option<String>,
    ) -> Self {
        InfrastructureError::FileSystem {
            operation,
            message: message.into(),
            path,
            permissions,
        }
    }

    /// Create a configuration error
    pub fn configuration(
        component: impl Into<String>,
        message: impl Into<String>,
        config_key: Option<String>,
        expected_format: Option<String>,
    ) -> Self {
        InfrastructureError::Configuration {
            component: component.into(),
            message: message.into(),
            config_key,
            expected_format,
        }
    }

    /// Generate a deterministic support code based on error content
    fn generate_support_code(&self) -> String {
        let mut hasher = DefaultHasher::new();
        match self {
            InfrastructureError::Database {
                operation, table, ..
            } => {
                format!("DB-{}-{:X}", operation.to_string().to_uppercase(), {
                    format!("{:?}{:?}", operation, table).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
            InfrastructureError::Jwt { operation, .. } => {
                format!("JWT-{}", operation.to_string().to_uppercase())
            }
            InfrastructureError::Network {
                operation,
                status_code,
                ..
            } => {
                if let Some(code) = status_code {
                    format!("NET-{}-{}", operation.to_string().to_uppercase(), code)
                } else {
                    format!("NET-{}-ERROR", operation.to_string().to_uppercase())
                }
            }
            InfrastructureError::ExternalService {
                service,
                response_code,
                ..
            } => {
                service.hash(&mut hasher);
                let service_hash = hasher.finish() % 10000;
                if let Some(code) = response_code {
                    format!("EXT-{}-{:X}", code, service_hash)
                } else {
                    format!("EXT-SERVICE-{:X}", service_hash)
                }
            }
            InfrastructureError::FileSystem { operation, .. } => {
                format!("FS-{}-ERROR", operation.to_string().to_uppercase())
            }
            InfrastructureError::Configuration { component, .. } => {
                component.hash(&mut hasher);
                format!("CONFIG-{:X}", hasher.finish() % 10000)
            }
        }
    }
}

impl UserFriendlyError for InfrastructureError {
    fn user_message(&self) -> String {
        match self {
            InfrastructureError::Database { operation, .. } => {
                match operation {
                    DatabaseOperation::Connect => "We're having trouble connecting to our database. Please try again in a moment.".to_string(),
                    DatabaseOperation::Query | DatabaseOperation::Insert | DatabaseOperation::Update | DatabaseOperation::Delete => {
                        "We're experiencing technical difficulties with our data services. Please try again shortly.".to_string()
                    }
                    DatabaseOperation::Migration | DatabaseOperation::Backup => {
                        "Our system is currently undergoing maintenance. Please try again later.".to_string()
                    }
                    DatabaseOperation::Transaction => {
                        "We couldn't complete your request due to a technical issue. Please try again.".to_string()
                    }
                }
            }
            InfrastructureError::Jwt { operation, .. } => {
                match operation {
                    JwtOperation::Encode | JwtOperation::Refresh => {
                        "We're having trouble with the authentication system. Please try signing in again.".to_string()
                    }
                    JwtOperation::Decode | JwtOperation::Validate => {
                        "Your session appears to be invalid. Please sign in again to continue.".to_string()
                    }
                    JwtOperation::Revoke => {
                        "We couldn't complete the sign-out process. You may already be signed out.".to_string()
                    }
                }
            }
            InfrastructureError::Network { status_code, .. } => {
                match status_code {
                    Some(404) => "The requested resource could not be found. Please check the URL and try again.".to_string(),
                    Some(500..=599) => "We're experiencing server issues. Please try again in a few minutes.".to_string(),
                    Some(400..=499) => "There was an issue with your request. Please check your information and try again.".to_string(),
                    _ => "We're having network connectivity issues. Please check your internet connection and try again.".to_string(),
                }
            }
            InfrastructureError::ExternalService { .. } => {
                "We're having trouble connecting to an external service that we depend on. Please try again in a few minutes.".to_string()
            }
            InfrastructureError::FileSystem { operation, .. } => {
                match operation {
                    FileSystemOperation::Read => "We couldn't access a required file. Please try again or contact support.".to_string(),
                    FileSystemOperation::Write => "We couldn't save your data right now. Please try again in a moment.".to_string(),
                    FileSystemOperation::Delete => "We couldn't delete the requested item. Please try again later.".to_string(),
                    FileSystemOperation::CreateDir => "We couldn't create the necessary directories. Please contact support.".to_string(),
                    FileSystemOperation::ChangePermissions => "There's an issue with file permissions. Please contact our support team.".to_string(),
                    FileSystemOperation::Move | FileSystemOperation::Copy => "We couldn't complete the file operation. Please try again.".to_string(),
                }
            }
            InfrastructureError::Configuration { .. } => {
                "There's a configuration issue that's preventing the system from working properly. Our technical team has been notified.".to_string()
            }
        }
    }

    fn developer_message(&self) -> String {
        match self {
            InfrastructureError::Database {
                operation,
                message,
                table,
                record_id,
            } => {
                let table_context = table
                    .as_ref()
                    .map(|t| format!(" [Table: {}]", t))
                    .unwrap_or_default();
                let record_context = record_id
                    .as_ref()
                    .map(|r| format!(" [Record: {}]", r))
                    .unwrap_or_default();
                format!(
                    "Database {} operation failed: {}{}{}",
                    operation, message, table_context, record_context
                )
            }
            InfrastructureError::Jwt {
                operation,
                message,
                token_preview,
            } => {
                let token_context = token_preview
                    .as_ref()
                    .map(|t| format!(" [Token Preview: {}]", t))
                    .unwrap_or_default();
                format!(
                    "JWT {} operation failed: {}{}",
                    operation, message, token_context
                )
            }
            InfrastructureError::Network {
                operation,
                message,
                endpoint,
                status_code,
            } => {
                let endpoint_context = endpoint
                    .as_ref()
                    .map(|e| format!(" [Endpoint: {}]", e))
                    .unwrap_or_default();
                let status_context = status_code
                    .map(|s| format!(" [Status: {}]", s))
                    .unwrap_or_default();
                format!(
                    "Network {} operation failed: {}{}{}",
                    operation, message, endpoint_context, status_context
                )
            }
            InfrastructureError::ExternalService {
                service,
                message,
                operation,
                response_code,
            } => {
                let operation_context = operation
                    .as_ref()
                    .map(|op| format!(" [Operation: {}]", op))
                    .unwrap_or_default();
                let response_context = response_code
                    .as_ref()
                    .map(|r| format!(" [Response: {}]", r))
                    .unwrap_or_default();
                format!(
                    "External service '{}' integration failed: {}{}{}",
                    service, message, operation_context, response_context
                )
            }
            InfrastructureError::FileSystem {
                operation,
                message,
                path,
                permissions,
            } => {
                let path_context = path
                    .as_ref()
                    .map(|p| format!(" [Path: {}]", p))
                    .unwrap_or_default();
                let perms_context = permissions
                    .as_ref()
                    .map(|p| format!(" [Permissions: {}]", p))
                    .unwrap_or_default();
                format!(
                    "Filesystem {} operation failed: {}{}{}",
                    operation, message, path_context, perms_context
                )
            }
            InfrastructureError::Configuration {
                component,
                message,
                config_key,
                expected_format,
            } => {
                let key_context = config_key
                    .as_ref()
                    .map(|k| format!(" [Key: {}]", k))
                    .unwrap_or_default();
                let format_context = expected_format
                    .as_ref()
                    .map(|f| format!(" [Expected: {}]", f))
                    .unwrap_or_default();
                format!(
                    "Configuration error in component '{}': {}{}{}",
                    component, message, key_context, format_context
                )
            }
        }
    }

    fn support_code(&self) -> String {
        self.generate_support_code()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            InfrastructureError::Database { operation, .. } => match operation {
                DatabaseOperation::Connect => ErrorSeverity::Critical,
                DatabaseOperation::Migration | DatabaseOperation::Backup => ErrorSeverity::Critical,
                _ => ErrorSeverity::Error,
            },
            InfrastructureError::Jwt { operation, .. } => match operation {
                JwtOperation::Encode | JwtOperation::Refresh => ErrorSeverity::Error,
                _ => ErrorSeverity::Warning,
            },
            InfrastructureError::Network { status_code, .. } => match status_code {
                Some(500..=599) => ErrorSeverity::Critical,
                Some(400..=499) => ErrorSeverity::Warning,
                _ => ErrorSeverity::Error,
            },
            InfrastructureError::ExternalService { .. } => ErrorSeverity::Error,
            InfrastructureError::FileSystem { operation, .. } => match operation {
                FileSystemOperation::Write => ErrorSeverity::Critical,
                FileSystemOperation::ChangePermissions => ErrorSeverity::Error,
                _ => ErrorSeverity::Warning,
            },
            InfrastructureError::Configuration { .. } => ErrorSeverity::Critical,
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            InfrastructureError::Database { operation, .. } => match operation {
                DatabaseOperation::Connect => vec![
                    "Wait a few minutes and try again".to_string(),
                    "Check our status page for any database maintenance notifications".to_string(),
                    "Contact support if the issue persists for more than 15 minutes".to_string(),
                ],
                DatabaseOperation::Query
                | DatabaseOperation::Insert
                | DatabaseOperation::Update
                | DatabaseOperation::Delete => vec![
                    "Try your request again in a moment".to_string(),
                    "Refresh the page and attempt the operation again".to_string(),
                    "Save your work locally if possible and try again later".to_string(),
                    "Contact support if you continue to experience issues".to_string(),
                ],
                DatabaseOperation::Migration | DatabaseOperation::Backup => vec![
                    "This is a system maintenance issue that will be resolved automatically"
                        .to_string(),
                    "Check our status page for maintenance schedules".to_string(),
                    "No action is required from you at this time".to_string(),
                ],
                DatabaseOperation::Transaction => vec![
                    "Try completing your transaction again".to_string(),
                    "Ensure all required information is provided".to_string(),
                    "Contact support if the transaction continues to fail".to_string(),
                ],
            },
            InfrastructureError::Jwt { operation, .. } => match operation {
                JwtOperation::Encode | JwtOperation::Refresh => vec![
                    "Try signing in again".to_string(),
                    "Clear your browser cookies and try again".to_string(),
                    "Contact support if you cannot sign in after multiple attempts".to_string(),
                ],
                JwtOperation::Decode | JwtOperation::Validate => vec![
                    "Sign out completely and sign back in".to_string(),
                    "Clear your browser cache and cookies".to_string(),
                    "Try using a different browser or incognito mode".to_string(),
                ],
                JwtOperation::Revoke => vec![
                    "You may already be signed out successfully".to_string(),
                    "Clear your browser data to ensure complete sign-out".to_string(),
                    "Close all browser windows for security".to_string(),
                ],
            },
            InfrastructureError::Network { status_code, .. } => match status_code {
                Some(404) => vec![
                    "Check the URL for typos and try again".to_string(),
                    "The page may have been moved or removed".to_string(),
                    "Use the navigation menu to find what you're looking for".to_string(),
                    "Contact support if you believe this page should exist".to_string(),
                ],
                Some(500..=599) => vec![
                    "Wait a few minutes and try again".to_string(),
                    "Check our status page for any ongoing issues".to_string(),
                    "Try refreshing the page".to_string(),
                    "Contact support if the problem persists".to_string(),
                ],
                Some(400..=499) => vec![
                    "Check that all required information is provided correctly".to_string(),
                    "Ensure you have permission to access this resource".to_string(),
                    "Try signing out and back in".to_string(),
                    "Contact support if you believe you should have access".to_string(),
                ],
                _ => vec![
                    "Check your internet connection".to_string(),
                    "Try refreshing the page".to_string(),
                    "Switch to a different network if possible".to_string(),
                    "Contact support if connectivity issues persist".to_string(),
                ],
            },
            InfrastructureError::ExternalService { .. } => vec![
                "Wait a few minutes and try your request again".to_string(),
                "This is likely a temporary issue with a service we depend on".to_string(),
                "Check our status page for any known service disruptions".to_string(),
                "Contact support if the issue continues for an extended period".to_string(),
            ],
            InfrastructureError::FileSystem { operation, .. } => match operation {
                FileSystemOperation::Read => vec![
                    "Try refreshing the page".to_string(),
                    "The file may be temporarily unavailable".to_string(),
                    "Contact support if you continue to experience issues".to_string(),
                ],
                FileSystemOperation::Write => vec![
                    "Ensure you have sufficient storage space".to_string(),
                    "Try saving your work again in a few minutes".to_string(),
                    "Contact support immediately if you're losing important data".to_string(),
                ],
                FileSystemOperation::Delete => vec![
                    "Try the delete operation again".to_string(),
                    "The item may already have been deleted".to_string(),
                    "Refresh the page to see the current state".to_string(),
                ],
                FileSystemOperation::CreateDir => vec![
                    "This is typically a system administration issue".to_string(),
                    "Contact our support team for assistance".to_string(),
                    "This may be related to storage capacity or permissions".to_string(),
                ],
                FileSystemOperation::ChangePermissions => vec![
                    "This requires system administrator intervention".to_string(),
                    "Contact our support team immediately".to_string(),
                    "Do not attempt to retry this operation".to_string(),
                ],
                FileSystemOperation::Move | FileSystemOperation::Copy => vec![
                    "Try the operation again in a few minutes".to_string(),
                    "Ensure the destination has sufficient space".to_string(),
                    "Contact support if file operations continue to fail".to_string(),
                ],
            },
            InfrastructureError::Configuration { .. } => vec![
                "This is a system configuration issue that requires administrator attention"
                    .to_string(),
                "Our technical team has been automatically notified".to_string(),
                "No action is required from you at this time".to_string(),
                "Contact support if this issue is blocking critical work".to_string(),
            ],
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            InfrastructureError::Database { operation, .. } => match operation {
                DatabaseOperation::Connect => true, // Connection issues often resolve
                DatabaseOperation::Migration | DatabaseOperation::Backup => false, // System operations
                _ => true,
            },
            InfrastructureError::Jwt { operation, .. } => match operation {
                JwtOperation::Encode | JwtOperation::Refresh => true, // User can retry auth
                JwtOperation::Revoke => false,                        // Revocation is final
                _ => true,
            },
            InfrastructureError::Network { status_code, .. } => match status_code {
                Some(404) => false,      // Resource doesn't exist
                Some(403) => false,      // Forbidden - permissions issue
                Some(401) => true,       // Unauthorized - can re-authenticate
                Some(500..=599) => true, // Server errors often temporary
                _ => true,
            },
            InfrastructureError::ExternalService { .. } => true, // External services may recover
            InfrastructureError::FileSystem { operation, .. } => match operation {
                FileSystemOperation::ChangePermissions => false, // Requires admin
                _ => true,
            },
            InfrastructureError::Configuration { .. } => false, // Config issues need admin fix
        }
    }
}
