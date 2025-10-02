//! Ports layer error types for interface contract violations.
//!
//! This module contains error types that represent failures in port interfaces
//! and contract violations between the application layer and external adapters.
//!
//! All port errors implement `UserFriendlyError` to provide appropriate
//! messaging for end users, developers, and support teams while maintaining
//! security and consistency.

use crate::errors::{ErrorSeverity, UserFriendlyError};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};
use thiserror::Error;

/// Port layer errors for interface contract violations.
///
/// These errors occur when adapters fail to properly implement port interfaces
/// or when there are contract violations between layers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PortError {
    /// Repository contract violation
    #[error("Repository error: {repository} - {message}")]
    Repository {
        /// The type of repository
        repository: RepositoryType,
        /// Description of the repository error
        message: String,
        /// The operation that failed
        operation: Option<String>,
        /// Additional context about the failure
        context: Option<String>,
    },

    /// Codec contract violation
    #[error("Codec error: {operation} - {message}")]
    Codec {
        /// The codec operation that failed
        operation: CodecOperation,
        /// Description of the codec error
        message: String,
        /// The payload type being processed
        payload_type: Option<String>,
        /// Expected format or structure
        expected_format: Option<String>,
    },

    /// Hashing service contract violation
    #[error("Hashing error: {operation} - {message}")]
    Hashing {
        /// The hashing operation that failed
        operation: HashingOperation,
        /// Description of the hashing error
        message: String,
        /// The hashing algorithm used
        algorithm: Option<String>,
        /// Expected hash format
        expected_format: Option<String>,
    },

    /// Serialization/Deserialization error
    #[error("Serialization error: {operation} - {message}")]
    Serialization {
        /// The serialization operation that failed
        operation: SerializationOperation,
        /// Description of the serialization error
        message: String,
        /// The data format being processed
        format: Option<String>,
        /// The field that caused the error
        field: Option<String>,
    },

    /// Cache interface contract violation
    #[error("Cache error: {operation} - {message}")]
    Cache {
        /// The cache operation that failed
        operation: CacheOperation,
        /// Description of the cache error
        message: String,
        /// The cache key involved
        cache_key: Option<String>,
        /// TTL or expiration info
        ttl: Option<String>,
    },

    /// Message queue interface contract violation
    #[error("Message queue error: {operation} - {message}")]
    MessageQueue {
        /// The queue operation that failed
        operation: QueueOperation,
        /// Description of the queue error
        message: String,
        /// The queue name involved
        queue_name: Option<String>,
        /// The message ID if applicable
        message_id: Option<String>,
    },
}

/// Repository type identifiers
#[derive(Debug, Clone)]
pub enum RepositoryType {
    /// Account repository
    Account,
    /// Secret repository
    Secret,
    /// Session repository
    Session,
    /// Permission repository
    Permission,
    /// Permission mapping repository
    PermissionMapping,
    /// Audit log repository
    AuditLog,
}

impl fmt::Display for RepositoryType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RepositoryType::Account => write!(f, "account"),
            RepositoryType::Secret => write!(f, "secret"),
            RepositoryType::Session => write!(f, "session"),
            RepositoryType::Permission => write!(f, "permission"),
            RepositoryType::PermissionMapping => write!(f, "permission_mapping"),
            RepositoryType::AuditLog => write!(f, "audit_log"),
        }
    }
}

/// Codec operation types
#[derive(Debug, Clone)]
pub enum CodecOperation {
    /// Encode operation
    Encode,
    /// Decode operation
    Decode,
    /// Serialize operation
    Serialize,
    /// Deserialize operation
    Deserialize,
    /// Validate operation
    Validate,
}

impl fmt::Display for CodecOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodecOperation::Encode => write!(f, "encode"),
            CodecOperation::Decode => write!(f, "decode"),
            CodecOperation::Serialize => write!(f, "serialize"),
            CodecOperation::Deserialize => write!(f, "deserialize"),
            CodecOperation::Validate => write!(f, "validate"),
        }
    }
}

/// Hashing operation types
#[derive(Debug, Clone)]
pub enum HashingOperation {
    /// Hash operation
    Hash,
    /// Verify operation
    Verify,
    /// Generate salt operation
    GenerateSalt,
    /// Update hash operation
    UpdateHash,
}

impl fmt::Display for HashingOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashingOperation::Hash => write!(f, "hash"),
            HashingOperation::Verify => write!(f, "verify"),
            HashingOperation::GenerateSalt => write!(f, "generate_salt"),
            HashingOperation::UpdateHash => write!(f, "update_hash"),
        }
    }
}

/// Serialization operation types
#[derive(Debug, Clone)]
pub enum SerializationOperation {
    /// Serialize to JSON
    SerializeJson,
    /// Deserialize from JSON
    DeserializeJson,
    /// Serialize to binary
    SerializeBinary,
    /// Deserialize from binary
    DeserializeBinary,
    /// Validate structure
    ValidateStructure,
}

impl fmt::Display for SerializationOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerializationOperation::SerializeJson => write!(f, "serialize_json"),
            SerializationOperation::DeserializeJson => write!(f, "deserialize_json"),
            SerializationOperation::SerializeBinary => write!(f, "serialize_binary"),
            SerializationOperation::DeserializeBinary => write!(f, "deserialize_binary"),
            SerializationOperation::ValidateStructure => write!(f, "validate_structure"),
        }
    }
}

/// Cache operation types
#[derive(Debug, Clone)]
pub enum CacheOperation {
    /// Get from cache
    Get,
    /// Set in cache
    Set,
    /// Delete from cache
    Delete,
    /// Check if key exists
    Exists,
    /// Clear cache
    Clear,
    /// Set expiration
    SetExpiration,
}

impl fmt::Display for CacheOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CacheOperation::Get => write!(f, "get"),
            CacheOperation::Set => write!(f, "set"),
            CacheOperation::Delete => write!(f, "delete"),
            CacheOperation::Exists => write!(f, "exists"),
            CacheOperation::Clear => write!(f, "clear"),
            CacheOperation::SetExpiration => write!(f, "set_expiration"),
        }
    }
}

/// Message queue operation types
#[derive(Debug, Clone)]
pub enum QueueOperation {
    /// Send message
    Send,
    /// Receive message
    Receive,
    /// Acknowledge message
    Acknowledge,
    /// Reject message
    Reject,
    /// Peek at message
    Peek,
    /// Purge queue
    Purge,
}

impl fmt::Display for QueueOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QueueOperation::Send => write!(f, "send"),
            QueueOperation::Receive => write!(f, "receive"),
            QueueOperation::Acknowledge => write!(f, "acknowledge"),
            QueueOperation::Reject => write!(f, "reject"),
            QueueOperation::Peek => write!(f, "peek"),
            QueueOperation::Purge => write!(f, "purge"),
        }
    }
}

impl PortError {
    /// Create a repository error
    pub fn repository(repository: RepositoryType, message: impl Into<String>) -> Self {
        PortError::Repository {
            repository,
            message: message.into(),
            operation: None,
            context: None,
        }
    }

    /// Create a repository error with operation context
    pub fn repository_with_operation(
        repository: RepositoryType,
        message: impl Into<String>,
        operation: impl Into<String>,
    ) -> Self {
        PortError::Repository {
            repository,
            message: message.into(),
            operation: Some(operation.into()),
            context: None,
        }
    }

    /// Create a repository error with full context
    pub fn repository_with_context(
        repository: RepositoryType,
        message: impl Into<String>,
        operation: Option<String>,
        context: Option<String>,
    ) -> Self {
        PortError::Repository {
            repository,
            message: message.into(),
            operation,
            context,
        }
    }

    /// Create a codec error
    pub fn codec(operation: CodecOperation, message: impl Into<String>) -> Self {
        PortError::Codec {
            operation,
            message: message.into(),
            payload_type: None,
            expected_format: None,
        }
    }

    /// Create a codec error with format context
    pub fn codec_with_format(
        operation: CodecOperation,
        message: impl Into<String>,
        payload_type: Option<String>,
        expected_format: Option<String>,
    ) -> Self {
        PortError::Codec {
            operation,
            message: message.into(),
            payload_type,
            expected_format,
        }
    }

    /// Create a hashing error with algorithm context
    pub fn hashing_with_algorithm(
        operation: HashingOperation,
        message: impl Into<String>,
        algorithm: impl Into<String>,
    ) -> Self {
        PortError::Hashing {
            operation,
            message: message.into(),
            algorithm: Some(algorithm.into()),
            expected_format: None,
        }
    }

    /// Create a hashing error with full context
    pub fn hashing_with_context(
        operation: HashingOperation,
        message: impl Into<String>,
        algorithm: Option<String>,
        expected_format: Option<String>,
    ) -> Self {
        PortError::Hashing {
            operation,
            message: message.into(),
            algorithm,
            expected_format,
        }
    }

    /// Create a serialization error
    pub fn serialization(
        operation: SerializationOperation,
        message: impl Into<String>,
        format: Option<String>,
        field: Option<String>,
    ) -> Self {
        PortError::Serialization {
            operation,
            message: message.into(),
            format,
            field,
        }
    }

    /// Create a cache error
    pub fn cache(
        operation: CacheOperation,
        message: impl Into<String>,
        cache_key: Option<String>,
        ttl: Option<String>,
    ) -> Self {
        PortError::Cache {
            operation,
            message: message.into(),
            cache_key,
            ttl,
        }
    }

    /// Create a message queue error
    pub fn message_queue(
        operation: QueueOperation,
        message: impl Into<String>,
        queue_name: Option<String>,
        message_id: Option<String>,
    ) -> Self {
        PortError::MessageQueue {
            operation,
            message: message.into(),
            queue_name,
            message_id,
        }
    }

    /// Generate a deterministic support code based on error content
    fn generate_support_code(&self) -> String {
        let mut hasher = DefaultHasher::new();
        match self {
            PortError::Repository {
                repository,
                operation,
                ..
            } => {
                format!("REPO-{}-{:X}", repository.to_string().to_uppercase(), {
                    format!("{:?}{:?}", repository, operation).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
            PortError::Codec {
                operation,
                payload_type,
                ..
            } => {
                format!("CODEC-{}-{:X}", operation.to_string().to_uppercase(), {
                    format!("{:?}{:?}", operation, payload_type).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
            PortError::Hashing {
                operation,
                algorithm,
                ..
            } => {
                format!("HASH-{}-{:X}", operation.to_string().to_uppercase(), {
                    format!("{:?}{:?}", operation, algorithm).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
            PortError::Serialization {
                operation, format, ..
            } => {
                format!("SERIAL-{}-{:X}", operation.to_string().to_uppercase(), {
                    format!("{:?}{:?}", operation, format).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
            PortError::Cache {
                operation,
                cache_key,
                ..
            } => {
                format!("CACHE-{}-{:X}", operation.to_string().to_uppercase(), {
                    format!("{:?}{:?}", operation, cache_key).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
            PortError::MessageQueue {
                operation,
                queue_name,
                ..
            } => {
                format!("QUEUE-{}-{:X}", operation.to_string().to_uppercase(), {
                    format!("{:?}{:?}", operation, queue_name).hash(&mut hasher);
                    hasher.finish() % 10000
                })
            }
        }
    }
}

impl UserFriendlyError for PortError {
    fn user_message(&self) -> String {
        match self {
            PortError::Repository { repository, .. } => {
                match repository {
                    RepositoryType::Account => "We're having trouble accessing your account information. Please try refreshing the page or signing in again.".to_string(),
                    RepositoryType::Secret => "There's an issue with the security system. Please try again or contact support if the problem continues.".to_string(),
                    RepositoryType::Session => "Your session information couldn't be processed. Please sign in again to continue.".to_string(),
                    RepositoryType::Permission => "We're having trouble verifying your permissions. Please try again or contact your administrator.".to_string(),
                    RepositoryType::AuditLog => "There's an issue with the activity logging system. Your action may not have been recorded, but it was likely completed successfully.".to_string(),
                    RepositoryType::PermissionMapping => "We're having trouble with the permission system. Your permissions are still active, but some features might not display correctly.".to_string(),
                }
            }
            PortError::Codec { operation, .. } => {
                match operation {
                    CodecOperation::Encode | CodecOperation::Serialize => "We couldn't process your data in the required format. Please check your input and try again.".to_string(),
                    CodecOperation::Decode | CodecOperation::Deserialize => "We received data in an unexpected format. This might be a temporary issue - please try again.".to_string(),
                    CodecOperation::Validate => "The data format couldn't be validated. Please check that all information is entered correctly.".to_string(),
                }
            }
            PortError::Hashing { operation, .. } => {
                match operation {
                    HashingOperation::Hash => "There's an issue with the security processing system. Please try again in a moment.".to_string(),
                    HashingOperation::Verify => "We couldn't verify your credentials due to a technical issue. Please try signing in again.".to_string(),
                    HashingOperation::GenerateSalt => "There's a problem with the security system setup. Please contact support.".to_string(),
                    HashingOperation::UpdateHash => "We couldn't update your security information. Please try again or contact support.".to_string(),
                }
            }
            PortError::Serialization { operation, .. } => {
                match operation {
                    SerializationOperation::SerializeJson | SerializationOperation::SerializeBinary => {
                        "We couldn't save your data in the required format. Please try again.".to_string()
                    }
                    SerializationOperation::DeserializeJson | SerializationOperation::DeserializeBinary => {
                        "We received data in an unexpected format. Please refresh the page and try again.".to_string()
                    }
                    SerializationOperation::ValidateStructure => {
                        "The data structure couldn't be validated. Please check your input and try again.".to_string()
                    }
                }
            }
            PortError::Cache { operation, .. } => {
                match operation {
                    CacheOperation::Get => "We're having trouble retrieving cached information. This may slow things down but shouldn't prevent you from continuing.".to_string(),
                    CacheOperation::Set => "We couldn't cache your data, but your request was likely processed successfully. Performance may be slower temporarily.".to_string(),
                    CacheOperation::Delete => "We couldn't clear cached data. This might mean you see outdated information temporarily.".to_string(),
                    CacheOperation::Exists => "We couldn't check cached data status. Please try your request again.".to_string(),
                    CacheOperation::Clear => "We couldn't clear the system cache. You might see some outdated information until this resolves.".to_string(),
                    CacheOperation::SetExpiration => "There's an issue with cache timing settings. This shouldn't affect your current session.".to_string(),
                }
            }
            PortError::MessageQueue { operation, .. } => {
                match operation {
                    QueueOperation::Send => "We couldn't queue your request for processing. Please try again in a moment.".to_string(),
                    QueueOperation::Receive => "There's an issue receiving queued messages. Some updates may be delayed.".to_string(),
                    QueueOperation::Acknowledge => "We couldn't confirm message processing. Your request may still be completed successfully.".to_string(),
                    QueueOperation::Reject => "There's an issue with message handling. Please contact support if problems continue.".to_string(),
                    QueueOperation::Peek => "We couldn't check the message queue status. This is likely a temporary issue.".to_string(),
                    QueueOperation::Purge => "We couldn't clear the message queue. This is a system administration issue.".to_string(),
                }
            }
        }
    }

    fn developer_message(&self) -> String {
        match self {
            PortError::Repository {
                repository,
                message,
                operation,
                context,
            } => {
                let operation_context = operation
                    .as_ref()
                    .map(|op| format!(" [Operation: {}]", op))
                    .unwrap_or_default();
                let context_info = context
                    .as_ref()
                    .map(|c| format!(" [Context: {}]", c))
                    .unwrap_or_default();
                format!(
                    "Repository contract violation in {} repository: {}{}{}",
                    repository, message, operation_context, context_info
                )
            }
            PortError::Codec {
                operation,
                message,
                payload_type,
                expected_format,
            } => {
                let payload_context = payload_type
                    .as_ref()
                    .map(|pt| format!(" [Payload: {}]", pt))
                    .unwrap_or_default();
                let format_context = expected_format
                    .as_ref()
                    .map(|ef| format!(" [Expected: {}]", ef))
                    .unwrap_or_default();
                format!(
                    "Codec contract violation during {} operation: {}{}{}",
                    operation, message, payload_context, format_context
                )
            }
            PortError::Hashing {
                operation,
                message,
                algorithm,
                expected_format,
            } => {
                let algorithm_context = algorithm
                    .as_ref()
                    .map(|a| format!(" [Algorithm: {}]", a))
                    .unwrap_or_default();
                let format_context = expected_format
                    .as_ref()
                    .map(|ef| format!(" [Expected: {}]", ef))
                    .unwrap_or_default();
                format!(
                    "Hashing service contract violation during {} operation: {}{}{}",
                    operation, message, algorithm_context, format_context
                )
            }
            PortError::Serialization {
                operation,
                message,
                format,
                field,
            } => {
                let format_context = format
                    .as_ref()
                    .map(|f| format!(" [Format: {}]", f))
                    .unwrap_or_default();
                let field_context = field
                    .as_ref()
                    .map(|f| format!(" [Field: {}]", f))
                    .unwrap_or_default();
                format!(
                    "Serialization contract violation during {} operation: {}{}{}",
                    operation, message, format_context, field_context
                )
            }
            PortError::Cache {
                operation,
                message,
                cache_key,
                ttl,
            } => {
                let key_context = cache_key
                    .as_ref()
                    .map(|k| format!(" [Key: {}]", k))
                    .unwrap_or_default();
                let ttl_context = ttl
                    .as_ref()
                    .map(|t| format!(" [TTL: {}]", t))
                    .unwrap_or_default();
                format!(
                    "Cache interface contract violation during {} operation: {}{}{}",
                    operation, message, key_context, ttl_context
                )
            }
            PortError::MessageQueue {
                operation,
                message,
                queue_name,
                message_id,
            } => {
                let queue_context = queue_name
                    .as_ref()
                    .map(|q| format!(" [Queue: {}]", q))
                    .unwrap_or_default();
                let message_context = message_id
                    .as_ref()
                    .map(|m| format!(" [Message: {}]", m))
                    .unwrap_or_default();
                format!(
                    "Message queue contract violation during {} operation: {}{}{}",
                    operation, message, queue_context, message_context
                )
            }
        }
    }

    fn support_code(&self) -> String {
        self.generate_support_code()
    }

    fn severity(&self) -> ErrorSeverity {
        match self {
            PortError::Repository { repository, .. } => match repository {
                RepositoryType::Account | RepositoryType::Secret => ErrorSeverity::Critical,
                RepositoryType::Session => ErrorSeverity::Error,
                RepositoryType::Permission => ErrorSeverity::Error,
                RepositoryType::PermissionMapping => ErrorSeverity::Warning,
                RepositoryType::AuditLog => ErrorSeverity::Warning,
            },
            PortError::Codec { operation, .. } => match operation {
                CodecOperation::Encode | CodecOperation::Decode => ErrorSeverity::Error,
                CodecOperation::Serialize | CodecOperation::Deserialize => ErrorSeverity::Error,
                CodecOperation::Validate => ErrorSeverity::Warning,
            },
            PortError::Hashing { operation, .. } => match operation {
                HashingOperation::Hash | HashingOperation::Verify => ErrorSeverity::Critical,
                HashingOperation::GenerateSalt => ErrorSeverity::Critical,
                HashingOperation::UpdateHash => ErrorSeverity::Error,
            },
            PortError::Serialization { .. } => ErrorSeverity::Error,
            PortError::Cache { operation, .. } => match operation {
                CacheOperation::Clear => ErrorSeverity::Warning,
                _ => ErrorSeverity::Info,
            },
            PortError::MessageQueue { operation, .. } => match operation {
                QueueOperation::Send | QueueOperation::Receive => ErrorSeverity::Error,
                QueueOperation::Purge => ErrorSeverity::Warning,
                _ => ErrorSeverity::Warning,
            },
        }
    }

    fn suggested_actions(&self) -> Vec<String> {
        match self {
            PortError::Repository { repository, .. } => match repository {
                RepositoryType::Account => vec![
                    "Try refreshing the page and signing in again".to_string(),
                    "Clear your browser cache and cookies".to_string(),
                    "Use a different browser or device if the issue persists".to_string(),
                    "Contact support if you cannot access your account".to_string(),
                ],
                RepositoryType::Secret => vec![
                    "This is a critical security system issue".to_string(),
                    "Contact our support team immediately".to_string(),
                    "Do not attempt to retry authentication operations".to_string(),
                    "Use alternative authentication methods if available".to_string(),
                ],
                RepositoryType::Session => vec![
                    "Sign out completely and sign back in".to_string(),
                    "Clear all browser data for this site".to_string(),
                    "Try using an incognito or private browsing window".to_string(),
                    "Contact support if session issues continue".to_string(),
                ],
                RepositoryType::Permission => vec![
                    "Contact your system administrator to verify your permissions".to_string(),
                    "Ensure you are signed in with the correct account".to_string(),
                    "Try accessing different resources to test your permissions".to_string(),
                    "Contact support if you believe your permissions are incorrect".to_string(),
                ],
                RepositoryType::AuditLog => vec![
                    "Your actions are likely being completed successfully".to_string(),
                    "This affects activity logging, not core functionality".to_string(),
                    "Continue with your work normally".to_string(),
                    "Report to support if audit trails are critical for compliance".to_string(),
                ],
                RepositoryType::PermissionMapping => vec![
                    "This affects permission name display, not actual permissions".to_string(),
                    "Your access rights remain unchanged and functional".to_string(),
                    "Continue using the system normally".to_string(),
                    "Contact support if permission names are not displaying correctly".to_string(),
                ],
            },
            PortError::Codec { operation, .. } => match operation {
                CodecOperation::Encode | CodecOperation::Serialize => vec![
                    "Check that all required fields are filled out correctly".to_string(),
                    "Ensure special characters are properly formatted".to_string(),
                    "Try simplifying your input and gradually add complexity".to_string(),
                    "Contact support if data formatting requirements are unclear".to_string(),
                ],
                CodecOperation::Decode | CodecOperation::Deserialize => vec![
                    "This is likely a temporary system issue".to_string(),
                    "Try refreshing the page and repeating your action".to_string(),
                    "Clear your browser cache if the problem persists".to_string(),
                    "Contact support if you continue receiving malformed data".to_string(),
                ],
                CodecOperation::Validate => vec![
                    "Review all input fields for formatting errors".to_string(),
                    "Ensure required fields are not empty".to_string(),
                    "Check for special characters that might not be allowed".to_string(),
                    "Refer to our formatting guidelines or contact support".to_string(),
                ],
            },
            PortError::Hashing { operation, .. } => match operation {
                HashingOperation::Hash | HashingOperation::GenerateSalt => vec![
                    "This is a critical security system error".to_string(),
                    "Contact our support team immediately".to_string(),
                    "Do not retry operations that involve password changes".to_string(),
                    "Use secure communication when reporting this issue".to_string(),
                ],
                HashingOperation::Verify => vec![
                    "Double-check your password for typos".to_string(),
                    "Ensure Caps Lock is not accidentally enabled".to_string(),
                    "If you're certain your password is correct, contact support".to_string(),
                    "Try using password recovery if verification continues to fail".to_string(),
                ],
                HashingOperation::UpdateHash => vec![
                    "Try updating your password again in a few minutes".to_string(),
                    "Ensure your new password meets all security requirements".to_string(),
                    "Contact support if password updates continue to fail".to_string(),
                    "Consider using a different device or browser".to_string(),
                ],
            },
            PortError::Serialization { .. } => vec![
                "This is typically a temporary system issue".to_string(),
                "Try your request again in a few minutes".to_string(),
                "Refresh the page and ensure you have the latest version".to_string(),
                "Contact support if data processing errors continue".to_string(),
            ],
            PortError::Cache { operation, .. } => match operation {
                CacheOperation::Get | CacheOperation::Set => vec![
                    "This may cause slower performance but shouldn't prevent functionality"
                        .to_string(),
                    "Continue with your work normally".to_string(),
                    "Try refreshing the page if you see outdated information".to_string(),
                    "Performance should return to normal once the issue resolves".to_string(),
                ],
                CacheOperation::Clear | CacheOperation::Delete => vec![
                    "You might see some outdated information temporarily".to_string(),
                    "Refresh the page to get the most current data".to_string(),
                    "This issue should resolve itself automatically".to_string(),
                    "Contact support if you continue seeing stale data".to_string(),
                ],
                _ => vec![
                    "This is a minor system issue that shouldn't affect core functionality"
                        .to_string(),
                    "Continue using the application normally".to_string(),
                    "The issue should resolve itself automatically".to_string(),
                ],
            },
            PortError::MessageQueue { operation, .. } => match operation {
                QueueOperation::Send => vec![
                    "Wait a moment and try your request again".to_string(),
                    "Your request may be processed with a slight delay".to_string(),
                    "Contact support if urgent requests are not being processed".to_string(),
                    "Consider breaking large requests into smaller parts".to_string(),
                ],
                QueueOperation::Receive => vec![
                    "Some updates or notifications may be delayed".to_string(),
                    "Refresh the page periodically to check for updates".to_string(),
                    "This issue typically resolves itself automatically".to_string(),
                    "Contact support if you're missing critical notifications".to_string(),
                ],
                QueueOperation::Purge => vec![
                    "This is a system administration issue".to_string(),
                    "Contact our technical support team".to_string(),
                    "Normal operations should continue unaffected".to_string(),
                    "Message processing may experience some delays".to_string(),
                ],
                _ => vec![
                    "This may cause delays in background processing".to_string(),
                    "Your immediate actions should work normally".to_string(),
                    "Some notifications or updates may be delayed".to_string(),
                    "Contact support if delays become significant".to_string(),
                ],
            },
        }
    }

    fn is_retryable(&self) -> bool {
        match self {
            PortError::Repository { repository, .. } => match repository {
                RepositoryType::Account | RepositoryType::Session => true, // User can re-auth
                RepositoryType::Secret => false, // Critical security issue
                RepositoryType::Permission => false, // Permission issues need admin
                RepositoryType::PermissionMapping => true, // Non-blocking, affects display only
                RepositoryType::AuditLog => true, // Non-blocking
            },
            PortError::Codec { operation, .. } => match operation {
                CodecOperation::Encode | CodecOperation::Serialize => true, // User can fix input
                CodecOperation::Decode | CodecOperation::Deserialize => true, // May be temporary
                CodecOperation::Validate => true, // User can correct validation errors
            },
            PortError::Hashing { operation, .. } => match operation {
                HashingOperation::Hash | HashingOperation::GenerateSalt => false, // Critical system issue
                HashingOperation::Verify => true, // User can retry with correct credentials
                HashingOperation::UpdateHash => true, // User can retry password update
            },
            PortError::Serialization { .. } => true, // Often temporary system issues
            PortError::Cache { .. } => true, // Cache issues are typically non-blocking and temporary
            PortError::MessageQueue { operation, .. } => match operation {
                QueueOperation::Send | QueueOperation::Receive => true, // Temporary queue issues
                QueueOperation::Purge => false,                         // Administrative operation
                _ => true, // Other queue operations can typically be retried
            },
        }
    }
}
