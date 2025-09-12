//! Value hashing implementations.
//!
//! Provides a *single* configurable Argon2id password hashing service with security‑first defaults.
//!
//! Build mode defaults:
//! - Release builds (`debug_assertions` disabled): HighSecurity preset
//! - Debug builds (`debug_assertions` enabled):   DevFast preset (faster local iteration)
//!
//! You can override the default explicitly with presets or a custom configuration.
//!
//! # Example
//! ```rust
//! use axum_gate::advanced::{Argon2Hasher, HashingService};
//!
//! // Default (build‑mode appropriate) hasher
//! let hasher = Argon2Hasher::default();
//! let hash = hasher.hash_value("secret").unwrap();
//! assert!(hasher.verify_value("secret", &hash).is_ok());
//! ```
//!
//! ⚠ The `DevFast` preset MUST NOT be used in production; it exists only to keep debug builds
//! responsive. When you explicitly construct a hasher, choose an appropriate security profile.
use crate::domain::values::VerificationResult;
use crate::errors::{Error, PortError, Result};
use crate::ports::auth::HashingService;
use crate::ports::errors::HashingOperation;
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordVerifier, Version};

/// A hashed value produced by password hashing algorithms.
///
/// This type represents the output of cryptographic password hashing functions,
/// typically containing the algorithm identifier, parameters, salt, and hash in
/// a standardized format.
///
/// ## Format
///
/// For Argon2id hashes, the format follows the PHC (Password Hashing Competition) standard:
/// ```text
/// $argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>
/// ```
///
/// Where:
/// - `argon2id` - Algorithm identifier
/// - `v=19` - Algorithm version
/// - `m=65536,t=3,p=1` - Memory cost, time cost, parallelism parameters
/// - `<salt>` - Base64-encoded random salt
/// - `<hash>` - Base64-encoded password hash
///
/// ## Security Properties
///
/// - **Self-contained**: Includes all information needed for verification
/// - **Salt included**: Each hash has a unique random salt to prevent rainbow table attacks
/// - **Parameter embedded**: Hash contains the parameters used, enabling verification
/// - **Future-proof**: Format supports algorithm upgrades and parameter changes
///
/// ## Usage
///
/// ```rust
/// use axum_gate::advanced::{Argon2Hasher, HashingService, HashedValue};
///
/// let hasher = Argon2Hasher::default();
/// let hashed: HashedValue = hasher.hash_value("my_password").unwrap();
///
/// // The hashed value is self-contained and can be stored directly
/// println!("Hashed password: {}", hashed);
///
/// // Later, verify against the stored hash
/// use axum_gate::advanced::VerificationResult;
/// let result = hasher.verify_value("my_password", &hashed).unwrap();
/// assert_eq!(result, VerificationResult::Ok);
/// ```
///
/// ## Storage Considerations
///
/// - **Database storage**: Store as TEXT/VARCHAR with sufficient length (≥100 characters recommended)
/// - **No additional encoding needed**: The string is already in a safe, printable format
/// - **Indexing**: Generally should not be indexed as hashes are not used for lookups
/// - **Migration**: Hash format changes require re-hashing passwords during user login
pub type HashedValue = String;

/// Argon2 parameter configuration (memory in KiB).
#[derive(Debug, Clone, Copy)]
pub struct Argon2Config {
    pub memory_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

impl Argon2Config {
    pub fn high_security() -> Self {
        Self {
            memory_kib: 64 * 1024, // 64 MiB
            time_cost: 3,
            parallelism: 1,
        }
    }
    pub fn interactive() -> Self {
        Self {
            memory_kib: 32 * 1024,
            time_cost: 2,
            parallelism: 1,
        }
    }
    pub fn dev_fast() -> Self {
        Self {
            memory_kib: 4 * 1024,
            time_cost: 1,
            parallelism: 1,
        }
    }
    pub fn with_memory_kib(mut self, v: u32) -> Self {
        self.memory_kib = v;
        self
    }
    pub fn with_time_cost(mut self, v: u32) -> Self {
        self.time_cost = v;
        self
    }
    pub fn with_parallelism(mut self, v: u32) -> Self {
        self.parallelism = v;
        self
    }
}

impl Default for Argon2Config {
    fn default() -> Self {
        Argon2Config::high_security()
    }
}

/// Preset selector for convenience.
#[derive(Debug, Clone, Copy)]
pub enum Argon2Preset {
    HighSecurity,
    Interactive,
    #[cfg(any(feature = "insecure-fast-hash", debug_assertions))]
    DevFast,
}

impl Argon2Preset {
    pub fn to_config(self) -> Argon2Config {
        match self {
            Self::HighSecurity => Argon2Config::high_security(),
            Self::Interactive => Argon2Config::interactive(),
            Self::DevFast => Argon2Config::dev_fast(),
        }
    }
}

/// Configurable Argon2id hasher.
#[derive(Clone)]
pub struct Argon2Hasher {
    config: Argon2Config,
    engine: Argon2<'static>,
}

impl Argon2Hasher {
    /// Create from explicit configuration.
    pub fn from_config(config: Argon2Config) -> Self {
        let params = Params::new(
            config.memory_kib,
            config.time_cost,
            config.parallelism,
            None,
        )
        .unwrap();
        let engine = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        Self { config, engine }
    }

    /// Create from a preset.
    pub fn from_preset(preset: Argon2Preset) -> Self {
        Self::from_config(preset.to_config())
    }

    /// Return current configuration.
    pub fn config(&self) -> &Argon2Config {
        &self.config
    }

    /// Maximum security hasher for production environments.
    ///
    /// **Parameters:**
    /// - Memory: 64 MiB (65,536 KiB)
    /// - Time cost: 3 iterations
    /// - Parallelism: 1 thread
    ///
    /// **Use cases:**
    /// - Production servers with sufficient memory
    /// - High-value accounts requiring maximum security
    /// - Applications where authentication latency is acceptable (~100-200ms)
    ///
    /// **Security:** Provides excellent protection against brute-force attacks
    /// and rainbow tables, suitable for protecting sensitive user credentials.
    ///
    /// **Performance:** Slowest option, designed for security over speed.
    pub fn high_security() -> Self {
        Self::from_preset(Argon2Preset::HighSecurity)
    }

    /// Balanced hasher for interactive applications.
    ///
    /// **Parameters:**
    /// - Memory: 32 MiB (32,768 KiB)
    /// - Time cost: 2 iterations
    /// - Parallelism: 1 thread
    ///
    /// **Use cases:**
    /// - Web applications with user-facing login forms
    /// - Mobile applications where response time matters
    /// - Services with moderate security requirements
    /// - Memory-constrained production environments
    ///
    /// **Security:** Good security level, still resistant to most attacks
    /// while providing reasonable authentication response times.
    ///
    /// **Performance:** Moderate speed (~50-100ms), good balance of security and usability.
    pub fn interactive() -> Self {
        Self::from_preset(Argon2Preset::Interactive)
    }

    /// Fast hasher for development and testing only.
    ///
    /// **⚠️ WARNING: DO NOT USE IN PRODUCTION**
    ///
    /// **Parameters:**
    /// - Memory: 4 MiB (4,096 KiB)
    /// - Time cost: 1 iteration
    /// - Parallelism: 1 thread
    ///
    /// **Use cases:**
    /// - Local development to speed up test cycles
    /// - Unit tests that need fast password hashing
    /// - CI/CD pipelines to reduce build times
    /// - Debug builds (automatically used by `default()`)
    ///
    /// **Security:** ⚠️ Insufficient for production use - vulnerable to brute-force attacks
    ///
    /// **Performance:** Very fast (~5-20ms), prioritizes development speed over security.
    ///
    /// This preset is only available in debug builds or when the `insecure-fast-hash`
    /// feature is explicitly enabled.
    #[cfg(any(feature = "insecure-fast-hash", debug_assertions))]
    pub fn dev_fast() -> Self {
        Self::from_preset(Argon2Preset::DevFast)
    }
}

impl Default for Argon2Hasher {
    fn default() -> Self {
        if cfg!(debug_assertions) {
            #[cfg(any(feature = "insecure-fast-hash", debug_assertions))]
            {
                return Self::dev_fast();
            }
        }
        // Fallback / release: always high security
        Self::high_security()
    }
}

impl HashingService for Argon2Hasher {
    fn hash_value(&self, plain_value: &str) -> Result<HashedValue> {
        let salt = SaltString::generate(&mut OsRng);
        Ok(self
            .engine
            .hash_password(plain_value.as_bytes(), &salt)
            .map_err(|e| {
                Error::Port(PortError::Hashing {
                    operation: HashingOperation::Hash,
                    message: format!("Could not hash secret: {e}"),
                    algorithm: Some("Argon2id".to_string()),
                    expected_format: Some("PHC".to_string()),
                })
            })?
            .to_string())
    }

    fn verify_value(&self, plain_value: &str, hashed_value: &str) -> Result<VerificationResult> {
        let hash = PasswordHash::new(hashed_value).map_err(|e| {
            Error::Port(PortError::Hashing {
                operation: HashingOperation::Verify,
                message: format!("Could not parse stored hash: {e}"),
                algorithm: Some("Argon2id".to_string()),
                expected_format: Some("PHC".to_string()),
            })
        })?;
        Ok(VerificationResult::from(
            self.engine
                .verify_password(plain_value.as_bytes(), &hash)
                .is_ok(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::auth::HashingService;

    #[test]
    fn default_build_mode() {
        let hasher = Argon2Hasher::default();
        let hash = hasher.hash_value("pw").unwrap();
        assert!(matches!(
            hasher.verify_value("pw", &hash),
            Ok(VerificationResult::Ok)
        ));
    }

    #[test]
    fn presets_work() {
        for preset in [
            Argon2Preset::HighSecurity,
            Argon2Preset::Interactive,
            #[cfg(any(feature = "insecure-fast-hash", debug_assertions))]
            Argon2Preset::DevFast,
        ] {
            let hasher = Argon2Hasher::from_preset(preset);
            let h = hasher.hash_value("secret").unwrap();
            assert_eq!(
                VerificationResult::Ok,
                hasher.verify_value("secret", &h).unwrap()
            );
            assert_eq!(
                VerificationResult::Unauthorized,
                hasher.verify_value("other", &h).unwrap()
            );
        }
    }

    #[test]
    fn custom_config() {
        let cfg = Argon2Config::default()
            .with_memory_kib(48 * 1024)
            .with_time_cost(2)
            .with_parallelism(1);
        let hasher = Argon2Hasher::from_config(cfg);
        let h = hasher.hash_value("abc").unwrap();
        assert!(matches!(
            hasher.verify_value("abc", &h),
            Ok(VerificationResult::Ok)
        ));
    }
}
