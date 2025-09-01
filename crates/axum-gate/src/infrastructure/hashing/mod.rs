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
//! use axum_gate::advanced::{Argon2Hasher, Argon2Preset, Argon2Config, HashingService};
//!
//! // Build-mode default
//! let hasher = Argon2Hasher::default();
//!
//! // Explicit preset
//! let interactive = Argon2Hasher::from_preset(Argon2Preset::Interactive);
//!
//! // Custom config
//! let custom = Argon2Hasher::from_config(
//!     Argon2Config::default()
//!         .with_memory_kib(96 * 1024)
//!         .with_time_cost(4)
//!         .with_parallelism(1)
//! );
//!
//! let hash = custom.hash_value("secret").unwrap();
//! assert!(matches!(custom.verify_value("secret", &hash), Ok(crate::domain::values::VerificationResult::Ok)));
//! ```
//!
//! ⚠ The `DevFast` preset MUST NOT be used in production; it exists only to keep debug builds
//! responsive. When you explicitly construct a hasher, choose an appropriate security profile.
use crate::domain::values::VerificationResult;
use crate::errors::{Error, HashingOperation, PortError, Result};
use crate::ports::auth::HashingService;
use argon2::password_hash::{PasswordHasher, SaltString, rand_core::OsRng};
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordVerifier, Version};

/// A hashed value.
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

    /// Security‑first high security hasher.
    pub fn high_security() -> Self {
        Self::from_preset(Argon2Preset::HighSecurity)
    }

    /// Lower‑latency interactive hasher.
    pub fn interactive() -> Self {
        Self::from_preset(Argon2Preset::Interactive)
    }

    /// Fast / insecure hasher (tests / debug only).
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
