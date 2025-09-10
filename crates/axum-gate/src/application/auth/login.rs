use crate::domain::entities::{Account, Credentials};
use crate::domain::traits::AccessHierarchy;
use crate::domain::values::VerificationResult;
use crate::infrastructure::jwt::{JwtClaims, RegisteredClaims};
use crate::ports::Codec;
use crate::ports::auth::CredentialsVerifier;
use crate::ports::repositories::AccountRepository;

use std::sync::Arc;

use subtle::Choice;
use tracing::{debug, error};
use uuid::Uuid;

/// Result of a login attempt produced by [`LoginService::authenticate`].
///
/// The variants deliberately avoid revealing whether an account exists to
/// mitigate username enumeration attacks. Both an unknown user and an
/// incorrect password are collapsed into [`LoginResult::InvalidCredentials`].
#[derive(Debug)]
pub enum LoginResult {
    /// Authentication succeeded and contains the issued JWT (already UTF‑8).
    Success(String),
    /// Credentials were invalid (unknown user OR wrong password).
    InvalidCredentials,
    /// An internal / infrastructural error (repository failure, hashing, JWT, etc.).
    InternalError(String),
}

/// Stateless service implementing constant‑time, enumeration‑resistant
/// authentication logic. It always performs:
/// 1. Account lookup by user identifier.
/// 2. Credential verification against either the real account UUID or a
///    fixed dummy UUID when the account is absent.
/// This equalises timing characteristics between "user not found" and
/// "wrong password" cases.
///
/// Type Params:
/// * `R` - Role type implementing [`AccessHierarchy`]
/// * `G` - Group type
pub struct LoginService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    _phantom: std::marker::PhantomData<(R, G)>,
}

impl<R, G> LoginService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    /// Creates a new stateless `LoginService`.
    ///
    /// The instance holds no mutable state; it is cheap to clone or recreate.
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Authenticates a user in a timing‑safe, enumeration‑resistant fashion.
    ///
    /// Steps:
    /// 1. Query account repository by user identifier.
    /// 2. Always invoke credential verification using either the real account
    ///    UUID or a fixed dummy UUID when the user is absent / lookup failed.
    /// 3. Combine (user_exists AND password_matches) with constant‑time bit logic.
    /// 4. On success, encode a JWT with the supplied registered claims.
    ///
    /// Returns:
    /// * [`LoginResult::Success`] with a JWT string on success.
    /// * [`LoginResult::InvalidCredentials`] for any auth failure that should not leak detail.
    /// * [`LoginResult::InternalError`] for infrastructural issues (these should be logged).
    ///
    /// Security: Avoids early returns that would create observable timing
    /// differences between "user not found" and "wrong password".
    pub async fn authenticate<CredVeri, AccRepo, C>(
        &self,
        credentials: Credentials<String>,
        registered_claims: RegisteredClaims,
        credentials_verifier: Arc<CredVeri>,
        account_repository: Arc<AccRepo>,
        codec: Arc<C>,
    ) -> LoginResult
    where
        CredVeri: CredentialsVerifier<Uuid>,
        AccRepo: AccountRepository<R, G>,
        C: Codec<Payload = JwtClaims<Account<R, G>>>,
    {
        let account_query_result = account_repository
            .query_account_by_user_id(&credentials.id)
            .await;

        let (account_opt, verification_uuid, user_exists_choice, query_error_opt) =
            match account_query_result {
                Ok(Some(acc)) => {
                    debug!("Account found for user_id: {}", credentials.id);
                    (Some(acc.clone()), acc.account_id, Choice::from(1u8), None)
                }
                Ok(None) => {
                    debug!("Account not found for user_id: {}", credentials.id);
                    let dummy_uuid = Uuid::from_bytes([
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x01,
                    ]);
                    (None, dummy_uuid, Choice::from(0u8), None)
                }
                Err(e) => {
                    error!("Error querying account: {}", e);
                    let dummy_uuid = Uuid::from_bytes([
                        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x01,
                    ]);
                    (None, dummy_uuid, Choice::from(0u8), Some(e))
                }
            };

        if let Some(error) = query_error_opt {
            return LoginResult::InternalError(error.to_string());
        }

        let creds_to_verify = Credentials::new(&verification_uuid, &credentials.secret);
        let verification_result = credentials_verifier
            .verify_credentials(creds_to_verify)
            .await;

        let auth_success_choice = match verification_result {
            Ok(VerificationResult::Ok) => {
                debug!(
                    "Credentials verified successfully for UUID: {}",
                    verification_uuid
                );
                Choice::from(1u8)
            }
            Ok(VerificationResult::Unauthorized) => {
                debug!(
                    "Credentials verification failed for UUID: {}",
                    verification_uuid
                );
                Choice::from(0u8)
            }
            Err(e) => {
                error!("Error verifying credentials: {}", e);
                return LoginResult::InternalError(e.to_string());
            }
        };

        let final_success_choice = user_exists_choice & auth_success_choice;
        let login_successful: bool = final_success_choice.into();

        if login_successful {
            if let Some(account) = account_opt {
                let claims = JwtClaims::new(account, registered_claims);
                let jwt = match codec.encode(&claims) {
                    Ok(token) => token,
                    Err(e) => {
                        error!("Error encoding JWT: {}", e);
                        return LoginResult::InternalError(e.to_string());
                    }
                };
                let jwt_string = match String::from_utf8(jwt) {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Error converting JWT to string: {}", e);
                        return LoginResult::InternalError(e.to_string());
                    }
                };
                debug!("Login successful, JWT generated");
                LoginResult::Success(jwt_string)
            } else {
                error!("Internal error: login marked successful but no account available");
                LoginResult::InternalError("Authentication state inconsistency".to_string())
            }
        } else {
            debug!("Login failed - invalid credentials");
            LoginResult::InvalidCredentials
        }
    }
}

impl<R, G> Default for LoginService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::values::Secret;
    use crate::infrastructure::hashing::Argon2Hasher;
    use crate::infrastructure::jwt::{JsonWebToken, JwtClaims};
    use crate::infrastructure::repositories::memory::{
        MemoryAccountRepository, MemorySecretRepository,
    };
    use crate::prelude::{Group, Role};
    use std::time::{Duration, Instant};

    fn median(durs: &[Duration]) -> Duration {
        let mut v = durs.to_vec();
        v.sort();
        v[v.len() / 2]
    }

    #[tokio::test]
    async fn test_timing_attack_protection() {
        // Setup
        let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
        let secret_repo = Arc::new(MemorySecretRepository::default());
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let login_service = LoginService::new();

        // Account + secret
        let existing_user = "existing@example.com";
        let password = "test_password";
        let account = Account::new(existing_user, &[Role::User], &[Group::new("test-group")]);
        let stored_account = account_repo.store_account(account).await.unwrap().unwrap();

        let secret = Secret::new(
            &stored_account.account_id,
            password,
            Argon2Hasher::default(),
        )
        .expect("secret");
        use crate::ports::repositories::SecretRepository;
        secret_repo.store_secret(secret).await.unwrap();

        let registered_claims = crate::infrastructure::jwt::RegisteredClaims::new(
            "test-issuer",
            chrono::Utc::now().timestamp() as u64 + 3600,
        );

        // Warm-up both failure paths (first Argon2 invocation can include allocation cost)
        {
            let creds = Credentials::new(&"nonexistent@example.com".to_string(), "pw");
            let _ = login_service
                .authenticate(
                    creds,
                    registered_claims.clone(),
                    secret_repo.clone(),
                    account_repo.clone(),
                    jwt_codec.clone(),
                )
                .await;
            let creds = Credentials::new(&existing_user.to_string(), "wrong_pw");
            let _ = login_service
                .authenticate(
                    creds,
                    registered_claims.clone(),
                    secret_repo.clone(),
                    account_repo.clone(),
                    jwt_codec.clone(),
                )
                .await;
        }

        let iterations = 6; // keep total runtime reasonable
        let mut nonexistent_times = Vec::with_capacity(iterations);
        let mut wrong_times = Vec::with_capacity(iterations);

        for i in 0..iterations {
            // Alternate ordering to reduce systemic bias
            if i % 2 == 0 {
                // nonexistent first
                let creds = Credentials::new(&"nonexistent@example.com".to_string(), "any_pw");
                let start = Instant::now();
                let r = login_service
                    .authenticate(
                        creds,
                        registered_claims.clone(),
                        secret_repo.clone(),
                        account_repo.clone(),
                        jwt_codec.clone(),
                    )
                    .await;
                assert!(matches!(r, LoginResult::InvalidCredentials));
                nonexistent_times.push(start.elapsed());

                let creds = Credentials::new(&existing_user.to_string(), "wrong_pw");
                let start = Instant::now();
                let r = login_service
                    .authenticate(
                        creds,
                        registered_claims.clone(),
                        secret_repo.clone(),
                        account_repo.clone(),
                        jwt_codec.clone(),
                    )
                    .await;
                assert!(matches!(r, LoginResult::InvalidCredentials));
                wrong_times.push(start.elapsed());
            } else {
                // wrong first
                let creds = Credentials::new(&existing_user.to_string(), "wrong_pw");
                let start = Instant::now();
                let r = login_service
                    .authenticate(
                        creds,
                        registered_claims.clone(),
                        secret_repo.clone(),
                        account_repo.clone(),
                        jwt_codec.clone(),
                    )
                    .await;
                assert!(matches!(r, LoginResult::InvalidCredentials));
                wrong_times.push(start.elapsed());

                let creds = Credentials::new(&"nonexistent@example.com".to_string(), "any_pw");
                let start = Instant::now();
                let r = login_service
                    .authenticate(
                        creds,
                        registered_claims.clone(),
                        secret_repo.clone(),
                        account_repo.clone(),
                        jwt_codec.clone(),
                    )
                    .await;
                assert!(matches!(r, LoginResult::InvalidCredentials));
                nonexistent_times.push(start.elapsed());
            }
        }

        // Measure success path (informational)
        let mut success_times = Vec::new();
        for _ in 0..3 {
            let creds = Credentials::new(&existing_user.to_string(), password);
            let start = Instant::now();
            let r = login_service
                .authenticate(
                    creds,
                    registered_claims.clone(),
                    secret_repo.clone(),
                    account_repo.clone(),
                    jwt_codec.clone(),
                )
                .await;
            assert!(matches!(r, LoginResult::Success(_)));
            success_times.push(start.elapsed());
        }

        let med_nonexistent = median(&nonexistent_times);
        let med_wrong = median(&wrong_times);
        let med_success = median(&success_times);

        let (fast, slow) = if med_nonexistent < med_wrong {
            (med_nonexistent, med_wrong)
        } else {
            (med_wrong, med_nonexistent)
        };
        let diff = slow - fast;
        let relative = diff.as_secs_f64() / fast.as_secs_f64().max(1e-9);

        // Thresholds:
        // - relative difference must stay below 0.75 (75%)
        // - absolute diff below 120ms (very generous for noisy CI)
        // If Argon2 is accidentally skipped for one path, relative diff will approach 1.0
        let relative_threshold = 0.75;
        let absolute_threshold_ms: u128 = 120;

        // Minimal expected Argon2 duration (debug fast preset vs release high security):
        let min_expected_ms: u128 = if cfg!(debug_assertions) { 2 } else { 5 };
        assert!(
            med_nonexistent.as_millis() >= min_expected_ms,
            "Nonexistent path too fast ({} ms) - Argon2 likely skipped",
            med_nonexistent.as_millis()
        );
        assert!(
            med_wrong.as_millis() >= min_expected_ms,
            "Wrong-password path too fast ({} ms) - Argon2 likely skipped",
            med_wrong.as_millis()
        );

        println!(
            "Timing medians -> nonexistent: {:?}, wrong: {:?}, success: {:?}, diff: {:?} ({} ms), rel: {:.2}",
            med_nonexistent,
            med_wrong,
            med_success,
            diff,
            diff.as_millis(),
            relative
        );

        assert!(
            diff.as_millis() < absolute_threshold_ms || relative < relative_threshold,
            "Timing difference suspicious: diff={}ms (limit {}ms), rel={:.2} (limit {:.2}). \
             Nonexistent samples: {:?} Wrong samples: {:?}",
            diff.as_millis(),
            absolute_threshold_ms,
            relative,
            relative_threshold,
            nonexistent_times,
            wrong_times
        );
    }

    #[tokio::test]
    async fn test_login_result_no_user_enumeration() {
        let account_repo = Arc::new(MemoryAccountRepository::<Role, Group>::default());
        let secret_repo = Arc::new(MemorySecretRepository::default());
        let jwt_codec = Arc::new(JsonWebToken::<JwtClaims<Account<Role, Group>>>::default());
        let login_service = LoginService::new();

        let registered_claims = crate::infrastructure::jwt::RegisteredClaims::new(
            "test-issuer",
            chrono::Utc::now().timestamp() as u64 + 3600,
        );

        let nonexistent_credentials =
            Credentials::new(&"nonexistent@example.com".to_string(), "password");
        let result = login_service
            .authenticate(
                nonexistent_credentials,
                registered_claims,
                secret_repo,
                account_repo,
                jwt_codec,
            )
            .await;

        assert!(matches!(result, LoginResult::InvalidCredentials));
    }
}
