use crate::domain::entities::Credentials;
use crate::domain::traits::AccessHierarchy;
use crate::domain::values::VerificationResult;
use crate::infrastructure::jwt::{JwtClaims, RegisteredClaims};
use crate::ports::Codec;
use crate::ports::auth::CredentialsVerifier;
use crate::ports::repositories::AccountRepository;
use crate::prelude::Account;

use std::sync::Arc;
use tracing::{debug, error};
use uuid::Uuid;

/// Result of a login attempt
#[derive(Debug)]
pub enum LoginResult {
    /// Login successful with JWT token
    Success(String),
    /// Account not found
    AccountNotFound,
    /// Invalid credentials
    InvalidCredentials,
    /// Internal error occurred
    InternalError(String),
}

/// Application service for handling user login
pub struct LoginService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq,
{
    _phantom: std::marker::PhantomData<(R, G)>,
}

impl<R, G> LoginService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq,
{
    /// Create a new login service
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Authenticate a user and generate a JWT token
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
        // Get account by user ID
        let account = match account_repository
            .query_account_by_user_id(&credentials.id)
            .await
        {
            Ok(Some(acc)) => acc,
            Ok(None) => {
                debug!("Account not found for user_id: {}", credentials.id);
                return LoginResult::AccountNotFound;
            }
            Err(e) => {
                error!("Error querying account: {}", e);
                return LoginResult::InternalError(e.to_string());
            }
        };

        // Verify credentials
        let creds_to_verify = Credentials::new(&account.account_id, &credentials.secret);

        match credentials_verifier
            .verify_credentials(creds_to_verify)
            .await
        {
            Ok(VerificationResult::Ok) => {
                debug!(
                    "Credentials verified successfully for account: {}",
                    account.account_id
                );
            }
            Ok(VerificationResult::Unauthorized) => {
                debug!(
                    "Credentials verification failed for account: {}",
                    account.account_id
                );
                return LoginResult::InvalidCredentials;
            }
            Err(e) => {
                error!("Error verifying credentials: {}", e);
                return LoginResult::InternalError(e.to_string());
            }
        }

        // Generate JWT token
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
    }
}

impl<R, G> Default for LoginService<R, G>
where
    R: AccessHierarchy + Eq,
    G: Eq,
{
    fn default() -> Self {
        Self::new()
    }
}
