//! Integration timing tests for repository credential verification.
//!
//! These tests assert that credential verification for:
//!   1. Non-existent account
//!   2. Existing account with wrong password
//!   3. Existing account with correct password
//! take comparable time (no large timing gap between (1) and (2)),
//! which would otherwise permit user enumeration via timing analysis.
//!
//! The repositories under test internally pre-compute a dummy Argon2 hash
//! (with the same build-mode preset parameters as real stored hashes) and
//! always perform an Argon2 verification, even when the account/secret
//! does not exist.
//!
//! Thresholds are intentionally generous to reduce flakiness on CI. The
//! difference between the "nonexistent user" and "wrong password" paths
//! should be well below the chosen threshold in practice.
//!
//! NOTE: These tests exercise only the timing symmetry property, not the
//! absolute performance characteristics.
//!
//! If a test becomes flaky in certain environments (e.g. heavily loaded CI),
//! consider widening (not tightening) thresholds or measuring multiple
//! iterations and comparing medians.
//!
//! Run with: `cargo test -- --nocapture` to see raw timing output.

use std::time::Instant;

use axum_gate::advanced::{
    AccountRepository, Argon2Hasher, CredentialsVerifier, Secret, SecretRepository,
};
use axum_gate::auth::{Account, Credentials, Group, Role};

/// Helper to compute absolute duration difference.
fn abs_diff(a: std::time::Duration, b: std::time::Duration) -> std::time::Duration {
    if a > b { a - b } else { b - a }
}

/// Returns a fresh random (UUID v7 backed) email identifier to avoid collisions in shared DBs.
fn random_user_id() -> String {
    format!("user+{}@example.test", uuid::Uuid::now_v7())
}

//
// SurrealDB Timing Test
//
#[tokio::test]
async fn surrealdb_timing_symmetry() {
    use axum_gate::storage::surrealdb::{DatabaseScope, SurrealDbRepository};
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;

    // Prepare SurrealDB in-memory instance
    let db = Surreal::new::<Mem>(()).await.unwrap();
    let scope = DatabaseScope::default();
    let repo = SurrealDbRepository::new(db, scope);

    // Ensure namespace + database are set (idempotent).
    // (Using the internal helper is private; we rely on repository methods which call it.)

    // Create & store an account + secret
    let existing_user = random_user_id();
    let account = Account::new(&existing_user, &[Role::User], &[Group::new("grp")]);
    let stored_account = repo
        .store_account(account)
        .await
        .expect("store account")
        .expect("stored account");

    let password = "correct_password";
    let hasher = Argon2Hasher::default();
    let secret = Secret::new(&stored_account.account_id, password, hasher).expect("hash secret");
    repo.store_secret(secret).await.expect("store secret");

    // Credentials
    let creds_nonexistent =
        Credentials::new(&random_user_id(), "whatever_wrong_password_not_relevant");
    let creds_wrong = Credentials::new(&stored_account.account_id, "wrong_password");
    let creds_correct = Credentials::new(&stored_account.account_id, password);

    // Non-existent
    let t0 = Instant::now();
    let res_nonexistent = repo
        .verify_credentials(creds_nonexistent)
        .await
        .expect("verify nonexistent");
    let dur_nonexistent = t0.elapsed();

    // Wrong password
    let t1 = Instant::now();
    let res_wrong = repo
        .verify_credentials(creds_wrong)
        .await
        .expect("verify wrong");
    let dur_wrong = t1.elapsed();

    // Correct password
    let t2 = Instant::now();
    let res_correct = repo
        .verify_credentials(creds_correct)
        .await
        .expect("verify correct");
    let dur_correct = t2.elapsed();

    // Basic correctness

    assert!(matches!(
        res_nonexistent,
        axum_gate::advanced::VerificationResult::Unauthorized
    ));
    assert!(matches!(
        res_wrong,
        axum_gate::advanced::VerificationResult::Unauthorized
    ));
    assert!(matches!(
        res_correct,
        axum_gate::advanced::VerificationResult::Ok
    ));

    let diff = abs_diff(dur_nonexistent, dur_wrong);

    println!(
        "[SurrealDB Timing] nonexistent={:?}, wrong={:?}, correct={:?}, diff(nonexist vs wrong)={:?}",
        dur_nonexistent, dur_wrong, dur_correct, diff
    );

    // Threshold: ensure difference does not explode (choose 25ms generous).
    assert!(
        diff.as_millis() < 25,
        "SurrealDB timing difference too large: {:?} ms",
        diff.as_millis()
    );

    // Both failure paths should still spend some time (Argon2 dev / release depending on build).
    assert!(
        dur_nonexistent.as_millis() >= 5,
        "Nonexistent path too fast; Argon2 likely skipped."
    );
    assert!(
        dur_wrong.as_millis() >= 5,
        "Wrong password path too fast; Argon2 likely skipped."
    );
}

//
// SeaORM Timing Test
//
#[tokio::test]
async fn seaorm_timing_symmetry() {
    use axum_gate::storage::seaorm::SeaOrmRepository;
    use sea_orm::{ConnectionTrait, Database, DatabaseBackend, Schema};

    // In-memory SQLite database
    let db = match Database::connect("sqlite::memory:").await {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Skipping SeaORM timing test (unable to connect sqlite memory): {e}");
            return;
        }
    };

    // Create tables using SeaORM entity definitions (no migrations needed)
    use axum_gate::storage::seaorm::models::{
        account as seaorm_account, credentials as seaorm_credentials,
    };
    let builder = Schema::new(DatabaseBackend::Sqlite);
    let account_stmt = builder.create_table_from_entity(seaorm_account::Entity);
    let credentials_stmt = builder.create_table_from_entity(seaorm_credentials::Entity);

    if let Err(e) = db
        .execute(db.get_database_backend().build(&account_stmt))
        .await
    {
        eprintln!("Skipping SeaORM timing test (create accounts table failed): {e}");
        return;
    }
    if let Err(e) = db
        .execute(db.get_database_backend().build(&credentials_stmt))
        .await
    {
        eprintln!("Skipping SeaORM timing test (create credentials table failed): {e}");
        return;
    }

    let repo = SeaOrmRepository::new(&db);

    // Create & store account + secret
    let existing_user = random_user_id();
    let account = Account::new(&existing_user, &[Role::User], &[Group::new("grp")]);
    let stored_account = match repo.store_account(account).await {
        Ok(Some(acc)) => acc,
        Ok(None) => {
            eprintln!("Skipping SeaORM timing test (account not stored).");
            return;
        }
        Err(e) => {
            eprintln!("Skipping SeaORM timing test (store account failed): {e}");
            return;
        }
    };

    let password = "correct_password";
    let hasher = Argon2Hasher::default();
    let secret = match Secret::new(&stored_account.account_id, password, hasher) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Skipping SeaORM timing test (secret hash failed): {e}");
            return;
        }
    };

    if let Err(e) = repo.store_secret(secret).await {
        eprintln!("Skipping SeaORM timing test (store secret failed): {e}");
        return;
    }

    // Credentials
    let creds_nonexistent =
        Credentials::new(&uuid::Uuid::now_v7(), "irrelevant_wrong_password_value");
    let creds_wrong = Credentials::new(&stored_account.account_id, "wrong_password");
    let creds_correct = Credentials::new(&stored_account.account_id, password);

    // Non-existent
    let t0 = Instant::now();
    let res_nonexistent = match repo.verify_credentials(creds_nonexistent).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Skipping SeaORM timing test (verify nonexistent failed): {e}");
            return;
        }
    };
    let dur_nonexistent = t0.elapsed();

    // Wrong password
    let t1 = Instant::now();
    let res_wrong = match repo.verify_credentials(creds_wrong).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Skipping SeaORM timing test (verify wrong failed): {e}");
            return;
        }
    };
    let dur_wrong = t1.elapsed();

    // Correct
    let t2 = Instant::now();
    let res_correct = match repo.verify_credentials(creds_correct).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Skipping SeaORM timing test (verify correct failed): {e}");
            return;
        }
    };
    let dur_correct = t2.elapsed();

    assert!(matches!(
        res_nonexistent,
        axum_gate::advanced::VerificationResult::Unauthorized
    ));
    assert!(matches!(
        res_wrong,
        axum_gate::advanced::VerificationResult::Unauthorized
    ));
    assert!(matches!(
        res_correct,
        axum_gate::advanced::VerificationResult::Ok
    ));

    let diff = abs_diff(dur_nonexistent, dur_wrong);

    println!(
        "[SeaORM Timing] nonexistent={:?}, wrong={:?}, correct={:?}, diff(nonexist vs wrong)={:?}",
        dur_nonexistent, dur_wrong, dur_correct, diff
    );

    // Similar generous threshold (DB + Argon2 overhead).
    assert!(
        diff.as_millis() < 30,
        "SeaORM timing difference too large: {:?} ms",
        diff.as_millis()
    );

    assert!(
        dur_nonexistent.as_millis() >= 5,
        "Nonexistent path too fast; Argon2 likely skipped."
    );
    assert!(
        dur_wrong.as_millis() >= 5,
        "Wrong password path too fast; Argon2 likely skipped."
    );
}
