trait AccountStorageBackend {
    fn create(&self, acc: Acc);
    fn update(&self, acc: Acc);
    fn delete(&self, username: &str);
    fn query(&self, username: &str);
}
trait SecretStorageBackend: Create + Update + Delete + Verify {}

trait StorageRequest
where
    A: AccountStorageBackend,
    S: SecretStorageBackend,
{
    fn execute(&self, account_storage: Arc<A>, secrets_storage: Arc<S>) -> Result<(), String>;
}

fn howto_create_and_delete_account() {
    // Create storage for account and secrets.
    let account_storage = AccountStorage::new();
    let secrets_storage = SecretStorage::new();

    // Create an account request.
    let account = CreationRequest::new()
        .with_username("admin@example.com") // borrowed
        .with_roles(vec![Role::Admin, Role::Reporter])
        .with_groups(vec![Group::Staff])
        .with_secret("my-secret-secret") // borrowed
        .execute(&account_storage, &secrets_storage)
        .await?;

    // This also deletes the secret from its storage.
    DeletionRequest::from(account)
        .execute(&account_storage, &secrets_storage)
        .await?;
}

fn howto_retrieve_account_and_verify_credentials() {
    let account_storage = AccountStorage::new();
    let secret_storage = SecretStorage::new();

    let account = account_storage
        .query_by_username("admin@example.com")
        .await?;

    match secret_storage
        .verify(&account.uuid, "my-totally-secret-secret")
        .await?
    {
        VerificationResult::Ok => (),
        VerificationResult::Unauthorized => (),
    };
}
