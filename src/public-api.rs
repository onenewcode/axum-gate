trait AccountStorageService {
    fn create(&self, acc: &AccountRegistration);
    fn update(&self, acc: &StoredAccount);
    fn delete(&self, acc: &StoredAccount);
    fn query_by_username(&self, username: &str);
}
trait SecretStorageService {
    fn create(&self, acc: &Secret);
    fn update(&self, acc: &Secret);
    fn delete(&self, user_id: &Uuid);
    fn verify(&self, user_id: &Uuid);
}

trait Account {
    fn id(&self) -> &Self::Id;
    fn username(&self) -> &str;
    fn roles(&self) -> &[Self::Role];
    fn groups(&self) -> &[Self::Group];
}

fn howto_create_and_delete_account() {
    // Create storage for account and secrets.
    let account_storage = AccountStorage::new();
    let secrets_storage = SecretStorage::new();

    // Create an account request.
    let account: StoredAccount<Id> =
        AccountRegisterService::register("admin@example.com", "my-secret-secret")
            .with_roles(vec![Role::Admin, Role::Reporter])
            .with_groups(vec![Group::Staff])
            .in_storages(&account_storage, &secrets_storage)
            .await?;

    // This also deletes the secret from its storage.
    AccountDeleteService::delete(account)
        .from_storages(&account_storage, &secrets_storage)
        .await?;
}

fn howto_retrieve_account_and_verify_secret() {
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
