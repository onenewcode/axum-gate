# 📜 Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.1] - 2025-11-10
### 📝 Other Changes
- Removed duplicated square brackets in changelog generation 25f3deb



## [1.0.1] - 2025-11-10
### 🐞 Bug Fixes
- Update_account and update_secret panic in seaorm (#8) * fix: update_account and update_secret panic in seaorm * fix: add unique constraints to account_id in Account and Credentials models * fix: qurey the primary key from database,then update secret or account --------- Co-authored-by: Yale <yale.yu@kuka.com> dc39e3d



### 📝 Other Changes
- Updated CHANGELOG.md a9e0bde

- Updated to v1.0.1 172d82c

- Docs.rs now excluding aws_lc_rs feature during build 5dda698

- Updated Cargo.lock 72fbecc

- Added basic update secret and account to sea-orm example 3aafc61

- Update feature arguments in CI workflow e5dae94

- Updated CI semver checks to pass with selected features 7a27c62

- Removed unnecessary comment form Cargo.toml 21576f0

- Trying to fix CI 2c32e12

- Tests in CI 13bfa2c

- Added missing features for clippy to pass integration tests ca16a08

- Clippy call in CI should not check the whole workspace when using aws_lc_rs feature 93edee0

- Updated pipeline to run for default and aws_lc_rs encryption 0fe3b4d

- Merge commit 48884c8

- OAuth2 github example now uses axum from workspace 67c4097

- Support rust_crypto encryption algorithms (#5) ee5bc7c

- OAuth2 github example now uses axum from workspace 58f51da

- Updated MSRV to 1.88 3d7111c

- Updated misleading documentation about key rotation 6327909

- Updated MSRV CI workflows ebbb895



## [1.0.0] - 2025-10-31
### 📝 Other Changes
- Updated CHANGELOG.md b7ff32a

- Git cliff no longer ignores pre-release tags 531304b

- Updated Cargo.lock 373c604

- Bumped to v1.0.0 51fada8

- Increased MSRV to 1.88 to be able to upgrade home dependency ab60a36

- Update axum-extra to 0.12 8a496ca

- Updated Cargo.lock 1c14a51

- Revert "feat: Added semver checks to CI" This reverts commit 1a7e94f1272abe6f45f58fd9b185d139f01bc246. 9c495d2

- Added semver checks to CI 1a7e94f

- Removed .rules and added to .gitignore as this file does not add value to the crate 149e9a3

- Crate level documentation improvements 7a6a525

- Now using subtle >= 2.6.1 as 2.6.0 is yanked d1d41d5

- OAuth2Gate no longer uses anyhow::Result 3d1e7b2

- Merged nightly branch e949763

- Merged nightly branch 03d8c1e

- Update GitHub Sponsors username in FUNDING.yml ef68d49

- Added license notice for surrealdb 7e6c733

- Added "Apache-2.0 WITH LLVM-exception" to deny.toml 9d8a930

- GitHub Bug issue template 69610bd

- Trying to fix those github issue templates 7ea12c5

- Bug issue template 7a0885f

- Updated issue templates bc61d87

- Added missing jwt_codec variable in OAuth2 doc-test 8111879

- Applied clippy hints 9f2f625

- Merge branch 'feat/oauth2' into 'nightly' Feat/oauth2 See merge request lprobst/axum-gate!6 b4da1c8

- Feat/oauth2 a38df7c

- Added issue template config 930749e

- Added github issue templates dac7e73

- Aligned BearerGate implementation to only insert Option<_> extensions 39d00e3

- Added Eq trait bound to Gate::cookie for clarity during build time 9ee26ec

- Updated cookie_template documentation 5786ca0

- :allow_anonymous_with_optional_user now only inserts Option<_> extensions c14ca3d

- Updated bearer gate implementation abf03fd

- Added all-features = true to docs.rs build f45bd84

- Updated .rules 33e4f66

- Updated .rules dafda2d

- BearerGate doc tests 0266b23

- Merge branch 'docs/cookie-gate' into 'nightly' docs: Updated documentation for CookieGate See merge request lprobst/axum-gate!7 0f8cce2

- Updated documentation for CookieGate 6a14edd

- Removed unused dependencies 809fa37

- Added cargo-machete to flake.nix 40dd708

- Added Troubleshooting section to CookieGate d52168e

- Disabled coverage report in gitlab ci 2050a82



## [1.0.0-rc.0] - 2025-10-25
### 🏗 Refactoring
- **💥 BREAKING CHANGE:** Introduced hashing module 0b5cb49

- **💥 BREAKING CHANGE:** Renamed BasicGroup to Group 7416517



### 🐞 Bug Fixes
- Fix and simplify doctests; correct imports and remove problematic permission validation section 10706e1



### 📄 Documentation
- Add missing documentation for prometheus_metrics module - Add comprehensive module-level documentation with usage examples - Document all enums (JwtInvalidKind, AccountDeleteOutcome, SecretRestored, AccountInsertOutcome) and their variants - Document Metrics struct and all its fields - Document metrics() function with return value explanations - Resolves all missing documentation errors (22 items) in audit.rs - Maintains compliance with #![deny(missing_docs)] lint cb4037c



### 📝 Other Changes
- Updated CHANGELOG.md 65e1c75

- Updated Cargo.lock 568cbd5

- Re-arranged use statements in permission-registry example 643656d

- Updated CHANGELOG.md fd38e04

- Updated Rust version to 2024 in permission-registry example 4f0b4c4

- Added snippets about prelude and re-exported crates 69c8f1e

- Allowed unwrap and expect at certain test modules 5e1ac35

- Examples 29d88f1

- Updated CHANGELOG.md a9f4873

- Updated README.md c96b048

- Added unwrap to convenient login check example 47faa87

- Extended prelude by RegisteredClaims and Permissions 2e26d5e

- Moved prelude to separate file 2745a14

- Now using cookie library directly instead of re-export 5ac5c80

- Removed serde_json re-export 0b6b666

- Updated surrealdb example imports 364fa7c

- Updated imports in simple-usage example 8f194bd

- Updated sea-orm example 478ee83

- Updated rate-limiting example 80cb059

- Updated permission-registry example 068f24f

- Updated distributed example ec5f393

- Updated import statements at crate level 5a09b63

- Merge branch 'refactor/errors-module' into 'nightly' refactor: Updated errors module to the ddd structure See merge request lprobst/axum-gate!5 d3a7510

- Doc-tests d73f335

- Removed unnecessary slashes in documentation 2bda856

- Removed unnecessary blank line 9208a25

- Applied clippy fix 5468aa5

- Removed unused variants of secrets::errors 055de11

- Removed unused variants in permissions::errors 7613bea

- Removed unused variants in accounts::errors 798bb92

- Removed unused codecs errors 597f119

- Removed unused variants in authz::errors a001f20

- Removed unused variants in authn errors fc89157

- Removed some leftovers f32a9fb

- Removed unused variants of repository errors 77e6e24

- Removed unused error variants 9dc9bfb

- Moved error modules to the top level categories a9609e3

- Removed unnecessary deny missing docs attributes 9dc15c3

- Wrong module documentation of errors::authn c9a1a51

- Updated errors module to the ddd structure d9c3da1

- Updated custom-roles example 3b34498

- Added some comments to the custom-roles example b9b8f7c

- Prometheus example e57fbab

- CI workflows 0c5ce13

- Doc-test a1b08a8

- Added type hint to Gate documentation example eaa1b53

- Updated CHANGELOG.md 709ba89

- Added github workflow 90dd0be

- Updated gitlab-ci to nightly instead of main f21cb99

- Resolved clippy error about type complexity 9b1c43d

- Updated Cargo.lock 766db79

- Switched from jsonwebtoken/rust_crypto to /aws_lc_rs to remove RSA (RUSTSEC-2023-0071) from dependencies 6e2f7ff

- Updated Cargo.lock 4818596

- Downgraded to v1.0.0-rc.0 d76fd46

- Updated to latest jsonwebtoken dependency a1a88ae

- Updated Cargo.lock 68dd4f4

- Restructured dependency organization 41158f9

- Updated .rules 5837b67

- Added bearer gate documentation to Gate e279caf

- Added Account::has_role, is_member_of and has_permission convenience methods b19dcf3

- Added example for custom enum permissions b04935f

- Moved route_handlers to separate modules 3fbaf9c

- Removed clippy warnings b8e48e3

- Updated README.md 57f02c4

- Updated to the latest state 083523f

- Removed unused doc folder 19c8646

- Updated prelude module 7c0b85e

- Now re-exporting axum_extra d4fd4e5

- Updated .rules cbfc7b7

- Revert "feat: Added metrics jwt_remaining_ttl_seconds" This reverts commit e5dce3d1f90ea2a8e3ee0f146d1010fca7bcbe9e. dc31802

- Added metrics jwt_remaining_ttl_seconds e5dce3d

- Added outcomes of JWT validation for latency labeling 94d8e61

- Integrated metrics to bearer gate, Added authz latency histogram 955a22b

- Merge branch 'refactor/category-domain-design' into 'nightly' Refactor/category domain design See merge request lprobst/axum-gate!2 5ebbaf6

- Updated README.md af01808

- Updated .rules e523190

- Polished documentation and public API 3413ff6

- Moved static_token_authorized module to gate::bearer b4f278a

- Moved as_permission_name module to permissions f4f3b75

- Tests 28fcce1

- Updated .rules 45209fa

- Updated ruleset 3bb4164

- Updated documentation ed8da88

- Errors now unified in errors module 03d4cb8

- Further refactoring, only errors left 9c0b79a

- Started moving to new structure f178687

- Merge branch 'wip/permission-mapping-repository' into 'nightly' Wip/permission mapping repository See merge request lprobst/axum-gate!1 45446a5

- Cargo clippy 912c85b

- Removed bulk demo as it is not implemented yet a6fd752

- Removed comment 524fbb0

- Removed unnecessary sentence 947c1d9

- Updated documentation for Role 1a9fa83

- Missing demonstration of with_cookie_template 7f5d2b7

- Moved crate to workspace root 605d07d

- Fixed documentation warnings cef3f07

- Doc-tests bcbbf22

- Updated bearer gate implementation 6ceab5e

- Fixed clippy warnings 6e66cdd

- Removed documentation part of SurrealPermissionMapping a71de8a

- Updated documentation for CookieGate::new_with_codec c20e742

- Moved CookieGate and CookieService to cookie module a333143

- Added optional user authentication configuration for Gate 14e0f15

- Re-added validation in new function, updated documentation 29fabf5

- Removed constructor that creates inconsistency e2d85d9

- Removed unnecessary validation of PermissionId be80432

- TableName is now gated to be only available when surrealdb or seaorm is activated 8af96db

- Applied clippy fix 284f410

- Unified TableNames for databases 2b9bb0d

- Updated table names for seaorm 6d9b606

- Added implementation of PermissionMappingRepository for seaorm baa9b10

- Updated documentation for LoginService 1e24b1a

- Updated surrealdb repository implementation 952731f

- Updated .rules 18c6b09

- Updated DatabaseScope default 7632352

- Added PermissionMappingRepository implementation for surrealdb 71b2b77

- Added surrealdb best practices to .rules e6229b0

- Simplified MemoryPermissionMapping implementation 75785ff

- Removed PermissionMapping::original_string d903556

- Added PermissionMappingRepository to docs b37112d

- Moved prometheus export to integrations module 1c9db09

- Updated .rules file 2a7d8e4

- Made rust-analyzer happy by adding type for .into() call b654824

- Removed normalized string parameter from PermissionMapping::new d6c2750

- All doc-tests are now running and passing b748825

- Renamed `utils` module to `integrations` as it only contains third party code 14b49f1

- Updated Cargo.lock c981f4c

- PermissionMappingRepository 614089d

- Updated Cargo.lock 48d8e7f

- Updated .rules file 0bd7b9c

- Added convenient method CookieGate::require_login b4be1f9

- Updated .rules ee0375c

- Updated MSRV in README.md to 1.86 f0654cd

- Doctest in audit module 59484d6

- Updated flake version number 629d52f

- Updated SECURITY.md 95a26e5

- Updated .rules file 5cc0875

- Updated prometheus dependency eaf9c19

- Removed clippy warnings 2452594

- Add Prometheus metrics feature, builder hooks, strum label enums, and example; re-export prometheus; instrument account insert success/failure 78dae20

- Updated SECURITY.md a84d2bb

- Updated .rules file dd340dd

- Updated version to v1.0.0-rc.1 1131e1c

- Added additional JWT secret management section to README.md 9eaf12e

- Limited visibility of modules to crate where not inteded to bleed to the outside 95f7edb

- Removed Cargo.lock from .gitignore to ensure correct Nix build 6f34fe2

- Fixed doctests in advanced module 8fbad7e

- Added planned feature section ad4a982

- Updated cliff.toml e1f0056

- Redesigned cliff.toml 1d3c29f

- Added security audit status to README.md 3729894

- Updated error messages 327381e

- Made error messages more user friendly ae92214

- Added cargo semver checks to gitlab-ci.yml 02627a0

- Removed access_policy_example test 5fc404d

- Remove repository_additions module, moved content to repositories 6366a33

- GitLab CI configuration for examples 66018ba

- Temporarily added paste and rsa to ignore parameter of audit until solved by surrealdb and sea-orm 11cdf54

- Using rust:latest image for CI 3c71769

- Tried to fix timing attack vector test for CI 5aa12ee

- Cargo deny check fd273b4

- Clippy warnings 803308d

- Hardened timing attack protection test to work with CI f8a8140

- Bool conversion test a579d27

- Clippy errors 4c7ffc7

- Moved test module to the bottom of the file in distributed example 062db6e

- Implemented FromIterator instead of custom from_iter function 26d0817

- Added Cargo.lock to gitignore 50738e3

- Rustfmt b7c10e2

- Updated MSRV to 1.86 745bf90

- Updated GitLab CI to Rust 1.85 f5be341

- Using resolver 2 e4a80ab

- Rust 2024 required f51ff0a

- Removed Cargo.lock 93a6b9c

- Updated examples to use 2021 instead of 2024 for backwards compatibility 7996956

- Applied clippy fix af439b8

- Updated resolver to 2 instead of 3 c0a4087

- Added initial GitLab CI file fe29804

- Updated documentation for validate_permissions macro 4a5d75a

- Re-arranged re-exports 9205118

- Re-added no_run to failing tests fdd5d69

- Updated MSRV and added policy to README.md 09baccb

- Updated documentations 05fd819

- Added rust-version to Cargo.toml c10c99e

- Bumped version to 1.0.0 a2dc4c5

- Updated README.md f5c0865

- Updated TableNames documentation 95388ec

- Updated repository docs 74df9c6

- Removed stability notice for advanced module 82bc301

- Overhaul ValidationReport documentation and restore Default derive 020d00b

- Improve CredentialsVerifier, HashingService, VerificationResult and Codec documentation c4491ce

- Improve AccountRepository and SecretRepository documentation with semantics, security and usage guidance a46d741

- Updated LoginResult and LoginService 9e8be98

- Moved advanced module to a separate file d960540

- Refactored and documented advanced module 4e676a1

- Failing tests, removed non_exhausting attribute from Error enum 1109617

- Updated documentation for repositories and storage root export d998613

- Restructured jwt module exports 9be02d0

- Replaced directory .rules with a .rules file ac81f49

- Updated documentation for errors module 6daffd1

- Renamed all error modules to errors caa3a95

- Removed obsolete validate_permission_uniqueness function 1b05b60

- Updated Credentials documentation d641659

- Updated Secret documentation a616884

- Updated crate::advanced module exports and documentation d4b6c79

- Updated Argon2Hasher documentation 8c523db

- Updated validation module documentation 2246f7a

- Updated crate root documentation 07deac1

- Updated authentication handlers section in crate root 5185336

- Added .rules folder 66b3646

- Added rate-limiting example 6a14849

- Merged Gate::cookie_deny_all into Gate::cookie 422d3f8

- Updated documentation for JWT key management 42dd3a9

- Added hint about JWT key regeneration, Fixed doc links eb4042e

- Removed unnecessary comments e2e8cb6

- Timing attack for non-existent users fa56d1c

- Implemented atomicity of removing secrets and accounts as close as possible ef75c17

- Updated documentation for CookieTemplateBuilder a2dbf11

- Updated documentation for CookieTemplateBuilder 72a2503

- Removed unused imports in examples 30fcf74

- Added CookieTemplateBuilder d7b5ef4

- Added .envrc for direnv a080188

- :default always returns DevFast variant on debug builds, HighSecurity on release builds 5820480

- Updated SECURITY.md e04e21a

- Fixed some import errors e6aa7fd

- Updated error to RoaringTreemap 4d8b2fd

- Replaced RoaringBitmap by RoaringTreemap 1b1f16c

- SurrealDB repository implementation 1693929

- Login function no longer required Json encoded credentials 468c276

- Removed unused import d2c36ff

- Simple usage example 6f3878b

- Json serialization of the cookie value was not required 4e385b3

- Updated simple-usage example 4e022d7

- Removed deleted demo definition in distributed example dc62511

- CommaSeparatedValue is now gated behind storage-seaorm feature as it is the only application for it 17c8424

- Moved the simple usage example to be used within the workspace 4ee9a9a

- Removed unused code warning 22bd782

- Removed readme from permission validation example 43cbd64

- Re-arranged use statements 3c8806a

- AsPermissionName is now in domain::traits c50ab89

- Re-arranged use statements ed0fc60

- Updated visibility of crate internal function 3d5f8dc

- Redesigned README.md 5b9c22d

- Updated README.md ffc96a8

- Added timing-attack protection 7e133eb

- Updated README.md 4bb15dd

- Updated README.md 5b19a12

- Updated crate documentation 7bed0ea

- Updated references to the new public API c9c2947

- Updated documentation of public exports fcc4ea1

- Removed unused files 7cd120b

- Updated public API ddf79ba

- Updated to the latest public crate API 9db1348

- Refined public crate API 75a4fd7

- Removed warning of unused imports 8f4c82b

- :from is now implemented for several types e179f67

- Added Permissions struct that replaces the raw usage of RoaringBitmap c54df45

- Removed some unnecessary comments 2b07b97

- Removed unused code 5bb03a9

- Tests d5aa84c

- Renamed storage in infrastructure to repositories 3398b1b

- Updated README.md 1158424

- Removed unused document 6dd4cb4

- Removed unused document 49b7077

- Moved CommaSeparatedValue to separate module 8b27aa7

- Updated documentation 2b108ba

- Renamed methods in AuthorizationService to get a clean API 4569631

- Implemented AccessPolicy within domain::services c124936

- Updated error implementation 6e20f22

- Extracted JWT validation logic into separate service c2cb06c

- Removed dead code because of early return b8e4974

- Extracted authorization logic to domain layer 04f5031

- Unused import warnings f8af654

- Moved VerificationResult from infrastructure to domain ca46f8b

- Moved business logic of login and logout to application layer e380290

- Moved Account*Services to application::accounts ba1a848

- Updated remaining structure double check markdown file daa08f8

- Removed compiler warnings 4e7a407

- Moved codecs module from infrastructure to ports b42e40b

- Moved credentials_verifier and hashing to ports 49555d2

- Moved infrastructure::services::secret_repository to ports:repositories::secret ec2fb4a

- Moved infrastructure::services::account_repository to ports::repositories::account 478eff4

- Renamed storages to repositories 23a9a04

- Applied hexagonal architecture internally bafac97

- Added structure double check markdown file 7a0756a

- Updated permissions example documentation f1cc4ff

- Added documentation for working with accounts and permissions 7c41a26

- Moved documentation from validation to permissions module d606773

- Merged ApplicationValidator::validate and ::validate_with_report e20d1d5

- Removed ValidationReport::duplicates 4e1e821

- Further implemented permissions module 1140838

- Removed warning about hidden lifetime 0815294

- Replaced custom SHA256 implementation by external crate b0b834e

- Replaced const definitions for permissions in distributed example 508558f

- Further updated new permission module bc9b762

- Started implementing the new permission system 065ca3a

- Updated flake.lock 9595d59

- Refactored flake.nix 7461c86

- Updated Cargo.toml 16fc4fb

- Updated flake.lock 67349fd

- Moved axum-gate to crates folder 1e5a460

- Added convenient builder option functions for JsonWebTokenOptions 7143adb

- Updated CHANGELOG.md 4ad0216

- Version bump to v1.0.0-rc.0 584ef22

- Updated README.md a0b4f3d

- Gate is now a intermediary struct and works as kind of builder for a Gate bf41702

- Updated README.md ac9b7ec

- Removed unused gate::state module b5f5834

- Renamed gate::cookie to gate::cookie_service 23ed034

- Moved GateService to cookie::CookieGateService in preparation for bearer auth support d93c632

- Updated documentation, added route handler for extending permission set da031a4

- Re-arranged use statements 7138a45

- Moved login and logout example from README.md to the module documentation 7feb578

- Removed security considerations part from README.md 230eff4

- Added initial PermissionSet implementation 4ba10e4

- Added integration test for authorization 0c9ac8d

- Added permission example to README.md 1f1721a

- Added Gate::grant_permissions that accepts a permission set 706e4cf

- Fine-grained permission support in extend to roles and groups 6bc6ecf

- Added initial, untested support for fine-grained permissions 1e35308

- Updated README.md by default Gate behavior 7bd53d5

- Added hint that all requests are denied by default in Gate::new documentation ecb0567

- Default behavior of a Gate is now to deny access 6cb6e90

- The unauthorized future is created only once da4c2d2

- Added permissions module in preparation for fine-grained permission support 4df38f0

- Removed unclear documentation for GateState 43fa629

- Replaced GateState::default by ::new to prevent a hidden setting of not_before_time 212f796

- Removed unnecessary comment 86db51e

- Moved AccessScope from gate to separate module 3918f65

- Revert "chore: Removed unnecessary result* from .gitignore" This reverts commit 72e64664171d5a92f3d305ed2d06c4d63b609ad3. 32e8243

- Added roaring dependency in preparation for fine-grained permission support 138d6f5

- Updated internal implementation of Gate in preparation for GateState and fine-grained permission support f3deb88

- Updated custom role and groups example 9628e1c

- Added custom roles and groups example dc536d9

- The iat claim is now set on creting the claims to Utc::now 0247304

- Removed README.md from sea-orm example b81295b

- Removed unnecessary result* from .gitignore 72e6466

- Added .env file to surrealdb example fbf3775

- Added surrealdb example 6968a6b

- Renamed sea-orm example, Now using the same storage instance for acc and sec 8753b65

- Sea-orm example now working as well 83c55f1

- Models module of sea-orm is now public again b77e5cc

- Updated README.md 073b361

- Updated README.md ba2e3c8

- Updated documentation 0903213

- Updated surrealdb storage to new API e48f8eb

- Secret now contains hashed value, Credentials stores only plain values 32a8324

- **💥 BREAKING CHANGE:** Started outsourcing of secret hashing to secret itself dbda109

- Support for sea-orm bf2c216

- Removed public-api module as it has been used for API design 80d7a26

- Applied clippy fix b692615

- Added surrealdb storage module aa6c2f5

- Applied clippy fix 1e4ffcd

- Re-arranged use statements in distributed example 95ad7f2

- Distributed example is now working with memory storage again 2a07049

- Further working on the new API 588edee

- Still thinking about the new API 6bff05c

- Thinking about a complete new API 0d297af

- Added missing import statement in sea_orm storage module da836fb

- Added SeaOrmStorage::new function 74bf982

- Implemented CredentialsVerifierService for SeaOrmStorage 1ede6a0

- Removed unnecessary Into<Vec<u8>> trait bound from route_handlers::login 7752642

- Added missing link hint in sea-orm documentation bf8fcf2

- Removed unnecessary trait bounds of Passport 9bcf1c2

- Updated README.md dabed5d

- Updated documentation b9d77c2

- Added issuer value to distributed example 48caaaa

- Gate now checks for issuer value 318ce27

- Updated route_handler::login to the new JwtClaims API 72d5466

- Added JwtClaims::has_issuer a300fab

- JWT now requires issuer and expiration time 24e910f

- Role is now Debug 6312a42

- Passport in Gate now requires Debug 909b22f

- Account is now Debug 0c200c8

- Registered claim "iss" is now Option<String> instead of Option<HashSet<String>> 4b9fe9c

- Updated Cargo.lock in distributed example 0dd424c

- Updated distributed example 36a127c

- Added hint about hashing to storage documentation a1f8312

- Hashing is now done in sea-orm storage as well for credentials insertion and update c6256be

- Updated sea-orm storage implementation to new API b4c613f

- Removed fully qualified syntax error in surrealdb storage 9a5d248

- Refactoring BasicRole 68e50a7

- Removed unnecessary line from Cargo.toml 806f925

- Support for sea-orm, restructuring 6953e63

- Removed documentation warnings 7332e94

- Added debug = false to profile.dev for faster debug builds ce348dd

- Moved TableNames to storage module 7698656

- MIT license 2ade8af

- Maximum release level is now info eb2e9bb

- Added BasicPassport::with_expires_at 46be5b4

- Removed unused PassportId ae1ea87

- Password verification is now outsourced to surrealdb instance bab23aa

- Updated flake.lock fcdc37e

- Updated examples to match the new API c1ac42d

- Added missing email field to surrealdb storage implementation 9086565

- Added BasicPassport::email field a2c6297

- BasicPassport now uses generic for ID 0c069a0

- Added Rust hint for logout example in README.md 751fe75

- README is not included in lib.rs documentation 05cdad9

- Added security notices to README.md a54eca6

- Added LICENSE 47ce3c9

- Added license and notices 700c9b7

- Added Rust hint to code examples in README.md fc89a23

- Added description from lib.rs to README.md de326e6

- Updated license to MIT/Apache-2 d893fba

- Removed comment from Cargo.toml 263f2c8



### 🚲 Miscellaneous
- **💥 BREAKING CHANGE:** Removed DecodingKey and EncodingKey from prelude bf35415

- **💥 BREAKING CHANGE:** Renamed update_permission_set to extend_permission_set 17dac0f

- **💥 BREAKING CHANGE:** Some JWT properties are now mandatory acae31b

- **💥 BREAKING CHANGE:** MemorySecretStorage::try_from is now ::from 6502a46

- **💥 BREAKING CHANGE:** CredentialsStorageService::store_credentials now returns the inserted credentials 08630e4

- **💥 BREAKING CHANGE:** Credentials::new now takes id as reference bounded by ToOwned 5268e6f

- **💥 BREAKING CHANGE:** Removed requirement of full qualified syntax for PassportStorage implementation f29e2af



### 🛳 Features
- **💥 BREAKING CHANGE:** Added deny unwrap, expect and unsafe code 71de97c

- Add tracing-based audit logging gated behind feature - Introduce audit module with spans/events (request, authz, JWT issues, account lifecycle) - Instrument gate, login/logout handlers, and account services - Remove unused audit functions and simplify module-level cfg gating - No secrets logged; structured fields only; feature-off has zero overhead *(audit)*  3a87d25

- Comprehensive security testing, code quality improvements, and documentation updates * Initial plan * Add comprehensive security tests and fix clippy warnings - Fixed all 10 clippy warnings for improved code quality - Added 44 new security-focused tests covering: * JWT manipulation and validation edge cases * Password hashing security and malformed input handling * Authorization bypass attempts and role escalation * Input validation against SQL injection and malformed data * Cookie security attributes and manipulation prevention * Storage layer isolation and concurrent access safety * Unicode/special character handling throughout system * Serialization security for sensitive data structures - Added timing attack awareness test (marked as ignore for CI stability) - Enhanced test coverage for edge cases and error conditions - All existing tests continue to pass Co-authored-by: emirror-de <30552361+emirror-de@users.noreply.github.com> * Add comprehensive security documentation and fix README example - Added SECURITY.md with detailed security considerations and best practices - Fixed README.md example to use consistent field names (user_id vs account_id) - Documented password security, JWT security, cookie security, and authorization security - Added guidance on timing attack considerations and security best practices - Included testing instructions for security test suites - All documentation examples validated and working Co-authored-by: emirror-de <30552361+emirror-de@users.noreply.github.com> * Address review comments: fix imports, remove unused code, use AccountDeleteService Co-authored-by: emirror-de <30552361+emirror-de@users.noreply.github.com> --------- Co-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com> Co-authored-by: emirror-de <30552361+emirror-de@users.noreply.github.com> 7bc5e6e

- **💥 BREAKING CHANGE:** Initial support for surrealdb f807944



## [0.1.0] - 2025-04-05
### 🏗 Refactoring
- **💥 BREAKING CHANGE:** API refinement 7eae628

- **💥 BREAKING CHANGE:** Some API improvements 835d7f6



### 🐞 Bug Fixes
- Added Gate::with_cookie_template because it uses the wrong cookie otherwise 1b4f6fc



### 📝 Other Changes
- Added CHANGELOG.md, Added cliff.toml 1c53048

- Removed unnecessary as_bytes call in documentation d1a6876

- Changed tokio feature full to sync faf05d7

- Removed auth_node example a4e5995

- Added initial, small README.md bb4c1ad

- Updated keywords, categories and other properties in Cargo.toml 5df0d8b

- Added licenses to deny.toml 0fdedf8

- Updated some description 7c6acdc

- Added distributed example, remove auth_node example 71f0a40

- Added **/target to .gitignore bfc967f

- It is now possible to pass a cookie template 72c247a

- Removed unrequired .as_bytes call from auth_node example f5e8144

- Added second group to example 9c39047

- Removed anonymous user because it does not make any sense b8c4df0

- Added group scope to auth node example 15f27ff

- Moved authorization of minimum role into AccessScope af4078b

- Added small description of the crate b4d17dc

- It is now possible to have multiple users and groups in a Gate e6481bb

- Added group authorization c0c7508

- Moved roles::role_hierarchy to crate::access_hierarchy c6a6606

- Added some documentation to the lib module 56ca140

- Renamed example to auth_node 0b644f3

- Removed some warnings a911ebb

- Removed unused tracing-attributes dependency a0ca70e

- Small refactor for cleanup, Fixed test 6b0e8d6

- Added secrets hasher service test 0b2a288

- Initial working version with example 9cd1188

- Initially able to create and deliver cookie with JWT 41d2c4d

- HashedCredentials need to be replaced by Credentials because hashing does not work for credential verification 25bfc9e

- Renamed module error to errors 010e4c8

- Updated to development state f2019b6

- Applied nixfmt, Updated to crane/master d23b8bc

- Added role and role_hierarchy module 4a7fcee

- Added initial project setup with Credentials struct de6d7ff



### 🚲 Miscellaneous
- Implemented BasicGroup instead of using a pure String for consistency 10eb0b7



---

<!-- generated by git-cliff -->
