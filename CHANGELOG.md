# 📜 Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2025-09-12
### 🏗 Refactoring
- **💥 BREAKING CHANGE:** Introduced hashing module [[0b5cb49]]

- **💥 BREAKING CHANGE:** Renamed BasicGroup to Group [[7416517]]



### 🐞 Bug Fixes
- Fix and simplify doctests; correct imports and remove problematic permission validation section [[10706e1]]



### 📝 Other Changes
- Redesigned cliff.toml [[1d3c29f]]

- Added security audit status to README.md [[3729894]]

- Updated error messages [[327381e]]

- Made error messages more user friendly [[ae92214]]

- Added cargo semver checks to gitlab-ci.yml [[02627a0]]

- Removed access_policy_example test [[5fc404d]]

- Remove repository_additions module, moved content to repositories [[6366a33]]

- GitLab CI configuration for examples [[66018ba]]

- Temporarily added paste and rsa to ignore parameter of audit until solved by surrealdb and sea-orm [[11cdf54]]

- Using rust:latest image for CI [[3c71769]]

- Tried to fix timing attack vector test for CI [[5aa12ee]]

- Cargo deny check [[fd273b4]]

- Clippy warnings [[803308d]]

- Hardened timing attack protection test to work with CI [[f8a8140]]

- Bool conversion test [[a579d27]]

- Clippy errors [[4c7ffc7]]

- Moved test module to the bottom of the file in distributed example [[062db6e]]

- Implemented FromIterator instead of custom from_iter function [[26d0817]]

- Added Cargo.lock to gitignore [[50738e3]]

- Rustfmt [[b7c10e2]]

- Updated MSRV to 1.86 [[745bf90]]

- Updated GitLab CI to Rust 1.85 [[f5be341]]

- Using resolver 2 [[e4a80ab]]

- Rust 2024 required [[f51ff0a]]

- Removed Cargo.lock [[93a6b9c]]

- Updated examples to use 2021 instead of 2024 for backwards compatibility [[7996956]]

- Applied clippy fix [[af439b8]]

- Updated resolver to 2 instead of 3 [[c0a4087]]

- Added initial GitLab CI file [[fe29804]]

- Updated documentation for validate_permissions macro [[4a5d75a]]

- Re-arranged re-exports [[9205118]]

- Re-added no_run to failing tests [[fdd5d69]]

- Updated MSRV and added policy to README.md [[09baccb]]

- Updated documentations [[05fd819]]

- Added rust-version to Cargo.toml [[c10c99e]]

- Bumped version to 1.0.0 [[a2dc4c5]]

- Updated README.md [[f5c0865]]

- Updated TableNames documentation [[95388ec]]

- Updated repository docs [[74df9c6]]

- Removed stability notice for advanced module [[82bc301]]

- Overhaul ValidationReport documentation and restore Default derive [[020d00b]]

- Improve CredentialsVerifier, HashingService, VerificationResult and Codec documentation [[c4491ce]]

- Improve AccountRepository and SecretRepository documentation with semantics, security and usage guidance [[a46d741]]

- Updated LoginResult and LoginService [[9e8be98]]

- Moved advanced module to a separate file [[d960540]]

- Refactored and documented advanced module [[4e676a1]]

- Failing tests, removed non_exhausting attribute from Error enum [[1109617]]

- Updated documentation for repositories and storage root export [[d998613]]

- Restructured jwt module exports [[9be02d0]]

- Replaced directory .rules with a .rules file [[ac81f49]]

- Updated documentation for errors module [[6daffd1]]

- Renamed all error modules to errors [[caa3a95]]

- Removed obsolete validate_permission_uniqueness function [[1b05b60]]

- Updated Credentials documentation [[d641659]]

- Updated Secret documentation [[a616884]]

- Updated crate::advanced module exports and documentation [[d4b6c79]]

- Updated Argon2Hasher documentation [[8c523db]]

- Updated validation module documentation [[2246f7a]]

- Updated crate root documentation [[07deac1]]

- Updated authentication handlers section in crate root [[5185336]]

- Added .rules folder [[66b3646]]

- Added rate-limiting example [[6a14849]]

- Merged Gate::cookie_deny_all into Gate::cookie [[422d3f8]]

- Updated documentation for JWT key management [[42dd3a9]]

- Added hint about JWT key regeneration, Fixed doc links [[eb4042e]]

- Removed unnecessary comments [[e2e8cb6]]

- Timing attack for non-existent users [[fa56d1c]]

- Implemented atomicity of removing secrets and accounts as close as possible [[ef75c17]]

- Updated documentation for CookieTemplateBuilder [[a2dbf11]]

- Updated documentation for CookieTemplateBuilder [[72a2503]]

- Removed unused imports in examples [[30fcf74]]

- Added CookieTemplateBuilder [[d7b5ef4]]

- Added .envrc for direnv [[a080188]]

- :default always returns DevFast variant on debug builds, HighSecurity on release builds [[5820480]]

- Updated SECURITY.md [[e04e21a]]

- Fixed some import errors [[e6aa7fd]]

- Updated error to RoaringTreemap [[4d8b2fd]]

- Replaced RoaringBitmap by RoaringTreemap [[1b1f16c]]

- SurrealDB repository implementation [[1693929]]

- Login function no longer required Json encoded credentials [[468c276]]

- Removed unused import [[d2c36ff]]

- Simple usage example [[6f3878b]]

- Json serialization of the cookie value was not required [[4e385b3]]

- Updated simple-usage example [[4e022d7]]

- Removed deleted demo definition in distributed example [[dc62511]]

- CommaSeparatedValue is now gated behind storage-seaorm feature as it is the only application for it [[17c8424]]

- Moved the simple usage example to be used within the workspace [[4ee9a9a]]

- Removed unused code warning [[22bd782]]

- Removed readme from permission validation example [[43cbd64]]

- Re-arranged use statements [[3c8806a]]

- AsPermissionName is now in domain::traits [[c50ab89]]

- Re-arranged use statements [[ed0fc60]]

- Updated visibility of crate internal function [[3d5f8dc]]

- Redesigned README.md [[5b9c22d]]

- Updated README.md [[ffc96a8]]

- Added timing-attack protection [[7e133eb]]

- Updated README.md [[4bb15dd]]

- Updated README.md [[5b19a12]]

- Updated crate documentation [[7bed0ea]]

- Updated references to the new public API [[c9c2947]]

- Updated documentation of public exports [[fcc4ea1]]

- Removed unused files [[7cd120b]]

- Updated public API [[ddf79ba]]

- Updated to the latest public crate API [[9db1348]]

- Refined public crate API [[75a4fd7]]

- Removed warning of unused imports [[8f4c82b]]

- :from is now implemented for several types [[e179f67]]

- Added Permissions struct that replaces the raw usage of RoaringBitmap [[c54df45]]

- Removed some unnecessary comments [[2b07b97]]

- Removed unused code [[5bb03a9]]

- Tests [[d5aa84c]]

- Renamed storage in infrastructure to repositories [[3398b1b]]

- Updated README.md [[1158424]]

- Removed unused document [[6dd4cb4]]

- Removed unused document [[49b7077]]

- Moved CommaSeparatedValue to separate module [[8b27aa7]]

- Updated documentation [[2b108ba]]

- Renamed methods in AuthorizationService to get a clean API [[4569631]]

- Implemented AccessPolicy within domain::services [[c124936]]

- Updated error implementation [[6e20f22]]

- Extracted JWT validation logic into separate service [[c2cb06c]]

- Removed dead code because of early return [[b8e4974]]

- Extracted authorization logic to domain layer [[04f5031]]

- Unused import warnings [[f8af654]]

- Moved VerificationResult from infrastructure to domain [[ca46f8b]]

- Moved business logic of login and logout to application layer [[e380290]]

- Moved Account*Services to application::accounts [[ba1a848]]

- Updated remaining structure double check markdown file [[daa08f8]]

- Removed compiler warnings [[4e7a407]]

- Moved codecs module from infrastructure to ports [[b42e40b]]

- Moved credentials_verifier and hashing to ports [[49555d2]]

- Moved infrastructure::services::secret_repository to ports:repositories::secret [[ec2fb4a]]

- Moved infrastructure::services::account_repository to ports::repositories::account [[478eff4]]

- Renamed storages to repositories [[23a9a04]]

- Applied hexagonal architecture internally [[bafac97]]

- Added structure double check markdown file [[7a0756a]]

- Updated permissions example documentation [[f1cc4ff]]

- Added documentation for working with accounts and permissions [[7c41a26]]

- Moved documentation from validation to permissions module [[d606773]]

- Merged ApplicationValidator::validate and ::validate_with_report [[e20d1d5]]

- Removed ValidationReport::duplicates [[4e1e821]]

- Further implemented permissions module [[1140838]]

- Removed warning about hidden lifetime [[0815294]]

- Replaced custom SHA256 implementation by external crate [[b0b834e]]

- Replaced const definitions for permissions in distributed example [[508558f]]

- Further updated new permission module [[bc9b762]]

- Started implementing the new permission system [[065ca3a]]

- Updated flake.lock [[9595d59]]

- Refactored flake.nix [[7461c86]]

- Updated Cargo.toml [[16fc4fb]]

- Updated flake.lock [[67349fd]]

- Moved axum-gate to crates folder [[1e5a460]]

- Added convenient builder option functions for JsonWebTokenOptions [[7143adb]]

- Updated CHANGELOG.md [[4ad0216]]

- Version bump to v1.0.0-rc.0 [[584ef22]]

- Updated README.md [[a0b4f3d]]

- Gate is now a intermediary struct and works as kind of builder for a Gate [[bf41702]]

- Updated README.md [[ac9b7ec]]

- Removed unused gate::state module [[b5f5834]]

- Renamed gate::cookie to gate::cookie_service [[23ed034]]

- Moved GateService to cookie::CookieGateService in preparation for bearer auth support [[d93c632]]

- Updated documentation, added route handler for extending permission set [[da031a4]]

- Re-arranged use statements [[7138a45]]

- Moved login and logout example from README.md to the module documentation [[7feb578]]

- Removed security considerations part from README.md [[230eff4]]

- Added initial PermissionSet implementation [[4ba10e4]]

- Added integration test for authorization [[0c9ac8d]]

- Added permission example to README.md [[1f1721a]]

- Added Gate::grant_permissions that accepts a permission set [[706e4cf]]

- Fine-grained permission support in extend to roles and groups [[6bc6ecf]]

- Added initial, untested support for fine-grained permissions [[1e35308]]

- Updated README.md by default Gate behavior [[7bd53d5]]

- Added hint that all requests are denied by default in Gate::new documentation [[ecb0567]]

- Default behavior of a Gate is now to deny access [[6cb6e90]]

- The unauthorized future is created only once [[da4c2d2]]

- Added permissions module in preparation for fine-grained permission support [[4df38f0]]

- Removed unclear documentation for GateState [[43fa629]]

- Replaced GateState::default by ::new to prevent a hidden setting of not_before_time [[212f796]]

- Removed unnecessary comment [[86db51e]]

- Moved AccessScope from gate to separate module [[3918f65]]

- Revert "chore: Removed unnecessary result* from .gitignore" This reverts commit 72e64664171d5a92f3d305ed2d06c4d63b609ad3. [[32e8243]]

- Added roaring dependency in preparation for fine-grained permission support [[138d6f5]]

- Updated internal implementation of Gate in preparation for GateState and fine-grained permission support [[f3deb88]]

- Updated custom role and groups example [[9628e1c]]

- Added custom roles and groups example [[dc536d9]]

- The iat claim is now set on creting the claims to Utc::now [[0247304]]

- Removed README.md from sea-orm example [[b81295b]]

- Removed unnecessary result* from .gitignore [[72e6466]]

- Added .env file to surrealdb example [[fbf3775]]

- Added surrealdb example [[6968a6b]]

- Renamed sea-orm example, Now using the same storage instance for acc and sec [[8753b65]]

- Sea-orm example now working as well [[83c55f1]]

- Models module of sea-orm is now public again [[b77e5cc]]

- Updated README.md [[073b361]]

- Updated README.md [[ba2e3c8]]

- Updated documentation [[0903213]]

- Updated surrealdb storage to new API [[e48f8eb]]

- Secret now contains hashed value, Credentials stores only plain values [[32a8324]]

- **💥 BREAKING CHANGE:** Started outsourcing of secret hashing to secret itself [[dbda109]]

- Support for sea-orm [[bf2c216]]

- Removed public-api module as it has been used for API design [[80d7a26]]

- Applied clippy fix [[b692615]]

- Added surrealdb storage module [[aa6c2f5]]

- Applied clippy fix [[1e4ffcd]]

- Re-arranged use statements in distributed example [[95ad7f2]]

- Distributed example is now working with memory storage again [[2a07049]]

- Further working on the new API [[588edee]]

- Still thinking about the new API [[6bff05c]]

- Thinking about a complete new API [[0d297af]]

- Added missing import statement in sea_orm storage module [[da836fb]]

- Added SeaOrmStorage::new function [[74bf982]]

- Implemented CredentialsVerifierService for SeaOrmStorage [[1ede6a0]]

- Removed unnecessary Into<Vec<u8>> trait bound from route_handlers::login [[7752642]]

- Added missing link hint in sea-orm documentation [[bf8fcf2]]

- Removed unnecessary trait bounds of Passport [[9bcf1c2]]

- Updated README.md [[dabed5d]]

- Updated documentation [[b9d77c2]]

- Added issuer value to distributed example [[48caaaa]]

- Gate now checks for issuer value [[318ce27]]

- Updated route_handler::login to the new JwtClaims API [[72d5466]]

- Added JwtClaims::has_issuer [[a300fab]]

- JWT now requires issuer and expiration time [[24e910f]]

- Role is now Debug [[6312a42]]

- Passport in Gate now requires Debug [[909b22f]]

- Account is now Debug [[0c200c8]]

- Registered claim "iss" is now Option<String> instead of Option<HashSet<String>> [[4b9fe9c]]

- Updated Cargo.lock in distributed example [[0dd424c]]

- Updated distributed example [[36a127c]]

- Added hint about hashing to storage documentation [[a1f8312]]

- Hashing is now done in sea-orm storage as well for credentials insertion and update [[c6256be]]

- Updated sea-orm storage implementation to new API [[b4c613f]]

- Removed fully qualified syntax error in surrealdb storage [[9a5d248]]

- Refactoring BasicRole [[68e50a7]]

- Removed unnecessary line from Cargo.toml [[806f925]]

- Support for sea-orm, restructuring [[6953e63]]

- Removed documentation warnings [[7332e94]]

- Added debug = false to profile.dev for faster debug builds [[ce348dd]]

- Moved TableNames to storage module [[7698656]]

- MIT license [[2ade8af]]

- Maximum release level is now info [[eb2e9bb]]

- Added BasicPassport::with_expires_at [[46be5b4]]

- Removed unused PassportId [[ae1ea87]]

- Password verification is now outsourced to surrealdb instance [[bab23aa]]

- Updated flake.lock [[fcdc37e]]

- Updated examples to match the new API [[c1ac42d]]

- Added missing email field to surrealdb storage implementation [[9086565]]

- Added BasicPassport::email field [[a2c6297]]

- BasicPassport now uses generic for ID [[0c069a0]]

- Added Rust hint for logout example in README.md [[751fe75]]

- README is not included in lib.rs documentation [[05cdad9]]

- Added security notices to README.md [[a54eca6]]

- Added LICENSE [[47ce3c9]]

- Added license and notices [[700c9b7]]

- Added Rust hint to code examples in README.md [[fc89a23]]

- Added description from lib.rs to README.md [[de326e6]]

- Updated license to MIT/Apache-2 [[d893fba]]

- Removed comment from Cargo.toml [[263f2c8]]



### 🚲 Miscellaneous
- **💥 BREAKING CHANGE:** Renamed update_permission_set to extend_permission_set [[17dac0f]]

- **💥 BREAKING CHANGE:** Some JWT properties are now mandatory [[acae31b]]

- **💥 BREAKING CHANGE:** MemorySecretStorage::try_from is now ::from [[6502a46]]

- **💥 BREAKING CHANGE:** CredentialsStorageService::store_credentials now returns the inserted credentials [[08630e4]]

- **💥 BREAKING CHANGE:** Credentials::new now takes id as reference bounded by ToOwned [[5268e6f]]

- **💥 BREAKING CHANGE:** Removed requirement of full qualified syntax for PassportStorage implementation [[f29e2af]]



### 🛳 Features
- Comprehensive security testing, code quality improvements, and documentation updates * Initial plan * Add comprehensive security tests and fix clippy warnings - Fixed all 10 clippy warnings for improved code quality - Added 44 new security-focused tests covering: * JWT manipulation and validation edge cases * Password hashing security and malformed input handling * Authorization bypass attempts and role escalation * Input validation against SQL injection and malformed data * Cookie security attributes and manipulation prevention * Storage layer isolation and concurrent access safety * Unicode/special character handling throughout system * Serialization security for sensitive data structures - Added timing attack awareness test (marked as ignore for CI stability) - Enhanced test coverage for edge cases and error conditions - All existing tests continue to pass Co-authored-by: emirror-de <30552361+emirror-de@users.noreply.github.com> * Add comprehensive security documentation and fix README example - Added SECURITY.md with detailed security considerations and best practices - Fixed README.md example to use consistent field names (user_id vs account_id) - Documented password security, JWT security, cookie security, and authorization security - Added guidance on timing attack considerations and security best practices - Included testing instructions for security test suites - All documentation examples validated and working Co-authored-by: emirror-de <30552361+emirror-de@users.noreply.github.com> * Address review comments: fix imports, remove unused code, use AccountDeleteService Co-authored-by: emirror-de <30552361+emirror-de@users.noreply.github.com> --------- Co-authored-by: copilot-swe-agent[bot] <198982749+Copilot@users.noreply.github.com> Co-authored-by: emirror-de <30552361+emirror-de@users.noreply.github.com> [[7bc5e6e]]

- **💥 BREAKING CHANGE:** Initial support for surrealdb [[f807944]]



## [0.1.0] - 2025-04-05
### 🏗 Refactoring
- **💥 BREAKING CHANGE:** API refinement [[7eae628]]

- **💥 BREAKING CHANGE:** Some API improvements [[835d7f6]]



### 🐞 Bug Fixes
- Added Gate::with_cookie_template because it uses the wrong cookie otherwise [[1b4f6fc]]



### 📝 Other Changes
- Added CHANGELOG.md, Added cliff.toml [[1c53048]]

- Removed unnecessary as_bytes call in documentation [[d1a6876]]

- Changed tokio feature full to sync [[faf05d7]]

- Removed auth_node example [[a4e5995]]

- Added initial, small README.md [[bb4c1ad]]

- Updated keywords, categories and other properties in Cargo.toml [[5df0d8b]]

- Added licenses to deny.toml [[0fdedf8]]

- Updated some description [[7c6acdc]]

- Added distributed example, remove auth_node example [[71f0a40]]

- Added **/target to .gitignore [[bfc967f]]

- It is now possible to pass a cookie template [[72c247a]]

- Removed unrequired .as_bytes call from auth_node example [[f5e8144]]

- Added second group to example [[9c39047]]

- Removed anonymous user because it does not make any sense [[b8c4df0]]

- Added group scope to auth node example [[15f27ff]]

- Moved authorization of minimum role into AccessScope [[af4078b]]

- Added small description of the crate [[b4d17dc]]

- It is now possible to have multiple users and groups in a Gate [[e6481bb]]

- Added group authorization [[c0c7508]]

- Moved roles::role_hierarchy to crate::access_hierarchy [[c6a6606]]

- Added some documentation to the lib module [[56ca140]]

- Renamed example to auth_node [[0b644f3]]

- Removed some warnings [[a911ebb]]

- Removed unused tracing-attributes dependency [[a0ca70e]]

- Small refactor for cleanup, Fixed test [[6b0e8d6]]

- Added secrets hasher service test [[0b2a288]]

- Initial working version with example [[9cd1188]]

- Initially able to create and deliver cookie with JWT [[41d2c4d]]

- HashedCredentials need to be replaced by Credentials because hashing does not work for credential verification [[25bfc9e]]

- Renamed module error to errors [[010e4c8]]

- Updated to development state [[f2019b6]]

- Applied nixfmt, Updated to crane/master [[d23b8bc]]

- Added role and role_hierarchy module [[4a7fcee]]

- Added initial project setup with Credentials struct [[de6d7ff]]



### 🚲 Miscellaneous
- Implemented BasicGroup instead of using a pure String for consistency [[10eb0b7]]



---

<!-- generated by git-cliff -->
