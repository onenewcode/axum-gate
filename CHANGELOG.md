# Changelog
## v1.0.0-rc.0
Release date: *2025-06-18*

### Global changes

#### 🏗  Refactor

- Moved TableNames to storage module [7698656]
- **BREAKING**: Renamed BasicGroup to Group
- **BREAKING**: Introduced hashing module
- Replaced GateState::default by ::new to prevent a hidden setting of not_before_time [212f796]
- Moved GateService to cookie::CookieGateService in preparation for bearer auth support [d93c632]

#### 🐞 Bug Fixes

- Added missing email field to surrealdb storage implementation [9086565]
- Removed fully qualified syntax error in surrealdb storage [9a5d248]
- Hashing is now done in sea-orm storage as well for credentials insertion and update [c6256be]
- Added missing import statement in sea_orm storage module [da836fb]
- Sea-orm example now working as well [83c55f1]

#### 📄 Documentation

- Added description from lib.rs to README.md [de326e6]
- Added Rust hint to code examples in README.md [fc89a23]
- Added license and notices [700c9b7]
- Added security notices to README.md [a54eca6]
- README is not included in lib.rs documentation [05cdad9]
- Added Rust hint for logout example in README.md [751fe75]
- Removed documentation warnings [7332e94]
- Added hint about hashing to storage documentation [a1f8312]
- Updated documentation [b9d77c2]
- Updated README.md [dabed5d]
- Added missing link hint in sea-orm documentation [bf8fcf2]
- Updated documentation [0903213]
- Updated README.md [ba2e3c8]
- Updated README.md [073b361]
- Removed unclear documentation for GateState [43fa629]
- Added hint that all requests are denied by default in Gate::new documentation [ecb0567]
- Updated README.md by default Gate behavior [7bd53d5]
- Added permission example to README.md [1f1721a]
- Removed security considerations part from README.md [230eff4]
- Moved login and logout example from README.md to the module documentation [7feb578]
- Updated README.md [ac9b7ec]
- Updated README.md [a0b4f3d]

#### 🚲 Miscellaneous Tasks

- Removed comment from Cargo.toml [263f2c8]
- Updated license to MIT/Apache-2 [d893fba]
- Added LICENSE [47ce3c9]
- Updated examples to match the new API [c1ac42d]
- Updated flake.lock [fcdc37e]
- Removed unused PassportId [ae1ea87]
- Maximum release level is now info [eb2e9bb]
- MIT license [2ade8af]
- Added debug = false to profile.dev for faster debug builds [ce348dd]
- Removed unnecessary line from Cargo.toml [806f925]
- **BREAKING**: Removed requirement of full qualified syntax for PassportStorage implementation
- Updated sea-orm storage implementation to new API [b4c613f]
- Updated distributed example [36a127c]
- Updated Cargo.lock in distributed example [0dd424c]
- Registered claim "iss" is now Option<String> instead of Option<HashSet<String>> [4b9fe9c]
- Passport in Gate now requires Debug [909b22f]
- JWT now requires issuer and expiration time [24e910f]
- Updated route_handler::login to the new JwtClaims API [72d5466]
- Added issuer value to distributed example [48caaaa]
- Removed unnecessary trait bounds of Passport [9bcf1c2]
- **BREAKING**: Credentials::new now takes id as reference bounded by ToOwned
- Removed unnecessary Into<Vec<u8>> trait bound from route_handlers::login [7752642]
- **BREAKING**: CredentialsStorageService::store_credentials now returns the inserted credentials
- Distributed example is now working with memory storage again [2a07049]
- Re-arranged use statements in distributed example [95ad7f2]
- Applied clippy fix [1e4ffcd]
- Applied clippy fix [b692615]
- Removed public-api module as it has been used for API design [80d7a26]
- Updated surrealdb storage to new API [e48f8eb]
- **BREAKING**: MemorySecretStorage::try_from is now ::from
- Models module of sea-orm is now public again [b77e5cc]
- Renamed sea-orm example, Now using the same storage instance for acc and sec [8753b65]
- Added .env file to surrealdb example [fbf3775]
- Removed unnecessary result* from .gitignore [72e6466]
- Removed README.md from sea-orm example [b81295b]
- The iat claim is now set on creting the claims to Utc::now [0247304]
- Added custom roles and groups example [dc536d9]
- Updated custom role and groups example [9628e1c]
- **BREAKING**: Some JWT properties are now mandatory
- Updated internal implementation of Gate in preparation for GateState and fine-grained permission support [f3deb88]
- Added roaring dependency in preparation for fine-grained permission support [138d6f5]
- Moved AccessScope from gate to separate module [3918f65]
- Removed unnecessary comment [86db51e]
- The unauthorized future is created only once [da4c2d2]
- Re-arranged use statements [7138a45]
- **BREAKING**: Renamed update_permission_set to extend_permission_set
- Updated documentation, added route handler for extending permission set [da031a4]
- Renamed gate::cookie to gate::cookie_service [23ed034]
- Removed unused gate::state module [b5f5834]
- Gate is now a intermediary struct and works as kind of builder for a Gate [bf41702]

#### 🛳  Features

- BasicPassport now uses generic for ID [0c069a0]
- **BREAKING**: Initial support for surrealdb
- Added BasicPassport::email field [a2c6297]
- Password verification is now outsourced to surrealdb instance [bab23aa]
- Added BasicPassport::with_expires_at [46be5b4]
- Account is now Debug [0c200c8]
- Role is now Debug [6312a42]
- Added JwtClaims::has_issuer [a300fab]
- Gate now checks for issuer value [318ce27]
- Implemented CredentialsVerifierService for SeaOrmStorage [1ede6a0]
- Added SeaOrmStorage::new function [74bf982]
- Added surrealdb storage module [aa6c2f5]
- Added surrealdb example [6968a6b]
- Default behavior of a Gate is now to deny access [6cb6e90]
- Fine-grained permission support in extend to roles and groups [6bc6ecf]
- Added Gate::grant_permissions that accepts a permission set [706e4cf]
- Added integration test for authorization [0c9ac8d]

## v0.1.0
Release date: *2025-04-05*

### Global changes

#### ⚒ Testing

- Added secrets hasher service test [0b2a288]

#### 🏗  Refactor

- Renamed module error to errors [010e4c8]
- **BREAKING**: Some API improvements
- **BREAKING**: API refinement
- Moved roles::role_hierarchy to crate::access_hierarchy [c6a6606]
- Moved authorization of minimum role into AccessScope [af4078b]

#### 🐞 Bug Fixes

- Fix: Added Gate::with_cookie_template because it uses the wrong cookie
otherwise [1b4f6fc]

#### 📄 Documentation

- Added some documentation to the lib module [56ca140]
- Added small description of the crate [b4d17dc]
- Added second group to example [9c39047]
- Added initial, small README.md [bb4c1ad]
- Added CHANGELOG.md, Added cliff.toml [1c53048]

#### 🚲 Miscellaneous Tasks

- Applied nixfmt, Updated to crane/master [d23b8bc]
- Removed unused tracing-attributes dependency [a0ca70e]
- Removed some warnings [a911ebb]
- Renamed example to auth_node [0b644f3]
- Added group scope to auth node example [15f27ff]
- Removed anonymous user because it does not make any sense [b8c4df0]
- Chore: Implemented BasicGroup instead of using a pure String for
consistency [10eb0b7]
- Removed unrequired .as_bytes call from auth_node example [f5e8144]
- Added **/target to .gitignore [bfc967f]
- Added distributed example, remove auth_node example [71f0a40]
- Updated some description [7c6acdc]
- Added licenses to deny.toml [0fdedf8]
- Updated keywords, categories and other properties in Cargo.toml [5df0d8b]
- Removed auth_node example [a4e5995]
- Changed tokio feature full to sync [faf05d7]
- Removed unnecessary as_bytes call in documentation [d1a6876]

#### 🛳  Features

- Added role and role_hierarchy module [4a7fcee]
- It is now possible to have multiple users and groups in a Gate [e6481bb]
- It is now possible to pass a cookie template [72c247a]


