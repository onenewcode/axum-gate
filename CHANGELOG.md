# Changelog
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


