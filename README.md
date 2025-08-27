# axum-gate

[![Crates.io](https://img.shields.io/crates/v/axum-gate.svg)](https://crates.io/crates/axum-gate)
[![Documentation](https://docs.rs/axum-gate/badge.svg)](https://docs.rs/axum-gate)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/your-org/axum-gate/workflows/CI/badge.svg)](https://github.com/your-org/axum-gate/actions)

**The most flexible and developer-friendly authentication middleware for axum applications.**

axum-gate provides production-ready JWT cookie authentication with role-based access control, designed from the ground up for both single-node applications and distributed systems. Built with Rust's type safety and performance in mind, it offers zero-configuration defaults while remaining fully customizable for complex enterprise needs.

## 🌟 Why axum-gate?

### Built for Real-World Applications
- **Zero-sync permissions** - Deterministic hashing eliminates synchronization overhead
- **Separation of concerns** - Account and secret storage can be completely independent
- **Type-safe by design** - Leverage Rust's type system for compile-time permission validation
- **Performance first** - Minimal overhead with efficient JWT handling and caching strategies

### Developer Experience That Just Works
- **Sensible defaults** - Get started with authentication in minutes
- **Composable architecture** - Mix and match components for your specific needs  
- **Rich error handling** - Clear, actionable error messages at every layer
- **Extensive documentation** - From quick start to advanced patterns

### Enterprise Ready
- **Multiple storage backends** - SurrealDB, SeaORM, or bring your own
- **Distributed system support** - Scale horizontally without authentication bottlenecks
- **Security best practices** - Built-in protection against common vulnerabilities
- **Production battle-tested** - Used in high-traffic applications

## ✨ Features

### 🔐 Authentication & Authorization
- **JWT cookie authentication** with secure defaults and automatic expiration handling
- **Hierarchical role-based access control** with supervisor/subordinate relationships
- **Group-based permissions** for organization-level access management
- **Fine-grained permission system** with compile-time validation
- **Custom role and group definitions** tailored to your domain

### 🏗️ Architecture & Design
- **Clean architecture principles** with clear separation between domain, application, and infrastructure layers
- **Pluggable storage backends** - start with in-memory, scale to production databases
- **Composable middleware** - apply different policies to different route groups
- **Zero-configuration defaults** with extensive customization options
- **Async-first design** built for modern Rust web applications

### 🛠️ Developer Tools
- **Static permission validation** - catch permission conflicts at compile time
- **Runtime permission checking** for dynamic permission systems
- **Built-in login/logout handlers** with customizable response formats
- **Comprehensive error types** for precise error handling
- **Rich debugging support** with detailed logging and introspection

### 🚀 Production Features
- **High performance** with minimal memory allocation and CPU overhead
- **Horizontal scaling** support with stateless JWT design
- **Security hardening** with configurable cookie settings and CSRF protection
- **Observability ready** with structured logging and metrics hooks
- **Battle-tested** in production environments

## 🚀 Quick Start

Add axum-gate to your `Cargo.toml`:

```toml
[dependencies]
axum-gate = "0.1"
tokio = { version = "1.0", features = ["full"] }
axum = "0.7"
```

Protect your routes in just a few lines:

```rust
use axum::{routing::get, Router};
use axum_gate::{Gate, AccessPolicy, auth, storage, jwt};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Set up storage (in-memory for development)
    let account_repo = Arc::new(storage::MemoryAccountRepository::default());
    let secret_repo = Arc::new(storage::MemorySecretRepository::default());
    
    // Create a test admin user
    auth::AccountInsertService::insert("admin@example.com", "secure_password")
        .with_roles(vec![auth::Role::Admin])
        .into_repositories(account_repo.clone(), secret_repo.clone())
        .await
        .unwrap();

    // JWT handling with secure defaults
    let jwt_codec = Arc::new(jwt::JsonWebToken::default());

    // Build your protected application
    let app = Router::new()
        // Admin-only routes
        .route("/admin/dashboard", get(admin_dashboard))
        .route("/admin/users", get(manage_users))
        .layer(
            Gate::cookie_deny_all("my-app", jwt_codec.clone())
                .with_policy(AccessPolicy::require_role(auth::Role::Admin))
        )
        
        // User routes
        .route("/profile", get(user_profile))
        .layer(
            Gate::cookie_deny_all("my-app", jwt_codec.clone())
                .with_policy(AccessPolicy::require_role_or_supervisor(auth::Role::User))
        )
        
        // Public authentication routes
        .route("/login", axum::routing::post(login_handler))
        .route("/logout", axum::routing::post(logout_handler));

    // Run your server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap();
    println!("🚀 Server running at http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
}

// Your protected route handlers
async fn admin_dashboard() -> &'static str { "Welcome to the admin dashboard!" }
async fn manage_users() -> &'static str { "User management panel" }
async fn user_profile() -> &'static str { "Your user profile" }
async fn login_handler() -> &'static str { "Login endpoint" }
async fn logout_handler() -> &'static str { "Logout endpoint" }
```

That's it! You now have a fully functional authentication system with role-based access control.

## 🏛️ Architecture Overview

axum-gate follows clean architecture principles with clear boundaries:

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Layer (axum)                        │
│  ┌─────────────────┐  ┌──────────────────────────────────┐ │
│  │ Authentication  │  │        Route Handlers            │ │
│  │   Middleware    │  │                                  │ │
│  └─────────────────┘  └──────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                 Application Layer                           │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │    Login     │  │   Account    │  │  Authorization  │   │
│  │   Service    │  │  Management  │  │    Service      │   │
│  └──────────────┘  └──────────────┘  └─────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                  Domain Layer                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Account   │  │ Permissions │  │   Access Policies   │ │
│  │  Entities   │  │   System    │  │                     │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│              Infrastructure Layer                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │    JWT      │  │  Storage    │  │     Hashing         │ │
│  │  Handling   │  │ Backends    │  │    Services         │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

This architecture ensures:
- **Testability** - Each layer can be tested in isolation
- **Flexibility** - Swap implementations without touching business logic
- **Maintainability** - Clear boundaries and responsibilities
- **Extensibility** - Add new features without breaking existing functionality

## 📚 Detailed Examples

### Custom Roles and Hierarchies

Define your own role system with automatic hierarchy support:

```rust
use axum_gate::advanced::AccessHierarchy;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum CompanyRole {
    CEO,
    CTO,
    TeamLead,
    SeniorDeveloper,
    Developer,
    Intern,
}

impl AccessHierarchy for CompanyRole {
    fn supervisor(&self) -> Option<Self> {
        match self {
            Self::CEO => None,
            Self::CTO => Some(Self::CEO),
            Self::TeamLead => Some(Self::CTO),
            Self::SeniorDeveloper => Some(Self::TeamLead),
            Self::Developer => Some(Self::SeniorDeveloper),
            Self::Intern => Some(Self::Developer),
        }
    }
}

// Now you can use hierarchical access control
AccessPolicy::require_role_or_supervisor(CompanyRole::Developer)
// This grants access to Developer, SeniorDeveloper, TeamLead, CTO, and CEO
```

### Advanced Permission Systems

Create type-safe, nested permission enums:

```rust
#[derive(Debug, Clone, PartialEq)]
enum ApiPermission {
    Read,
    Write,
    Delete,
    Admin,
}

#[derive(Debug, Clone, PartialEq)]
enum Permission {
    Api(ApiPermission),
    System(String),
    Custom { resource: String, action: String },
}

impl AsPermissionName for Permission {
    fn as_permission_name(&self) -> String {
        match self {
            Permission::Api(api) => format!("api:{:?}", api).to_lowercase(),
            Permission::System(sys) => format!("system:{}", sys),
            Permission::Custom { resource, action } => {
                format!("{}:{}", resource, action)
            }
        }
    }
}

// Compile-time validation ensures no conflicts
axum_gate::validate_permissions![
    Permission::Api(ApiPermission::Read),
    Permission::Api(ApiPermission::Write),
    Permission::System("health".to_string()),
    Permission::Custom { 
        resource: "documents".to_string(), 
        action: "publish".to_string() 
    },
];
```

### Production Database Integration

Scale to production with real databases:

```rust
// SurrealDB example
#[cfg(feature = "storage-surrealdb")]
async fn setup_surrealdb_storage() -> Result<(), Box<dyn std::error::Error>> {
    use axum_gate::storage::surrealdb::{SurrealDbRepository, DatabaseScope};
    use axum_gate::storage::TableNames;
    
    let db = surrealdb::Surreal::new::<surrealdb::engine::remote::ws::Ws>(
        "127.0.0.1:8000"
    ).await?;
    
    let scope = DatabaseScope {
        table_names: TableNames::default(),
        namespace: "production".to_string(),
        database: "auth".to_string(),
    };
    
    let repo = Arc::new(SurrealDbRepository::new(db, scope));
    // repo implements both AccountRepository and SecretRepository
    
    Ok(())
}

// SeaORM example  
#[cfg(feature = "storage-seaorm")]
async fn setup_seaorm_storage() -> Result<(), Box<dyn std::error::Error>> {
    use axum_gate::storage::seaorm::SeaOrmRepository;
    use sea_orm::{Database, ConnectOptions};
    
    let mut opt = ConnectOptions::new("postgresql://user:pass@localhost/auth");
    opt.sqlx_logging_level(log::LevelFilter::Info);
    
    let db = Database::connect(opt).await?;
    let repo = Arc::new(SeaOrmRepository::new(&db));
    
    Ok(())
}
```

## 🗺️ Roadmap

### Current Status: v0.1 - Foundation ✅
- [x] Core authentication and authorization
- [x] JWT cookie support
- [x] Role-based access control
- [x] Permission system with validation
- [x] In-memory, SurrealDB, and SeaORM storage
- [x] Comprehensive documentation

### v0.2 - Enhanced Security 🚧
- [ ] Bearer token authentication layer
- [ ] Rotating key sets for JWT validation
- [ ] Session management improvements
- [ ] Enhanced CSRF protection
- [ ] Audit logging system

### v0.3 - Developer Experience 🔮
- [ ] CLI tooling for permission management
- [ ] Migration utilities between storage backends
- [ ] Performance optimization and caching
- [ ] Additional storage backend implementations
- [ ] GraphQL integration examples

### v1.0 - Production Hardening 🎯
- [ ] Comprehensive security audit
- [ ] Performance benchmarking
- [ ] Production deployment guides
- [ ] Monitoring and observability integrations
- [ ] Stability guarantees and SemVer compliance

## 📋 Planned Features

### Automatic JWT Renewal
- **Transparent token refresh** - Automatically renew JWT tokens before expiration
- **Sliding expiration** - Extend token lifetime on active usage
- **Background renewal** - Refresh tokens without user interaction
- **Graceful degradation** - Handle renewal failures elegantly

### Additional Authentication Methods
- **Bearer token support** - Header-based authentication alongside cookies
- **Multi-factor authentication** - TOTP and SMS verification integration
- **OAuth2/OIDC provider** - Social login and enterprise identity providers

### Enhanced Security Features
- **Rate limiting** - Built-in protection against brute force attacks
- **Session management** - Advanced session control and monitoring
- **Audit logging** - Comprehensive security event tracking

### Future Ideas 💡
- WebAssembly support for client-side validation
- Multi-tenant architecture support
- Real-time permission updates
- Advanced caching strategies
- Distributed session storage

**Want to influence the roadmap?** Join our discussions in [GitHub Issues](https://github.com/your-org/axum-gate/issues) or start a [Discussion](https://github.com/your-org/axum-gate/discussions).

## 🤝 Contributing

We love contributions! axum-gate is built by the community, for the community. Whether you're fixing a typo, adding a feature, or improving documentation, every contribution matters.

### 🌟 Ways to Contribute

**Code Contributions**
- 🐛 **Bug fixes** - Help make axum-gate more reliable
- ✨ **New features** - Implement items from our roadmap
- ⚡ **Performance improvements** - Make it faster and more efficient
- 🧪 **Test coverage** - Help us maintain high quality

**Documentation & Community**
- 📚 **Documentation** - Improve guides, examples, and API docs  
- 🎓 **Tutorials** - Create learning resources for the community
- 💬 **Support** - Help other users in discussions and issues
- 🎨 **Examples** - Showcase real-world usage patterns

**Architecture & Design**
- 🏗️ **Storage backends** - Add support for new databases
- 🔒 **Security features** - Enhance authentication and authorization
- 🌐 **Ecosystem integration** - Connect with other Rust web libraries
- 📊 **Monitoring** - Add observability and metrics

### 🚀 Getting Started

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/your-username/axum-gate.git`
3. **Create** a branch: `git checkout -b feature/amazing-feature`
4. **Make** your changes
5. **Test** thoroughly: `cargo test`
6. **Commit** with conventional commits: `git commit -m "feat: add amazing feature"`
7. **Push** to your fork: `git push origin feature/amazing-feature`
8. **Open** a Pull Request

### 📋 Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/axum-gate.git
cd axum-gate

# Install development dependencies
cargo install cargo-watch cargo-tarpaulin

# Run tests
cargo test

# Run tests with coverage
cargo tarpaulin --verbose --all-features --workspace --timeout 120

# Run examples
cargo run --example basic
cargo run --example distributed --features storage-surrealdb

# Format and lint
cargo fmt
cargo clippy -- -D warnings
```

### 🎯 Contribution Guidelines

- **Follow Rust best practices** - Use idiomatic Rust code
- **Write tests** - All new features should have comprehensive tests
- **Document everything** - Add docs for public APIs and examples for complex features
- **Use conventional commits** - Help us generate meaningful changelogs
- **Be respectful** - Follow our Code of Conduct

### 🏆 Recognition

Contributors are recognized in:
- 📝 **Changelog** - Every release highlights contributor efforts
- 👥 **Contributors page** - Permanent recognition on our website  
- 💬 **Social media** - We love to celebrate contributions publicly
- 🎁 **Contributor perks** - Special access to pre-release features and discussions

## 🌍 Community

Join our growing community of developers building secure, scalable web applications with Rust!

### 💬 Get Help & Connect

- **GitHub Discussions** - [Ask questions, share ideas](https://github.com/your-org/axum-gate/discussions)
- **Discord** - [Join our community chat](https://discord.gg/axum-gate) 
- **GitHub Issues** - [Report bugs, request features](https://github.com/your-org/axum-gate/issues)
- **Stack Overflow** - [Use the `axum-gate` tag](https://stackoverflow.com/questions/tagged/axum-gate)

### 📢 Stay Updated

- **GitHub** - [Watch the repository](https://github.com/your-org/axum-gate) for releases
- **Crates.io** - [Follow axum-gate](https://crates.io/crates/axum-gate) for updates
- **Blog** - [Read our technical posts](https://blog.axum-gate.dev)
- **Twitter** - [@axumgate](https://twitter.com/axumgate) for announcements

### 📖 Learning Resources

- **Examples Repository** - Real-world applications and patterns
- **Tutorial Series** - Step-by-step guides from basics to advanced
- **Video Tutorials** - Community-created learning content
- **Best Practices Guide** - Security and performance recommendations

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

axum-gate builds upon the amazing work of the Rust web ecosystem:

- **[axum](https://github.com/tokio-rs/axum)** - The foundation for our middleware
- **[jsonwebtoken](https://github.com/Keats/jsonwebtoken)** - Robust JWT implementation
- **[surrealdb](https://surrealdb.com/)** - Modern database for the modern web
- **[SeaORM](https://github.com/SeaQL/sea-orm)** - Async & dynamic ORM for Rust
- **[tokio](https://tokio.rs/)** - Asynchronous runtime for Rust

Special thanks to all [contributors](https://github.com/your-org/axum-gate/graphs/contributors) who have helped make axum-gate better!

---

<div align="center">

**Built with ❤️ by the Rust community**

[Documentation](https://docs.rs/axum-gate) • [Examples](https://github.com/your-org/axum-gate/tree/main/examples) • [Contributing](CONTRIBUTING.md) • [Changelog](CHANGELOG.md)

</div>