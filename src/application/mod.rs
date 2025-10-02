//! Application layer containing use cases and application services.
//!
//! This layer orchestrates the flow of data to and from the domain layer,
//! and coordinates the execution of business use cases. It contains:
//! - Use cases that implement specific application workflows
//! - Application services that coordinate domain services
//! - DTOs and data transfer logic

pub(crate) mod accounts;
pub(crate) mod auth;
pub(crate) mod errors;
pub(crate) mod permissions;
