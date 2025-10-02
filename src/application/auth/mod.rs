//! Authentication application services module.
//!
//! This module contains application services for authentication workflows
//! such as login and logout operations. These services contain the business
//! logic for authentication processes and are technology-agnostic.

mod login;
mod logout;

pub use login::{LoginResult, LoginService};
pub use logout::LogoutService;
