/// Extension wrapper for static token optional/strict modes.
#[derive(Debug, Clone, Copy)]
pub struct StaticTokenAuthorized(bool);

impl StaticTokenAuthorized {
    /// Creates a new instance with the given authorized state.
    pub fn new(authorized: bool) -> Self {
        Self(authorized)
    }

    /// Returns whether the request token is authorized.
    pub fn is_authorized(&self) -> bool {
        self.0
    }
}
