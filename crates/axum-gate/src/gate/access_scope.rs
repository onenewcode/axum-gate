use crate::utils::AccessHierarchy;

use tracing::debug;

/// Contains information about the granted access scope.
#[derive(Debug, Clone)]
pub struct AccessScope<Role> {
    /// The role attached to the scope.
    pub role: Role,
    /// Whether all supervisors are granted access.
    pub allow_supervisor_access: bool,
}

impl<Role> AccessScope<Role>
where
    Role: AccessHierarchy + Eq + std::fmt::Display,
{
    /// Creates a new scope with the given role.
    pub fn new(role: Role) -> Self {
        Self {
            role,
            allow_supervisor_access: false,
        }
    }

    /// Returns `true` if the given role matches the scope.
    pub fn grants_role(&self, role: &Role) -> bool {
        self.role.eq(role)
    }

    /// Returns `true` if one of the supervisor of the given role is allowed to access.
    pub fn grants_supervisor(&self, role: &Role) -> bool {
        if !self.allow_supervisor_access {
            debug!(
                "Scope for role {} does not allow supervisor access.",
                self.role
            );
            return false;
        }
        debug!(
            "Checking user role {role} if it is a supervisor of the required role {}.",
            self.role
        );
        let mut subordinate_traveller_role = role.subordinate();
        while let Some(ref r) = subordinate_traveller_role {
            debug!("Logged in Role: {role}, Current subordinate to check: {r}");
            if self.grants_role(r) {
                return true;
            }
            subordinate_traveller_role = r.subordinate();
        }
        false
    }

    /// Allows access to all supervisor of the role of the scope.
    pub fn allow_supervisor(mut self) -> Self {
        self.allow_supervisor_access = true;
        self
    }
}
