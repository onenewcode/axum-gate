//! Verification value objects for domain operations.
//!
//! This module contains value objects that represent the results
//! of verification operations in the domain layer.

/// The result of a verification operation.
///
/// This represents the domain concept of whether a verification
/// (such as credential verification) was successful or not.
#[derive(Eq, PartialEq, Debug, Clone, Copy)]
pub enum VerificationResult {
    /// The verification was successful.
    Ok,
    /// The verification failed - unauthorized.
    Unauthorized,
}

impl From<bool> for VerificationResult {
    fn from(value: bool) -> Self {
        if value { Self::Ok } else { Self::Unauthorized }
    }
}

impl From<VerificationResult> for bool {
    fn from(result: VerificationResult) -> Self {
        matches!(result, VerificationResult::Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bool_conversion() {
        assert_eq!(VerificationResult::Ok, VerificationResult::from(true));
        assert_eq!(
            VerificationResult::Unauthorized,
            VerificationResult::from(false)
        );
    }

    #[test]
    fn to_bool_conversion() {
        assert_eq!(true, bool::from(VerificationResult::Ok));
        assert_eq!(false, bool::from(VerificationResult::Unauthorized));
    }

    #[test]
    fn verification_result_properties() {
        let ok_result = VerificationResult::Ok;
        let unauthorized_result = VerificationResult::Unauthorized;

        // Test equality
        assert_eq!(ok_result, VerificationResult::Ok);
        assert_eq!(unauthorized_result, VerificationResult::Unauthorized);
        assert_ne!(ok_result, unauthorized_result);

        // Test copy/clone
        let copied_ok = ok_result;
        assert_eq!(ok_result, copied_ok);

        let cloned_unauthorized = unauthorized_result.clone();
        assert_eq!(unauthorized_result, cloned_unauthorized);
    }
}
