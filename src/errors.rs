//! Error types for AnchorKit
//!
//! All errors are represented as [`AnchorKitError`], a unified base error type
//! carrying a [`code`](AnchorKitError::code), [`message`](AnchorKitError::message),
//! and optional [`context`](AnchorKitError::context).
//!
//! The [`ErrorCode`] enum enumerates every distinct error kind. Use the
//! provided constructor helpers (e.g. [`AnchorKitError::already_initialized`])
//! to build errors without touching raw codes.


extern crate alloc;

use alloc::string::String;
use soroban_sdk::contracterror;

// ---------------------------------------------------------------------------
// ErrorCode — the canonical list of all error kinds (replaces the old Error enum)
// ---------------------------------------------------------------------------

/// Numeric error codes for every AnchorKit error kind.
///
/// # Numbering scheme
///
/// Codes are grouped by category. Gaps are intentional to allow future additions
/// within each group without renumbering existing codes.
///
/// | Range  | Category                        |
/// |--------|---------------------------------|
/// |  1–10  | Auth / attestor errors          |
/// | 11–19  | Validation / quote / flow errors|
/// | 20–29  | KYC / webhook / state errors    |
/// | 48–49  | Cache errors                    |
///
/// # Discriminant changelog (issue #160 — merge-conflict resolution)
///
/// The following values changed from their conflicted branch values to the
/// canonical values below. Downstream consumers that hard-code numeric codes
/// must update accordingly:
///
/// | Variant              | Old (conflicted)  | Canonical |
/// |----------------------|-------------------|-----------|
/// | `KycPending`         | 20 or 22          | 20        |
/// | `KycRejected`        | 21 or 23          | 21        |
/// | `WebhookDeliveryFailed` | 24             | 22        |
/// | `NotInitialized`     | 22, 25            | 23        |
/// | `IllegalTransition`  | 23, 24, 26        | 24        |
/// | `SessionExpired`     | 25, 27            | 25        |
/// | `SessionClosed`      | 26 (one branch)   | 26        |
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ErrorCode {
    // Auth / attestor errors (1–10)
    AlreadyInitialized        = 1,
    AttestorAlreadyRegistered = 2,
    AttestorNotRegistered     = 3,
    UnauthorizedAttestor      = 4,
    InvalidTimestamp          = 5,
    ReplayAttack              = 6,
    InvalidQuote              = 7,
    InvalidServiceType        = 8,
    InvalidTransactionIntent  = 9,
    StaleQuote                = 10,

    // Validation / quote / flow errors (11–19)
    ComplianceNotMet          = 11,
    InvalidEndpointFormat     = 12,
    NoQuotesAvailable         = 13,
    ServicesNotConfigured     = 14,
    ValidationError           = 15,
    RateLimitExceeded         = 16,
    AttestationNotFound       = 17,
    InvalidSep10Token         = 18,
    KycNotFound               = 19,

    // KYC / webhook / state errors (20–29)
    KycPending                = 20,
    KycRejected               = 21,
    WebhookDeliveryFailed     = 22,
    NotInitialized            = 23,
    IllegalTransition         = 24,
    SessionExpired            = 25,
    SessionClosed             = 26,

    // Session / routing errors (27–30)
    SessionOperationLimitExceeded = 27,
    InvalidWeights                = 28,

    // Rate limiter extensions (29)
    RateLimitBurstExceeded        = 29,

    // Cache errors (48–49)
    CacheExpired              = 48,
    CacheNotFound             = 49,
}

impl ErrorCode {
    /// Returns the canonical human-readable message for this error code.
    ///
    /// The returned string is a static `&str` suitable for embedding in
    /// [`AnchorKitError::message`] without heap allocation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::ErrorCode;
    ///
    /// assert_eq!(
    ///     ErrorCode::AlreadyInitialized.default_message(),
    ///     "Contract is already initialized"
    /// );
    /// assert!(!ErrorCode::ValidationError.default_message().is_empty());
    /// ```
    pub fn default_message(&self) -> &'static str {
        match self {
            ErrorCode::AlreadyInitialized        => "Contract is already initialized",
            ErrorCode::AttestorAlreadyRegistered => "Attestor is already registered",
            ErrorCode::AttestorNotRegistered     => "Attestor is not registered",
            ErrorCode::UnauthorizedAttestor      => "Attestor is not authorized",
            ErrorCode::InvalidTimestamp          => "Timestamp is invalid",
            ErrorCode::ReplayAttack              => "Replay attack detected",
            ErrorCode::InvalidQuote              => "Quote is invalid",
            ErrorCode::InvalidServiceType        => "Service type is invalid",
            ErrorCode::InvalidTransactionIntent  => "Transaction intent is invalid",
            ErrorCode::StaleQuote                => "Quote has expired",
            ErrorCode::ComplianceNotMet          => "Compliance requirements not met",
            ErrorCode::InvalidEndpointFormat     => "Endpoint format is invalid",
            ErrorCode::NoQuotesAvailable         => "No quotes are available",
            ErrorCode::ServicesNotConfigured     => "Services are not configured",
            ErrorCode::ValidationError           => "Response schema validation failed",
            ErrorCode::RateLimitExceeded         => "Rate limit exceeded",
            ErrorCode::AttestationNotFound       => "Attestation not found",
            ErrorCode::InvalidSep10Token         => "SEP-10 JWT is missing, expired, or invalid",
            ErrorCode::KycNotFound               => "KYC record not found",
            ErrorCode::KycPending                => "KYC verification is pending",
            ErrorCode::KycRejected               => "KYC verification was rejected",
            ErrorCode::WebhookDeliveryFailed     => "Webhook delivery failed validation",
            ErrorCode::NotInitialized            => "Contract is not initialized",
            ErrorCode::IllegalTransition         => "Illegal transaction state transition",
            ErrorCode::SessionExpired            => "Session has expired",
            ErrorCode::SessionClosed                  => "Session is closed",
            ErrorCode::SessionOperationLimitExceeded   => "Session operation limit exceeded",
            ErrorCode::InvalidWeights                  => "Routing weights must sum to 1.0",
            ErrorCode::RateLimitBurstExceeded     => "Submission burst limit exceeded; slow down and retry after the burst window refills",
            ErrorCode::CacheExpired              => "Cache entry has expired",
            ErrorCode::CacheNotFound             => "Cache entry not found",
        }
    }
}

// ---------------------------------------------------------------------------
// AnchorKitError — the unified base error type
// ---------------------------------------------------------------------------

/// The base error type for all AnchorKit errors.
///
/// Every error carries:
/// - `code`: the [`ErrorCode`] identifying the error kind
/// - `message`: a human-readable description
/// - `context`: optional extra detail (field name, received value, etc.)
///
/// Prefer the named constructors (e.g. [`AnchorKitError::replay_attack`]) over
/// constructing this struct directly so that messages stay consistent.
///
/// # Examples
///
/// ```rust
/// use anchorkit::{AnchorKitError, ErrorCode};
///
/// // Named constructor
/// let err = AnchorKitError::replay_attack();
/// assert_eq!(err.code, ErrorCode::ReplayAttack);
///
/// // Custom message
/// let err = AnchorKitError::new(ErrorCode::InvalidQuote, "Quote amount is zero");
/// assert_eq!(err.message, "Quote amount is zero");
///
/// // With context detail
/// let err = AnchorKitError::with_context(
///     ErrorCode::ValidationError,
///     "Schema mismatch",
///     "field: transaction_id",
/// );
/// assert_eq!(err.context.as_deref(), Some("field: transaction_id"));
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorKitError {
    pub code: ErrorCode,
    pub message: String,
    pub context: Option<String>,
}

impl AnchorKitError {
    /// Create a new error with a custom message and no context.
    ///
    /// # Arguments
    ///
    /// * `code` - The [`ErrorCode`] variant that classifies this error.
    /// * `message` - A human-readable description of what went wrong.
    ///
    /// # Returns
    ///
    /// A new [`AnchorKitError`] with `context` set to `None`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::{AnchorKitError, ErrorCode};
    ///
    /// let err = AnchorKitError::new(ErrorCode::InvalidQuote, "Quote amount is zero");
    /// assert_eq!(err.code, ErrorCode::InvalidQuote);
    /// assert_eq!(err.message, "Quote amount is zero");
    /// assert!(err.context.is_none());
    /// ```
    pub fn new(code: ErrorCode, message: &str) -> Self {
        AnchorKitError {
            code,
            message: String::from(message),
            context: None,
        }
    }

    /// Create a new error with a custom message and context detail.
    ///
    /// # Arguments
    ///
    /// * `code` - The [`ErrorCode`] variant that classifies this error.
    /// * `message` - A human-readable description of what went wrong.
    /// * `context` - Additional detail such as a field name or received value.
    ///
    /// # Returns
    ///
    /// A new [`AnchorKitError`] with `context` populated.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::{AnchorKitError, ErrorCode};
    ///
    /// let err = AnchorKitError::with_context(
    ///     ErrorCode::ValidationError,
    ///     "Schema mismatch",
    ///     "field: transaction_id",
    /// );
    /// assert_eq!(err.context.as_deref(), Some("field: transaction_id"));
    /// ```
    pub fn with_context(code: ErrorCode, message: &str, context: &str) -> Self {
        AnchorKitError {
            code,
            message: String::from(message),
            context: Some(String::from(context)),
        }
    }

    /// Create an error using the default message for the given code.
    ///
    /// This is the preferred way to construct errors when no additional context
    /// is needed, as it keeps messages consistent across the codebase.
    ///
    /// # Arguments
    ///
    /// * `code` - The [`ErrorCode`] variant to construct an error for.
    ///
    /// # Returns
    ///
    /// A new [`AnchorKitError`] whose `message` is [`ErrorCode::default_message`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use anchorkit::{AnchorKitError, ErrorCode};
    ///
    /// let err = AnchorKitError::from_code(ErrorCode::AlreadyInitialized);
    /// assert_eq!(err.message, "Contract is already initialized");
    /// ```
    pub fn from_code(code: ErrorCode) -> Self {
        let message = code.default_message();
        AnchorKitError::new(code, message)
    }

    // ------------------------------------------------------------------
    // Named constructors — one per ErrorCode variant
    // ------------------------------------------------------------------

    pub fn already_initialized() -> Self { Self::from_code(ErrorCode::AlreadyInitialized) }
    pub fn attestor_already_registered() -> Self { Self::from_code(ErrorCode::AttestorAlreadyRegistered) }
    pub fn attestor_not_registered() -> Self { Self::from_code(ErrorCode::AttestorNotRegistered) }
    pub fn unauthorized_attestor() -> Self { Self::from_code(ErrorCode::UnauthorizedAttestor) }
    pub fn invalid_timestamp() -> Self { Self::from_code(ErrorCode::InvalidTimestamp) }
    pub fn replay_attack() -> Self { Self::from_code(ErrorCode::ReplayAttack) }
    pub fn invalid_quote() -> Self { Self::from_code(ErrorCode::InvalidQuote) }
    pub fn invalid_service_type() -> Self { Self::from_code(ErrorCode::InvalidServiceType) }
    pub fn invalid_transaction_intent() -> Self { Self::from_code(ErrorCode::InvalidTransactionIntent) }
    pub fn stale_quote() -> Self { Self::from_code(ErrorCode::StaleQuote) }
    pub fn compliance_not_met() -> Self { Self::from_code(ErrorCode::ComplianceNotMet) }
    pub fn invalid_endpoint_format() -> Self { Self::from_code(ErrorCode::InvalidEndpointFormat) }
    pub fn no_quotes_available() -> Self { Self::from_code(ErrorCode::NoQuotesAvailable) }
    pub fn services_not_configured() -> Self { Self::from_code(ErrorCode::ServicesNotConfigured) }
    pub fn not_initialized() -> Self { Self::from_code(ErrorCode::NotInitialized) }
    pub fn attestation_not_found() -> Self { Self::from_code(ErrorCode::AttestationNotFound) }
    pub fn invalid_sep10_token() -> Self { Self::from_code(ErrorCode::InvalidSep10Token) }
    pub fn kyc_not_found() -> Self { Self::from_code(ErrorCode::KycNotFound) }
    pub fn kyc_pending() -> Self { Self::from_code(ErrorCode::KycPending) }
    pub fn kyc_rejected() -> Self { Self::from_code(ErrorCode::KycRejected) }
    pub fn webhook_delivery_failed() -> Self { Self::from_code(ErrorCode::WebhookDeliveryFailed) }
    pub fn rate_limit_exceeded() -> Self { Self::from_code(ErrorCode::RateLimitExceeded) }
    pub fn rate_limit_burst_exceeded() -> Self { Self::from_code(ErrorCode::RateLimitBurstExceeded) }
    pub fn session_expired() -> Self { Self::from_code(ErrorCode::SessionExpired) }
    pub fn session_closed() -> Self { Self::from_code(ErrorCode::SessionClosed) }
    pub fn session_operation_limit_exceeded() -> Self { Self::from_code(ErrorCode::SessionOperationLimitExceeded) }
    pub fn invalid_weights() -> Self { Self::from_code(ErrorCode::InvalidWeights) }
    pub fn cache_expired() -> Self { Self::from_code(ErrorCode::CacheExpired) }
    pub fn cache_not_found() -> Self { Self::from_code(ErrorCode::CacheNotFound) }

    /// Richer constructor that captures how many attempts were made and the
    /// last transport/HTTP error string.
    pub fn webhook_delivery_failed_with_details(attempts_made: u32, last_error: &str) -> Self {
        Self::with_context(
            ErrorCode::WebhookDeliveryFailed,
            ErrorCode::WebhookDeliveryFailed.default_message(),
            &alloc::format!("attempts_made={} last_error={}", attempts_made, last_error),
        )
    }

    pub fn validation_error(context: &str) -> Self {
        Self::with_context(
            ErrorCode::ValidationError,
            ErrorCode::ValidationError.default_message(),
            context,
        )
    }

    pub fn illegal_transition(from: &str, to: &str) -> Self {
        Self::with_context(
            ErrorCode::IllegalTransition,
            ErrorCode::IllegalTransition.default_message(),
            &alloc::format!("{} -> {}", from, to),
        )
    }
}

// ---------------------------------------------------------------------------
// Backward-compat type alias so existing code using `Error` still compiles
// ---------------------------------------------------------------------------

/// Backward-compatible alias. Prefer [`AnchorKitError`] for new code.
pub type Error = AnchorKitError;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_code_sets_message() {
        let err = AnchorKitError::from_code(ErrorCode::AlreadyInitialized);
        assert_eq!(err.code, ErrorCode::AlreadyInitialized);
        assert_eq!(err.message, "Contract is already initialized");
        assert!(err.context.is_none());
    }

    #[test]
    fn test_new_custom_message() {
        let err = AnchorKitError::new(ErrorCode::InvalidQuote, "Quote amount is zero");
        assert_eq!(err.code, ErrorCode::InvalidQuote);
        assert_eq!(err.message, "Quote amount is zero");
        assert!(err.context.is_none());
    }

    #[test]
    fn test_with_context() {
        let err = AnchorKitError::with_context(
            ErrorCode::ValidationError,
            "Schema mismatch",
            "field: transaction_id",
        );
        assert_eq!(err.code, ErrorCode::ValidationError);
        assert_eq!(err.message, "Schema mismatch");
        assert_eq!(err.context, Some(String::from("field: transaction_id")));
    }

    #[test]
    fn test_named_constructors() {
        assert_eq!(AnchorKitError::already_initialized().code,          ErrorCode::AlreadyInitialized);
        assert_eq!(AnchorKitError::attestor_already_registered().code,  ErrorCode::AttestorAlreadyRegistered);
        assert_eq!(AnchorKitError::attestor_not_registered().code,      ErrorCode::AttestorNotRegistered);
        assert_eq!(AnchorKitError::unauthorized_attestor().code,        ErrorCode::UnauthorizedAttestor);
        assert_eq!(AnchorKitError::invalid_timestamp().code,            ErrorCode::InvalidTimestamp);
        assert_eq!(AnchorKitError::replay_attack().code,                ErrorCode::ReplayAttack);
        assert_eq!(AnchorKitError::invalid_quote().code,                ErrorCode::InvalidQuote);
        assert_eq!(AnchorKitError::invalid_service_type().code,         ErrorCode::InvalidServiceType);
        assert_eq!(AnchorKitError::invalid_transaction_intent().code,   ErrorCode::InvalidTransactionIntent);
        assert_eq!(AnchorKitError::stale_quote().code,                  ErrorCode::StaleQuote);
        assert_eq!(AnchorKitError::compliance_not_met().code,           ErrorCode::ComplianceNotMet);
        assert_eq!(AnchorKitError::invalid_endpoint_format().code,      ErrorCode::InvalidEndpointFormat);
        assert_eq!(AnchorKitError::no_quotes_available().code,          ErrorCode::NoQuotesAvailable);
        assert_eq!(AnchorKitError::services_not_configured().code,      ErrorCode::ServicesNotConfigured);
        assert_eq!(AnchorKitError::invalid_sep10_token().code,          ErrorCode::InvalidSep10Token);
        assert_eq!(AnchorKitError::kyc_not_found().code,                ErrorCode::KycNotFound);
        assert_eq!(AnchorKitError::kyc_pending().code,                  ErrorCode::KycPending);
        assert_eq!(AnchorKitError::kyc_rejected().code,                 ErrorCode::KycRejected);
        assert_eq!(AnchorKitError::webhook_delivery_failed().code,      ErrorCode::WebhookDeliveryFailed);
    }

    #[test]
    fn test_validation_error_has_context() {
        let err = AnchorKitError::validation_error("missing field: status");
        assert_eq!(err.code, ErrorCode::ValidationError);
        assert_eq!(err.context, Some(String::from("missing field: status")));
    }

    #[test]
    fn test_error_code_default_messages_are_non_empty() {
        let codes = [
            ErrorCode::AlreadyInitialized,
            ErrorCode::AttestorAlreadyRegistered,
            ErrorCode::AttestorNotRegistered,
            ErrorCode::UnauthorizedAttestor,
            ErrorCode::InvalidTimestamp,
            ErrorCode::ReplayAttack,
            ErrorCode::InvalidQuote,
            ErrorCode::InvalidServiceType,
            ErrorCode::InvalidTransactionIntent,
            ErrorCode::StaleQuote,
            ErrorCode::ComplianceNotMet,
            ErrorCode::InvalidEndpointFormat,
            ErrorCode::NoQuotesAvailable,
            ErrorCode::ServicesNotConfigured,
            ErrorCode::ValidationError,
            ErrorCode::RateLimitExceeded,
            ErrorCode::AttestationNotFound,
            ErrorCode::InvalidSep10Token,
            ErrorCode::KycNotFound,
            ErrorCode::KycPending,
            ErrorCode::KycRejected,
            ErrorCode::WebhookDeliveryFailed,
            ErrorCode::NotInitialized,
            ErrorCode::IllegalTransition,
            ErrorCode::SessionExpired,
            ErrorCode::SessionClosed,
            ErrorCode::SessionOperationLimitExceeded,
            ErrorCode::InvalidWeights,
            ErrorCode::RateLimitBurstExceeded,
            ErrorCode::CacheExpired,
            ErrorCode::CacheNotFound,
        ];
        for code in codes {
            assert!(!code.default_message().is_empty());
        }
    }

    #[test]
    fn test_no_duplicate_discriminants() {
        // Verify canonical discriminant values
        assert_eq!(ErrorCode::KycPending            as u32, 20);
        assert_eq!(ErrorCode::KycRejected           as u32, 21);
        assert_eq!(ErrorCode::WebhookDeliveryFailed as u32, 22);
        assert_eq!(ErrorCode::NotInitialized        as u32, 23);
        assert_eq!(ErrorCode::IllegalTransition     as u32, 24);
        assert_eq!(ErrorCode::SessionExpired        as u32, 25);
        assert_eq!(ErrorCode::SessionClosed         as u32, 26);
        assert_eq!(ErrorCode::CacheExpired          as u32, 48);
        assert_eq!(ErrorCode::CacheNotFound         as u32, 49);
    }

    #[test]
    fn test_type_alias_error_works() {
        let err: Error = AnchorKitError::from_code(ErrorCode::InvalidEndpointFormat);
        assert_eq!(err.code, ErrorCode::InvalidEndpointFormat);
    }

    #[test]
    fn test_errors_are_cloneable_and_comparable() {
        let a = AnchorKitError::from_code(ErrorCode::StaleQuote);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
