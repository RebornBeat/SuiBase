//! Enhanced error handling for production TEE operations

use std::fmt;
use thiserror::Error;

/// Comprehensive error type for TEE operations
#[derive(Debug, Error)]
pub enum TEEError {
    /// Configuration related errors
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// Attestation process failures with detailed reason
    #[error("Attestation failed: {reason} ({details})")]
    AttestationError {
        reason: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Enclave creation or management errors
    #[error("Enclave error: {reason} ({details})")]
    EnclaveError {
        reason: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Cryptographic operation errors
    #[error("Cryptographic error: {reason} ({details})")]
    CryptoError {
        reason: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Platform-specific TEE errors
    #[error("Platform TEE error: {platform}: {reason} ({details})")]
    PlatformError {
        platform: String,
        reason: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Runtime errors during TEE execution
    #[error("Runtime error: {0}")]
    RuntimeError(String),

    /// I/O related errors
    #[error("I/O error: {0}")]
    IOError(#[from] std::io::Error),

    /// Memory-related errors
    #[error("Memory error: {reason} ({details})")]
    MemoryError {
        reason: String,
        details: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Hardware-related errors
    #[error("Hardware error: {component}: {reason}")]
    HardwareError {
        component: String,
        reason: String,
        recoverable: bool,
    },

    /// Security policy violations
    #[error("Security policy violation: {policy}: {reason}")]
    SecurityPolicyViolation {
        policy: String,
        reason: String,
        severity: SecurityViolationSeverity,
    },

    /// Network-related errors
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Integration-related errors
    #[error("Integration error: {component}: {reason}")]
    IntegrationError { component: String, reason: String },

    /// Generic error for wrap other error types
    #[error("Generic TEE error: {0}")]
    Generic(String),
}

/// Severity of security violations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityViolationSeverity {
    /// Low severity, informational only
    Low,

    /// Medium severity, potential security impact
    Medium,

    /// High severity, likely security impact
    High,

    /// Critical severity, immediate action required
    Critical,
}

/// Result type using TEEError
pub type TEEResult<T> = Result<T, TEEError>;

/// Extension trait for additional error handling utilities
pub trait TEEErrorExt {
    /// Convert to a TEE-specific error
    fn to_tee_error(self) -> TEEError;

    /// Convert to a TEE-specific error with context
    fn to_tee_error_with_context(self, context: &str) -> TEEError;
}

// Implement TEEErrorExt for common error types
impl<E: std::error::Error + 'static> TEEErrorExt for E {
    fn to_tee_error(self) -> TEEError {
        TEEError::Generic(self.to_string())
    }

    fn to_tee_error_with_context(self, context: &str) -> TEEError {
        TEEError::Generic(format!("{}: {}", context, self))
    }
}

/// Secure error logging that avoids leaking sensitive information
pub struct SecureErrorLogger;

impl SecureErrorLogger {
    /// Log error with appropriate filtering of sensitive data
    pub fn log_error(error: &TEEError, level: log::Level) {
        // Remove any sensitive data before logging
        let sanitized_error = Self::sanitize_error(error);

        match level {
            log::Level::Error => log::error!("{}", sanitized_error),
            log::Level::Warn => log::warn!("{}", sanitized_error),
            log::Level::Info => log::info!("{}", sanitized_error),
            log::Level::Debug => log::debug!("{}", sanitized_error),
            log::Level::Trace => log::trace!("{}", sanitized_error),
        }
    }

    /// Sanitize error message to remove sensitive information
    fn sanitize_error(error: &TEEError) -> String {
        let error_string = error.to_string();

        // Remove potentially sensitive patterns
        let sanitized = error_string
            .replace(
                |c: char| c.is_ascii_hexdigit() && error_string.contains("key"),
                "*",
            )
            .replace(
                |c: char| c.is_ascii_hexdigit() && error_string.contains("secret"),
                "*",
            )
            .replace(
                |c: char| c.is_ascii_hexdigit() && error_string.contains("password"),
                "*",
            );

        sanitized
    }

    /// Log error with structured context
    pub fn log_error_with_context(error: &TEEError, context: &str, level: log::Level) {
        let sanitized_error = Self::sanitize_error(error);

        match level {
            log::Level::Error => log::error!("{}: {}", context, sanitized_error),
            log::Level::Warn => log::warn!("{}: {}", context, sanitized_error),
            log::Level::Info => log::info!("{}: {}", context, sanitized_error),
            log::Level::Debug => log::debug!("{}: {}", context, sanitized_error),
            log::Level::Trace => log::trace!("{}: {}", context, sanitized_error),
        }
    }
}

/// Error context builder for better error context propagation
#[derive(Default)]
pub struct ErrorContextBuilder {
    component: Option<String>,
    operation: Option<String>,
    details: Vec<(String, String)>,
}

impl ErrorContextBuilder {
    /// Create a new error context builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set component name
    pub fn component(mut self, component: impl Into<String>) -> Self {
        self.component = Some(component.into());
        self
    }

    /// Set operation name
    pub fn operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = Some(operation.into());
        self
    }

    /// Add context detail
    pub fn detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.push((key.into(), value.into()));
        self
    }

    /// Build context string
    pub fn build(&self) -> String {
        let mut context = String::new();

        if let Some(component) = &self.component {
            context.push_str(&format!("[{}] ", component));
        }

        if let Some(operation) = &self.operation {
            context.push_str(&format!("{}: ", operation));
        }

        if !self.details.is_empty() {
            let details = self
                .details
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(", ");

            context.push_str(&format!("({})", details));
        }

        context
    }

    /// Create error
    pub fn create_error<E: std::error::Error + 'static>(
        &self,
        error_type: fn(String) -> TEEError,
        message: impl Into<String>,
        source: Option<E>,
    ) -> TEEError {
        let context = self.build();
        let message = message.into();
        let full_message = if context.is_empty() {
            message
        } else {
            format!("{} - {}", context, message)
        };

        match source {
            Some(err) => {
                let boxed_err = Box::new(err);
                match error_type("".to_string()) {
                    TEEError::AttestationError { .. } => TEEError::AttestationError {
                        reason: full_message,
                        details: err.to_string(),
                        source: Some(boxed_err),
                    },
                    TEEError::EnclaveError { .. } => TEEError::EnclaveError {
                        reason: full_message,
                        details: err.to_string(),
                        source: Some(boxed_err),
                    },
                    TEEError::CryptoError { .. } => TEEError::CryptoError {
                        reason: full_message,
                        details: err.to_string(),
                        source: Some(boxed_err),
                    },
                    TEEError::PlatformError { .. } => TEEError::PlatformError {
                        platform: self
                            .component
                            .clone()
                            .unwrap_or_else(|| "unknown".to_string()),
                        reason: full_message,
                        details: err.to_string(),
                        source: Some(boxed_err),
                    },
                    _ => error_type(full_message),
                }
            }
            None => error_type(full_message),
        }
    }
}

/// Enhanced macro for creating attestation errors
#[macro_export]
macro_rules! attestation_error {
    ($reason:expr) => {
        $crate::core::error::TEEError::AttestationError {
            reason: $reason.to_string(),
            details: String::new(),
            source: None,
        }
    };
    ($reason:expr, $details:expr) => {
        $crate::core::error::TEEError::AttestationError {
            reason: $reason.to_string(),
            details: $details.to_string(),
            source: None,
        }
    };
    ($reason:expr, $details:expr, $source:expr) => {
        $crate::core::error::TEEError::AttestationError {
            reason: $reason.to_string(),
            details: $details.to_string(),
            source: Some(Box::new($source)),
        }
    };
}

/// Enhanced macro for creating enclave errors
#[macro_export]
macro_rules! enclave_error {
    ($reason:expr) => {
        $crate::core::error::TEEError::EnclaveError {
            reason: $reason.to_string(),
            details: String::new(),
            source: None,
        }
    };
    ($reason:expr, $details:expr) => {
        $crate::core::error::TEEError::EnclaveError {
            reason: $reason.to_string(),
            details: $details.to_string(),
            source: None,
        }
    };
    ($reason:expr, $details:expr, $source:expr) => {
        $crate::core::error::TEEError::EnclaveError {
            reason: $reason.to_string(),
            details: $details.to_string(),
            source: Some(Box::new($source)),
        }
    };
}

/// Enhanced macro for creating crypto errors
#[macro_export]
macro_rules! crypto_error {
    ($reason:expr) => {
        $crate::core::error::TEEError::CryptoError {
            reason: $reason.to_string(),
            details: String::new(),
            source: None,
        }
    };
    ($reason:expr, $details:expr) => {
        $crate::core::error::TEEError::CryptoError {
            reason: $reason.to_string(),
            details: $details.to_string(),
            source: None,
        }
    };
    ($reason:expr, $details:expr, $source:expr) => {
        $crate::core::error::TEEError::CryptoError {
            reason: $reason.to_string(),
            details: $details.to_string(),
            source: Some(Box::new($source)),
        }
    };
}

/// Enhanced macro for creating platform errors
#[macro_export]
macro_rules! platform_error {
    ($platform:expr, $reason:expr) => {
        $crate::core::error::TEEError::PlatformError {
            platform: $platform.to_string(),
            reason: $reason.to_string(),
            details: String::new(),
            source: None,
        }
    };
    ($platform:expr, $reason:expr, $details:expr) => {
        $crate::core::error::TEEError::PlatformError {
            platform: $platform.to_string(),
            reason: $reason.to_string(),
            details: $details.to_string(),
            source: None,
        }
    };
    ($platform:expr, $reason:expr, $details:expr, $source:expr) => {
        $crate::core::error::TEEError::PlatformError {
            platform: $platform.to_string(),
            reason: $reason.to_string(),
            details: $details.to_string(),
            source: Some(Box::new($source)),
        }
    };
}
