//! # SuiStack0X Trusted Execution Environment (TEE) Framework
//!
//! A comprehensive, platform-agnostic TEE implementation for secure, privacy-preserving computing.

// Public modules
pub mod cli;
pub mod core;
pub mod crypto;
pub mod node;
pub mod optimization;
pub mod platforms;
pub mod sui;
pub mod utils;
pub mod verification;

// Re-exports for convenient usage
pub use core::{
    attestation::Attestation,
    enclave::{Enclave, EnclaveBuilder},
    error::{TEEError, TEEResult},
};
pub use node::integration::TEENodeIntegration;
pub use sui::blockchain_interface::TEEBlockchainInterface;
pub use verification::mcp::MCPGenerator;

// Prelude for easy importing
pub mod prelude {
    pub use super::core::attestation::Attestation;
    pub use super::core::enclave::{Enclave, EnclaveBuilder};
    pub use super::core::error::{TEEError, TEEResult};
}

/// Global configuration and initialization
pub fn init() -> TEEResult<()> {
    // Initialize logging
    utils::logging::init_logger()?;

    // Load global configuration
    utils::config::load_global_config()?;

    Ok(())
}

/// Check current system's TEE capabilities
pub fn check_tee_support() -> TEEResult<Vec<String>> {
    let mut supported_platforms = Vec::new();

    #[cfg(feature = "intel-sgx")]
    supported_platforms.push("Intel SGX".to_string());

    #[cfg(feature = "amd-sev")]
    supported_platforms.push("AMD SEV".to_string());

    #[cfg(feature = "arm-trustzone")]
    supported_platforms.push("ARM TrustZone".to_string());

    #[cfg(feature = "aws-nitro")]
    supported_platforms.push("AWS Nitro Enclaves".to_string());

    Ok(supported_platforms)
}
