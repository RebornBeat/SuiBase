//! Intel SGX Platform Implementation for SuiStack0X TEE Framework

use crate::core::error::{TEEError, TEEResult};
use crate::platforms::{OpenSourceStatus, PlatformState, PrivacyLevel, SecurityLevel, TEEPlatform};
use std::sync::atomic::{AtomicBool, Ordering};

pub mod attestation;
pub mod enclave;

/// Intel SGX Platform Constants
pub const SGX_QUOTE_MINIMUM_SIZE: usize = 432;
pub const SGX_MEASUREMENT_SIZE: usize = 32;
pub const SGX_KEY_SIZE: usize = 32;

/// Intel SGX Platform Implementation
pub struct IntelSGXPlatform {
    initialized: AtomicBool,
    features: SGXFeatures,
    state: PlatformState,
}

/// SGX-specific features and capabilities
#[derive(Debug, Clone)]
pub struct SGXFeatures {
    pub sgx1_supported: bool,
    pub sgx2_supported: bool,
    pub enclave_size_64bit: bool,
    pub max_enclave_size: usize,
    pub aesm_service_available: bool,
    pub quote_provider_available: bool,
}

/// Quote structure layout for SGX
#[derive(Debug, Clone)]
pub struct SGXQuoteLayout {
    pub header_size: usize,
    pub body_size: usize,
    pub signature_size: usize,
    pub mrenclave_offset: usize,
    pub mrsigner_offset: usize,
}

impl IntelSGXPlatform {
    /// Create a new Intel SGX platform instance
    pub fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            features: SGXFeatures {
                sgx1_supported: false,
                sgx2_supported: false,
                enclave_size_64bit: false,
                max_enclave_size: 0,
                aesm_service_available: false,
                quote_provider_available: false,
            },
            state: PlatformState::Uninitialized,
        }
    }

    /// Get SGX quote layout information
    pub fn get_quote_layout() -> SGXQuoteLayout {
        SGXQuoteLayout {
            header_size: 48,
            body_size: 384,
            signature_size: 64,
            mrenclave_offset: 112,
            mrsigner_offset: 176,
        }
    }

    /// Check if SGX is supported on this hardware
    fn check_sgx_support(&self) -> TEEResult<bool> {
        #[cfg(target_arch = "x86_64")]
        {
            use raw_cpuid::CpuId;
            let cpuid = CpuId::new();

            // Check SGX leaf
            if let Some(sgx_leaf) = cpuid.get_extended_feature_info() {
                return Ok(sgx_leaf.has_sgx());
            }
        }

        Ok(false)
    }

    /// Detect available SGX features
    fn detect_sgx_features(&mut self) -> TEEResult<()> {
        #[cfg(target_arch = "x86_64")]
        {
            use raw_cpuid::CpuId;
            let cpuid = CpuId::new();

            if let Some(sgx_leaf) = cpuid.get_sgx_info() {
                self.features.sgx1_supported = sgx_leaf.has_sgx1();
                self.features.sgx2_supported = sgx_leaf.has_sgx2();
                self.features.enclave_size_64bit = sgx_leaf.has_enclave_size_64bit();
                self.features.max_enclave_size = 1 << sgx_leaf.max_enclave_size_64();
            }

            // Check AESM service availability
            self.features.aesm_service_available =
                std::fs::metadata("/var/run/aesmd/aesm.socket").is_ok();

            // Check quote provider
            self.features.quote_provider_available =
                std::fs::metadata("/dev/sgx/provision").is_ok();
        }

        Ok(())
    }
}

impl TEEPlatform for IntelSGXPlatform {
    fn initialize(&mut self) -> TEEResult<()> {
        // Ensure we only initialize once
        if self.initialized.load(Ordering::SeqCst) {
            return Err(TEEError::PlatformError {
                platform: "intel_sgx".to_string(),
                reason: "Already initialized".to_string(),
                details: "Platform can only be initialized once".to_string(),
                source: None,
            });
        }

        // Check SGX support
        if !self.check_sgx_support()? {
            return Err(TEEError::PlatformError {
                platform: "intel_sgx".to_string(),
                reason: "SGX not supported".to_string(),
                details: "Hardware does not support Intel SGX".to_string(),
                source: None,
            });
        }

        // Detect features
        self.detect_sgx_features()?;

        // Verify minimum requirements
        if !self.features.sgx1_supported {
            return Err(TEEError::PlatformError {
                platform: "intel_sgx".to_string(),
                reason: "SGX1 not supported".to_string(),
                details: "SGX1 is required minimum feature".to_string(),
                source: None,
            });
        }

        // Check AESM service
        if !self.features.aesm_service_available {
            return Err(TEEError::PlatformError {
                platform: "intel_sgx".to_string(),
                reason: "AESM service unavailable".to_string(),
                details: "Intel AESM service is required for attestation".to_string(),
                source: None,
            });
        }

        self.state = PlatformState::Initialized;
        self.initialized.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn create_enclave(&mut self) -> TEEResult<Box<dyn crate::platforms::SecureEnclave>> {
        if !self.initialized.load(Ordering::SeqCst) {
            return Err(TEEError::PlatformError {
                platform: "intel_sgx".to_string(),
                reason: "Not initialized".to_string(),
                details: "Platform must be initialized before creating enclaves".to_string(),
                source: None,
            });
        }

        Ok(Box::new(enclave::SGXEnclave::new()?))
    }

    fn get_security_level(&self) -> SecurityLevel {
        SecurityLevel::High
    }

    fn get_privacy_level(&self) -> PrivacyLevel {
        PrivacyLevel::Strong
    }

    fn get_open_source_status(&self) -> OpenSourceStatus {
        OpenSourceStatus::PartiallyOpen
    }

    fn get_state(&self) -> PlatformState {
        self.state
    }
}

// Provide a convenient way to create Intel SGX platform
pub fn create_sgx_platform() -> TEEResult<IntelSGXPlatform> {
    let mut platform = IntelSGXPlatform::new();
    platform.initialize()?;
    Ok(platform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sgx_platform_initialization() -> TEEResult<()> {
        let mut platform = IntelSGXPlatform::new();

        // Test initialization
        match platform.initialize() {
            Ok(_) => {
                assert!(platform.initialized.load(Ordering::SeqCst));
                assert_eq!(platform.get_state(), PlatformState::Initialized);
            }
            Err(e) => {
                // On systems without SGX, initialization should fail gracefully
                assert!(!platform.initialized.load(Ordering::SeqCst));
                println!(
                    "SGX initialization failed (expected on non-SGX systems): {}",
                    e
                );
            }
        }

        Ok(())
    }

    #[test]
    fn test_sgx_security_properties() {
        let platform = IntelSGXPlatform::new();
        assert_eq!(platform.get_security_level(), SecurityLevel::High);
        assert_eq!(platform.get_privacy_level(), PrivacyLevel::Strong);
        assert_eq!(
            platform.get_open_source_status(),
            OpenSourceStatus::PartiallyOpen
        );
    }
}
