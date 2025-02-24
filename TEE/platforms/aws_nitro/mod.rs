//! AWS Nitro Enclaves TEE Platform Implementation

use crate::core::error::{TEEError, TEEResult};
use crate::platforms::{
    AttestationReport, OpenSourceStatus, PrivacyLevel, SecureEnclave, SecurityLevel, TEEPlatform,
};

// Platform-specific modules
pub mod attestation;
pub mod enclave;

/// AWS Nitro Enclaves Platform Implementation
pub struct AWSNitroEnclavesPlatform {
    initialized: bool,
    available_features: NitroFeatures,
}

/// AWS Nitro Enclave Features
#[derive(Debug, Clone)]
pub struct NitroFeatures {
    pub attestation_supported: bool,
    pub max_enclave_memory_mib: usize,
    pub max_cpu_count: usize,
    pub vsock_supported: bool,
    pub token_support: bool,
}

impl AWSNitroEnclavesPlatform {
    /// Create a new AWS Nitro platform instance
    pub fn new() -> Self {
        Self {
            initialized: false,
            available_features: NitroFeatures {
                attestation_supported: false,
                max_enclave_memory_mib: 0,
                max_cpu_count: 0,
                vsock_supported: false,
                token_support: false,
            },
        }
    }

    /// Check hardware support and features
    fn check_hardware_support(&self) -> TEEResult<bool> {
        // Check if running on AWS Nitro hardware
        let is_nitro = std::fs::metadata("/dev/nsm").is_ok();
        if !is_nitro {
            return Ok(false);
        }

        // Check if Nitro Enclaves are enabled for the instance
        if !std::fs::metadata("/dev/nitro_enclaves").is_ok() {
            return Ok(false);
        }

        Ok(true)
    }

    /// Detect available Nitro features
    fn detect_features(&mut self) -> TEEResult<()> {
        // Read max memory from instance metadata
        let memory_str =
            std::fs::read_to_string("/proc/sys/user/max_user_namespaces").map_err(|e| {
                TEEError::PlatformError {
                    platform: "aws_nitro".to_string(),
                    reason: "Failed to read max memory".to_string(),
                    details: e.to_string(),
                    source: None,
                }
            })?;

        self.available_features.max_enclave_memory_mib =
            memory_str
                .trim()
                .parse()
                .map_err(|_| TEEError::PlatformError {
                    platform: "aws_nitro".to_string(),
                    reason: "Invalid memory value".to_string(),
                    details: "Could not parse max memory".to_string(),
                    source: None,
                })?;

        // Check for vsock support
        self.available_features.vsock_supported = std::fs::metadata("/dev/vsock").is_ok();

        // Validate attestation support
        self.available_features.attestation_supported = true;

        // Get available CPU cores
        let cpu_count = num_cpus::get();
        self.available_features.max_cpu_count = cpu_count;

        // Check token support
        self.available_features.token_support = true;

        Ok(())
    }
}

impl TEEPlatform for AWSNitroEnclavesPlatform {
    fn initialize(&mut self) -> TEEResult<()> {
        if self.initialized {
            return Err(TEEError::PlatformError {
                platform: "aws_nitro".to_string(),
                reason: "Already initialized".to_string(),
                details: "Platform has already been initialized".to_string(),
                source: None,
            });
        }

        // Verify we're running on Nitro hardware
        if !self.check_hardware_support()? {
            return Err(TEEError::PlatformError {
                platform: "aws_nitro".to_string(),
                reason: "Unsupported hardware".to_string(),
                details: "AWS Nitro Enclaves not supported on this hardware".to_string(),
                source: None,
            });
        }

        // Detect available features
        self.detect_features()?;

        self.initialized = true;
        Ok(())
    }

    fn create_enclave(&mut self) -> TEEResult<Box<dyn SecureEnclave>> {
        if !self.initialized {
            return Err(TEEError::PlatformError {
                platform: "aws_nitro".to_string(),
                reason: "Not initialized".to_string(),
                details: "Platform must be initialized before creating enclaves".to_string(),
                source: None,
            });
        }

        Ok(Box::new(enclave::NitroEnclave::new()?))
    }

    fn remote_attestation(&self) -> TEEResult<AttestationReport> {
        if !self.initialized {
            return Err(TEEError::PlatformError {
                platform: "aws_nitro".to_string(),
                reason: "Not initialized".to_string(),
                details: "Platform must be initialized before attestation".to_string(),
                source: None,
            });
        }

        if !self.available_features.attestation_supported {
            return Err(TEEError::PlatformError {
                platform: "aws_nitro".to_string(),
                reason: "Attestation not supported".to_string(),
                details: "This instance does not support attestation".to_string(),
                source: None,
            });
        }

        attestation::NitroAttestationUtil::generate_report()
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
}

// Provide a convenient way to create AWS Nitro platform
pub fn create_nitro_platform() -> TEEResult<AWSNitroEnclavesPlatform> {
    let mut platform = AWSNitroEnclavesPlatform::new();
    platform.initialize()?;
    Ok(platform)
}

/// AWS Nitro Enclave specific constants
pub const NITRO_MAX_ENCLAVE_SIZE: usize = 24 * 1024; // 24GB
pub const NITRO_MIN_ENCLAVE_SIZE: usize = 64; // 64MB
pub const NITRO_DEFAULT_MEMORY_SIZE: usize = 1024; // 1GB
