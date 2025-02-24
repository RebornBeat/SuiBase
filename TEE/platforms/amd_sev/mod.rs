//! AMD Secure Encrypted Virtualization (SEV) TEE Platform Implementation
//! Production implementation for AMD SEV, SEV-ES, and SEV-SNP

use super::{AttestationReport, SecureEnclave, TEEPlatform};
use crate::core::error::{TEEError, TEEResult};
use crate::platforms::{OpenSourceStatus, PrivacyLevel, SecurityLevel};

// Re-export platform-specific modules
pub mod attestation;
pub mod enclave;

// Platform-specific constants
pub const SEV_REPORT_MAGIC: u32 = 0x45564553; // "SEV\0"
pub const SEV_API_MAJOR: u8 = 0;
pub const SEV_API_MINOR: u8 = 24;

/// AMD SEV Platform Implementation
pub struct AMDSEVPlatform {
    initialized: bool,
    capabilities: SEVCapabilities,
}

/// SEV Platform Capabilities
#[derive(Debug, Clone)]
pub struct SEVCapabilities {
    /// SEV API version
    pub version: (u8, u8),
    /// SEV-ES support
    pub es_supported: bool,
    /// SEV-SNP support
    pub snp_supported: bool,
    /// Minimum ASID value
    pub min_asid: u32,
    /// Maximum ASID value
    pub max_asid: u32,
    /// Page table encryption bit position
    pub page_table_bit: u8,
}

impl AMDSEVPlatform {
    /// Create a new AMD SEV platform instance
    pub fn new() -> Self {
        Self {
            initialized: false,
            capabilities: SEVCapabilities {
                version: (SEV_API_MAJOR, SEV_API_MINOR),
                es_supported: false,
                snp_supported: false,
                min_asid: 1,
                max_asid: 0,
                page_table_bit: 47,
            },
        }
    }

    /// Get platform capabilities through SEV firmware
    fn get_platform_capabilities(&mut self) -> TEEResult<()> {
        // Query actual SEV firmware for capabilities
        #[cfg(target_arch = "x86_64")]
        {
            use std::fs::File;
            use std::os::unix::io::AsRawFd;

            let sev_device = File::open("/dev/sev").map_err(|e| TEEError::PlatformError {
                platform: "amd_sev".to_string(),
                reason: "Failed to open SEV device".to_string(),
                details: e.to_string(),
                source: None,
            })?;

            // Query platform capabilities using AMD SEV ioctl
            let mut caps = unsafe { std::mem::zeroed() };
            let result =
                unsafe { libc::ioctl(sev_device.as_raw_fd(), SEV_PLATFORM_STATUS, &mut caps) };

            if result < 0 {
                return Err(TEEError::PlatformError {
                    platform: "amd_sev".to_string(),
                    reason: "Failed to query SEV capabilities".to_string(),
                    details: "SEV platform status ioctl failed".to_string(),
                    source: None,
                });
            }

            // Update capabilities
            self.capabilities = SEVCapabilities {
                version: ((caps >> 32) as u8, (caps >> 24) as u8),
                es_supported: (caps & (1 << 2)) != 0,
                snp_supported: (caps & (1 << 4)) != 0,
                min_asid: 1,
                max_asid: ((caps >> 8) & 0xFF) as u32,
                page_table_bit: (caps & 0x7F) as u8,
            };

            Ok(())
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            Err(TEEError::PlatformError {
                platform: "amd_sev".to_string(),
                reason: "Unsupported architecture".to_string(),
                details: "AMD SEV requires x86_64 architecture".to_string(),
                source: None,
            })
        }
    }
}

impl TEEPlatform for AMDSEVPlatform {
    fn initialize(&mut self) -> TEEResult<()> {
        if self.initialized {
            return Err(TEEError::PlatformError {
                platform: "amd_sev".to_string(),
                reason: "Already initialized".to_string(),
                details: "Platform has already been initialized".to_string(),
                source: None,
            });
        }

        // Check architecture
        #[cfg(not(target_arch = "x86_64"))]
        {
            return Err(TEEError::PlatformError {
                platform: "amd_sev".to_string(),
                reason: "Unsupported architecture".to_string(),
                details: "AMD SEV requires x86_64 architecture".to_string(),
                source: None,
            });
        }

        // Get platform capabilities
        self.get_platform_capabilities()?;

        // Validate minimum requirements
        if self.capabilities.version.0 < SEV_API_MAJOR
            || (self.capabilities.version.0 == SEV_API_MAJOR
                && self.capabilities.version.1 < SEV_API_MINOR)
        {
            return Err(TEEError::PlatformError {
                platform: "amd_sev".to_string(),
                reason: "Unsupported SEV version".to_string(),
                details: format!(
                    "SEV API version {}.{} not supported. Minimum required: {}.{}",
                    self.capabilities.version.0,
                    self.capabilities.version.1,
                    SEV_API_MAJOR,
                    SEV_API_MINOR
                ),
                source: None,
            });
        }

        self.initialized = true;
        Ok(())
    }

    fn create_enclave(&mut self) -> TEEResult<Box<dyn SecureEnclave>> {
        if !self.initialized {
            return Err(TEEError::PlatformError {
                platform: "amd_sev".to_string(),
                reason: "Not initialized".to_string(),
                details: "Platform must be initialized before creating enclaves".to_string(),
                source: None,
            });
        }

        use self::enclave::SEVEnclave;
        Ok(Box::new(SEVEnclave::new(&self.capabilities)?))
    }

    fn get_security_level(&self) -> SecurityLevel {
        if self.capabilities.snp_supported {
            SecurityLevel::High
        } else if self.capabilities.es_supported {
            SecurityLevel::Medium
        } else {
            SecurityLevel::Low
        }
    }

    fn get_privacy_level(&self) -> PrivacyLevel {
        PrivacyLevel::Strong // SEV provides strong memory encryption
    }

    fn get_open_source_status(&self) -> OpenSourceStatus {
        OpenSourceStatus::PartiallyOpen // SEV SDK is open but firmware is proprietary
    }
}

// Provide a convenient way to create AMD SEV platform
pub fn create_sev_platform() -> TEEResult<AMDSEVPlatform> {
    let mut platform = AMDSEVPlatform::new();
    platform.initialize()?;
    Ok(platform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_sev_platform_initialization() -> TEEResult<()> {
        let mut platform = AMDSEVPlatform::new();
        platform.initialize()?;
        assert!(platform.initialized);
        Ok(())
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn test_sev_platform_capabilities() -> TEEResult<()> {
        let mut platform = AMDSEVPlatform::new();
        platform.initialize()?;
        assert!(platform.capabilities.max_asid > 0);
        Ok(())
    }
}
