use crate::core::attestation::Attestation;
use crate::core::enclave::SecureEnclave;
use crate::core::error::{TEEError, TEEResult};
use crate::platforms::OpenSourceStatus;
use crate::platforms::PrivacyLevel;
use crate::platforms::SecurityLevel;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// SEV-specific security configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SEVSecurityConfig {
    /// SEV policy configuration
    pub policy: SEVPolicy,
    /// Memory encryption configuration
    pub memory_config: SEVMemoryConfig,
    /// Measurement configuration
    pub measurement_config: SEVMeasurementConfig,
}

/// SEV policy configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SEVPolicy {
    /// Require SEV-SNP if available
    pub require_snp: bool,
    /// Require secure guest injection
    pub require_secure_guest: bool,
    /// Require debug mode to be disabled
    pub require_no_debug: bool,
    /// Minimum platform firmware version
    pub min_platform_version: u32,
}

/// SEV memory configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SEVMemoryConfig {
    /// Memory encryption enabled
    pub encryption_enabled: bool,
    /// Full memory integrity protection
    pub integrity_protection: bool,
    /// Page validation levels
    pub validation_levels: u8,
}

/// SEV measurement configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SEVMeasurementConfig {
    /// Required measurement registers
    pub required_registers: Vec<String>,
    /// Expected measurement values
    pub expected_values: HashMap<String, Vec<u8>>,
}

/// AMD SEV Enclave implementation
pub struct SEVEnclave {
    /// Unique identifier
    id: String,
    /// Memory allocation
    memory: usize,
    /// Security configuration
    security_config: SEVSecurityConfig,
    /// Current measurement
    measurement: Arc<Mutex<Vec<u8>>>,
    /// Platform verification key
    platform_key: Vec<u8>,
    /// Enclave launch blob
    launch_blob: Vec<u8>,
}

impl SEVEnclave {
    /// Create a new SEV enclave
    pub fn new(memory: usize, config: SEVSecurityConfig) -> TEEResult<Self> {
        // Check for SEV support
        if !Self::check_sev_support()? {
            return Err(TEEError::PlatformError {
                platform: "amd_sev".to_string(),
                reason: "SEV not supported".to_string(),
                details: "CPU does not support AMD SEV".to_string(),
                source: None,
            });
        }

        // Generate unique ID
        let id = uuid::Uuid::new_v4().to_string();

        // Initialize platform verification
        let (platform_key, launch_blob) = Self::init_platform_verification()?;

        Ok(Self {
            id,
            memory,
            security_config: config,
            measurement: Arc::new(Mutex::new(Vec::new())),
            platform_key,
            launch_blob,
        })
    }

    /// Check if SEV is supported on this platform
    fn check_sev_support() -> TEEResult<bool> {
        // Check CPUID for AMD CPU
        #[cfg(target_arch = "x86_64")]
        {
            use raw_cpuid::CpuId;
            let cpuid = CpuId::new();

            // Check vendor is AMD
            if let Some(vendor) = cpuid.get_vendor_info() {
                if vendor.as_str() != "AuthenticAMD" {
                    return Ok(false);
                }
            }

            // Check SEV feature flag
            if let Some(extended) = cpuid.get_extended_feature_info() {
                return Ok(extended.has_sev());
            }
        }

        Ok(false)
    }

    /// Initialize platform verification
    fn init_platform_verification() -> TEEResult<(Vec<u8>, Vec<u8>)> {
        // Get platform endorsement key
        let platform_key = Self::get_platform_key()?;

        // Generate launch blob
        let launch_blob = Self::generate_launch_blob(&platform_key)?;

        Ok((platform_key, launch_blob))
    }

    /// Get the platform endorsement key
    fn get_platform_key() -> TEEResult<Vec<u8>> {
        // Call into SEV firmware API to get platform key
        #[cfg(target_os = "linux")]
        {
            use sev::firmware::Firmware;
            let mut fw = Firmware::open()?;
            let key = fw.get_identifier()?;
            Ok(key.to_bytes().to_vec())
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(TEEError::PlatformError {
                platform: "amd_sev".to_string(),
                reason: "Unsupported OS".to_string(),
                details: "SEV requires Linux".to_string(),
                source: None,
            })
        }
    }

    /// Generate launch blob for attestation
    fn generate_launch_blob(platform_key: &[u8]) -> TEEResult<Vec<u8>> {
        #[cfg(target_os = "linux")]
        {
            use sev::launch::Policy;
            use sev::session::Session;

            // Create launch session
            let session = Session::new()?;

            // Set launch policy
            let policy = Policy::default()
                .set_no_debug()
                .set_api_major(1)
                .set_api_minor(0);

            // Generate launch blob
            let mut launch_blob = session.start(policy)?;
            launch_blob.extend_from_slice(platform_key);

            Ok(launch_blob)
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(TEEError::PlatformError {
                platform: "amd_sev".to_string(),
                reason: "Unsupported OS".to_string(),
                details: "SEV requires Linux".to_string(),
                source: None,
            })
        }
    }

    /// Update enclave measurement
    fn update_measurement(&self, data: &[u8]) -> TEEResult<()> {
        let mut measurement = self.measurement.lock().unwrap();

        // Use SEV specific measurement update
        #[cfg(target_os = "linux")]
        {
            use sev::measurement::Measurement;
            let mut measure = Measurement::from_bytes(&measurement)?;
            measure.extend(data);
            *measurement = measure.to_bytes();
        }

        Ok(())
    }
}

impl SecureEnclave for SEVEnclave {
    fn initialize(&mut self) -> TEEResult<()> {
        // Apply SEV security policy
        #[cfg(target_os = "linux")]
        {
            use sev::launch::Policy;

            // Create launch policy from config
            let mut policy = Policy::default();

            if self.security_config.policy.require_no_debug {
                policy = policy.set_no_debug();
            }

            if self.security_config.policy.require_snp {
                policy = policy.set_snp();
            }

            // Initialize SEV for this enclave
            let mut fw = sev::firmware::Firmware::open()?;
            fw.pdh_cert_export()?;

            // Initialize memory encryption
            if self.security_config.memory_config.encryption_enabled {
                fw.set_encrypted_state(true)?;
            }
        }

        Ok(())
    }

    fn execute<F, R>(&self, computation: F) -> TEEResult<R>
    where
        F: FnOnce() -> R,
    {
        // Ensure enclave is initialized
        if self.measurement.lock().unwrap().is_empty() {
            return Err(TEEError::EnclaveError {
                reason: "Enclave not initialized".to_string(),
                details: "Must initialize enclave before execution".to_string(),
                source: None,
            });
        }

        // Execute in SEV protected mode
        #[cfg(target_os = "linux")]
        {
            use sev::launch::Launcher;

            // Create SEV launch session
            let launcher = Launcher::new()?;

            // Launch computation
            let result = launcher.launch(|| {
                // Update measurement
                self.update_measurement(b"execution")?;

                // Execute computation
                Ok(computation())
            })?;

            Ok(result)
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(TEEError::PlatformError {
                platform: "amd_sev".to_string(),
                reason: "Unsupported OS".to_string(),
                details: "SEV requires Linux".to_string(),
                source: None,
            })
        }
    }

    fn get_attestation(&self) -> TEEResult<Attestation> {
        use crate::platforms::amd_sev::attestation::SEVAttestationUtil;

        // Get current measurement
        let measurement = self.measurement.lock().unwrap().clone();

        // Generate attestation report
        let report = SEVAttestationUtil::generate_report(&measurement)?;

        // Create attestation
        Ok(Attestation::new(
            self.id.clone(),
            "amd_sev".to_string(),
            report,
            self.platform_key.clone(),
            measurement,
        ))
    }

    fn get_measurement(&self) -> Vec<u8> {
        self.measurement.lock().unwrap().clone()
    }
}

impl Drop for SEVEnclave {
    fn drop(&mut self) {
        // Cleanup SEV resources
        #[cfg(target_os = "linux")]
        {
            if let Ok(mut fw) = sev::firmware::Firmware::open() {
                let _ = fw.set_encrypted_state(false);
            }
        }
    }
}

// Constants
pub const SEV_MIN_API_VERSION: u32 = 0x1000; // v1.0
pub const SEV_MAX_API_VERSION: u32 = 0x1001; // v1.1
