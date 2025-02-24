//! Core enclave coordination for TEE platforms

use crate::core::attestation::Attestation;
use crate::core::error::{TEEError, TEEResult};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};

/// Represents a Trusted Execution Environment Enclave
pub trait SecureEnclave: Send + Sync {
    /// Initialize the enclave
    fn initialize(&mut self) -> TEEResult<()>;

    /// Execute function within secure environment
    fn execute<F, R>(&self, computation: F) -> TEEResult<R>
    where
        F: FnOnce() -> R + Send;

    /// Generate attestation for this enclave
    fn get_attestation(&self) -> TEEResult<Attestation>;

    /// Get enclave measurement
    fn get_measurement(&self) -> Vec<u8>;

    /// Get enclave state
    fn get_state(&self) -> EnclaveState;

    /// Pause enclave
    fn pause(&self) -> TEEResult<()>;

    /// Resume enclave
    fn resume(&self) -> TEEResult<()>;

    /// Terminate enclave
    fn terminate(&self) -> TEEResult<()>;
}

/// Atomic enclave state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveState {
    Created,
    Initialized,
    Running,
    Paused,
    Terminated,
    Error,
}

/// Core enclave configuration
#[derive(Clone)]
pub struct EnclaveConfig {
    /// Maximum memory allocation
    pub max_memory: usize,

    /// Platform-specific settings
    pub settings: HashMap<String, String>,

    /// Environment variables
    pub environment: HashMap<String, String>,

    /// Resource constraints
    pub constraints: ResourceConstraints,
}

/// Resource constraints for enclave
#[derive(Clone)]
pub struct ResourceConstraints {
    pub cpu_limit: u8,
    pub network_bandwidth_mbps: u32,
    pub storage_quota_mb: u32,
}

/// Builder for creating secure enclaves
pub struct EnclaveBuilder {
    platform: Option<String>,
    config: EnclaveConfig,
}

impl EnclaveBuilder {
    /// Create a new enclave builder
    pub fn new() -> Self {
        Self {
            platform: None,
            config: EnclaveConfig {
                max_memory: 1024 * 1024 * 1024, // 1GB default
                settings: HashMap::new(),
                environment: HashMap::new(),
                constraints: ResourceConstraints {
                    cpu_limit: 100,
                    network_bandwidth_mbps: 1000,
                    storage_quota_mb: 1024,
                },
            },
        }
    }

    /// Set TEE platform
    pub fn platform(mut self, platform: String) -> Self {
        self.platform = Some(platform);
        self
    }

    /// Set maximum memory allocation
    pub fn max_memory(mut self, memory: usize) -> Self {
        self.config.max_memory = memory;
        self
    }

    /// Add platform-specific setting
    pub fn add_setting(mut self, key: String, value: String) -> Self {
        self.config.settings.insert(key, value);
        self
    }

    /// Add environment variable
    pub fn add_env(mut self, key: String, value: String) -> Self {
        self.config.environment.insert(key, value);
        self
    }

    /// Set resource constraints
    pub fn set_constraints(mut self, constraints: ResourceConstraints) -> Self {
        self.config.constraints = constraints;
        self
    }

    /// Build platform-specific enclave
    pub fn build(self) -> TEEResult<Box<dyn SecureEnclave>> {
        let platform = self
            .platform
            .ok_or_else(|| TEEError::EnclaveError("Platform must be specified".to_string()))?;

        match platform.as_str() {
            "intel_sgx" => {
                use crate::platforms::intel_sgx::enclave::SGXEnclave;
                Ok(Box::new(SGXEnclave::new(self.config)?))
            }
            "amd_sev" => {
                use crate::platforms::amd_sev::enclave::SEVEnclave;
                Ok(Box::new(SEVEnclave::new(self.config)?))
            }
            "arm_trustzone" => {
                use crate::platforms::arm_trustzone::enclave::TrustZoneEnclave;
                Ok(Box::new(TrustZoneEnclave::new(self.config)?))
            }
            "aws_nitro" => {
                use crate::platforms::aws_nitro::enclave::NitroEnclave;
                Ok(Box::new(NitroEnclave::new(self.config)?))
            }
            _ => Err(TEEError::EnclaveError(format!(
                "Unsupported platform: {}",
                platform
            ))),
        }
    }
}

/// Manager for enclave lifecycle
pub struct EnclaveManager {
    /// Active enclaves
    enclaves: HashMap<String, Box<dyn SecureEnclave>>,
}

impl EnclaveManager {
    /// Create new enclave manager
    pub fn new() -> Self {
        Self {
            enclaves: HashMap::new(),
        }
    }

    /// Create new enclave
    pub fn create_enclave(&mut self, builder: EnclaveBuilder) -> TEEResult<String> {
        let enclave = builder.build()?;
        let id = uuid::Uuid::new_v4().to_string();
        self.enclaves.insert(id.clone(), enclave);
        Ok(id)
    }

    /// Get enclave by ID
    pub fn get_enclave(&self, id: &str) -> TEEResult<&Box<dyn SecureEnclave>> {
        self.enclaves
            .get(id)
            .ok_or_else(|| TEEError::EnclaveError(format!("Enclave not found: {}", id)))
    }

    /// Get enclave state
    pub fn get_enclave_state(&self, id: &str) -> TEEResult<EnclaveState> {
        let enclave = self.get_enclave(id)?;
        Ok(enclave.get_state())
    }

    /// Execute function in enclave
    pub fn execute<F, R>(&self, id: &str, computation: F) -> TEEResult<R>
    where
        F: FnOnce() -> R + Send,
    {
        let enclave = self.get_enclave(id)?;
        enclave.execute(computation)
    }

    /// Get attestation for enclave
    pub fn get_attestation(&self, id: &str) -> TEEResult<Attestation> {
        let enclave = self.get_enclave(id)?;
        enclave.get_attestation()
    }

    /// Terminate enclave
    pub fn terminate_enclave(&mut self, id: &str) -> TEEResult<()> {
        if let Some(enclave) = self.enclaves.remove(id) {
            enclave.terminate()?;
        }
        Ok(())
    }

    /// List active enclave IDs
    pub fn list_enclaves(&self) -> Vec<String> {
        self.enclaves.keys().cloned().collect()
    }
}
