//! AWS Nitro Enclaves Secure Enclave Implementation

use crate::core::{
    attestation::Attestation,
    enclave::SecureEnclave,
    error::{TEEError, TEEResult},
};
use crate::platforms::aws_nitro::attestation::NitroAttestationUtil;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Represents an AWS Nitro Secure Enclave
pub struct NitroEnclave {
    /// Unique identifier for the enclave
    id: String,

    /// Enclave configuration
    config: NitroEnclaveConfig,

    /// Enclave measurement
    measurement: Vec<u8>,

    /// Enclave state
    state: Arc<Mutex<NitroEnclaveState>>,
}

/// Configuration for Nitro Enclave
#[derive(Clone)]
pub struct NitroEnclaveConfig {
    /// Memory allocation in MB
    pub memory_mb: usize,

    /// Number of vCPUs
    pub cpu_count: u32,

    /// Custom metadata
    pub metadata: HashMap<String, String>,

    /// Enclave image file
    pub image_file: String,
}

/// Enclave operational state
#[derive(Debug, Clone, PartialEq)]
pub enum NitroEnclaveState {
    Created,
    Running,
    Paused,
    Terminated,
}

impl NitroEnclave {
    /// Create a new Nitro Enclave
    pub fn new(config: NitroEnclaveConfig) -> TEEResult<Self> {
        // Validate configuration
        if config.memory_mb < 64 || config.memory_mb > 24576 {
            return Err(TEEError::EnclaveError {
                reason: "Invalid memory configuration".to_string(),
                details: "Memory must be between 64MB and 24GB".to_string(),
                source: None,
            });
        }

        if config.cpu_count < 1 || config.cpu_count > 8 {
            return Err(TEEError::EnclaveError {
                reason: "Invalid CPU configuration".to_string(),
                details: "CPU count must be between 1 and 8".to_string(),
                source: None,
            });
        }

        // Generate unique ID
        let id = uuid::Uuid::new_v4().to_string();

        // Create initial enclave measurement
        let measurement = Self::generate_measurement(&id, &config)?;

        Ok(Self {
            id,
            config,
            measurement,
            state: Arc::new(Mutex::new(NitroEnclaveState::Created)),
        })
    }

    /// Generate enclave measurement
    fn generate_measurement(id: &str, config: &NitroEnclaveConfig) -> TEEResult<Vec<u8>> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(id.as_bytes());
        hasher.update(&config.memory_mb.to_le_bytes());
        hasher.update(&config.cpu_count.to_le_bytes());

        Ok(hasher.finalize().to_vec())
    }
}

impl SecureEnclave for NitroEnclave {
    fn execute<F, R>(&self, computation: F) -> TEEResult<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let state = self.state.lock().map_err(|_| TEEError::EnclaveError {
            reason: "State lock poisoned".to_string(),
            details: "Failed to acquire state lock".to_string(),
            source: None,
        })?;

        if *state != NitroEnclaveState::Running {
            return Err(TEEError::EnclaveError {
                reason: "Invalid enclave state".to_string(),
                details: format!("Enclave must be running, current state: {:?}", *state),
                source: None,
            });
        }

        // Use AWS Nitro SDK to execute computation
        #[cfg(feature = "nitro-sdk")]
        {
            use aws_nitro_enclaves_sdk as nitro;

            // Create secure execution context
            let ctx = nitro::enclave::EnclaveContext::new()?;

            // Execute computation in secure context
            let result = ctx.run(computation)?;

            Ok(result)
        }

        #[cfg(not(feature = "nitro-sdk"))]
        {
            Err(TEEError::EnclaveError {
                reason: "Nitro SDK not available".to_string(),
                details: "Build with nitro-sdk feature for production use".to_string(),
                source: None,
            })
        }
    }

    fn get_attestation(&self) -> TEEResult<Attestation> {
        let state = self.state.lock().map_err(|_| TEEError::EnclaveError {
            reason: "State lock poisoned".to_string(),
            details: "Failed to acquire state lock".to_string(),
            source: None,
        })?;

        if *state != NitroEnclaveState::Running {
            return Err(TEEError::EnclaveError {
                reason: "Invalid enclave state".to_string(),
                details: format!("Enclave must be running, current state: {:?}", *state),
                source: None,
            });
        }

        // Generate attestation using Nitro-specific implementation
        let report = NitroAttestationUtil::generate_report(&self.measurement)?;

        // Create attestation using core type
        Ok(Attestation::new(
            self.id.clone(),
            "aws_nitro".to_string(),
            report,
            vec![], // Public key will be added by attestation process
            self.measurement.clone(),
        ))
    }

    fn get_measurement(&self) -> Vec<u8> {
        self.measurement.clone()
    }

    fn get_id(&self) -> String {
        self.id.clone()
    }

    fn get_state(&self) -> EnclaveState {
        let state = self.state.lock().unwrap();
        match *state {
            NitroEnclaveState::Created => EnclaveState::Created,
            NitroEnclaveState::Running => EnclaveState::Running,
            NitroEnclaveState::Paused => EnclaveState::Paused,
            NitroEnclaveState::Terminated => EnclaveState::Terminated,
        }
    }

    fn pause(&self) -> TEEResult<()> {
        let mut state = self.state.lock().map_err(|_| TEEError::EnclaveError {
            reason: "State lock poisoned".to_string(),
            details: "Failed to acquire state lock".to_string(),
            source: None,
        })?;

        if *state != NitroEnclaveState::Running {
            return Err(TEEError::EnclaveError {
                reason: "Invalid state transition".to_string(),
                details: "Can only pause running enclaves".to_string(),
                source: None,
            });
        }

        // Use Nitro SDK to pause enclave
        #[cfg(feature = "nitro-sdk")]
        {
            // Implement actual pause logic
        }

        *state = NitroEnclaveState::Paused;
        Ok(())
    }

    fn resume(&self) -> TEEResult<()> {
        let mut state = self.state.lock().map_err(|_| TEEError::EnclaveError {
            reason: "State lock poisoned".to_string(),
            details: "Failed to acquire state lock".to_string(),
            source: None,
        })?;

        if *state != NitroEnclaveState::Paused {
            return Err(TEEError::EnclaveError {
                reason: "Invalid state transition".to_string(),
                details: "Can only resume paused enclaves".to_string(),
                source: None,
            });
        }

        // Use Nitro SDK to resume enclave
        #[cfg(feature = "nitro-sdk")]
        {
            // Implement actual resume logic
        }

        *state = NitroEnclaveState::Running;
        Ok(())
    }

    fn terminate(&self) -> TEEResult<()> {
        let mut state = self.state.lock().map_err(|_| TEEError::EnclaveError {
            reason: "State lock poisoned".to_string(),
            details: "Failed to acquire state lock".to_string(),
            source: None,
        })?;

        if *state == NitroEnclaveState::Terminated {
            return Ok(());
        }

        // Use Nitro SDK to terminate enclave
        #[cfg(feature = "nitro-sdk")]
        {
            // Implement actual termination logic
        }

        *state = NitroEnclaveState::Terminated;
        Ok(())
    }
}

/// Builder for creating Nitro Enclaves
pub struct NitroEnclaveBuilder {
    memory_mb: Option<usize>,
    cpu_count: Option<u32>,
    metadata: HashMap<String, String>,
    image_file: Option<String>,
}

impl NitroEnclaveBuilder {
    pub fn new() -> Self {
        Self {
            memory_mb: None,
            cpu_count: None,
            metadata: HashMap::new(),
            image_file: None,
        }
    }

    pub fn memory(mut self, memory_mb: usize) -> Self {
        self.memory_mb = Some(memory_mb);
        self
    }

    pub fn cpu_count(mut self, count: u32) -> Self {
        self.cpu_count = Some(count);
        self
    }

    pub fn metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    pub fn image_file(mut self, path: String) -> Self {
        self.image_file = Some(path);
        self
    }

    pub fn build(self) -> TEEResult<NitroEnclave> {
        let config = NitroEnclaveConfig {
            memory_mb: self.memory_mb.unwrap_or(512),
            cpu_count: self.cpu_count.unwrap_or(1),
            metadata: self.metadata,
            image_file: self.image_file.ok_or_else(|| TEEError::EnclaveError {
                reason: "Missing image file".to_string(),
                details: "Enclave image file path is required".to_string(),
                source: None,
            })?,
        };

        NitroEnclave::new(config)
    }
}
