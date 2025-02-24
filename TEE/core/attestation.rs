//! Core attestation types and coordination for TEE platforms

use crate::core::crypto::SignatureUtil;
use crate::core::error::{TEEError, TEEResult};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents a TEE Platform's Attestation Report
#[derive(Debug, Clone)]
pub struct Attestation {
    /// Unique identifier for the TEE instance
    pub instance_id: String,

    /// TEE platform identifier
    pub platform_id: String,

    /// Platform-specific attestation report
    pub report: Vec<u8>,

    /// Cryptographic signatures for verification
    pub signatures: HashMap<String, Vec<u8>>,

    /// Public key for verification
    pub public_key: Vec<u8>,

    /// Measurement of the TEE environment
    pub measurement: Vec<u8>,

    /// Timestamp of attestation creation
    pub timestamp: u64,

    /// Additional platform-specific metadata
    pub metadata: HashMap<String, String>,
}

/// Platform-specific attestation data structure
#[derive(Debug, Clone)]
pub struct AttestationReportData {
    /// Platform identifier
    pub platform: String,
    /// Raw quote or attestation data
    pub quote: Vec<u8>,
    /// Measurement of the TEE
    pub measurement: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
}

impl Attestation {
    /// Create a new attestation instance
    pub fn new(
        instance_id: String,
        platform_id: String,
        report: Vec<u8>,
        public_key: Vec<u8>,
        measurement: Vec<u8>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            instance_id,
            platform_id,
            report,
            signatures: HashMap::new(),
            public_key,
            measurement,
            timestamp,
            metadata: HashMap::new(),
        }
    }

    /// Add a signature to the attestation
    pub fn add_signature(&mut self, signer_id: String, signature: Vec<u8>) {
        self.signatures.insert(signer_id, signature);
    }

    /// Add metadata to the attestation
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// Parse attestation report based on platform
    pub fn parse_report(&self) -> TEEResult<AttestationReportData> {
        match self.platform_id.as_str() {
            "intel_sgx" => {
                use crate::platforms::intel_sgx::attestation::SGXAttestationUtil;
                SGXAttestationUtil::parse_report(&self.report)
            }
            "amd_sev" => {
                use crate::platforms::amd_sev::attestation::SEVAttestationUtil;
                SEVAttestationUtil::parse_report(&self.report)
            }
            "arm_trustzone" => {
                use crate::platforms::arm_trustzone::attestation::TrustZoneAttestationUtil;
                TrustZoneAttestationUtil::parse_report(&self.report)
            }
            "aws_nitro" => {
                use crate::platforms::aws_nitro::attestation::NitroAttestationUtil;
                NitroAttestationUtil::parse_report(&self.report)
            }
            _ => Err(TEEError::AttestationError(format!(
                "Unsupported platform: {}",
                self.platform_id
            ))),
        }
    }

    /// Verify attestation integrity
    pub fn verify(&self) -> TEEResult<bool> {
        // Basic validation
        if self.report.is_empty() {
            return Err(TEEError::AttestationError(
                "Empty attestation report".to_string(),
            ));
        }

        // Verify signatures
        if self.signatures.is_empty() {
            return Err(TEEError::AttestationError(
                "No signatures provided".to_string(),
            ));
        }

        // Verify each signature using centralized crypto utilities
        for (key_id, signature) in &self.signatures {
            // Get public key from metadata if available
            let public_key = if let Some(key) = self.metadata.get(&format!("public_key_{}", key_id))
            {
                hex::decode(key).map_err(|e| {
                    TEEError::AttestationError(format!("Invalid public key format: {}", e))
                })?
            } else {
                self.public_key.clone()
            };

            // Use centralized SignatureUtil for verification
            if !SignatureUtil::verify(&public_key, &self.report, signature)? {
                return Ok(false);
            }
        }

        // Platform-specific verification
        match self.platform_id.as_str() {
            "intel_sgx" => {
                use crate::platforms::intel_sgx::attestation::SGXAttestationUtil;
                SGXAttestationUtil::verify_report(&self.report)
            }
            "amd_sev" => {
                use crate::platforms::amd_sev::attestation::SEVAttestationUtil;
                SEVAttestationUtil::verify_report(&self.report)
            }
            "arm_trustzone" => {
                use crate::platforms::arm_trustzone::attestation::TrustZoneAttestationUtil;
                TrustZoneAttestationUtil::verify_report(&self.report)
            }
            "aws_nitro" => {
                use crate::platforms::aws_nitro::attestation::NitroAttestationUtil;
                NitroAttestationUtil::verify_report(&self.report)
            }
            _ => Err(TEEError::AttestationError(format!(
                "Unsupported platform: {}",
                self.platform_id
            ))),
        }
    }
}

/// Builder for creating attestation instances
pub struct AttestationBuilder {
    instance_id: Option<String>,
    platform_id: Option<String>,
    report: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    measurement: Option<Vec<u8>>,
    signatures: HashMap<String, Vec<u8>>,
    metadata: HashMap<String, String>,
}

impl AttestationBuilder {
    /// Create a new attestation builder
    pub fn new() -> Self {
        Self {
            instance_id: None,
            platform_id: None,
            report: None,
            public_key: None,
            measurement: None,
            signatures: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    /// Set the instance ID
    pub fn instance_id(mut self, id: String) -> Self {
        self.instance_id = Some(id);
        self
    }

    /// Set the platform ID
    pub fn platform_id(mut self, id: String) -> Self {
        self.platform_id = Some(id);
        self
    }

    /// Set the attestation report
    pub fn report(mut self, report: Vec<u8>) -> Self {
        self.report = Some(report);
        self
    }

    /// Set the public key
    pub fn public_key(mut self, key: Vec<u8>) -> Self {
        self.public_key = Some(key);
        self
    }

    /// Set the measurement
    pub fn measurement(mut self, measurement: Vec<u8>) -> Self {
        self.measurement = Some(measurement);
        self
    }

    /// Add a signature
    pub fn add_signature(mut self, signer_id: String, signature: Vec<u8>) -> Self {
        self.signatures.insert(signer_id, signature);
        self
    }

    /// Add metadata
    pub fn add_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Build the Attestation instance
    pub fn build(self) -> TEEResult<Attestation> {
        let instance_id = self
            .instance_id
            .ok_or_else(|| TEEError::AttestationError("Instance ID is required".to_string()))?;

        let platform_id = self
            .platform_id
            .ok_or_else(|| TEEError::AttestationError("Platform ID is required".to_string()))?;

        let report = self.report.ok_or_else(|| {
            TEEError::AttestationError("Attestation report is required".to_string())
        })?;

        let public_key = self
            .public_key
            .ok_or_else(|| TEEError::AttestationError("Public key is required".to_string()))?;

        let measurement = self
            .measurement
            .ok_or_else(|| TEEError::AttestationError("Measurement is required".to_string()))?;

        let mut attestation =
            Attestation::new(instance_id, platform_id, report, public_key, measurement);

        // Copy signatures and metadata
        attestation.signatures = self.signatures;
        attestation.metadata = self.metadata;

        Ok(attestation)
    }
}
