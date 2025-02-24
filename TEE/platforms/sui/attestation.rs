//! Sui blockchain attestation verification and management

use crate::core::attestation::Attestation;
use crate::core::error::{TEEError, TEEResult};
use crate::sui::blockchain_interface::SuiClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Attestation proof for Sui blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiAttestationProof {
    /// Platform identifier
    pub platform: String,

    /// Measurement hash
    pub measurement: Vec<u8>,

    /// Timestamp of attestation
    pub timestamp: u64,

    /// Validator signatures
    pub signatures: HashMap<String, Vec<u8>>,

    /// Public key
    pub public_key: Vec<u8>,
}

/// Manages attestation verification and registration with Sui blockchain
pub struct SuiAttestationManager {
    pub blockchain_client: SuiClient,
}

impl SuiAttestationManager {
    /// Create a new attestation manager
    pub fn new(blockchain_client: SuiClient) -> Self {
        Self { blockchain_client }
    }

    /// Verify attestation against on-chain validator registry
    pub async fn verify_attestation(&self, attestation: &Attestation) -> TEEResult<bool> {
        // First perform basic attestation validation
        if !attestation.verify()? {
            log::warn!("Attestation failed basic validation");
            return Ok(false);
        }

        // Get validators from blockchain
        let validators = self.blockchain_client.get_active_validators().await?;

        // Verify we have the required threshold of validator signatures (2/3 majority)
        let required_signatures = (validators.len() * 2) / 3;
        if attestation.signatures.len() < required_signatures {
            log::warn!(
                "Attestation has insufficient validator signatures: {} of {} required",
                attestation.signatures.len(),
                required_signatures
            );
            return Ok(false);
        }

        // Verify each signature
        let mut valid_signatures = 0;

        for (validator_id, signature) in &attestation.signatures {
            // Find validator with matching ID
            if let Some(validator) = validators.iter().find(|v| v.id == *validator_id) {
                // Verify signature using validator's public key
                use ring::signature::{ED25519, UnparsedPublicKey};
                let public_key = UnparsedPublicKey::new(&ED25519, &validator.public_key);

                match public_key.verify(&attestation.report, signature) {
                    Ok(_) => {
                        valid_signatures += 1;
                    }
                    Err(e) => {
                        log::warn!("Invalid signature from validator {}: {:?}", validator_id, e);
                    }
                }
            } else {
                log::warn!("Unknown validator ID: {}", validator_id);
            }
        }

        // Ensure we have enough valid signatures
        if valid_signatures < required_signatures {
            log::warn!(
                "Not enough valid signatures: {} of {} required",
                valid_signatures,
                required_signatures
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Register attestation with the blockchain
    pub async fn register_attestation(&self, attestation: &Attestation) -> TEEResult<String> {
        // Create attestation proof for the blockchain
        let proof = SuiAttestationProof {
            platform: attestation.platform_id.clone(),
            measurement: attestation.measurement.clone(),
            timestamp: attestation.timestamp,
            signatures: attestation.signatures.clone(),
            public_key: attestation.public_key.clone(),
        };

        // Serialize proof
        let serialized_proof = bcs::to_bytes(&proof)
            .map_err(|e| TEEError::AttestationError(format!("Failed to serialize proof: {}", e)))?;

        // Submit to blockchain
        let transaction_id = self
            .blockchain_client
            .submit_transaction(
                "suistack0x::tee::registry::register_attestation",
                vec![sui_sdk::types::SuiParameter::Pure(serialized_proof)],
            )
            .await?;

        // Wait for transaction to complete
        let result = self
            .blockchain_client
            .wait_for_transaction(&transaction_id)
            .await?;

        if result.status != "success" {
            return Err(TEEError::AttestationError(format!(
                "Transaction failed: {}",
                result.error.unwrap_or_default()
            )));
        }

        // Extract attestation ID from transaction effects
        let attestation_id = result
            .effects
            .created
            .iter()
            .find(|obj| obj.object_type.contains("::TEEAttestation"))
            .map(|obj| obj.reference.object_id.clone())
            .ok_or_else(|| {
                TEEError::AttestationError("Failed to find attestation ID".to_string())
            })?;

        Ok(attestation_id)
    }

    /// Verify on-chain attestation by ID
    pub async fn verify_on_chain_attestation(&self, attestation_id: &str) -> TEEResult<bool> {
        // Fetch attestation from chain
        let attestation_obj = self.blockchain_client.get_object(attestation_id).await?;

        // Extract attestation data
        let attestation_data = attestation_obj
            .data
            .get("attestation")
            .ok_or_else(|| TEEError::AttestationError("Invalid attestation object".to_string()))?;

        // Verify basic structure
        if !attestation_data.is_object() {
            return Ok(false);
        }

        // Verify attestation has not expired
        let timestamp = attestation_data
            .get("timestamp")
            .and_then(|t| t.as_u64())
            .ok_or_else(|| TEEError::AttestationError("Missing timestamp".to_string()))?;

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| TEEError::AttestationError(e.to_string()))?
            .as_secs();

        // Check if attestation has expired (24 hours)
        if current_time > timestamp + 86400 {
            return Ok(false);
        }

        // Extract signatures and measurement from attestation data
        let signatures_value = attestation_data
            .get("signatures")
            .ok_or_else(|| TEEError::AttestationError("Missing signatures".to_string()))?;

        let signatures: HashMap<String, Vec<u8>> = serde_json::from_value(signatures_value.clone())
            .map_err(|e| TEEError::AttestationError(format!("Invalid signatures format: {}", e)))?;

        // Extract measurement and platform data
        let measurement = attestation_data
            .get("measurement")
            .and_then(|m| m.as_array())
            .ok_or_else(|| TEEError::AttestationError("Missing measurement".to_string()))?
            .iter()
            .filter_map(|v| v.as_u64().map(|n| n as u8))
            .collect::<Vec<u8>>();

        let platform = attestation_data
            .get("platform")
            .and_then(|p| p.as_str())
            .ok_or_else(|| TEEError::AttestationError("Missing platform".to_string()))?
            .to_string();

        // Get current active validators
        let current_validators = self.blockchain_client.get_active_validators().await?;

        // Calculate required signatures (2/3 majority)
        let required_signatures = (current_validators.len() * 2) / 3;
        if signatures.len() < required_signatures {
            log::warn!(
                "On-chain attestation has insufficient validator signatures: {} of {} required",
                signatures.len(),
                required_signatures
            );
            return Ok(false);
        }

        // Recreate attestation data for signature verification
        let mut attestation_data_bytes = Vec::new();

        // Add platform identifier
        attestation_data_bytes.extend_from_slice(platform.as_bytes());
        attestation_data_bytes.push(0); // Null terminator

        // Add measurement
        attestation_data_bytes.extend_from_slice(&measurement);

        // Add timestamp
        attestation_data_bytes.extend_from_slice(&timestamp.to_le_bytes());

        // Verify each signature against current validators
        let mut valid_signatures = 0;

        for (validator_id, signature) in signatures {
            // Find validator with matching ID
            if let Some(validator) = current_validators.iter().find(|v| v.id == validator_id) {
                // Verify signature using validator's public key
                use ring::signature::{ED25519, UnparsedPublicKey};

                // Verify the validator is still active and not jailed
                if !validator.is_active {
                    log::warn!("Validator {} is no longer active", validator_id);
                    continue;
                }

                // Create public key from validator's key
                let public_key = UnparsedPublicKey::new(&ED25519, &validator.public_key);

                // Verify signature
                match public_key.verify(&attestation_data_bytes, &signature) {
                    Ok(_) => {
                        valid_signatures += 1;
                    }
                    Err(e) => {
                        log::warn!("Invalid signature from validator {}: {:?}", validator_id, e);
                    }
                }
            } else {
                log::warn!("Validator {} is no longer registered", validator_id);
            }
        }

        // Check if we have enough valid signatures from currently active validators
        if valid_signatures < required_signatures {
            log::warn!(
                "Not enough valid signatures from current validators: {} of {} required",
                valid_signatures,
                required_signatures
            );
            return Ok(false);
        }

        // Verify measurement against trusted registry
        if let Err(e) = self
            .verify_measurement_against_registry(&platform, &measurement)
            .await
        {
            log::warn!("Measurement verification failed: {}", e);
            return Ok(false);
        }

        Ok(true)
    }

    /// Verify measurement against on-chain trusted enclave registry
    async fn verify_measurement_against_registry(
        &self,
        platform: &str,
        measurement: &[u8],
    ) -> TEEResult<()> {
        // Fetch trusted measurements from blockchain
        let trusted_measurements = self
            .blockchain_client
            .query_trusted_measurements(platform)
            .await?;

        // Check if measurement is trusted
        if !trusted_measurements.contains(measurement) {
            return Err(TEEError::AttestationError(format!(
                "Measurement not found in trusted registry for platform {}",
                platform
            )));
        }

        // For high-security platforms, check revocation status
        if platform == "intel_sgx" || platform == "aws_nitro" {
            let revocation_list = self
                .blockchain_client
                .query_revoked_measurements(platform)
                .await?;

            if revocation_list.contains(measurement) {
                return Err(TEEError::AttestationError(format!(
                    "Measurement has been revoked for platform {}",
                    platform
                )));
            }
        }

        Ok(())
    }
}
