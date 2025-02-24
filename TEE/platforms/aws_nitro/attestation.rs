//! AWS Nitro Enclaves Attestation Implementation

use crate::core::error::{TEEError, TEEResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// AWS Nitro Attestation Document Format
#[derive(Debug, Serialize, Deserialize)]
struct NitroAttestationDocument {
    /// Module ID
    module_id: String,

    /// Digest of the enclave image
    pcr0: String,

    /// Digest of the enclave kernel and bootstrap
    pcr1: String,

    /// Digest of the IAM role and user data
    pcr2: String,

    /// Nonce used for freshness
    nonce: Option<String>,

    /// Public key used for verification
    public_key: String,

    /// User-supplied data
    user_data: Option<String>,

    /// Timestamp of attestation
    timestamp: u64,

    /// AWS instance information
    instance_info: NitroInstanceInfo,

    /// Certificate chain for verification
    certificate_chain: Vec<String>,

    /// Document signature
    signature: String,
}

/// AWS Instance Information
#[derive(Debug, Serialize, Deserialize)]
struct NitroInstanceInfo {
    /// Instance ID
    instance_id: String,

    /// Instance type
    instance_type: String,

    /// AWS region
    region: String,

    /// Domain name
    domain: String,
}

/// AWS Nitro Attestation Implementation
pub struct NitroAttestationUtil;

impl NitroAttestationUtil {
    /// Generate attestation report using AWS Nitro Enclaves API
    pub fn generate_report(measurement: &[u8]) -> TEEResult<Vec<u8>> {
        // Required AWS Nitro includes
        use aws_nitro_enclaves_sdk as nitro;
        use nitro::nsm_api;

        // Create attestation request
        let request = nsm_api::Request {
            attestation: Some(nsm_api::AttestationDoc {
                user_data: Some(measurement.to_vec()),
                nonce: Some(Self::generate_nonce()?),
                ..Default::default()
            }),
            ..Default::default()
        };

        // Get attestation from Nitro Security Module
        let response = nsm_api::nsm_process_request(&request).map_err(|e| {
            TEEError::AttestationError(format!("Failed to get Nitro attestation: {}", e))
        })?;

        // Extract attestation document
        let attestation_doc = response
            .attestation
            .ok_or_else(|| TEEError::AttestationError("No attestation in response".to_string()))?;

        // Serialize document
        serde_json::to_vec(&attestation_doc).map_err(|e| {
            TEEError::AttestationError(format!("Failed to serialize attestation: {}", e))
        })
    }

    /// Parse Nitro attestation report
    pub fn parse_report(
        report: &[u8],
    ) -> TEEResult<crate::core::attestation::AttestationReportData> {
        // Parse attestation document
        let doc: NitroAttestationDocument = serde_json::from_slice(report).map_err(|e| {
            TEEError::AttestationError(format!("Failed to parse Nitro attestation: {}", e))
        })?;

        // Extract measurement from PCR0
        let measurement = hex::decode(&doc.pcr0)
            .map_err(|e| TEEError::AttestationError(format!("Invalid PCR0 format: {}", e)))?;

        Ok(crate::core::attestation::AttestationReportData {
            platform: "aws_nitro".to_string(),
            quote: report.to_vec(),
            measurement,
            timestamp: doc.timestamp,
        })
    }

    /// Verify Nitro attestation report
    pub fn verify_report(report: &[u8]) -> TEEResult<bool> {
        // Parse attestation document
        let doc: NitroAttestationDocument = serde_json::from_slice(report).map_err(|e| {
            TEEError::AttestationError(format!("Failed to parse Nitro attestation: {}", e))
        })?;

        // Verify timestamp freshness
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| TEEError::AttestationError(e.to_string()))?
            .as_secs();

        if current_time > doc.timestamp + 3600 {
            return Ok(false); // Attestation too old
        }

        // Verify certificate chain
        Self::verify_certificate_chain(&doc.certificate_chain)?;

        // Verify document signature using AWS public key
        Self::verify_document_signature(&doc, &doc.signature, &doc.certificate_chain[0])?;

        Ok(true)
    }

    /// Generate nonce for attestation request
    fn generate_nonce() -> TEEResult<Vec<u8>> {
        use rand::{RngCore, thread_rng};

        let mut nonce = vec![0u8; 32];
        thread_rng().fill_bytes(&mut nonce);
        Ok(nonce)
    }

    /// Verify AWS certificate chain
    fn verify_certificate_chain(chain: &[String]) -> TEEResult<()> {
        use x509_parser::prelude::*;

        let mut last_cert = None;

        for cert_pem in chain {
            // Parse certificate
            let (_, cert) = X509Certificate::from_pem(cert_pem.as_bytes())
                .map_err(|e| TEEError::AttestationError(format!("Invalid certificate: {}", e)))?;

            // Verify certificate validity period
            if !cert.validity().is_valid_at_timestamp(SystemTime::now()) {
                return Err(TEEError::AttestationError(
                    "Certificate expired".to_string(),
                ));
            }

            // Verify certificate chain
            if let Some(last) = last_cert {
                if !cert.verify_signature(Some(last)).is_ok() {
                    return Err(TEEError::AttestationError(
                        "Invalid certificate chain".to_string(),
                    ));
                }
            }

            last_cert = Some(cert);
        }

        Ok(())
    }

    /// Verify attestation document signature
    fn verify_document_signature(
        doc: &NitroAttestationDocument,
        signature: &str,
        cert_pem: &str,
    ) -> TEEResult<()> {
        use x509_parser::prelude::*;

        // Parse signing certificate
        let (_, cert) = X509Certificate::from_pem(cert_pem.as_bytes()).map_err(|e| {
            TEEError::AttestationError(format!("Invalid signing certificate: {}", e))
        })?;

        // Get document bytes without signature
        let mut doc_clone = doc.clone();
        doc_clone.signature = String::new();
        let doc_bytes = serde_json::to_vec(&doc_clone).map_err(|e| {
            TEEError::AttestationError(format!("Failed to serialize document: {}", e))
        })?;

        // Verify signature
        let signature_bytes = base64::decode(signature).map_err(|e| {
            TEEError::AttestationError(format!("Invalid signature encoding: {}", e))
        })?;

        cert.verify_signature(None, &doc_bytes, &signature_bytes)
            .map_err(|e| {
                TEEError::AttestationError(format!("Invalid document signature: {}", e))
            })?;

        Ok(())
    }
}
