//! Minimal Computation Proof (MCP) generation and verification

use crate::core::crypto::SignatureUtil;
use crate::core::error::{TEEError, TEEResult};
use ring::signature::{self, KeyPair};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Minimal Computation Proof generator
pub struct MCPGenerator {
    /// Private key for signing proofs
    signing_keys: Arc<Mutex<HashMap<String, SigningKey>>>,
    /// Proof protocol version
    protocol_version: u8,
    /// Performance tracking
    proof_generation_times: Arc<Mutex<Vec<u64>>>,
}

/// Signing key for proof generation
struct SigningKey {
    keypair: signature::Ed25519KeyPair,
    platform: String,
    creation_time: std::time::SystemTime,
}

/// MCP verification result
pub struct MCPVerificationResult {
    /// Overall verification result
    pub valid: bool,
    /// Verification details
    pub details: Vec<VerificationDetail>,
    /// Signer identifier
    pub signer_id: Option<String>,
    /// Timestamp of the proof
    pub timestamp: u64,
}

/// Verification detail
pub struct VerificationDetail {
    /// Component name
    pub component: String,
    /// Verification status
    pub status: bool,
    /// Additional information
    pub info: String,
}

impl MCPGenerator {
    /// Create a new MCP generator
    pub fn new() -> Self {
        Self {
            signing_keys: Arc::new(Mutex::new(HashMap::new())),
            protocol_version: 1,
            proof_generation_times: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Register a signing key for a platform
    pub fn register_signing_key(&self, platform: &str) -> TEEResult<String> {
        use ring::rand::SystemRandom;

        // Generate a new key pair
        let rng = SystemRandom::new();
        let pkcs8_bytes =
            signature::Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| TEEError::CryptoError {
                reason: "Failed to generate key pair".to_string(),
                details: "PKCS#8 generation failed".to_string(),
                source: None,
            })?;

        let keypair =
            signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).map_err(|_| {
                TEEError::CryptoError {
                    reason: "Failed to load key pair".to_string(),
                    details: "PKCS#8 parsing failed".to_string(),
                    source: None,
                }
            })?;

        // Generate key ID
        let public_key = keypair.public_key().as_ref();
        let mut hasher = Sha256::new();
        hasher.update(public_key);
        let key_id = hex::encode(hasher.finalize());

        // Store key
        let mut keys = self.signing_keys.lock().unwrap();
        keys.insert(
            key_id.clone(),
            SigningKey {
                keypair,
                platform: platform.to_string(),
                creation_time: std::time::SystemTime::now(),
            },
        );

        Ok(key_id)
    }

    /// Generate a Minimal Computation Proof
    pub fn generate_proof(
        &self,
        result: &[u8],
        contract: &[u8],
        args: &[Vec<u8>],
    ) -> TEEResult<Vec<u8>> {
        // Track proof generation time
        let start_time = std::time::Instant::now();

        // Ensure we have at least one signing key
        let keys = self.signing_keys.lock().unwrap();
        if keys.is_empty() {
            // Generate a default key if none exists
            drop(keys);
            self.register_signing_key("default")?;
        }

        // Get a key for signing
        let keys = self.signing_keys.lock().unwrap();
        let (key_id, key) = keys.iter().next().ok_or_else(|| TEEError::CryptoError {
            reason: "No signing keys available".to_string(),
            details: "Register a signing key before generating proofs".to_string(),
            source: None,
        })?;

        // Create a minimal proof that can verify execution
        // Hash key parts of execution path rather than full recomputation
        let mut proof_data = Vec::new();

        // Add protocol version
        proof_data.push(self.protocol_version);

        // Add key ID
        proof_data.extend_from_slice(key_id.as_bytes());
        proof_data.push(0); // Null terminator

        // Add timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        proof_data.extend_from_slice(&timestamp.to_le_bytes());

        // Add contract hash (we don't include full contract for efficiency)
        let mut hasher = Sha256::new();
        hasher.update(contract);
        let contract_hash = hasher.finalize();
        proof_data.extend_from_slice(&contract_hash);

        // Add args fingerprints
        let arg_count = args.len() as u32;
        proof_data.extend_from_slice(&arg_count.to_le_bytes());

        for arg in args {
            let mut arg_hasher = Sha256::new();
            arg_hasher.update(arg);
            let arg_hash = arg_hasher.finalize();
            proof_data.extend_from_slice(&arg_hash);
        }

        // Add result hash
        let mut result_hasher = Sha256::new();
        result_hasher.update(result);
        let result_hash = result_hasher.finalize();
        proof_data.extend_from_slice(&result_hash);

        // Sign the proof data
        let signature = key.keypair.sign(&proof_data);

        // Combine proof data and signature
        let mut complete_proof = proof_data;
        complete_proof.extend_from_slice(signature.as_ref());

        // Record generation time
        let elapsed = start_time.elapsed();
        let mut times = self.proof_generation_times.lock().unwrap();
        times.push(elapsed.as_micros() as u64);
        if times.len() > 100 {
            times.remove(0); // Keep only the last 100 times
        }

        Ok(complete_proof)
    }

    /// Verify a Minimal Computation Proof
    pub fn verify_proof(
        &self,
        proof: &[u8],
        result: &[u8],
        contract: &[u8],
        args: &[Vec<u8>],
        public_key: &[u8],
    ) -> TEEResult<MCPVerificationResult> {
        // Basic length validation
        if proof.len() < 74 {
            // Version + min key ID + timestamp + signature
            return Ok(MCPVerificationResult {
                valid: false,
                details: vec![VerificationDetail {
                    component: "proof_length".to_string(),
                    status: false,
                    info: "Proof too short".to_string(),
                }],
                signer_id: None,
                timestamp: 0,
            });
        }

        // Parse protocol version
        let protocol_version = proof[0];
        if protocol_version != self.protocol_version {
            return Ok(MCPVerificationResult {
                valid: false,
                details: vec![VerificationDetail {
                    component: "protocol_version".to_string(),
                    status: false,
                    info: format!(
                        "Protocol version mismatch: expected {}, got {}",
                        self.protocol_version, protocol_version
                    ),
                }],
                signer_id: None,
                timestamp: 0,
            });
        }

        // Parse key ID
        let mut key_id_end = 1;
        while key_id_end < proof.len() && proof[key_id_end] != 0 {
            key_id_end += 1;
        }

        if key_id_end >= proof.len() {
            return Ok(MCPVerificationResult {
                valid: false,
                details: vec![VerificationDetail {
                    component: "key_id".to_string(),
                    status: false,
                    info: "Invalid key ID format".to_string(),
                }],
                signer_id: None,
                timestamp: 0,
            });
        }

        let key_id =
            std::str::from_utf8(&proof[1..key_id_end]).map_err(|_| TEEError::CryptoError {
                reason: "Invalid key ID".to_string(),
                details: "Key ID is not valid UTF-8".to_string(),
                source: None,
            })?;

        // Parse timestamp
        let timestamp_start = key_id_end + 1;
        if timestamp_start + 8 >= proof.len() {
            return Ok(MCPVerificationResult {
                valid: false,
                details: vec![VerificationDetail {
                    component: "timestamp".to_string(),
                    status: false,
                    info: "Proof too short for timestamp".to_string(),
                }],
                signer_id: Some(key_id.to_string()),
                timestamp: 0,
            });
        }

        let timestamp_bytes: [u8; 8] = proof[timestamp_start..timestamp_start + 8]
            .try_into()
            .map_err(|_| TEEError::CryptoError {
                reason: "Invalid timestamp".to_string(),
                details: "Failed to parse timestamp bytes".to_string(),
                source: None,
            })?;

        let timestamp = u64::from_le_bytes(timestamp_bytes);

        // Calculate signature start position (proof data length)
        let signature_start = proof.len() - 64; // Ed25519 signature is 64 bytes
        if signature_start <= timestamp_start + 8 {
            return Ok(MCPVerificationResult {
                valid: false,
                details: vec![VerificationDetail {
                    component: "signature".to_string(),
                    status: false,
                    info: "Proof too short for signature".to_string(),
                }],
                signer_id: Some(key_id.to_string()),
                timestamp,
            });
        }

        // Extract proof data and signature
        let proof_data = &proof[0..signature_start];
        let signature_bytes = &proof[signature_start..];

        // Verify signature
        let verify_result = SignatureUtil::verify(public_key, proof_data, signature_bytes)?;
        if !verify_result {
            return Ok(MCPVerificationResult {
                valid: false,
                details: vec![VerificationDetail {
                    component: "signature".to_string(),
                    status: false,
                    info: "Signature verification failed".to_string(),
                }],
                signer_id: Some(key_id.to_string()),
                timestamp,
            });
        }

        // Verify contract hash
        let contract_hash_start = timestamp_start + 8;
        if contract_hash_start + 32 > signature_start {
            return Ok(MCPVerificationResult {
                valid: false,
                details: vec![VerificationDetail {
                    component: "contract_hash".to_string(),
                    status: false,
                    info: "Proof too short for contract hash".to_string(),
                }],
                signer_id: Some(key_id.to_string()),
                timestamp,
            });
        }

        let contract_hash = &proof[contract_hash_start..contract_hash_start + 32];

        let mut hasher = Sha256::new();
        hasher.update(contract);
        let expected_contract_hash = hasher.finalize();

        if contract_hash != expected_contract_hash.as_slice() {
            return Ok(MCPVerificationResult {
                valid: false,
                details: vec![VerificationDetail {
                    component: "contract_hash".to_string(),
                    status: false,
                    info: "Contract hash mismatch".to_string(),
                }],
                signer_id: Some(key_id.to_string()),
                timestamp,
            });
        }

        // Verify args count and hashes
        let args_count_start = contract_hash_start + 32;
        if args_count_start + 4 > signature_start {
            return Ok(MCPVerificationResult {
                valid: false,
                details: vec![VerificationDetail {
                    component: "args_count".to_string(),
                    status: false,
                    info: "Proof too short for args count".to_string(),
                }],
                signer_id: Some(key_id.to_string()),
                timestamp,
            });
        }

        let args_count_bytes: [u8; 4] = proof[args_count_start..args_count_start + 4]
            .try_into()
            .unwrap_or([0; 4]);
        let args_count = u32::from_le_bytes(args_count_bytes);

        if args_count as usize != args.len() {
            return Ok(MCPVerificationResult {
                valid: false,
                details: vec![VerificationDetail {
                    component: "args_count".to_string(),
                    status: false,
                    info: format!(
                        "Arguments count mismatch: expected {}, got {}",
                        args.len(),
                        args_count
                    ),
                }],
                signer_id: Some(key_id.to_string()),
                timestamp,
            });
        }

        // Verify arg hashes
        let mut arg_hash_start = args_count_start + 4;
        let mut valid_args = true;
        let mut arg_details = Vec::new();

        for (i, arg) in args.iter().enumerate() {
            if arg_hash_start + 32 > signature_start {
                valid_args = false;
                arg_details.push(VerificationDetail {
                    component: format!("arg_{}_hash", i),
                    status: false,
                    info: "Proof too short for arg hash".to_string(),
                });
                break;
            }

            let arg_hash = &proof[arg_hash_start..arg_hash_start + 32];

            let mut hasher = Sha256::new();
            hasher.update(arg);
            let expected_arg_hash = hasher.finalize();

            if arg_hash != expected_arg_hash.as_slice() {
                valid_args = false;
                arg_details.push(VerificationDetail {
                    component: format!("arg_{}_hash", i),
                    status: false,
                    info: "Argument hash mismatch".to_string(),
                });
            } else {
                arg_details.push(VerificationDetail {
                    component: format!("arg_{}_hash", i),
                    status: true,
                    info: "Argument hash verified".to_string(),
                });
            }

            arg_hash_start += 32;
        }

        // Verify result hash
        if arg_hash_start + 32 > signature_start {
            return Ok(MCPVerificationResult {
                valid: false,
                details: vec![VerificationDetail {
                    component: "result_hash".to_string(),
                    status: false,
                    info: "Proof too short for result hash".to_string(),
                }],
                signer_id: Some(key_id.to_string()),
                timestamp,
            });
        }

        let result_hash = &proof[arg_hash_start..arg_hash_start + 32];

        let mut hasher = Sha256::new();
        hasher.update(result);
        let expected_result_hash = hasher.finalize();

        let result_valid = result_hash == expected_result_hash.as_slice();

        // Compile all verification details
        let mut all_details = vec![
            VerificationDetail {
                component: "protocol_version".to_string(),
                status: true,
                info: format!("Protocol version {}", protocol_version),
            },
            VerificationDetail {
                component: "signature".to_string(),
                status: true,
                info: "Signature verified".to_string(),
            },
            VerificationDetail {
                component: "contract_hash".to_string(),
                status: true,
                info: "Contract hash verified".to_string(),
            },
            VerificationDetail {
                component: "result_hash".to_string(),
                status: result_valid,
                info: if result_valid {
                    "Result hash verified".to_string()
                } else {
                    "Result hash mismatch".to_string()
                },
            },
        ];

        all_details.extend(arg_details);

        // Final verification result
        let valid = verify_result && result_valid && valid_args;

        Ok(MCPVerificationResult {
            valid,
            details: all_details,
            signer_id: Some(key_id.to_string()),
            timestamp,
        })
    }

    /// Get average proof generation time in microseconds
    pub fn get_average_generation_time(&self) -> f64 {
        let times = self.proof_generation_times.lock().unwrap();
        if times.is_empty() {
            return 0.0;
        }

        let sum: u64 = times.iter().sum();
        sum as f64 / times.len() as f64
    }
}
