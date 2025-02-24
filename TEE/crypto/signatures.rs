use crate::core::error::{TEEError, TEEResult};
use ed25519_dalek::{
    Keypair, Signature, SigningKey, VerifyingKey,
    signature::{Signer, Verifier},
};
use ring::rand::SystemRandom;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

/// Digital Signature Utility providing high-level signature operations
pub struct SignatureUtil {
    rng: SystemRandom,
    cached_keys: Arc<Mutex<HashMap<String, CachedKeyPair>>>,
}

/// Cached keypair with metadata and expiration
struct CachedKeyPair {
    keypair: SigningKey,
    created_at: SystemTime,
    expires_at: Option<SystemTime>,
    key_id: String,
}

/// A production-ready digital signature scheme
pub struct DigitalSignature {
    /// Key type and parameters
    pub key_type: SignatureKeyType,
    /// Additional signature metadata
    pub metadata: HashMap<String, String>,
    /// Signature timestamp
    pub timestamp: u64,
    /// Signature data
    signature: Vec<u8>,
}

/// Supported signature key types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureKeyType {
    Ed25519,
    P256,
}

impl SignatureUtil {
    /// Create a new signature utility instance
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
            cached_keys: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Generate a new keypair with optional expiration
    pub fn generate_keypair(
        &self,
        key_type: SignatureKeyType,
        expiration_secs: Option<u64>,
    ) -> TEEResult<(Vec<u8>, Vec<u8>, String)> {
        match key_type {
            SignatureKeyType::Ed25519 => {
                // Generate Ed25519 keypair
                let mut seed = [0u8; 32];
                self.rng
                    .fill(&mut seed)
                    .map_err(|e| TEEError::CryptoError {
                        reason: "Failed to generate random seed".to_string(),
                        details: e.to_string(),
                        source: None,
                    })?;

                let signing_key = SigningKey::from_bytes(&seed);
                let verifying_key = signing_key.verifying_key();

                // Generate key ID
                let mut hasher = Sha256::new();
                hasher.update(&verifying_key.to_bytes());
                let key_id = hex::encode(hasher.finalize());

                // Store in cache if expiration provided
                if let Some(expiration) = expiration_secs {
                    let expires_at = SystemTime::now() + std::time::Duration::from_secs(expiration);

                    let cached_key = CachedKeyPair {
                        keypair: signing_key.clone(),
                        created_at: SystemTime::now(),
                        expires_at: Some(expires_at),
                        key_id: key_id.clone(),
                    };

                    let mut cache = self.cached_keys.lock().unwrap();
                    cache.insert(key_id.clone(), cached_key);
                }

                // Zero out sensitive data
                seed.zeroize();

                Ok((
                    signing_key.to_bytes().to_vec(),
                    verifying_key.to_bytes().to_vec(),
                    key_id,
                ))
            }
            SignatureKeyType::P256 => {
                // Generate P-256 keypair using ring
                unimplemented!("P-256 signature support not yet implemented");
            }
        }
    }

    /// Sign a message using the provided private key
    pub fn sign(
        &self,
        private_key: &[u8],
        message: &[u8],
        key_type: SignatureKeyType,
    ) -> TEEResult<DigitalSignature> {
        match key_type {
            SignatureKeyType::Ed25519 => {
                // Create signing key
                let signing_key = SigningKey::from_bytes(private_key.try_into().map_err(|_| {
                    TEEError::CryptoError {
                        reason: "Invalid private key length".to_string(),
                        details: "Ed25519 private key must be 32 bytes".to_string(),
                        source: None,
                    }
                })?);

                // Sign message
                let signature = signing_key.sign(message);

                // Create signature with metadata
                Ok(DigitalSignature {
                    key_type,
                    metadata: HashMap::new(),
                    timestamp: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    signature: signature.to_bytes().to_vec(),
                })
            }
            SignatureKeyType::P256 => {
                unimplemented!("P-256 signature support not yet implemented");
            }
        }
    }

    /// Verify a signature
    pub fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &DigitalSignature,
    ) -> TEEResult<bool> {
        match signature.key_type {
            SignatureKeyType::Ed25519 => {
                // Create verifying key
                let verifying_key =
                    VerifyingKey::from_bytes(public_key.try_into().map_err(|_| {
                        TEEError::CryptoError {
                            reason: "Invalid public key length".to_string(),
                            details: "Ed25519 public key must be 32 bytes".to_string(),
                            source: None,
                        }
                    })?);

                // Parse signature
                let sig =
                    Signature::from_bytes(signature.signature.as_slice().try_into().map_err(
                        |_| TEEError::CryptoError {
                            reason: "Invalid signature length".to_string(),
                            details: "Ed25519 signature must be 64 bytes".to_string(),
                            source: None,
                        },
                    )?);

                // Verify
                match verifying_key.verify(message, &sig) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            SignatureKeyType::P256 => {
                unimplemented!("P-256 signature verification not yet implemented");
            }
        }
    }

    /// Sign with a cached key by ID
    pub fn sign_with_cached_key(
        &self,
        key_id: &str,
        message: &[u8],
    ) -> TEEResult<Option<DigitalSignature>> {
        let cache = self.cached_keys.lock().unwrap();

        if let Some(cached_key) = cache.get(key_id) {
            // Check expiration
            if let Some(expires_at) = cached_key.expires_at {
                if SystemTime::now() > expires_at {
                    return Ok(None);
                }
            }

            // Sign with cached key
            let signature = cached_key.keypair.sign(message);

            Ok(Some(DigitalSignature {
                key_type: SignatureKeyType::Ed25519,
                metadata: HashMap::new(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                signature: signature.to_bytes().to_vec(),
            }))
        } else {
            Ok(None)
        }
    }

    /// Clean expired cached keys
    pub fn clean_expired_keys(&self) {
        let mut cache = self.cached_keys.lock().unwrap();
        cache.retain(|_, v| {
            if let Some(expires_at) = v.expires_at {
                SystemTime::now() <= expires_at
            } else {
                true
            }
        });
    }
}

/// Multi-signature support
pub struct MultiSignature {
    /// Key type used
    pub key_type: SignatureKeyType,
    /// Individual signatures
    signatures: HashMap<String, DigitalSignature>,
    /// Required signatures threshold
    threshold: usize,
    /// Metadata
    metadata: HashMap<String, String>,
}

impl MultiSignature {
    /// Create new multi-signature instance
    pub fn new(key_type: SignatureKeyType, threshold: usize) -> Self {
        Self {
            key_type,
            signatures: HashMap::new(),
            threshold,
            metadata: HashMap::new(),
        }
    }

    /// Add a signature
    pub fn add_signature(
        &mut self,
        signer_id: String,
        signature: DigitalSignature,
    ) -> TEEResult<()> {
        // Verify signature type matches
        if signature.key_type != self.key_type {
            return Err(TEEError::CryptoError {
                reason: "Invalid signature type".to_string(),
                details: format!(
                    "Expected {:?} signature, got {:?}",
                    self.key_type, signature.key_type
                ),
                source: None,
            });
        }

        self.signatures.insert(signer_id, signature);
        Ok(())
    }

    /// Check if enough valid signatures are present
    pub fn is_complete(&self) -> bool {
        self.signatures.len() >= self.threshold
    }

    /// Verify all signatures
    pub fn verify_all(
        &self,
        message: &[u8],
        public_keys: &HashMap<String, Vec<u8>>,
    ) -> TEEResult<bool> {
        let sig_util = SignatureUtil::new();

        // Verify each signature
        for (signer_id, signature) in &self.signatures {
            if let Some(public_key) = public_keys.get(signer_id) {
                if !sig_util.verify(public_key, message, signature)? {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }
        }

        Ok(self.is_complete())
    }
}

impl Default for SignatureUtil {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for DigitalSignature {
    fn clone(&self) -> Self {
        Self {
            key_type: self.key_type,
            metadata: self.metadata.clone(),
            timestamp: self.timestamp,
            signature: self.signature.clone(),
        }
    }
}
