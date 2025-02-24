//! Cryptographic primitives for SuiStack0X TEE Framework

// Public module exports
pub mod encryption;
pub mod hashing;
pub mod key_management;
pub mod mpc;
pub mod signatures;
pub mod zk_proofs;

// Re-exports for convenient access
pub use encryption::{AsymmetricEncryption, EncryptionError, KeyExchange, SymmetricEncryption};
pub use hashing::{HashFunction, HashUtil};
pub use key_management::{Key, KeyManager, KeyPair, KeyType, SecureKeyStorage};
pub use mpc::{ComputationState, ExecutionContext, MultiPartyComputation, Participant};
pub use signatures::{DigitalSignature, MultiSignature, SignatureError, SignatureScheme};
pub use zk_proofs::{RangeProof, SetMembershipProof, ZKProofSystem, ZeroKnowledgeProof};

/// Unified cryptographic context for secure operations
pub struct CryptoContext {
    /// Symmetric encryption mechanism
    pub symmetric_encryption: SymmetricEncryption,

    /// Asymmetric encryption mechanism
    pub asymmetric_encryption: AsymmetricEncryption,

    /// Digital signature scheme
    pub signature_scheme: SignatureScheme,

    /// Zero-knowledge proof system
    pub zk_proof_system: ZKProofSystem,

    /// Hashing utility
    pub hash_util: HashUtil,

    /// Key management
    pub key_manager: KeyManager,

    /// Multi-party computation
    pub mpc: MultiPartyComputation,
}

impl CryptoContext {
    /// Create a new cryptographic context with default configurations
    pub fn new() -> Self {
        Self {
            symmetric_encryption: SymmetricEncryption::new(),
            asymmetric_encryption: AsymmetricEncryption::new(),
            signature_scheme: SignatureScheme::new(),
            zk_proof_system: ZKProofSystem::new(),
            hash_util: HashUtil::new(HashFunction::SHA256),
            key_manager: KeyManager::new(),
            mpc: MultiPartyComputation::new(),
        }
    }

    /// Perform a comprehensive security operation
    pub fn secure_operation<F, R>(&self, operation: F) -> Result<R, CryptoError>
    where
        F: FnOnce(&CryptoContext) -> Result<R, CryptoError>,
    {
        operation(self)
    }
}

/// Unified crypto error type
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Encryption error: {0}")]
    EncryptionError(#[from] EncryptionError),

    #[error("Signature error: {0}")]
    SignatureError(#[from] SignatureError),

    #[error("Zero-knowledge proof error: {0}")]
    ZKProofError(String),

    #[error("Hashing error: {0}")]
    HashingError(String),

    #[error("Key management error: {0}")]
    KeyManagementError(String),

    #[error("Multi-party computation error: {0}")]
    MPCError(String),

    #[error("General cryptographic error: {0}")]
    GeneralError(String),
}

/// Trait for cryptographic primitives that can be serialized
pub trait CryptoSerializable {
    /// Serialize the cryptographic primitive
    fn serialize(&self) -> Vec<u8>;

    /// Deserialize from bytes
    fn deserialize(bytes: &[u8]) -> Result<Self, CryptoError>
    where
        Self: Sized;
}

// Default implementation for standard types
impl CryptoSerializable for Vec<u8> {
    fn serialize(&self) -> Vec<u8> {
        self.clone()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, CryptoError> {
        Ok(bytes.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_context_creation() {
        let context = CryptoContext::new();

        // Verify components are initialized
        assert!(context.symmetric_encryption.is_initialized());
        assert!(context.asymmetric_encryption.is_initialized());
        assert!(context.signature_scheme.is_initialized());
        assert!(context.zk_proof_system.is_initialized());
        assert!(context.hash_util.is_initialized());
        assert!(context.key_manager.is_initialized());
        assert!(context.mpc.is_initialized());
    }

    #[test]
    fn test_secure_operation() -> Result<(), CryptoError> {
        let context = CryptoContext::new();

        // Example secure operation
        let result = context.secure_operation(|ctx| {
            // Perform some cryptographic operation
            let message = b"test message";
            let signature = ctx.signature_scheme.sign(message)?;
            ctx.signature_scheme.verify(message, &signature)
        })?;

        assert!(result);
        Ok(())
    }
}
