//! Core module for SuiStack0X TEE Framework

// Public exports
pub mod attestation;
pub mod crypto;
pub mod enclave;
pub mod error;

// Re-exports for convenient access
pub use attestation::Attestation;
pub use crypto::{
    CryptoContext, CryptoError, CryptoResult,
    encryption::{AsymmetricEncryption, EncryptionUtil, SymmetricEncryption},
    hashing::{HashFunction, HashUtil},
    hmac::{HMACUtil, MAC},
    kdf::{HKDF, KeyDerivation},
    rng::{RNGUtil, SecureRandom},
    signatures::{DigitalSignature, MultiSignature, SignatureScheme, SignatureUtil},
    storage::{KeyType, SecureKeyStorage},
    zk_proofs::{RangeProof, SetMembershipProof, ZKProofSystem},
};
pub use enclave::Enclave;
pub use error::{TEEError, TEEResult};
