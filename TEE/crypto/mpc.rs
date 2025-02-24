//! Production implementation of Multi-Party Computation protocols
//! Implements Shamir Secret Sharing, Oblivious Transfer, and secure MPC primitives

use crate::core::error::{TEEError, TEEResult};
use crate::crypto::{
    encryption::{AsymmetricEncryption, SymmetricEncryption},
    hashing::HashFunction,
    key_management::{KeyManager, KeyType},
};
use rand::{CryptoRng, RngCore};
use ring::agreement::{Algorithm, EphemeralPrivateKey, PublicKey};
use ring::rand::SystemRandom;
use std::collections::HashMap;
use std::sync::Arc;

/// Represents a participant in multi-party computation
#[derive(Clone, Debug)]
pub struct Participant {
    /// Unique participant ID
    pub id: String,
    /// Public key for communication
    pub public_key: Vec<u8>,
    /// Share of the computation
    share: Vec<u8>,
    /// Current computation state
    state: ComputationState,
}

/// Current state of MPC computation
#[derive(Clone, Debug, PartialEq)]
pub enum ComputationState {
    /// Initial state
    Setup,
    /// Share distribution complete
    SharesDistributed,
    /// Computation in progress
    Computing,
    /// Computation complete
    Complete,
    /// Error state
    Error(String),
}

/// Multi-party computation manager
pub struct MultiPartyComputation {
    /// Participants in the computation
    participants: HashMap<String, Participant>,
    /// Threshold for reconstruction
    threshold: usize,
    /// Total number of participants
    total_participants: usize,
    /// Key manager for crypto operations
    key_manager: Arc<KeyManager>,
    /// RNG for cryptographic operations
    rng: SystemRandom,
}

impl MultiPartyComputation {
    /// Create new MPC instance
    pub fn new(
        threshold: usize,
        total_participants: usize,
        key_manager: Arc<KeyManager>,
    ) -> TEEResult<Self> {
        if threshold > total_participants {
            return Err(TEEError::CryptoError {
                reason: "Invalid threshold".to_string(),
                details: "Threshold cannot be greater than total participants".to_string(),
                source: None,
            });
        }

        Ok(Self {
            participants: HashMap::new(),
            threshold,
            total_participants,
            key_manager,
            rng: SystemRandom::new(),
        })
    }

    /// Add participant to computation
    pub fn add_participant(&mut self, id: String, public_key: Vec<u8>) -> TEEResult<()> {
        if self.participants.len() >= self.total_participants {
            return Err(TEEError::CryptoError {
                reason: "Too many participants".to_string(),
                details: "Maximum number of participants reached".to_string(),
                source: None,
            });
        }

        let participant = Participant {
            id: id.clone(),
            public_key,
            share: Vec::new(),
            state: ComputationState::Setup,
        };

        self.participants.insert(id, participant);
        Ok(())
    }

    /// Generate shares for secret using Shamir's Secret Sharing
    pub fn generate_shares(&mut self, secret: &[u8]) -> TEEResult<Vec<Vec<u8>>> {
        if self.participants.len() != self.total_participants {
            return Err(TEEError::CryptoError {
                reason: "Invalid participant count".to_string(),
                details: "Not all participants have joined".to_string(),
                source: None,
            });
        }

        // Generate polynomial coefficients
        let mut coefficients = Vec::with_capacity(self.threshold);
        coefficients.push(secret.to_vec());

        for _ in 1..self.threshold {
            let mut coeff = vec![0u8; secret.len()];
            self.rng
                .fill(&mut coeff)
                .map_err(|e| TEEError::CryptoError {
                    reason: "RNG error".to_string(),
                    details: e.to_string(),
                    source: None,
                })?;
            coefficients.push(coeff);
        }

        // Generate shares for each participant
        let mut shares = Vec::with_capacity(self.total_participants);
        for i in 1..=self.total_participants {
            let mut share = secret.to_vec();
            let x = i as u8;

            // Evaluate polynomial at point x
            for j in 1..self.threshold {
                let mut term = coefficients[j].clone();
                for _ in 0..j {
                    for byte in term.iter_mut() {
                        *byte = (*byte).wrapping_mul(x);
                    }
                }
                for (s, t) in share.iter_mut().zip(term.iter()) {
                    *s ^= *t;
                }
            }

            shares.push(share);
        }

        // Update participant states
        for (i, participant) in self.participants.values_mut().enumerate() {
            participant.share = shares[i].clone();
            participant.state = ComputationState::SharesDistributed;
        }

        Ok(shares)
    }

    /// Reconstruct secret from shares using Lagrange interpolation
    pub fn reconstruct_secret(&self, shares: &[Vec<u8>]) -> TEEResult<Vec<u8>> {
        if shares.len() < self.threshold {
            return Err(TEEError::CryptoError {
                reason: "Insufficient shares".to_string(),
                details: "Not enough shares for reconstruction".to_string(),
                source: None,
            });
        }

        let share_len = shares[0].len();
        let mut secret = vec![0u8; share_len];

        // Lagrange interpolation
        for i in 0..self.threshold {
            let mut lagrange_basis = vec![1u8; share_len];

            for j in 0..self.threshold {
                if i != j {
                    let x_i = (i + 1) as u8;
                    let x_j = (j + 1) as u8;
                    let mut factor = x_j;
                    factor = factor.wrapping_div(x_j.wrapping_sub(x_i));

                    for byte in lagrange_basis.iter_mut() {
                        *byte = byte.wrapping_mul(factor);
                    }
                }
            }

            for (s, (l, &share)) in secret
                .iter_mut()
                .zip(lagrange_basis.iter().zip(shares[i].iter()))
            {
                *s ^= l.wrapping_mul(share);
            }
        }

        Ok(secret)
    }

    /// Perform 1-out-of-2 oblivious transfer
    pub async fn oblivious_transfer(
        &self,
        sender_id: &str,
        receiver_id: &str,
        message0: &[u8],
        message1: &[u8],
    ) -> TEEResult<Vec<u8>> {
        // Get participants
        let sender = self
            .participants
            .get(sender_id)
            .ok_or_else(|| TEEError::CryptoError {
                reason: "Invalid sender".to_string(),
                details: "Sender not found".to_string(),
                source: None,
            })?;

        let receiver = self
            .participants
            .get(receiver_id)
            .ok_or_else(|| TEEError::CryptoError {
                reason: "Invalid receiver".to_string(),
                details: "Receiver not found".to_string(),
                source: None,
            })?;

        // Generate ephemeral keys
        let sender_ephemeral = EphemeralPrivateKey::generate(&Algorithm::X25519, &self.rng)
            .map_err(|e| TEEError::CryptoError {
                reason: "Key generation failed".to_string(),
                details: e.to_string(),
                source: None,
            })?;

        let receiver_ephemeral = EphemeralPrivateKey::generate(&Algorithm::X25519, &self.rng)
            .map_err(|e| TEEError::CryptoError {
                reason: "Key generation failed".to_string(),
                details: e.to_string(),
                source: None,
            })?;

        // Perform OT protocol
        let (k0, k1) = self.generate_ot_keys(&sender_ephemeral, &receiver_ephemeral)?;

        // Encrypt messages
        let c0 = self.encrypt_ot_message(message0, &k0)?;
        let c1 = self.encrypt_ot_message(message1, &k1)?;

        Ok(if receiver.share[0] & 1 == 0 { c0 } else { c1 })
    }

    /// Generate keys for oblivious transfer
    fn generate_ot_keys(
        &self,
        sender_key: &EphemeralPrivateKey,
        receiver_key: &EphemeralPrivateKey,
    ) -> TEEResult<(Vec<u8>, Vec<u8>)> {
        // Generate shared secrets
        let k0 = agreement::agree_ephemeral(
            sender_key,
            &agreement::UnparsedPublicKey::new(
                &Algorithm::X25519,
                receiver_key.public_key().as_ref(),
            ),
            ring::error::Unspecified,
            |k| Ok(k.to_vec()),
        )
        .map_err(|e| TEEError::CryptoError {
            reason: "Key agreement failed".to_string(),
            details: e.to_string(),
            source: None,
        })?;

        let k1 = agreement::agree_ephemeral(
            receiver_key,
            &agreement::UnparsedPublicKey::new(
                &Algorithm::X25519,
                sender_key.public_key().as_ref(),
            ),
            ring::error::Unspecified,
            |k| Ok(k.to_vec()),
        )
        .map_err(|e| TEEError::CryptoError {
            reason: "Key agreement failed".to_string(),
            details: e.to_string(),
            source: None,
        })?;

        Ok((k0, k1))
    }

    /// Encrypt message for oblivious transfer
    fn encrypt_ot_message(&self, message: &[u8], key: &[u8]) -> TEEResult<Vec<u8>> {
        let symmetric = SymmetricEncryption::new(key.to_vec())?;
        symmetric.encrypt(message)
    }

    /// Get computation status
    pub fn get_status(&self) -> HashMap<String, ComputationState> {
        self.participants
            .iter()
            .map(|(id, p)| (id.clone(), p.state.clone()))
            .collect()
    }

    /// Clean up sensitive data
    pub fn cleanup(&mut self) {
        for participant in self.participants.values_mut() {
            participant.share.zeroize();
        }
    }
}

// Implement Drop to ensure cleanup
impl Drop for MultiPartyComputation {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_sharing() -> TEEResult<()> {
        let key_manager = Arc::new(KeyManager::new()?);
        let mut mpc = MultiPartyComputation::new(3, 5, key_manager)?;

        // Add participants
        for i in 0..5 {
            mpc.add_participant(
                format!("participant{}", i),
                vec![0u8; 32], // Test public keys
            )?;
        }

        // Generate shares
        let secret = b"test secret";
        let shares = mpc.generate_shares(secret)?;

        // Reconstruct with sufficient shares
        let reconstructed = mpc.reconstruct_secret(&shares[0..3])?;
        assert_eq!(reconstructed, secret);

        Ok(())
    }

    #[test]
    fn test_oblivious_transfer() -> TEEResult<()> {
        let key_manager = Arc::new(KeyManager::new()?);
        let mut mpc = MultiPartyComputation::new(2, 2, key_manager)?;

        // Add participants
        mpc.add_participant("sender".to_string(), vec![0u8; 32])?;
        mpc.add_participant("receiver".to_string(), vec![0u8; 32])?;

        // Perform OT
        let msg0 = b"message0";
        let msg1 = b"message1";

        let result = async_std::task::block_on(async {
            mpc.oblivious_transfer("sender", "receiver", msg0, msg1)
                .await
        })?;

        assert!(!result.is_empty());
        Ok(())
    }
}
