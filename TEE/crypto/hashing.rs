//! Cryptographic hashing utilities for secure operations

use crate::core::error::{TEEError, TEEResult};
use ring::digest::{Context, Digest, SHA256, SHA384, SHA512};
use zeroize::Zeroize;

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256 (32 bytes output)
    SHA256,
    /// SHA-384 (48 bytes output)
    SHA384,
    /// SHA-512 (64 bytes output)
    SHA512,
}

/// Handles cryptographic hashing operations with secure memory management
pub struct HashUtil {
    algorithm: HashAlgorithm,
    context: Context,
}

impl HashUtil {
    /// Create a new hash context with specified algorithm
    pub fn new(algorithm: HashAlgorithm) -> Self {
        let context = match algorithm {
            HashAlgorithm::SHA256 => Context::new(&SHA256),
            HashAlgorithm::SHA384 => Context::new(&SHA384),
            HashAlgorithm::SHA512 => Context::new(&SHA512),
        };

        Self { algorithm, context }
    }

    /// Update hash context with new data
    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    /// Finalize and get hash value, consuming the context
    pub fn finalize(self) -> Vec<u8> {
        self.context.finish().as_ref().to_vec()
    }

    /// One-shot hash computation
    pub fn hash(algorithm: HashAlgorithm, data: &[u8]) -> Vec<u8> {
        let mut hasher = Self::new(algorithm);
        hasher.update(data);
        hasher.finalize()
    }

    /// Verify a hash matches expected value (constant-time comparison)
    pub fn verify(algorithm: HashAlgorithm, data: &[u8], expected: &[u8]) -> TEEResult<bool> {
        let computed = Self::hash(algorithm, data);

        if computed.len() != expected.len() {
            return Ok(false);
        }

        // Constant-time comparison
        Ok(ring::constant_time::verify_slices_are_equal(&computed, expected).is_ok())
    }
}

/// Merkle tree implementation for secure data verification
pub struct MerkleTree {
    /// Root hash of the tree
    root: Vec<u8>,
    /// Leaf nodes (hashes)
    leaves: Vec<Vec<u8>>,
    /// Internal nodes for path verification
    nodes: Vec<Vec<Vec<u8>>>,
    /// Hash algorithm used
    algorithm: HashAlgorithm,
}

impl MerkleTree {
    /// Create a new Merkle tree from a list of data items
    pub fn new(data: &[Vec<u8>], algorithm: HashAlgorithm) -> TEEResult<Self> {
        if data.is_empty() {
            return Err(TEEError::CryptoError {
                reason: "Empty data".to_string(),
                details: "Cannot create Merkle tree from empty data".to_string(),
                source: None,
            });
        }

        // Create leaf nodes by hashing data
        let mut leaves: Vec<Vec<u8>> = data
            .iter()
            .map(|item| HashUtil::hash(algorithm, item))
            .collect();

        // Ensure power of 2 number of leaves by duplicating last leaf
        while !is_power_of_two(leaves.len()) {
            leaves.push(leaves.last().unwrap().clone());
        }

        // Build tree levels bottom-up
        let mut nodes = Vec::new();
        let mut current_level = leaves.clone();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let mut combined = Vec::new();
                combined.extend_from_slice(&chunk[0]);
                combined.extend_from_slice(chunk.get(1).unwrap_or(&chunk[0]));
                next_level.push(HashUtil::hash(algorithm, &combined));
            }
            nodes.push(current_level);
            current_level = next_level;
        }

        let root = current_level[0].clone();
        nodes.push(current_level);

        Ok(Self {
            root,
            leaves,
            nodes,
            algorithm,
        })
    }

    /// Get Merkle root hash
    pub fn root_hash(&self) -> &[u8] {
        &self.root
    }

    /// Generate proof for data at given index
    pub fn generate_proof(&self, index: usize) -> TEEResult<MerkleProof> {
        if index >= self.leaves.len() {
            return Err(TEEError::CryptoError {
                reason: "Invalid index".to_string(),
                details: "Index out of bounds for Merkle tree".to_string(),
                source: None,
            });
        }

        let mut proof = Vec::new();
        let mut current_index = index;

        for level in &self.nodes {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < level.len() {
                proof.push(level[sibling_index].clone());
            }

            current_index /= 2;
        }

        Ok(MerkleProof {
            proof,
            index,
            algorithm: self.algorithm,
        })
    }

    /// Clear sensitive data when dropped
    fn clear(&mut self) {
        self.root.zeroize();
        for leaf in &mut self.leaves {
            leaf.zeroize();
        }
        for level in &mut self.nodes {
            for node in level {
                node.zeroize();
            }
        }
    }
}

impl Drop for MerkleTree {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Merkle proof for verifying inclusion
pub struct MerkleProof {
    proof: Vec<Vec<u8>>,
    index: usize,
    algorithm: HashAlgorithm,
}

impl MerkleProof {
    /// Verify proof for given data
    pub fn verify(&self, data: &[u8], root: &[u8]) -> TEEResult<bool> {
        let mut hash = HashUtil::hash(self.algorithm, data);
        let mut current_index = self.index;

        for sibling in &self.proof {
            let mut combined = Vec::new();
            if current_index % 2 == 0 {
                combined.extend_from_slice(&hash);
                combined.extend_from_slice(sibling);
            } else {
                combined.extend_from_slice(sibling);
                combined.extend_from_slice(&hash);
            }
            hash = HashUtil::hash(self.algorithm, &combined);
            current_index /= 2;
        }

        Ok(ring::constant_time::verify_slices_are_equal(&hash, root).is_ok())
    }

    /// Clear sensitive data when dropped
    fn clear(&mut self) {
        for hash in &mut self.proof {
            hash.zeroize();
        }
    }
}

impl Drop for MerkleProof {
    fn drop(&mut self) {
        self.clear();
    }
}

// Helper function to check if number is power of 2
fn is_power_of_two(n: usize) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_operations() {
        let data = b"test data";
        let hash = HashUtil::hash(HashAlgorithm::SHA256, data);
        assert_eq!(hash.len(), 32);

        let expected = HashUtil::hash(HashAlgorithm::SHA256, data);
        assert!(HashUtil::verify(HashAlgorithm::SHA256, data, &expected).unwrap());
    }

    #[test]
    fn test_merkle_tree() -> TEEResult<()> {
        let data = vec![
            b"data1".to_vec(),
            b"data2".to_vec(),
            b"data3".to_vec(),
            b"data4".to_vec(),
        ];

        let tree = MerkleTree::new(&data, HashAlgorithm::SHA256)?;
        let proof = tree.generate_proof(1)?;

        assert!(proof.verify(&data[1], tree.root_hash())?);
        Ok(())
    }
}
