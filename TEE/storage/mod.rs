//! Secure Storage Module for TEE Framework

use crate::core::error::{TEEError, TEEResult};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Secure storage provider
pub trait SecureStorage {
    /// Store data securely
    fn store(&self, key: &str, data: &[u8]) -> TEEResult<()>;

    /// Retrieve data securely
    fn retrieve(&self, key: &str) -> TEEResult<Vec<u8>>;

    /// Delete data securely
    fn delete(&self, key: &str) -> TEEResult<()>;

    /// Check if data exists
    fn exists(&self, key: &str) -> TEEResult<bool>;
}

/// Storage protection level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageProtectionLevel {
    /// Hardware-backed storage
    Hardware,

    /// Software-backed storage
    Software,

    /// Memory-only storage (ephemeral)
    Memory,
}

/// File-based secure storage
pub struct FileSecureStorage {
    /// Root directory for storage
    root_dir: PathBuf,

    /// Encryption key
    encryption_key: Vec<u8>,

    /// Protection level
    protection_level: StorageProtectionLevel,
}

impl FileSecureStorage {
    /// Create a new file-based secure storage
    pub fn new<P: AsRef<Path>>(root_dir: P, encryption_key: Vec<u8>) -> TEEResult<Self> {
        let root_dir = root_dir.as_ref().to_path_buf();

        // Create directory if it doesn't exist
        if !root_dir.exists() {
            std::fs::create_dir_all(&root_dir).map_err(|e| TEEError::IOError(e))?;
        }

        // Determine protection level
        let protection_level = Self::detect_protection_level()?;

        Ok(Self {
            root_dir,
            encryption_key,
            protection_level,
        })
    }

    /// Detect storage protection level
    fn detect_protection_level() -> TEEResult<StorageProtectionLevel> {
        // Check for hardware-backed key storage
        #[cfg(feature = "sgx")]
        {
            // Check if SGX sealing is available
            if is_sgx_sealing_available() {
                return Ok(StorageProtectionLevel::Hardware);
            }
        }

        #[cfg(target_os = "android")]
        {
            // Check for Android Keystore
            if is_android_keystore_available() {
                return Ok(StorageProtectionLevel::Hardware);
            }
        }

        // Default to software protection
        Ok(StorageProtectionLevel::Software)
    }

    /// Get file path for a key
    fn get_file_path(&self, key: &str) -> PathBuf {
        // Hash the key to create a filename
        use ring::digest::{SHA256, digest};

        let key_hash = digest(&SHA256, key.as_bytes());
        let filename = hex::encode(key_hash.as_ref());

        self.root_dir.join(filename)
    }

    /// Encrypt data
    fn encrypt_data(&self, data: &[u8]) -> TEEResult<Vec<u8>> {
        use aes_gcm::{
            Aes256Gcm, Key, Nonce,
            aead::{Aead, NewAead},
        };
        use rand::RngCore;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Create cipher
        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key);
        let cipher = Aes256Gcm::new(key);

        // Encrypt data
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|_| TEEError::CryptoError {
                reason: "Encryption failed".to_string(),
                details: "Failed to encrypt data for secure storage".to_string(),
                source: None,
            })?;

        // Combine nonce and ciphertext
        let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data
    fn decrypt_data(&self, encrypted_data: &[u8]) -> TEEResult<Vec<u8>> {
        use aes_gcm::{
            Aes256Gcm, Key, Nonce,
            aead::{Aead, NewAead},
        };

        if encrypted_data.len() < 12 {
            return Err(TEEError::CryptoError {
                reason: "Invalid encrypted data".to_string(),
                details: "Encrypted data is too short".to_string(),
                source: None,
            });
        }

        // Split nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Create cipher
        let key = Key::<Aes256Gcm>::from_slice(&self.encryption_key);
        let cipher = Aes256Gcm::new(key);

        // Decrypt data
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| TEEError::CryptoError {
                reason: "Decryption failed".to_string(),
                details: "Failed to decrypt data from secure storage".to_string(),
                source: None,
            })?;

        Ok(plaintext)
    }
}

impl SecureStorage for FileSecureStorage {
    fn store(&self, key: &str, data: &[u8]) -> TEEResult<()> {
        let file_path = self.get_file_path(key);

        // Encrypt data
        let encrypted_data = self.encrypt_data(data)?;

        // Write to file
        std::fs::write(&file_path, encrypted_data).map_err(|e| TEEError::IOError(e))?;

        Ok(())
    }

    fn retrieve(&self, key: &str) -> TEEResult<Vec<u8>> {
        let file_path = self.get_file_path(key);

        // Check if file exists
        if !file_path.exists() {
            return Err(TEEError::Generic(format!("Key '{}' not found", key)));
        }

        // Read from file
        let encrypted_data = std::fs::read(&file_path).map_err(|e| TEEError::IOError(e))?;

        // Decrypt data
        let data = self.decrypt_data(&encrypted_data)?;

        Ok(data)
    }

    fn delete(&self, key: &str) -> TEEResult<()> {
        let file_path = self.get_file_path(key);

        // Check if file exists
        if !file_path.exists() {
            return Ok(());
        }

        // Delete file
        std::fs::remove_file(&file_path).map_err(|e| TEEError::IOError(e))?;

        Ok(())
    }

    fn exists(&self, key: &str) -> TEEResult<bool> {
        let file_path = self.get_file_path(key);

        Ok(file_path.exists())
    }
}

/// Memory-based secure storage (for ephemeral data)
pub struct MemorySecureStorage {
    /// Storage data
    data: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl MemorySecureStorage {
    /// Create a new memory-based secure storage
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl SecureStorage for MemorySecureStorage {
    fn store(&self, key: &str, data: &[u8]) -> TEEResult<()> {
        let mut storage = self
            .data
            .write()
            .map_err(|_| TEEError::Generic("Failed to acquire write lock".to_string()))?;

        storage.insert(key.to_string(), data.to_vec());

        Ok(())
    }

    fn retrieve(&self, key: &str) -> TEEResult<Vec<u8>> {
        let storage = self
            .data
            .read()
            .map_err(|_| TEEError::Generic("Failed to acquire read lock".to_string()))?;

        storage
            .get(key)
            .cloned()
            .ok_or_else(|| TEEError::Generic(format!("Key '{}' not found", key)))
    }

    fn delete(&self, key: &str) -> TEEResult<()> {
        let mut storage = self
            .data
            .write()
            .map_err(|_| TEEError::Generic("Failed to acquire write lock".to_string()))?;

        storage.remove(key);

        Ok(())
    }

    fn exists(&self, key: &str) -> TEEResult<bool> {
        let storage = self
            .data
            .read()
            .map_err(|_| TEEError::Generic("Failed to acquire read lock".to_string()))?;

        Ok(storage.contains_key(key))
    }
}

/// Hardware-backed secure storage (TEE-specific)
pub struct TEESecureStorage {
    /// TEE platform
    platform: String,

    /// Delegate to platform-specific implementation
    delegate: Box<dyn SecureStorage + Send + Sync>,
}

impl TEESecureStorage {
    /// Create a new TEE-specific secure storage
    pub fn new(platform: &str) -> TEEResult<Self> {
        // Create platform-specific storage
        let delegate: Box<dyn SecureStorage + Send + Sync> = match platform {
            "intel_sgx" => {
                #[cfg(feature = "sgx")]
                {
                    Box::new(SGXSecureStorage::new()?)
                }
                #[cfg(not(feature = "sgx"))]
                {
                    // Fallback to file-based storage
                    let key = Self::derive_encryption_key(platform)?;
                    Box::new(FileSecureStorage::new("./sgx_storage", key)?)
                }
            }
            "amd_sev" => {
                #[cfg(feature = "sev")]
                {
                    Box::new(SEVSecureStorage::new()?)
                }
                #[cfg(not(feature = "sev"))]
                {
                    // Fallback to file-based storage
                    let key = Self::derive_encryption_key(platform)?;
                    Box::new(FileSecureStorage::new("./sev_storage", key)?)
                }
            }
            "arm_trustzone" => {
                #[cfg(feature = "trustzone")]
                {
                    Box::new(TrustZoneSecureStorage::new()?)
                }
                #[cfg(not(feature = "trustzone"))]
                {
                    // Fallback to file-based storage
                    let key = Self::derive_encryption_key(platform)?;
                    Box::new(FileSecureStorage::new("./trustzone_storage", key)?)
                }
            }
            "aws_nitro" => {
                #[cfg(feature = "nitro")]
                {
                    Box::new(NitroSecureStorage::new()?)
                }
                #[cfg(not(feature = "nitro"))]
                {
                    // Fallback to file-based storage
                    let key = Self::derive_encryption_key(platform)?;
                    Box::new(FileSecureStorage::new("./nitro_storage", key)?)
                }
            }
            _ => {
                // Default to memory storage
                Box::new(MemorySecureStorage::new())
            }
        };

        Ok(Self {
            platform: platform.to_string(),
            delegate,
        })
    }

    /// Derive encryption key for the platform
    fn derive_encryption_key(platform: &str) -> TEEResult<Vec<u8>> {
        use ring::digest::{SHA256, digest};

        // In a real implementation, this would use platform-specific key derivation
        // For now, derive a key from the platform name
        let key = digest(&SHA256, platform.as_bytes());

        Ok(key.as_ref().to_vec())
    }
}

impl SecureStorage for TEESecureStorage {
    fn store(&self, key: &str, data: &[u8]) -> TEEResult<()> {
        self.delegate.store(key, data)
    }

    fn retrieve(&self, key: &str) -> TEEResult<Vec<u8>> {
        self.delegate.retrieve(key)
    }

    fn delete(&self, key: &str) -> TEEResult<()> {
        self.delegate.delete(key)
    }

    fn exists(&self, key: &str) -> TEEResult<bool> {
        self.delegate.exists(key)
    }
}

// Platform-specific storage implementations
#[cfg(feature = "sgx")]
mod sgx {
    use super::*;

    pub struct SGXSecureStorage;

    impl SGXSecureStorage {
        pub fn new() -> TEEResult<Self> {
            Ok(Self)
        }
    }

    impl SecureStorage for SGXSecureStorage {
        // Implementation using SGX sealing functions
        fn store(&self, key: &str, data: &[u8]) -> TEEResult<()> {
            // Use SGX sealing functionality
            unimplemented!()
        }

        fn retrieve(&self, key: &str) -> TEEResult<Vec<u8>> {
            // Use SGX unsealing functionality
            unimplemented!()
        }

        fn delete(&self, key: &str) -> TEEResult<()> {
            // Delete sealed data
            unimplemented!()
        }

        fn exists(&self, key: &str) -> TEEResult<bool> {
            // Check if sealed data exists
            unimplemented!()
        }
    }
}

// Storage factory for creating appropriate storage
pub struct SecureStorageFactory;

impl SecureStorageFactory {
    /// Create a secure storage provider
    pub fn create_storage(
        storage_type: StorageType,
    ) -> TEEResult<Box<dyn SecureStorage + Send + Sync>> {
        match storage_type {
            StorageType::Memory => Ok(Box::new(MemorySecureStorage::new())),
            StorageType::File(path, key) => Ok(Box::new(FileSecureStorage::new(path, key)?)),
            StorageType::TEE(platform) => Ok(Box::new(TEESecureStorage::new(&platform)?)),
        }
    }
}

/// Type of secure storage
pub enum StorageType {
    /// Memory-based storage (ephemeral)
    Memory,

    /// File-based storage
    File(PathBuf, Vec<u8>),

    /// TEE-specific storage
    TEE(String),
}
