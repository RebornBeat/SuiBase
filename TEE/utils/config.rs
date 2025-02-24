use crate::core::error::{TEEError, TEEResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Global Configuration Manager
pub struct ConfigurationManager;

impl ConfigurationManager {
    /// Load validator configuration
    pub fn load_validator_config() -> TEEResult<TEEValidatorConfig> {
        // Try environment variable first
        let config_path = std::env::var("TEE_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/etc/suistack0x/config.toml"));

        // Load and validate configuration
        let config = Self::load_from_file(&config_path)?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> TEEResult<TEEValidatorConfig> {
        let contents = fs::read_to_string(path).map_err(|e| {
            TEEError::ConfigurationError(format!("Failed to read config file: {}", e))
        })?;

        let config: TEEValidatorConfig = toml::from_str(&contents)
            .map_err(|e| TEEError::ConfigurationError(format!("Failed to parse config: {}", e)))?;

        Ok(config)
    }

    /// Save enclave configuration
    pub fn save_enclave_config<P: AsRef<Path>>(path: P, enclave_id: String) -> TEEResult<()> {
        let config = EnclaveConfig {
            id: enclave_id,
            created_at: chrono::Utc::now(),
        };

        let contents = serde_json::to_string_pretty(&config).map_err(|e| {
            TEEError::ConfigurationError(format!("Failed to serialize config: {}", e))
        })?;

        fs::write(path, contents)
            .map_err(|e| TEEError::ConfigurationError(format!("Failed to write config: {}", e)))?;

        Ok(())
    }

    /// Load enclave configuration
    pub fn load_enclave_config<P: AsRef<Path>>(path: P) -> TEEResult<String> {
        let contents = fs::read_to_string(path)
            .map_err(|e| TEEError::ConfigurationError(format!("Failed to read config: {}", e)))?;

        let config: EnclaveConfig = serde_json::from_str(&contents)
            .map_err(|e| TEEError::ConfigurationError(format!("Failed to parse config: {}", e)))?;

        Ok(config.id)
    }
}

/// Complete Validator Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEEValidatorConfig {
    /// Platform configuration
    pub platform: PlatformConfig,
    /// Network configuration
    pub network: NetworkConfig,
    /// Security configuration
    pub security: SecurityConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Monitoring configuration
    pub monitoring: MonitoringConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
}

/// Platform-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformConfig {
    /// Platform type (intel_sgx, amd_sev, etc)
    pub platform_type: String,
    /// Memory allocation in MB
    pub memory_size: usize,
    /// Number of CPU cores
    pub cpu_cores: usize,
    /// Maximum concurrent tasks
    pub max_concurrent_tasks: u32,
    /// Platform-specific settings
    pub settings: HashMap<String, String>,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Sui node endpoint
    pub sui_endpoint: String,
    /// Validator address
    pub validator_address: String,
    /// Network name (mainnet, testnet, devnet)
    pub network_name: String,
    /// Network timeout in seconds
    pub timeout_secs: u64,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Connection backoff settings
    pub backoff: BackoffConfig,
    /// Gas settings
    pub gas_budget: u64,
    /// Gas price
    pub gas_price: u64,
    /// Authentication token
    pub auth_token: String,
    /// Geographic region
    pub region: String,
    /// Minimum fee
    pub min_fee: u64,
    /// Compute endpoint
    pub compute_endpoint: String,
    /// Edge endpoint
    pub edge_endpoint: String,
    /// Index endpoint
    pub index_endpoint: String,
    /// Metrics endpoint
    pub metrics_endpoint: String,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Minimum attestation validity period in seconds
    pub min_attestation_validity: u64,
    /// Maximum attestation validity period in seconds
    pub max_attestation_validity: u64,
    /// Required security level
    pub required_security_level: SecurityLevel,
    /// Required TEE features
    pub required_features: Vec<String>,
    /// Cryptographic settings
    pub crypto: CryptoConfig,
    /// Access control settings
    pub access_control: AccessControlConfig,
    /// Rate limiting settings
    pub rate_limiting: RateLimitConfig,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Base storage directory
    pub storage_dir: PathBuf,
    /// Maximum storage size in bytes
    pub max_size: u64,
    /// Secure storage configuration
    pub secure_storage: SecureStorageConfig,
    /// Cache configuration
    pub cache: CacheConfig,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Health check interval in seconds
    pub health_check_interval: u64,
    /// Metrics collection interval in seconds
    pub metrics_interval: u64,
    /// Resource usage thresholds
    pub thresholds: ThresholdConfig,
    /// Alert configuration
    pub alerts: AlertConfig,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: LogLevel,
    /// Log file path
    pub log_file: Option<PathBuf>,
    /// Maximum log file size in bytes
    pub max_size: u64,
    /// Number of log files to retain
    pub max_files: u32,
    /// Log format
    pub format: LogFormat,
}

/// Backoff configuration for retries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackoffConfig {
    /// Initial delay in milliseconds
    pub initial_delay_ms: u64,
    /// Maximum delay in milliseconds
    pub max_delay_ms: u64,
    /// Backoff multiplier
    pub multiplier: f64,
    /// Maximum retry attempts
    pub max_attempts: u32,
}

/// Cryptographic configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Minimum key size in bits
    pub min_key_size: usize,
    /// Allowed signature algorithms
    pub signature_algorithms: Vec<String>,
    /// Allowed encryption algorithms
    pub encryption_algorithms: Vec<String>,
    /// Key rotation interval in seconds
    pub key_rotation_interval: u64,
}

/// Access control configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlConfig {
    /// Maximum failed authentication attempts
    pub max_auth_attempts: u32,
    /// Authentication lockout duration in seconds
    pub lockout_duration: u64,
    /// Session timeout in seconds
    pub session_timeout: u64,
    /// Required authentication methods
    pub required_auth_methods: Vec<String>,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests per second
    pub max_requests_per_second: u32,
    /// Maximum concurrent connections
    pub max_concurrent_connections: u32,
    /// Rate limit window in seconds
    pub window_seconds: u64,
}

/// Secure storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureStorageConfig {
    /// Storage encryption algorithm
    pub encryption_algorithm: String,
    /// Key derivation parameters
    pub key_derivation: KeyDerivationConfig,
    /// Storage rotation interval in seconds
    pub rotation_interval: u64,
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Maximum cache size in bytes
    pub max_size: u64,
    /// Cache entry TTL in seconds
    pub ttl_seconds: u64,
    /// Cache cleanup interval in seconds
    pub cleanup_interval: u64,
}

/// Threshold configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    /// CPU usage threshold percentage
    pub cpu_threshold: f64,
    /// Memory usage threshold percentage
    pub memory_threshold: f64,
    /// Storage usage threshold percentage
    pub storage_threshold: f64,
    /// Error rate threshold
    pub error_rate_threshold: f64,
}

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Alert destinations
    pub destinations: Vec<String>,
    /// Minimum alert severity
    pub min_severity: AlertSeverity,
    /// Alert throttling interval in seconds
    pub throttle_interval: u64,
}

/// Key derivation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationConfig {
    /// Key derivation algorithm
    pub algorithm: String,
    /// Number of iterations
    pub iterations: u32,
    /// Memory size in KB
    pub memory_size: u32,
}

/// Security levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityLevel {
    High,
    Medium,
    Low,
}

/// Log levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// Log formats
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Enclave configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveConfig {
    /// Enclave ID
    pub id: String,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Default for TEEValidatorConfig {
    fn default() -> Self {
        Self {
            platform: PlatformConfig {
                platform_type: String::new(),
                memory_size: 8192, // 8GB
                cpu_cores: 4,
                max_concurrent_tasks: 100,
                settings: HashMap::new(),
            },
            network: NetworkConfig {
                sui_endpoint: "https://mainnet.sui.io".to_string(),
                validator_address: String::new(),
                network_name: "mainnet".to_string(),
                timeout_secs: 30,
                max_retries: 3,
                backoff: BackoffConfig {
                    initial_delay_ms: 100,
                    max_delay_ms: 60000,
                    multiplier: 2.0,
                    max_attempts: 5,
                },
                gas_budget: 50000,
                gas_price: 1000,
                auth_token: String::new(),
                region: "us-east-1".to_string(),
                min_fee: 1000,
                compute_endpoint: "http://localhost:8080".to_string(),
                edge_endpoint: "http://localhost:8081".to_string(),
                index_endpoint: "http://localhost:8082".to_string(),
                metrics_endpoint: "http://localhost:9090".to_string(),
            },
            security: SecurityConfig {
                min_attestation_validity: 3600,  // 1 hour
                max_attestation_validity: 86400, // 24 hours
                required_security_level: SecurityLevel::High,
                required_features: vec![
                    "remote-attestation".to_string(),
                    "secure-storage".to_string(),
                ],
                crypto: CryptoConfig {
                    min_key_size: 2048,
                    signature_algorithms: vec!["Ed25519".to_string(), "ECDSA-P256".to_string()],
                    encryption_algorithms: vec![
                        "AES-256-GCM".to_string(),
                        "ChaCha20-Poly1305".to_string(),
                    ],
                    key_rotation_interval: 86400, // 24 hours
                },
                access_control: AccessControlConfig {
                    max_auth_attempts: 5,
                    lockout_duration: 300, // 5 minutes
                    session_timeout: 3600, // 1 hour
                    required_auth_methods: vec!["token".to_string()],
                },
                rate_limiting: RateLimitConfig {
                    max_requests_per_second: 1000,
                    max_concurrent_connections: 100,
                    window_seconds: 60,
                },
            },
            storage: StorageConfig {
                storage_dir: PathBuf::from("/var/lib/suistack0x"),
                max_size: 100 * 1024 * 1024 * 1024, // 100GB
                secure_storage: SecureStorageConfig {
                    encryption_algorithm: "AES-256-GCM".to_string(),
                    key_derivation: KeyDerivationConfig {
                        algorithm: "PBKDF2-SHA256".to_string(),
                        iterations: 100000,
                        memory_size: 64 * 1024, // 64MB
                    },
                    rotation_interval: 86400, // 24 hours
                },
                cache: CacheConfig {
                    max_size: 1024 * 1024 * 1024, // 1GB
                    ttl_seconds: 3600,            // 1 hour
                    cleanup_interval: 300,        // 5 minutes
                },
            },
            monitoring: MonitoringConfig {
                health_check_interval: 30,
                metrics_interval: 60,
                thresholds: ThresholdConfig {
                    cpu_threshold: 80.0,
                    memory_threshold: 80.0,
                    storage_threshold: 80.0,
                    error_rate_threshold: 1.0, // 1% error rate
                },
                alerts: AlertConfig {
                    destinations: vec![],
                    min_severity: AlertSeverity::High,
                    throttle_interval: 300, // 5 minutes
                },
            },
            logging: LoggingConfig {
                level: LogLevel::Info,
                log_file: Some(PathBuf::from("/var/log/suistack0x/validator.log")),
                max_size: 100 * 1024 * 1024, // 100MB
                max_files: 5,
                format: LogFormat::Json,
            },
        }
    }
}

impl TEEValidatorConfig {
    /// Validate configuration
    pub fn validate(&self) -> TEEResult<()> {
        // Platform validation
        if self.platform.memory_size < 1024 {
            return Err(TEEError::ConfigurationError(
                "Memory size must be at least 1024MB".to_string(),
            ));
        }

        if self.platform.cpu_cores == 0 {
            return Err(TEEError::ConfigurationError(
                "Must specify at least 1 CPU core".to_string(),
            ));
        }

        // Network validation
        if self.network.timeout_secs == 0 {
            return Err(TEEError::ConfigurationError(
                "Network timeout cannot be zero".to_string(),
            ));
        }

        if self.network.validator_address.is_empty() {
            return Err(TEEError::ConfigurationError(
                "Validator address must be specified".to_string(),
            ));
        }

        if !is_valid_url(&self.network.sui_endpoint) {
            return Err(TEEError::ConfigurationError(
                "Invalid Sui endpoint URL".to_string(),
            ));
        }

        // Security validation
        if self.security.min_attestation_validity >= self.security.max_attestation_validity {
            return Err(TEEError::ConfigurationError(
                "Min attestation validity must be less than max".to_string(),
            ));
        }

        if self.security.crypto.min_key_size < 2048 {
            return Err(TEEError::ConfigurationError(
                "Minimum key size must be at least 2048 bits".to_string(),
            ));
        }

        if self.security.crypto.signature_algorithms.is_empty() {
            return Err(TEEError::ConfigurationError(
                "At least one signature algorithm must be specified".to_string(),
            ));
        }

        // Storage validation
        if !self.storage.storage_dir.exists() {
            return Err(TEEError::ConfigurationError(format!(
                "Storage directory does not exist: {}",
                self.storage.storage_dir.display()
            )));
        }

        if !self.storage.storage_dir.is_absolute() {
            return Err(TEEError::ConfigurationError(
                "Storage directory must be an absolute path".to_string(),
            ));
        }

        if self.storage.max_size < 1024 * 1024 * 1024 {
            // 1GB
            return Err(TEEError::ConfigurationError(
                "Storage size must be at least 1GB".to_string(),
            ));
        }

        // Monitoring validation
        if self.monitoring.health_check_interval == 0 {
            return Err(TEEError::ConfigurationError(
                "Health check interval cannot be zero".to_string(),
            ));
        }

        if self.monitoring.thresholds.cpu_threshold > 100.0
            || self.monitoring.thresholds.memory_threshold > 100.0
            || self.monitoring.thresholds.storage_threshold > 100.0
        {
            return Err(TEEError::ConfigurationError(
                "Threshold percentages cannot exceed 100%".to_string(),
            ));
        }

        // Logging validation
        if let Some(log_file) = &self.logging.log_file {
            if !log_file.parent().map_or(false, |p| p.exists()) {
                return Err(TEEError::ConfigurationError(format!(
                    "Log directory does not exist: {}",
                    log_file.parent().unwrap().display()
                )));
            }
        }

        Ok(())
    }

    /// Check if version is compatible
    pub fn is_version_compatible(&self, version: &str) -> bool {
        // Parse versions
        let current_version = parse_version(env!("CARGO_PKG_VERSION"));
        let target_version = parse_version(version);

        match (current_version, target_version) {
            (Ok(current), Ok(target)) => {
                // Major version must match
                if current.0 != target.0 {
                    return false;
                }

                // Target minor version must not be greater
                if target.1 > current.1 {
                    return false;
                }

                // If minor versions match, target patch must not be greater
                if target.1 == current.1 && target.2 > current.2 {
                    return false;
                }

                true
            }
            _ => false,
        }
    }

    /// Create production configuration
    pub fn production() -> Self {
        let mut config = Self::default();

        // Increase security settings for production
        config.security.required_security_level = SecurityLevel::High;
        config.security.crypto.min_key_size = 4096;
        config.security.crypto.key_rotation_interval = 43200; // 12 hours
        config.security.access_control.max_auth_attempts = 3;
        config.security.access_control.session_timeout = 1800; // 30 minutes
        config.security.rate_limiting.max_requests_per_second = 500;

        // Stricter monitoring
        config.monitoring.health_check_interval = 15; // 15 seconds
        config.monitoring.metrics_interval = 30; // 30 seconds
        config.monitoring.thresholds.cpu_threshold = 70.0;
        config.monitoring.thresholds.memory_threshold = 70.0;
        config.monitoring.thresholds.error_rate_threshold = 0.1; // 0.1%

        // Production logging
        config.logging.level = LogLevel::Info;
        config.logging.format = LogFormat::Json;
        config.logging.max_files = 10;

        config
    }

    /// Get network timeout duration
    pub fn network_timeout(&self) -> Duration {
        Duration::from_secs(self.network.timeout_secs)
    }

    /// Get network backoff config
    pub fn backoff_config(&self) -> &BackoffConfig {
        &self.network.backoff
    }

    /// Get required features
    pub fn required_features(&self) -> &[String] {
        &self.security.required_features
    }

    /// Get storage limits
    pub fn storage_limits(&self) -> (u64, u64) {
        (self.storage.max_size, self.storage.cache.max_size)
    }

    /// Get monitoring thresholds
    pub fn monitoring_thresholds(&self) -> &ThresholdConfig {
        &self.monitoring.thresholds
    }
}

/// Parse version string into (major, minor, patch)
fn parse_version(version: &str) -> Result<(u32, u32, u32), String> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid version format".to_string());
    }

    let major = parts[0].parse().map_err(|_| "Invalid major version")?;
    let minor = parts[1].parse().map_err(|_| "Invalid minor version")?;
    let patch = parts[2].parse().map_err(|_| "Invalid patch version")?;

    Ok((major, minor, patch))
}

/// Validate URL format
fn is_valid_url(url: &str) -> bool {
    url::Url::parse(url).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = TEEValidatorConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_config() {
        let mut config = TEEValidatorConfig::default();
        config.platform.memory_size = 512; // Too small
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_version_compatibility() {
        let config = TEEValidatorConfig::default();
        assert!(config.is_version_compatible(env!("CARGO_PKG_VERSION")));
        assert!(config.is_version_compatible("1.0.0")); // Assuming current is >= 1.0.0
        assert!(!config.is_version_compatible("2.0.0")); // Major version mismatch
    }

    #[test]
    fn test_production_config() {
        let config = TEEValidatorConfig::production();
        assert_eq!(config.security.required_security_level, SecurityLevel::High);
        assert_eq!(config.security.crypto.min_key_size, 4096);
        assert!(config.validate().is_ok());
    }
}
