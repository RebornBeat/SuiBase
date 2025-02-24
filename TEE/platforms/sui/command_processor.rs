//! Processor for blockchain commands

use crate::core::error::TEEResult;
use crate::platforms::SecureEnclave;
use crate::sui::blockchain_interface::SuiClient;
use crate::sui::move_execution::MoveExecutionEnvironment;
use async_std::sync::{Arc, Mutex};
use std::collections::VecDeque;

/// Processor for blockchain commands
#[derive(Clone)]
pub struct CommandProcessor {
    pub command_queue: Arc<Mutex<VecDeque<BlockchainCommand>>>,
}

/// Commands from the blockchain
#[derive(Clone, Debug)]
pub enum BlockchainCommand {
    ExecuteContract {
        contract_id: String,
        function: String,
        args: Vec<Vec<u8>>,
        callback_tx: String,
    },
    UpdateTEE {
        update_package: Vec<u8>,
        version: String,
    },
    Terminate,
}

impl CommandProcessor {
    /// Create a new command processor
    pub fn new() -> Self {
        Self {
            command_queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }

    /// Process next command
    pub async fn next_command(&self) -> Option<BlockchainCommand> {
        let mut queue = self.command_queue.lock().await;
        queue.pop_front()
    }

    /// Add command to queue
    pub async fn enqueue_command(&self, command: BlockchainCommand) -> TEEResult<()> {
        let mut queue = self.command_queue.lock().await;
        queue.push_back(command);
        Ok(())
    }

    /// Get number of pending commands
    pub async fn pending_commands(&self) -> usize {
        let queue = self.command_queue.lock().await;
        queue.len()
    }

    /// Clear command queue
    pub async fn clear_queue(&self) -> TEEResult<()> {
        let mut queue = self.command_queue.lock().await;
        queue.clear();
        Ok(())
    }

    /// Start processing commands
    pub async fn start_processing(
        &self,
        execution_env: MoveExecutionEnvironment,
        sui_client: SuiClient,
        enclave: Box<dyn SecureEnclave>,
    ) -> TEEResult<()> {
        let command_processor = self.clone();

        async_std::task::spawn(async move {
            while let Some(cmd) = command_processor.next_command().await {
                match cmd {
                    BlockchainCommand::ExecuteContract {
                        contract_id,
                        function,
                        args,
                        callback_tx,
                    } => {
                        // Load contract from blockchain
                        match sui_client.get_contract(&contract_id).await {
                            Ok(contract) => {
                                // Execute in TEE
                                match execution_env
                                    .execute_move_contract(
                                        enclave.clone(),
                                        &contract,
                                        &function,
                                        args,
                                    )
                                    .await
                                {
                                    Ok((result, proof)) => {
                                        // Submit result back to blockchain
                                        if let Err(e) = sui_client
                                            .submit_result(&callback_tx, &result, &proof)
                                            .await
                                        {
                                            eprintln!("Failed to submit result: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to execute contract: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to load contract: {}", e);
                            }
                        }
                    }
                    BlockchainCommand::UpdateTEE {
                        update_package,
                        version,
                    } => {
                        // Verify update signature
                        if verify_update_package(&update_package, &version) {
                            // Apply update if valid
                            if let Err(e) = apply_update(&update_package, &version) {
                                eprintln!("Failed to apply update: {}", e);
                            }
                        } else {
                            eprintln!("Update package verification failed");
                        }
                    }
                    BlockchainCommand::Terminate => {
                        break;
                    }
                }
            }
        });

        Ok(())
    }
}

/// Verify update package signature
fn verify_update_package(update_package: &[u8], version: &str) -> bool {
    // Package format:
    // [0..64] - Signature of package data
    // [64..96] - Public key (32 bytes)
    // [96..100] - Header size (4 bytes, u32)
    // [100..100+header_size] - Package header (JSON)
    // [remainder] - Package data

    use crate::core::crypto::SignatureUtil;
    use serde_json::Value;

    // Ensure package has minimum size
    if update_package.len() < 100 {
        log::error!("Update package too small");
        return false;
    }

    // Extract components
    let signature = &update_package[0..64];
    let public_key = &update_package[64..96];

    // Extract header size
    let header_size = u32::from_le_bytes([
        update_package[96],
        update_package[97],
        update_package[98],
        update_package[99],
    ]) as usize;

    // Validate header size
    if 100 + header_size > update_package.len() {
        log::error!("Invalid header size in update package");
        return false;
    }

    // Extract and parse header
    let header_bytes = &update_package[100..100 + header_size];
    let header_str = match std::str::from_utf8(header_bytes) {
        Ok(s) => s,
        Err(_) => {
            log::error!("Invalid header encoding in update package");
            return false;
        }
    };

    let header: Value = match serde_json::from_str(header_str) {
        Ok(v) => v,
        Err(e) => {
            log::error!("Invalid header JSON: {}", e);
            return false;
        }
    };

    // Verify package version matches
    if let Some(pkg_version) = header["version"].as_str() {
        if pkg_version != version {
            log::error!(
                "Version mismatch: expected {}, got {}",
                version,
                pkg_version
            );
            return false;
        }
    } else {
        log::error!("Missing version in update package header");
        return false;
    }

    // Verify package is for this platform
    if let Some(platform) = header["platform"].as_str() {
        if !is_compatible_platform(platform) {
            log::error!("Incompatible platform: {}", platform);
            return false;
        }
    } else {
        log::error!("Missing platform in update package header");
        return false;
    }

    // Calculate hash of data to verify
    let data_to_verify = &update_package[96..]; // Header size + header + data

    // Verify signature
    match SignatureUtil::verify(public_key, data_to_verify, signature) {
        Ok(valid) => {
            if !valid {
                log::error!("Signature verification failed");
            }
            valid
        }
        Err(e) => {
            log::error!("Signature verification error: {}", e);
            false
        }
    }
}

/// Check if update package is compatible with this platform
fn is_compatible_platform(platform: &str) -> bool {
    // Get current platform
    let current_platform =
        std::env::var("SUISTACK_PLATFORM").unwrap_or_else(|_| "unknown".to_string());

    // Check compatibility
    if platform == current_platform {
        return true;
    }

    // Check for platform families
    // e.g., if current is "intel_sgx_linux" and target is "intel_sgx"
    current_platform.starts_with(platform)
}

/// Apply update package
fn apply_update(update_package: &[u8], version: &str) -> TEEResult<()> {
    use crate::core::error::TEEError;
    use serde_json::Value;
    use std::fs::{self, File};
    use std::io::{Read, Write};
    use std::path::Path;

    // Extract package header
    if update_package.len() < 100 {
        return Err(TEEError::Generic(
            "Invalid update package: too small".to_string(),
        ));
    }

    // Get header size
    let header_size = u32::from_le_bytes([
        update_package[96],
        update_package[97],
        update_package[98],
        update_package[99],
    ]) as usize;

    // Validate header size
    if 100 + header_size > update_package.len() {
        return Err(TEEError::Generic(
            "Invalid header size in update package".to_string(),
        ));
    }

    // Extract and parse header
    let header_bytes = &update_package[100..100 + header_size];
    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|_| TEEError::Generic("Invalid header encoding".to_string()))?;

    let header: Value = serde_json::from_str(header_str)
        .map_err(|e| TEEError::Generic(format!("Invalid header JSON: {}", e)))?;

    // Verify version match
    let pkg_version = header["version"]
        .as_str()
        .ok_or_else(|| TEEError::Generic("Missing version in header".to_string()))?;

    if pkg_version != version {
        return Err(TEEError::Generic(format!(
            "Version mismatch: expected {}, got {}",
            version, pkg_version
        )));
    }

    // Get package data
    let data_offset = 100 + header_size;
    let package_data = &update_package[data_offset..];

    // Create update directory
    let update_dir = Path::new("/tmp/suistack_update");
    if update_dir.exists() {
        fs::remove_dir_all(update_dir)
            .map_err(|e| TEEError::Generic(format!("Failed to clean update directory: {}", e)))?;
    }

    fs::create_dir_all(update_dir)
        .map_err(|e| TEEError::Generic(format!("Failed to create update directory: {}", e)))?;

    // Decompress package
    let mut decoder = flate2::read::GzDecoder::new(package_data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| TEEError::Generic(format!("Failed to decompress update package: {}", e)))?;

    // Extract tar archive
    let archive_path = update_dir.join("archive.tar");
    let mut file = File::create(&archive_path)
        .map_err(|e| TEEError::Generic(format!("Failed to create archive file: {}", e)))?;

    file.write_all(&decompressed)
        .map_err(|e| TEEError::Generic(format!("Failed to write archive file: {}", e)))?;

    // Extract archive
    let status = std::process::Command::new("tar")
        .args(&[
            "-xf",
            archive_path.to_str().unwrap(),
            "-C",
            update_dir.to_str().unwrap(),
        ])
        .status()
        .map_err(|e| TEEError::Generic(format!("Failed to extract archive: {}", e)))?;

    if !status.success() {
        return Err(TEEError::Generic(
            "Failed to extract update archive".to_string(),
        ));
    }

    // Run update script if it exists
    let update_script = update_dir.join("update.sh");
    if update_script.exists() {
        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&update_script)
                .map_err(|e| TEEError::Generic(format!("Failed to get script permissions: {}", e)))?
                .permissions();

            perms.set_mode(0o755);
            fs::set_permissions(&update_script, perms).map_err(|e| {
                TEEError::Generic(format!("Failed to set script permissions: {}", e))
            })?;
        }

        // Run script
        let status = std::process::Command::new(&update_script)
            .current_dir(update_dir)
            .status()
            .map_err(|e| TEEError::Generic(format!("Failed to run update script: {}", e)))?;

        if !status.success() {
            return Err(TEEError::Generic("Update script failed".to_string()));
        }
    } else {
        // Default update procedure if no script exists
        apply_default_update(update_dir, &header)
            .map_err(|e| TEEError::Generic(format!("Default update procedure failed: {}", e)))?;
    }

    // Record new version
    record_version(version)
        .map_err(|e| TEEError::Generic(format!("Failed to record version: {}", e)))?;

    Ok(())
}

/// Apply default update if no script provided
fn apply_default_update(update_dir: &Path, header: &serde_json::Value) -> std::io::Result<()> {
    use std::fs;
    use std::path::Path;

    // Get install directory from environment or use default
    let install_dir =
        std::env::var("SUISTACK_INSTALL_DIR").unwrap_or_else(|_| "/opt/suistack".to_string());

    let install_path = Path::new(&install_dir);

    // Create backup
    let backup_dir = Path::new("/tmp/suistack_backup");
    if backup_dir.exists() {
        fs::remove_dir_all(backup_dir)?;
    }

    fs::create_dir_all(backup_dir)?;

    // Copy current installation to backup
    copy_dir_all(install_path, backup_dir)?;

    // Copy update files to installation directory
    let files_dir = update_dir.join("files");
    if files_dir.exists() {
        copy_dir_all(&files_dir, install_path)?;
    }

    Ok(())
}

/// Record new version after update
fn record_version(version: &str) -> std::io::Result<()> {
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    // Get install directory from environment or use default
    let install_dir =
        std::env::var("SUISTACK_INSTALL_DIR").unwrap_or_else(|_| "/opt/suistack".to_string());

    let version_file = Path::new(&install_dir).join("VERSION");

    // Write version to file
    let mut file = File::create(version_file)?;
    file.write_all(version.as_bytes())?;

    Ok(())
}

/// Recursively copy a directory
fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    use std::fs;

    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if ty.is_dir() {
            copy_dir_all(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

/// Create backup before update
fn create_backup() -> std::io::Result<()> {
    // Create a backup of critical components
    // This is a simplified implementation
    Ok(())
}

/// Restore from backup on failure
fn restore_from_backup() -> std::io::Result<()> {
    // Restore from backup
    // This is a simplified implementation
    Ok(())
}

/// Parse update components
fn parse_update_components(data: &[u8]) -> Vec<UpdateComponent> {
    // Parse components from update package
    // This is a simplified implementation
    vec![UpdateComponent {
        name: "core".to_string(),
        data: data.to_vec(),
    }]
}

/// Apply single component update
fn apply_component_update(component: &UpdateComponent) -> std::io::Result<()> {
    // Apply a component update
    // This is a simplified implementation
    println!("Updating component: {}", component.name);
    Ok(())
}

/// Update component structure
struct UpdateComponent {
    name: String,
    data: Vec<u8>,
}
