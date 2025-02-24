//! TEE Platform-specific implementations

pub mod amd_sev;
pub mod arm_trustzone;
pub mod aws_nitro;
pub mod intel_sgx;

// Trait for common TEE platform functionality
pub trait TEEPlatform {
    /// Initialize the TEE platform
    fn initialize(&mut self) -> crate::core::error::TEEResult<()>;

    /// Create a secure enclave
    fn create_enclave(&mut self) -> crate::core::error::TEEResult<Box<dyn SecureEnclave>>;

    /// Perform remote attestation
    fn remote_attestation(&self) -> crate::core::error::TEEResult<AttestationReport>;

    // Security assessment
    fn get_security_level(&self) -> SecurityLevel;
    fn get_privacy_level(&self) -> PrivacyLevel;
    fn get_open_source_status(&self) -> OpenSourceStatus;
}

/// Trait for secure enclave operations
pub trait SecureEnclave: Send + Sync {
    /// Execute a computation within the secure environment
    fn execute<F, R>(&self, computation: F) -> crate::core::error::TEEResult<R>
    where
        F: FnOnce() -> R + Send;

    /// Get enclave measurement
    fn get_measurement(&self) -> Vec<u8>;

    /// Get enclave unique identifier
    fn get_id(&self) -> String;

    /// Get enclave state
    fn get_state(&self) -> EnclaveState;

    /// Pause enclave
    fn pause(&self) -> crate::core::error::TEEResult<()>;

    /// Resume enclave
    fn resume(&self) -> crate::core::error::TEEResult<()>;

    /// Terminate enclave
    fn terminate(&self) -> crate::core::error::TEEResult<()>;
}

/// Additional trait for blockchain-aware TEE platforms
pub trait BlockchainAwareTEE: TEEPlatform {
    /// Get platform attestation for blockchain registration
    fn get_blockchain_attestation(&self) -> crate::core::error::TEEResult<Vec<u8>>;

    /// Process blockchain command
    fn process_blockchain_command(
        &self,
        command: &str,
        args: &[Vec<u8>],
    ) -> crate::core::error::TEEResult<Vec<u8>>;

    /// Verify the integrity of a blockchain transaction
    fn verify_transaction_integrity(
        &self,
        transaction: &[u8],
    ) -> crate::core::error::TEEResult<bool>;

    /// Execute Move bytecode within platform-specific enclave
    fn execute_move_bytecode(
        &self,
        bytecode: &[u8],
        function: &str,
        args: &[Vec<u8>],
    ) -> crate::core::error::TEEResult<Vec<u8>>;

    /// Generate minimal computation proof
    fn generate_computation_proof(
        &self,
        bytecode: &[u8],
        function: &str,
        args: &[Vec<u8>],
        result: &[u8],
    ) -> crate::core::error::TEEResult<Vec<u8>>;

    /// Verify computation proof
    fn verify_computation_proof(
        &self,
        proof: &[u8],
        bytecode: &[u8],
        function: &str,
        args: &[Vec<u8>],
        result: &[u8],
    ) -> crate::core::error::TEEResult<bool>;
}

/// Implement default blockchain-aware behavior for all TEE platforms
impl<T: TEEPlatform + ?Sized> BlockchainAwareTEE for T {
    fn get_blockchain_attestation(&self) -> crate::core::error::TEEResult<Vec<u8>> {
        use crate::core::crypto::CryptoKeyPair;
        use crate::core::crypto::{EncryptionUtil, SignatureUtil};

        // Get standard remote attestation
        let attestation = self.remote_attestation()?;

        // Generate key pair for signing
        let keypair = SignatureUtil::generate_keypair()?;

        // Create attestation bundle
        let mut attestation_bundle = Vec::new();

        // Add platform identifier
        attestation_bundle.extend_from_slice(attestation.platform.as_bytes());
        attestation_bundle.push(0); // Null terminator

        // Add report data
        let report_len = attestation.report_data.len() as u32;
        attestation_bundle.extend_from_slice(&report_len.to_le_bytes());
        attestation_bundle.extend_from_slice(&attestation.report_data);

        // Add timestamp
        attestation_bundle.extend_from_slice(&attestation.timestamp.to_le_bytes());

        // Add public key
        attestation_bundle.extend_from_slice(&keypair.public_key);

        // Sign the bundle
        let signature = SignatureUtil::sign(&keypair, &attestation_bundle)?;

        // Add signature to the end
        attestation_bundle.extend_from_slice(&signature);

        Ok(attestation_bundle)
    }

    fn process_blockchain_command(
        &self,
        command: &str,
        args: &[Vec<u8>],
    ) -> crate::core::error::TEEResult<Vec<u8>> {
        use crate::core::error::TEEError;

        match command {
            "attest" => self.get_blockchain_attestation(),
            "execute" => {
                if args.len() < 3 {
                    return Err(TEEError::PlatformError {
                        platform: "unknown".to_string(),
                        reason: "Invalid arguments".to_string(),
                        details: "Execute command requires bytecode, function name, and arguments"
                            .to_string(),
                        source: None,
                    });
                }

                let bytecode = &args[0];
                let function =
                    std::str::from_utf8(&args[1]).map_err(|e| TEEError::PlatformError {
                        platform: "unknown".to_string(),
                        reason: "Invalid function name".to_string(),
                        details: e.to_string(),
                        source: None,
                    })?;

                let execution_args = &args[2..];
                self.execute_move_bytecode(bytecode, function, execution_args)
            }
            "verify" => {
                if args.len() < 5 {
                    return Err(TEEError::PlatformError {
                        platform: "unknown".to_string(),
                        reason: "Invalid arguments".to_string(),
                        details: "Verify command requires proof, bytecode, function name, arguments, and result".to_string(),
                        source: None,
                    });
                }

                let proof = &args[0];
                let bytecode = &args[1];
                let function =
                    std::str::from_utf8(&args[2]).map_err(|e| TEEError::PlatformError {
                        platform: "unknown".to_string(),
                        reason: "Invalid function name".to_string(),
                        details: e.to_string(),
                        source: None,
                    })?;
                let execution_args = &args[3..args.len() - 1];
                let result = &args[args.len() - 1];

                let verification_result = self.verify_computation_proof(
                    proof,
                    bytecode,
                    function,
                    execution_args,
                    result,
                )?;

                Ok(vec![verification_result as u8])
            }
            _ => Err(TEEError::PlatformError {
                platform: "unknown".to_string(),
                reason: "Unsupported command".to_string(),
                details: format!("Command '{}' not supported", command),
                source: None,
            }),
        }
    }

    fn verify_transaction_integrity(
        &self,
        transaction: &[u8],
    ) -> crate::core::error::TEEResult<bool> {
        use crate::core::crypto::SignatureUtil;
        use crate::core::error::TEEError;
        use sha2::{Digest, Sha256};

        // Ensure transaction has minimum required length
        if transaction.len() < 100 {
            // Minimum size for header, data, and signature
            return Err(TEEError::CryptoError {
                reason: "Invalid transaction format".to_string(),
                details: "Transaction too small to contain required fields".to_string(),
                source: None,
            });
        }

        // Parse transaction format:
        // [4 bytes] header size
        // [header_size bytes] header (JSON)
        // [8 bytes] payload size
        // [payload_size bytes] payload
        // [remainder] signature

        let header_size = u32::from_le_bytes([
            transaction[0],
            transaction[1],
            transaction[2],
            transaction[3],
        ]) as usize;

        if 4 + header_size + 8 >= transaction.len() {
            return Err(TEEError::CryptoError {
                reason: "Invalid transaction format".to_string(),
                details: "Transaction header or payload size exceeds transaction length"
                    .to_string(),
                source: None,
            });
        }

        let header = &transaction[4..4 + header_size];

        let payload_size_offset = 4 + header_size;
        let payload_size = u64::from_le_bytes([
            transaction[payload_size_offset],
            transaction[payload_size_offset + 1],
            transaction[payload_size_offset + 2],
            transaction[payload_size_offset + 3],
            transaction[payload_size_offset + 4],
            transaction[payload_size_offset + 5],
            transaction[payload_size_offset + 6],
            transaction[payload_size_offset + 7],
        ]) as usize;

        if payload_size_offset + 8 + payload_size >= transaction.len() {
            return Err(TEEError::CryptoError {
                reason: "Invalid transaction format".to_string(),
                details: "Transaction payload exceeds transaction length".to_string(),
                source: None,
            });
        }

        let payload = &transaction[payload_size_offset + 8..payload_size_offset + 8 + payload_size];
        let signature = &transaction[payload_size_offset + 8 + payload_size..];

        // Create enclave
        let enclave = self.create_enclave()?;

        // Execute verification within enclave
        enclave.execute(move || {
            let header_str = std::str::from_utf8(header).map_err(|_| TEEError::CryptoError {
                reason: "Invalid header encoding".to_string(),
                details: "Header is not valid UTF-8".to_string(),
                source: None,
            })?;

            // Parse header JSON
            let header_json: serde_json::Value =
                serde_json::from_str(header_str).map_err(|e| TEEError::CryptoError {
                    reason: "Invalid header JSON".to_string(),
                    details: format!("Failed to parse header JSON: {}", e),
                    source: None,
                })?;

            // Extract signer public key
            let signer_public_key =
                header_json["signer"]
                    .as_str()
                    .ok_or_else(|| TEEError::CryptoError {
                        reason: "Missing signer public key".to_string(),
                        details: "Transaction header missing 'signer' field".to_string(),
                        source: None,
                    })?;

            // Decode signer public key
            let public_key_bytes =
                hex::decode(signer_public_key).map_err(|e| TEEError::CryptoError {
                    reason: "Invalid public key format".to_string(),
                    details: format!("Failed to decode hex public key: {}", e),
                    source: None,
                })?;

            // Create message to verify
            let mut message = Vec::with_capacity(header.len() + payload.len());
            message.extend_from_slice(header);
            message.extend_from_slice(payload);

            // Verify signature
            SignatureUtil::verify(&public_key_bytes, &message, signature)
        })
    }

    fn execute_move_bytecode(
        &self,
        bytecode: &[u8],
        function: &str,
        args: &[Vec<u8>],
    ) -> crate::core::error::TEEResult<Vec<u8>> {
        use crate::core::error::TEEError;

        // Create enclave
        let enclave = self.create_enclave()?;

        // Execute within enclave
        enclave.execute(move || {
            // Parse Move module and function
            let parts: Vec<&str> = function.split("::").collect();
            if parts.len() != 3 {
                return Err(TEEError::EnclaveError {
                    reason: "Invalid function format".to_string(),
                    details: "Expected format: 'address::module::function'".to_string(),
                    source: None,
                });
            }

            let address_str = parts[0];
            let module_name = parts[1];
            let function_name = parts[2];

            #[cfg(feature = "move-vm")]
            {
                use move_binary_format::file_format::CompiledModule;
                use move_core_types::account_address::AccountAddress;
                use move_core_types::identifier::Identifier;
                use move_core_types::language_storage::ModuleId;
                use move_core_types::value::MoveValue;
                use move_vm_runtime::move_vm::MoveVM;
                use move_vm_types::gas::UnmeteredGasMeter;

                // Parse address
                let address = AccountAddress::from_hex_literal(address_str).map_err(|e| {
                    TEEError::EnclaveError {
                        reason: "Invalid address".to_string(),
                        details: format!("Failed to parse address: {}", e),
                        source: None,
                    }
                })?;

                // Create module ID
                let module_id = ModuleId::new(
                    address,
                    Identifier::new(module_name).map_err(|e| TEEError::EnclaveError {
                        reason: "Invalid module name".to_string(),
                        details: format!("Failed to create module identifier: {}", e),
                        source: None,
                    })?,
                );

                // Create function identifier
                let function_id =
                    Identifier::new(function_name).map_err(|e| TEEError::EnclaveError {
                        reason: "Invalid function name".to_string(),
                        details: format!("Failed to create function identifier: {}", e),
                        source: None,
                    })?;

                // Parse module
                let compiled_module =
                    CompiledModule::deserialize(bytecode).map_err(|e| TEEError::EnclaveError {
                        reason: "Invalid bytecode".to_string(),
                        details: format!("Failed to deserialize Move module: {}", e),
                        source: None,
                    })?;

                // Create Move VM
                let vm = MoveVM::new();

                // Initialize VM with published module
                let mut vm_data_store = move_vm_runtime::data_cache::InMemoryStorage::new();
                vm_data_store
                    .publish_module(module_id.clone(), bytecode.to_vec())
                    .map_err(|e| TEEError::EnclaveError {
                        reason: "Module publishing failed".to_string(),
                        details: format!("Failed to publish module: {:?}", e),
                        source: None,
                    })?;

                // Create VM session
                let mut session = vm.new_session(&vm_data_store);

                // Convert arguments to MoveValues
                let move_args = args
                    .iter()
                    .map(|arg| MoveValue::vector_u8(arg.clone()))
                    .collect();

                // Execute function
                let gas_meter = UnmeteredGasMeter;
                let result = session
                    .execute_function(
                        &module_id,
                        &function_id,
                        vec![], // No type arguments
                        move_args,
                        &mut gas_meter,
                    )
                    .map_err(|e| TEEError::EnclaveError {
                        reason: "Execution failed".to_string(),
                        details: format!("Failed to execute Move function: {:?}", e),
                        source: None,
                    })?;

                // Process result
                if result.is_empty() {
                    return Ok(Vec::new());
                }

                // Convert the first return value to bytes
                let result_value = &result[0];
                match result_value {
                    MoveValue::Vector(bytes)
                        if bytes.iter().all(|v| matches!(v, MoveValue::U8(_))) =>
                    {
                        // Convert vector of u8 to bytes
                        bytes
                            .iter()
                            .map(|v| {
                                if let MoveValue::U8(b) = v {
                                    Ok(*b)
                                } else {
                                    Err(TEEError::EnclaveError {
                                        reason: "Invalid return type".to_string(),
                                        details: "Expected vector<u8>".to_string(),
                                        source: None,
                                    })
                                }
                            })
                            .collect()
                    }
                    _ => {
                        // For other types, use BCS serialization
                        use bcs::to_bytes;
                        to_bytes(result_value).map_err(|e| TEEError::EnclaveError {
                            reason: "Serialization error".to_string(),
                            details: format!("Failed to serialize result: {}", e),
                            source: None,
                        })
                    }
                }
            }

            #[cfg(not(feature = "move-vm"))]
            {
                Err(TEEError::EnclaveError {
                    reason: "Move VM not enabled".to_string(),
                    details: "This build doesn't include Move VM support".to_string(),
                    source: None,
                })
            }
        })
    }

    fn generate_computation_proof(
        &self,
        bytecode: &[u8],
        function: &str,
        args: &[Vec<u8>],
        result: &[u8],
    ) -> crate::core::error::TEEResult<Vec<u8>> {
        use crate::core::crypto::{EncryptionUtil, SignatureUtil};
        use sha2::{Digest, Sha256};

        // Create enclave
        let enclave = self.create_enclave()?;

        // Generate proof within enclave
        enclave.execute(move || {
            // Generate key pair for signing
            let keypair = SignatureUtil::generate_keypair()?;

            // Create proof bundle
            let mut proof_bundle = Vec::new();

            // Add bytecode hash
            let mut hasher = Sha256::new();
            hasher.update(bytecode);
            let bytecode_hash = hasher.finalize();
            proof_bundle.extend_from_slice(&bytecode_hash);

            // Add function name
            proof_bundle.extend_from_slice(function.as_bytes());
            proof_bundle.push(0); // Null terminator

            // Add argument hashes
            for arg in args {
                let mut hasher = Sha256::new();
                hasher.update(arg);
                let arg_hash = hasher.finalize();
                proof_bundle.extend_from_slice(&arg_hash);
            }

            // Add result hash
            let mut hasher = Sha256::new();
            hasher.update(result);
            let result_hash = hasher.finalize();
            proof_bundle.extend_from_slice(&result_hash);

            // Add enclave measurement
            proof_bundle.extend_from_slice(&enclave.get_measurement());

            // Add timestamp
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            proof_bundle.extend_from_slice(&timestamp.to_le_bytes());

            // Sign the proof
            let signature = SignatureUtil::sign(&keypair, &proof_bundle)?;

            // Add public key and signature
            proof_bundle.extend_from_slice(&keypair.public_key);
            proof_bundle.extend_from_slice(&signature);

            Ok(proof_bundle)
        })
    }

    fn verify_computation_proof(
        &self,
        proof: &[u8],
        bytecode: &[u8],
        function: &str,
        args: &[Vec<u8>],
        result: &[u8],
    ) -> crate::core::error::TEEResult<bool> {
        use crate::core::crypto::SignatureUtil;
        use crate::core::error::TEEError;
        use sha2::{Digest, Sha256};

        // Proof format:
        // [0..32] Bytecode hash
        // [32..36] Function name length (u32)
        // [36..36+func_len] Function name
        // [func_offset..func_offset+4] Number of args (u32)
        // For each arg:
        //   [offset..offset+4] Arg length (u32)
        //   [offset+4..offset+4+arg_len] Arg hash
        // [args_end..args_end+32] Result hash
        // [args_end+32..args_end+64] Enclave measurement
        // [args_end+64..args_end+72] Timestamp (u64)
        // [args_end+72..args_end+104] Public key
        // [args_end+104..] Signature

        if proof.len() < 200 {
            // Minimum size for all required fields
            return Err(TEEError::CryptoError {
                reason: "Invalid proof format".to_string(),
                details: "Proof too small to contain required fields".to_string(),
                source: None,
            });
        }

        // Create enclave for secure verification
        let enclave = self.create_enclave()?;

        // Execute verification within enclave
        enclave.execute(move || {
            // Extract bytecode hash
            let bytecode_hash = &proof[0..32];

            // Compute actual bytecode hash
            let mut hasher = Sha256::new();
            hasher.update(bytecode);
            let computed_bytecode_hash = hasher.finalize();

            // Verify bytecode hash
            if bytecode_hash != computed_bytecode_hash.as_slice() {
                return Ok(false);
            }

            // Extract function name length
            let func_len =
                u32::from_le_bytes([proof[32], proof[33], proof[34], proof[35]]) as usize;

            let func_offset = 36 + func_len;
            if func_offset >= proof.len() {
                return Err(TEEError::CryptoError {
                    reason: "Invalid proof format".to_string(),
                    details: "Function name exceeds proof length".to_string(),
                    source: None,
                });
            }

            // Extract function name
            let proof_function = std::str::from_utf8(&proof[36..func_offset]).map_err(|_| {
                TEEError::CryptoError {
                    reason: "Invalid function name".to_string(),
                    details: "Function name is not valid UTF-8".to_string(),
                    source: None,
                }
            })?;

            // Verify function name
            if proof_function != function {
                return Ok(false);
            }

            // Extract number of args
            let num_args = u32::from_le_bytes([
                proof[func_offset],
                proof[func_offset + 1],
                proof[func_offset + 2],
                proof[func_offset + 3],
            ]) as usize;

            // Verify number of args
            if num_args != args.len() {
                return Ok(false);
            }

            // Track current offset
            let mut current_offset = func_offset + 4;

            // Verify each arg hash
            for arg in args {
                if current_offset + 4 >= proof.len() {
                    return Err(TEEError::CryptoError {
                        reason: "Invalid proof format".to_string(),
                        details: "Argument length field exceeds proof length".to_string(),
                        source: None,
                    });
                }

                // Extract arg hash length (should be 32 for SHA-256)
                let arg_hash_len = u32::from_le_bytes([
                    proof[current_offset],
                    proof[current_offset + 1],
                    proof[current_offset + 2],
                    proof[current_offset + 3],
                ]) as usize;

                current_offset += 4;

                if current_offset + arg_hash_len > proof.len() {
                    return Err(TEEError::CryptoError {
                        reason: "Invalid proof format".to_string(),
                        details: "Argument hash exceeds proof length".to_string(),
                        source: None,
                    });
                }

                // Extract arg hash
                let arg_hash = &proof[current_offset..current_offset + arg_hash_len];

                // Compute actual arg hash
                let mut hasher = Sha256::new();
                hasher.update(arg);
                let computed_arg_hash = hasher.finalize();

                // Verify arg hash
                if arg_hash != computed_arg_hash.as_slice() {
                    return Ok(false);
                }

                current_offset += arg_hash_len;
            }

            // Extract result hash
            if current_offset + 32 > proof.len() {
                return Err(TEEError::CryptoError {
                    reason: "Invalid proof format".to_string(),
                    details: "Result hash field exceeds proof length".to_string(),
                    source: None,
                });
            }

            let result_hash = &proof[current_offset..current_offset + 32];

            // Compute actual result hash
            let mut hasher = Sha256::new();
            hasher.update(result);
            let computed_result_hash = hasher.finalize();

            // Verify result hash
            if result_hash != computed_result_hash.as_slice() {
                return Ok(false);
            }

            // Extract rest of the fields
            let enclave_measurement_offset = current_offset + 32;
            let timestamp_offset = enclave_measurement_offset + 32;
            let public_key_offset = timestamp_offset + 8;
            let signature_offset = public_key_offset + 32;

            if signature_offset >= proof.len() {
                return Err(TEEError::CryptoError {
                    reason: "Invalid proof format".to_string(),
                    details: "Signature field exceeds proof length".to_string(),
                    source: None,
                });
            }

            // Extract public key and signature
            let public_key = &proof[public_key_offset..signature_offset];
            let signature = &proof[signature_offset..];

            // Verify signature
            // The signature is over all proof data except the public key and signature itself
            let signature_data = &proof[0..public_key_offset];

            SignatureUtil::verify(public_key, signature_data, signature)
        })
    }
}

/// Represents an attestation report from a TEE platform
#[derive(Debug, Clone)]
pub struct AttestationReport {
    pub platform: String,
    pub report_data: Vec<u8>,
    pub timestamp: u64,
}

/// Helper structure for Move bytecode
struct MoveBytecode {
    module_id: String,
    function_name: String,
    bytecode: Vec<u8>,
}

/// Helper function to execute move bytecode
fn execute_bytecode(
    bytecode: MoveBytecode,
    args: Vec<Vec<u8>>,
) -> crate::core::error::TEEResult<Vec<u8>> {
    use crate::core::error::TEEError;

    #[cfg(feature = "move-vm")]
    {
        use move_binary_format::file_format::CompiledModule;
        use move_core_types::account_address::AccountAddress;
        use move_core_types::identifier::Identifier;
        use move_core_types::language_storage::ModuleId;
        use move_core_types::value::MoveValue;
        use move_vm_runtime::move_vm::MoveVM;
        use move_vm_types::gas::UnmeteredGasMeter;

        // Parse module ID parts
        let parts: Vec<&str> = bytecode.module_id.split("::").collect();
        if parts.len() != 2 {
            return Err(TEEError::EnclaveError {
                reason: "Invalid module ID format".to_string(),
                details: "Expected format: 'address::module'".to_string(),
                source: None,
            });
        }

        // Parse address
        let address =
            AccountAddress::from_hex_literal(parts[0]).map_err(|e| TEEError::EnclaveError {
                reason: "Invalid address".to_string(),
                details: format!("Failed to parse address: {}", e),
                source: None,
            })?;

        // Create module ID
        let module_id = ModuleId::new(
            address,
            Identifier::new(parts[1]).map_err(|e| TEEError::EnclaveError {
                reason: "Invalid module name".to_string(),
                details: format!("Failed to create module identifier: {}", e),
                source: None,
            })?,
        );

        // Create function identifier
        let function_id =
            Identifier::new(&bytecode.function_name).map_err(|e| TEEError::EnclaveError {
                reason: "Invalid function name".to_string(),
                details: format!("Failed to create function identifier: {}", e),
                source: None,
            })?;

        // Create Move VM
        let vm = MoveVM::new();

        // Initialize VM with published module
        let mut vm_data_store = move_vm_runtime::data_cache::InMemoryStorage::new();
        vm_data_store
            .publish_module(module_id.clone(), bytecode.bytecode)
            .map_err(|e| TEEError::EnclaveError {
                reason: "Module publishing failed".to_string(),
                details: format!("Failed to publish module: {:?}", e),
                source: None,
            })?;

        // Create VM session
        let mut session = vm.new_session(&vm_data_store);

        // Convert arguments to MoveValues
        let move_args = args
            .iter()
            .map(|arg| MoveValue::vector_u8(arg.clone()))
            .collect();

        // Execute function
        let mut gas_meter = UnmeteredGasMeter;
        let result = session
            .execute_function(
                &module_id,
                &function_id,
                vec![], // No type arguments
                move_args,
                &mut gas_meter,
            )
            .map_err(|e| TEEError::EnclaveError {
                reason: "Execution failed".to_string(),
                details: format!("Failed to execute Move function: {:?}", e),
                source: None,
            })?;

        // Process result
        if result.is_empty() {
            return Ok(Vec::new());
        }

        // Convert the first return value to bytes
        let result_value = &result[0];
        match result_value {
            MoveValue::Vector(bytes) if bytes.iter().all(|v| matches!(v, MoveValue::U8(_))) => {
                // Convert vector of u8 to bytes
                bytes
                    .iter()
                    .map(|v| {
                        if let MoveValue::U8(b) = v {
                            Ok(*b)
                        } else {
                            Err(TEEError::EnclaveError {
                                reason: "Invalid return type".to_string(),
                                details: "Expected vector<u8>".to_string(),
                                source: None,
                            })
                        }
                    })
                    .collect()
            }
            _ => {
                // For other types, use BCS serialization
                use bcs::to_bytes;
                to_bytes(result_value).map_err(|e| TEEError::EnclaveError {
                    reason: "Serialization error".to_string(),
                    details: format!("Failed to serialize result: {}", e),
                    source: None,
                })
            }
        }
    }

    #[cfg(not(feature = "move-vm"))]
    {
        Err(TEEError::EnclaveError {
            reason: "Move VM not enabled".to_string(),
            details: "This build doesn't include Move VM support".to_string(),
            source: None,
        })
    }
}

// Enclave state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveState {
    Created,
    Initialized,
    Running,
    Paused,
    Terminated,
    Error,
}

// Security level assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyLevel {
    Strong,
    Moderate,
    Basic,
}

// Open-source status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenSourceStatus {
    FullyOpen,
    PartiallyOpen,
    Proprietary,
}

/// Create platform manager
pub struct PlatformManager {
    initialized_platforms: std::collections::HashMap<String, Box<dyn TEEPlatform + Send + Sync>>,
}

impl PlatformManager {
    /// Create a new platform manager
    pub fn new() -> crate::core::error::TEEResult<Self> {
        Ok(Self {
            initialized_platforms: std::collections::HashMap::new(),
        })
    }

    /// Initialize a specific platform
    pub fn initialize_platform(
        &mut self,
        platform_name: &str,
    ) -> crate::core::error::TEEResult<()> {
        use crate::core::error::TEEError;

        // Check if already initialized
        if self.initialized_platforms.contains_key(platform_name) {
            return Ok(());
        }

        // Initialize platform
        let mut platform: Box<dyn TEEPlatform + Send + Sync> = match platform_name {
            "intel_sgx" => Box::new(crate::platforms::intel_sgx::IntelSGXPlatform::new()),
            "amd_sev" => Box::new(crate::platforms::amd_sev::AMDSEVPlatform::new()),
            "arm_trustzone" => {
                Box::new(crate::platforms::arm_trustzone::ARMTrustZonePlatform::new())
            }
            "aws_nitro" => Box::new(crate::platforms::aws_nitro::AWSNitroEnclavesPlatform::new()),
            _ => {
                return Err(TEEError::PlatformError {
                    platform: platform_name.to_string(),
                    reason: "Unsupported platform".to_string(),
                    details: format!("Platform '{}' is not supported", platform_name),
                    source: None,
                });
            }
        };

        // Initialize the platform
        platform.initialize()?;

        // Store initialized platform
        self.initialized_platforms
            .insert(platform_name.to_string(), platform);

        Ok(())
    }

    /// Create an enclave
    pub fn create_enclave(
        &mut self,
        platform_name: &str,
    ) -> crate::core::error::TEEResult<Box<dyn SecureEnclave>> {
        use crate::core::error::TEEError;

        // Get platform
        let platform = self
            .initialized_platforms
            .get_mut(platform_name)
            .ok_or_else(|| TEEError::PlatformError {
                platform: platform_name.to_string(),
                reason: "Platform not initialized".to_string(),
                details: format!("Platform '{}' has not been initialized", platform_name),
                source: None,
            })?;

        // Create enclave
        platform.create_enclave()
    }

    /// Get platform
    pub fn get_platform(
        &self,
        platform_name: &str,
    ) -> crate::core::error::TEEResult<&dyn TEEPlatform> {
        use crate::core::error::TEEError;

        // Get platform
        let platform = self
            .initialized_platforms
            .get(platform_name)
            .ok_or_else(|| TEEError::PlatformError {
                platform: platform_name.to_string(),
                reason: "Platform not initialized".to_string(),
                details: format!("Platform '{}' has not been initialized", platform_name),
                source: None,
            })?;

        Ok(&**platform)
    }
}
