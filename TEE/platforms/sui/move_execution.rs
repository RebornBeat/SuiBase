//! Move contract execution environment for TEE

use crate::core::error::{TEEError, TEEResult};
use crate::platforms::SecureEnclave;
use crate::verification::mcp::MCPGenerator;
use async_std::sync::{Arc, Mutex};
use sha2::{Digest, Sha256};

/// Move execution environment within a TEE
pub struct MoveExecutionEnvironment {
    mcp_generator: MCPGenerator,
    execution_stats: Arc<Mutex<ExecutionStats>>,
    cache: Arc<Mutex<ContractCache>>,
}

/// Result of Move execution
pub struct MoveExecutionResult {
    /// Execution output
    pub result: Vec<u8>,
    /// Minimal computation proof
    pub proof: Vec<u8>,
    /// Gas used
    pub gas_used: u64,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
}

/// Statistics for Move execution
struct ExecutionStats {
    total_executions: u64,
    total_gas_used: u64,
    average_execution_time_ms: f64,
    cache_hits: u64,
    cache_misses: u64,
}

/// Cache for contract bytecode
struct ContractCache {
    entries: std::collections::HashMap<String, CacheEntry>,
    max_entries: usize,
}

/// Cache entry
struct CacheEntry {
    bytecode: Vec<u8>,
    last_used: std::time::Instant,
    access_count: u64,
}

impl MoveExecutionEnvironment {
    /// Create a new Move execution environment
    pub fn new() -> Self {
        Self {
            mcp_generator: MCPGenerator::new(),
            execution_stats: Arc::new(Mutex::new(ExecutionStats {
                total_executions: 0,
                total_gas_used: 0,
                average_execution_time_ms: 0.0,
                cache_hits: 0,
                cache_misses: 0,
            })),
            cache: Arc::new(Mutex::new(ContractCache {
                entries: std::collections::HashMap::new(),
                max_entries: 100, // Configurable cache size
            })),
        }
    }

    /// Execute a Move contract within the TEE
    pub async fn execute_move_contract(
        &self,
        enclave: Box<dyn SecureEnclave>,
        contract: &[u8],
        function: &str,
        args: Vec<Vec<u8>>,
    ) -> TEEResult<(Vec<u8>, Vec<u8>)> {
        // (result, proof)
        // Create a contract ID for caching
        let contract_id = generate_contract_id(contract, function);

        // Try to get bytecode from cache
        let cached_bytecode = self.check_cache(&contract_id).await;

        // Stats tracking
        let execution_start = std::time::Instant::now();

        // Parse contract to move bytecode
        let bytecode = match cached_bytecode {
            Some(cached) => {
                // Using cached bytecode
                self.update_cache_stats(true).await;
                cached
            }
            None => {
                // Parse new bytecode
                self.update_cache_stats(false).await;
                let parsed = parse_move_contract(contract, function)?;
                // Add to cache
                self.add_to_cache(&contract_id, parsed.clone()).await;
                parsed
            }
        };

        // Execute in enclave
        let result =
            enclave.execute(move || execute_move_bytecode(bytecode.clone(), args.clone()))?;

        // Track execution time
        let execution_time = execution_start.elapsed();
        let execution_time_ms = execution_time.as_millis() as u64;

        // Update execution stats
        self.update_execution_stats(execution_time_ms, 1000).await; // Dummy gas cost

        // Generate MCP proof for verification without full recomputation
        let proof = self
            .mcp_generator
            .generate_proof(&result, contract, &args)?;

        Ok((result, proof))
    }

    /// Check cache for contract bytecode
    async fn check_cache(&self, contract_id: &str) -> Option<MoveBytecode> {
        let mut cache = self.cache.lock().await;

        if let Some(entry) = cache.entries.get_mut(contract_id) {
            // Update cache entry metadata
            entry.last_used = std::time::Instant::now();
            entry.access_count += 1;

            // Return clone of bytecode
            return Some(MoveBytecode {
                module_id: String::new(),     // Simplified
                function_name: String::new(), // Will be filled by executor
                bytecode: entry.bytecode.clone(),
            });
        }

        None
    }

    /// Add bytecode to cache
    async fn add_to_cache(&self, contract_id: &str, bytecode: MoveBytecode) {
        let mut cache = self.cache.lock().await;

        // Evict least recently used entry if cache is full
        if cache.entries.len() >= cache.max_entries {
            if let Some(oldest_id) = cache
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(id, _)| id.clone())
            {
                cache.entries.remove(&oldest_id);
            }
        }

        // Add new entry
        cache.entries.insert(
            contract_id.to_string(),
            CacheEntry {
                bytecode: bytecode.bytecode.clone(),
                last_used: std::time::Instant::now(),
                access_count: 1,
            },
        );
    }

    /// Update cache hit/miss stats
    async fn update_cache_stats(&self, hit: bool) {
        let mut stats = self.execution_stats.lock().await;

        if hit {
            stats.cache_hits += 1;
        } else {
            stats.cache_misses += 1;
        }
    }

    /// Update execution statistics
    async fn update_execution_stats(&self, execution_time_ms: u64, gas_used: u64) {
        let mut stats = self.execution_stats.lock().await;

        // Update counters
        stats.total_executions += 1;
        stats.total_gas_used += gas_used;

        // Update moving average of execution time
        if stats.total_executions == 1 {
            stats.average_execution_time_ms = execution_time_ms as f64;
        } else {
            stats.average_execution_time_ms =
                0.95 * stats.average_execution_time_ms + 0.05 * execution_time_ms as f64;
        }
    }

    /// Get execution statistics
    pub async fn get_stats(&self) -> ExecutionStats {
        self.execution_stats.lock().await.clone()
    }
}

/// Move bytecode representation
#[derive(Clone)]
struct MoveBytecode {
    module_id: String,
    function_name: String,
    bytecode: Vec<u8>,
}

/// Parse Move contract bytecode
fn parse_move_contract(contract: &[u8], function: &str) -> TEEResult<MoveBytecode> {
    #[cfg(feature = "move-vm")]
    {
        use crate::core::error::TEEError;
        use move_binary_format::file_format::CompiledModule;
        use move_core_types::account_address::AccountAddress;
        use move_core_types::identifier::Identifier;
        use move_core_types::language_storage::ModuleId;

        // Function path parsing
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

        // Parse address
        let address = if address_str.starts_with("0x") {
            AccountAddress::from_hex_literal(address_str)
        } else {
            AccountAddress::from_hex(address_str)
        }
        .map_err(|e| TEEError::EnclaveError {
            reason: "Invalid address".to_string(),
            details: format!("Failed to parse address: {}", e),
            source: None,
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

        // Parse module
        let compiled_module =
            CompiledModule::deserialize(contract).map_err(|e| TEEError::EnclaveError {
                reason: "Invalid bytecode".to_string(),
                details: format!("Failed to deserialize Move module: {}", e),
                source: None,
            })?;

        // Create full module_id string
        let module_id_str = format!("{}::{}", address_str, module_name);

        Ok(MoveBytecode {
            module_id: module_id_str,
            function_name: function_name.to_string(),
            bytecode: contract.to_vec(),
        })
    }

    #[cfg(not(feature = "move-vm"))]
    {
        use crate::core::error::TEEError;

        // Function path parsing without Move VM
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

        // Create module_id string
        let module_id = format!("{}::{}", address_str, module_name);

        // Basic bytecode validation
        if contract.len() < 32 {
            return Err(TEEError::EnclaveError {
                reason: "Invalid bytecode".to_string(),
                details: "Bytecode too small to be a valid Move module".to_string(),
                source: None,
            });
        }

        Ok(MoveBytecode {
            module_id,
            function_name: function_name.to_string(),
            bytecode: contract.to_vec(),
        })
    }
}

/// Execute Move bytecode
fn execute_move_bytecode(bytecode: MoveBytecode, args: Vec<Vec<u8>>) -> TEEResult<Vec<u8>> {
    #[cfg(feature = "move-vm")]
    {
        use crate::core::error::TEEError;
        use move_binary_format::file_format::CompiledModule;
        use move_core_types::account_address::AccountAddress;
        use move_core_types::identifier::Identifier;
        use move_core_types::language_storage::ModuleId;
        use move_core_types::value::MoveValue;
        use move_vm_runtime::move_vm::MoveVM;
        use move_vm_types::gas::UnmeteredGasMeter;

        // Parse module ID
        let parts: Vec<&str> = bytecode.module_id.split("::").collect();
        if parts.len() != 2 {
            return Err(TEEError::EnclaveError {
                reason: "Invalid module ID".to_string(),
                details: format!("Expected 'address::module', got '{}'", bytecode.module_id),
                source: None,
            });
        }

        let address_str = parts[0];
        let module_name = parts[1];

        // Parse address
        let address = if address_str.starts_with("0x") {
            AccountAddress::from_hex_literal(address_str)
        } else {
            AccountAddress::from_hex(address_str)
        }
        .map_err(|e| TEEError::EnclaveError {
            reason: "Invalid address".to_string(),
            details: format!("Failed to parse address: {}", e),
            source: None,
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
                bcs::to_bytes(result_value).map_err(|e| TEEError::EnclaveError {
                    reason: "Serialization error".to_string(),
                    details: format!("Failed to serialize result: {}", e),
                    source: None,
                })
            }
        }
    }

    #[cfg(not(feature = "move-vm"))]
    {
        use crate::core::error::TEEError;

        // Log warning about missing Move VM
        log::warn!(
            "Move VM not available, using fallback execution for {}",
            bytecode.function_name
        );

        // Without Move VM, run a deterministic computation based on inputs
        use sha2::{Digest, Sha256};

        // Deterministic execution
        let mut hasher = Sha256::new();

        // Include bytecode hash for deterministic output
        let mut bytecode_hasher = Sha256::new();
        bytecode_hasher.update(&bytecode.bytecode);
        hasher.update(bytecode_hasher.finalize());

        // Include module ID and function name
        hasher.update(bytecode.module_id.as_bytes());
        hasher.update(bytecode.function_name.as_bytes());

        // Include arguments
        for arg in &args {
            hasher.update(arg);
        }

        // Return hash as result
        Ok(hasher.finalize().to_vec())
    }
}

/// Generate ID for contract caching
fn generate_contract_id(contract: &[u8], function: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(contract);
    hasher.update(function.as_bytes());
    let hash = hasher.finalize();

    hex::encode(hash)
}

// Add implementation of Clone for ExecutionStats
impl Clone for ExecutionStats {
    fn clone(&self) -> Self {
        Self {
            total_executions: self.total_executions,
            total_gas_used: self.total_gas_used,
            average_execution_time_ms: self.average_execution_time_ms,
            cache_hits: self.cache_hits,
            cache_misses: self.cache_misses,
        }
    }
}
