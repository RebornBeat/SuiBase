//! Interface for interacting with Sui blockchain from TEE environment

use crate::core::attestation::Attestation;
use crate::core::error::{TEEError, TEEResult};
use crate::platforms::SecureEnclave;
use crate::sui::command_processor::{BlockchainCommand, CommandProcessor};
use crate::sui::move_execution::{MoveBytecode, execute_move_bytecode, parse_move_contract};
use crate::sui::{TEE_EXECUTION_MODULE, TEE_REGISTRY_MODULE, TEE_VERIFICATION_MODULE};
use crate::verification::mcp::MCPGenerator;
use async_std::sync::Mutex;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Sui blockchain client for TEE interactions
#[derive(Clone)]
pub struct SuiClient {
    /// Client URL
    endpoint: String,
    /// Authentication credentials
    credentials: Option<BlockchainCredentials>,
    /// HTTP client for API calls
    http_client: reqwest::Client,
    /// Connection timeout
    timeout: Duration,
    /// Retry configuration
    max_retries: u32,
    /// Validator endpoints
    validator_endpoints: Vec<String>,
}

impl SuiClient {
    /// Create a new Sui client
    pub fn new(endpoint: String) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self {
            endpoint,
            credentials: None,
            http_client,
            timeout: Duration::from_secs(30),
            max_retries: 3,
            validator_endpoints: Vec::new(),
        }
    }

    /// Configure timeouts and retries
    pub fn with_timeouts(mut self, timeout_secs: u64, max_retries: u32) -> Self {
        self.timeout = Duration::from_secs(timeout_secs);
        self.max_retries = max_retries;
        self
    }

    /// Set authentication credentials
    pub fn with_credentials(mut self, credentials: BlockchainCredentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// Set validator endpoints for quorum operations
    pub fn with_validators(mut self, validator_endpoints: Vec<String>) -> Self {
        self.validator_endpoints = validator_endpoints;
        self
    }

    /// Submit transaction to blockchain with retry logic
    pub async fn submit_transaction(&self, payload: Vec<u8>, function: &str) -> TEEResult<String> {
        let mut attempts = 0;
        let mut last_error = None;

        while attempts < self.max_retries {
            match self.try_submit_transaction(&payload, function).await {
                Ok(hash) => return Ok(hash),
                Err(e) => {
                    attempts += 1;
                    last_error = Some(e);

                    if attempts < self.max_retries {
                        // Exponential backoff: 1s, 2s, 4s, ...
                        async_std::task::sleep(Duration::from_secs(1 << (attempts - 1))).await;
                    }
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| TEEError::Generic("Failed to submit transaction".to_string())))
    }

    /// Single attempt at transaction submission
    async fn try_submit_transaction(&self, payload: &[u8], function: &str) -> TEEResult<String> {
        // Ensure credentials are available
        let credentials = self.credentials.as_ref().ok_or_else(|| {
            TEEError::Generic("No credentials provided for blockchain client".to_string())
        })?;

        // Build transaction parameters
        let params = serde_json::json!({
            "function": function,
            "sender": credentials.address,
            "gas_budget": credentials.gas_budget,
            "args": [base64::encode(payload)],
            "gas_price": credentials.gas_price,
        });

        // Send request to Sui
        let response = self
            .http_client
            .post(format!("{}/transactions", self.endpoint))
            .header("Content-Type", "application/json")
            .header("X-Sui-Auth", &credentials.auth_token)
            .json(&params)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| TEEError::Generic(format!("Failed to submit transaction: {}", e)))?;

        // Process response
        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(TEEError::Generic(format!(
                "Transaction submission failed: {} - {}",
                status, error_text
            )));
        }

        let response_json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| TEEError::Generic(format!("Failed to parse response: {}", e)))?;

        // Extract transaction digest
        let tx_digest = response_json["digest"]
            .as_str()
            .ok_or_else(|| TEEError::Generic("Failed to get transaction digest".to_string()))?
            .to_string();

        Ok(tx_digest)
    }

    /// Get active validators
    pub async fn get_active_validators(&self) -> TEEResult<Vec<Validator>> {
        let response = self
            .http_client
            .get(format!("{}/validators", self.endpoint))
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| TEEError::Generic(format!("Failed to fetch validators: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(TEEError::Generic(format!(
                "Failed to fetch validators: {} - {}",
                response.status(),
                error_text
            )));
        }

        let validators_json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| TEEError::Generic(format!("Failed to parse validator response: {}", e)))?;

        let validators = validators_json["validators"]
            .as_array()
            .ok_or_else(|| TEEError::Generic("Invalid validator response format".to_string()))?;

        let mut result = Vec::with_capacity(validators.len());
        for validator in validators {
            let id = validator["id"]
                .as_str()
                .ok_or_else(|| TEEError::Generic("Invalid validator ID format".to_string()))?
                .to_string();

            let public_key = validator["public_key"].as_str().ok_or_else(|| {
                TEEError::Generic("Invalid validator public key format".to_string())
            })?;

            let public_key_bytes = base64::decode(public_key).map_err(|e| {
                TEEError::Generic(format!("Failed to decode validator public key: {}", e))
            })?;

            result.push(Validator {
                id,
                public_key: public_key_bytes,
                voting_power: validator["voting_power"].as_u64().unwrap_or(0),
                address: validator["address"].as_str().unwrap_or("").to_string(),
            });
        }

        Ok(result)
    }

    /// Get registered enclave keys
    pub async fn get_registered_enclave_keys(&self) -> TEEResult<Vec<EnclaveRegistration>> {
        let response = self
            .http_client
            .get(format!(
                "{}/objects/{}/registered_enclaves",
                self.endpoint, TEE_REGISTRY_MODULE
            ))
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| TEEError::Generic(format!("Failed to fetch enclave keys: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(TEEError::Generic(format!(
                "Failed to fetch enclave keys: {} - {}",
                response.status(),
                error_text
            )));
        }

        let enclaves_json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| TEEError::Generic(format!("Failed to parse enclave response: {}", e)))?;

        let enclaves = enclaves_json["enclaves"]
            .as_array()
            .ok_or_else(|| TEEError::Generic("Invalid enclave response format".to_string()))?;

        let mut result = Vec::with_capacity(enclaves.len());
        for enclave in enclaves {
            let id = enclave["id"]
                .as_str()
                .ok_or_else(|| TEEError::Generic("Invalid enclave ID format".to_string()))?
                .to_string();

            let public_key = enclave["public_key"].as_str().ok_or_else(|| {
                TEEError::Generic("Invalid enclave public key format".to_string())
            })?;

            let public_key_bytes = base64::decode(public_key).map_err(|e| {
                TEEError::Generic(format!("Failed to decode enclave public key: {}", e))
            })?;

            let platform = enclave["platform"]
                .as_str()
                .ok_or_else(|| TEEError::Generic("Invalid enclave platform format".to_string()))?
                .to_string();

            let measurement = enclave["measurement"].as_str().ok_or_else(|| {
                TEEError::Generic("Invalid enclave measurement format".to_string())
            })?;

            let measurement_bytes = base64::decode(measurement).map_err(|e| {
                TEEError::Generic(format!("Failed to decode enclave measurement: {}", e))
            })?;

            result.push(EnclaveRegistration {
                id,
                public_key: public_key_bytes,
                platform,
                measurement: measurement_bytes,
                registration_time: enclave["registration_time"].as_u64().unwrap_or(0),
                approved_by: enclave["approved_by"]
                    .as_array()
                    .map(|validators| {
                        validators
                            .iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default(),
            });
        }

        Ok(result)
    }

    /// Get contract by ID
    pub async fn get_contract(&self, contract_id: &str) -> TEEResult<Vec<u8>> {
        let response = self
            .http_client
            .get(format!("{}/objects/{}", self.endpoint, contract_id))
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| TEEError::Generic(format!("Failed to fetch contract: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(TEEError::Generic(format!(
                "Failed to fetch contract: {} - {}",
                response.status(),
                error_text
            )));
        }

        let contract_json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| TEEError::Generic(format!("Failed to parse contract response: {}", e)))?;

        let bytecode = contract_json["bytecode"]
            .as_str()
            .ok_or_else(|| TEEError::Generic("Invalid contract bytecode format".to_string()))?;

        base64::decode(bytecode)
            .map_err(|e| TEEError::Generic(format!("Failed to decode contract bytecode: {}", e)))
    }

    /// Poll for commands directed to this TEE
    pub async fn poll_commands(&self, tee_id: &str) -> TEEResult<Vec<BlockchainCommand>> {
        let response = self
            .http_client
            .get(format!("{}/tee_commands/{}", self.endpoint, tee_id))
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| TEEError::Generic(format!("Failed to poll commands: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(TEEError::Generic(format!(
                "Failed to poll commands: {} - {}",
                response.status(),
                error_text
            )));
        }

        let commands_json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| TEEError::Generic(format!("Failed to parse commands response: {}", e)))?;

        let commands = commands_json["commands"]
            .as_array()
            .ok_or_else(|| TEEError::Generic("Invalid commands response format".to_string()))?;

        let mut result = Vec::with_capacity(commands.len());
        for cmd in commands {
            let command_type = cmd["type"]
                .as_str()
                .ok_or_else(|| TEEError::Generic("Invalid command type".to_string()))?;

            match command_type {
                "execute_contract" => {
                    let contract_id = cmd["contract_id"]
                        .as_str()
                        .ok_or_else(|| TEEError::Generic("Missing contract_id".to_string()))?
                        .to_string();

                    let function = cmd["function"]
                        .as_str()
                        .ok_or_else(|| TEEError::Generic("Missing function".to_string()))?
                        .to_string();

                    let args_json = cmd["args"]
                        .as_array()
                        .ok_or_else(|| TEEError::Generic("Invalid args format".to_string()))?;

                    let mut args = Vec::with_capacity(args_json.len());
                    for arg in args_json {
                        let arg_str = arg
                            .as_str()
                            .ok_or_else(|| TEEError::Generic("Invalid arg format".to_string()))?;

                        let arg_bytes = base64::decode(arg_str).map_err(|e| {
                            TEEError::Generic(format!("Failed to decode arg: {}", e))
                        })?;

                        args.push(arg_bytes);
                    }

                    let callback_tx = cmd["callback_tx"]
                        .as_str()
                        .ok_or_else(|| TEEError::Generic("Missing callback_tx".to_string()))?
                        .to_string();

                    result.push(BlockchainCommand::ExecuteContract {
                        contract_id,
                        function,
                        args,
                        callback_tx,
                    });
                }
                "update_tee" => {
                    let update_package_str = cmd["update_package"]
                        .as_str()
                        .ok_or_else(|| TEEError::Generic("Missing update_package".to_string()))?;

                    let update_package = base64::decode(update_package_str).map_err(|e| {
                        TEEError::Generic(format!("Failed to decode update package: {}", e))
                    })?;

                    let version = cmd["version"]
                        .as_str()
                        .ok_or_else(|| TEEError::Generic("Missing version".to_string()))?
                        .to_string();

                    result.push(BlockchainCommand::UpdateTEE {
                        update_package,
                        version,
                    });
                }
                "terminate" => {
                    result.push(BlockchainCommand::Terminate);
                }
                _ => {
                    return Err(TEEError::Generic(format!(
                        "Unknown command type: {}",
                        command_type
                    )));
                }
            }
        }

        Ok(result)
    }

    /// Submit execution result
    pub async fn submit_result(
        &self,
        callback_tx: &str,
        result: &[u8],
        proof: &[u8],
    ) -> TEEResult<String> {
        // Ensure credentials are available
        let credentials = self.credentials.as_ref().ok_or_else(|| {
            TEEError::Generic("No credentials provided for blockchain client".to_string())
        })?;

        // Build result parameters
        let mut result_data = Vec::with_capacity(8 + result.len() + proof.len());
        result_data.extend_from_slice(&(result.len() as u32).to_le_bytes());
        result_data.extend_from_slice(result);
        result_data.extend_from_slice(proof);

        // Build transaction parameters
        let params = serde_json::json!({
            "function": format!("{}::submit_result", TEE_EXECUTION_MODULE),
            "sender": credentials.address,
            "gas_budget": credentials.gas_budget,
            "args": [
                callback_tx,
                base64::encode(result_data)
            ],
            "gas_price": credentials.gas_price,
        });

        // Send request to Sui
        let response = self
            .http_client
            .post(format!("{}/transactions", self.endpoint))
            .header("Content-Type", "application/json")
            .header("X-Sui-Auth", &credentials.auth_token)
            .json(&params)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| TEEError::Generic(format!("Failed to submit result: {}", e)))?;

        // Process response
        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(TEEError::Generic(format!(
                "Result submission failed: {} - {}",
                status, error_text
            )));
        }

        let response_json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| TEEError::Generic(format!("Failed to parse response: {}", e)))?;

        // Extract transaction digest
        let tx_digest = response_json["digest"]
            .as_str()
            .ok_or_else(|| TEEError::Generic("Failed to get transaction digest".to_string()))?
            .to_string();

        Ok(tx_digest)
    }
}

/// Represents a blockchain validator
#[derive(Debug, Clone)]
pub struct Validator {
    pub id: String,
    pub public_key: Vec<u8>,
    pub voting_power: u64,
    pub address: String,
}

/// Represents a registered enclave
#[derive(Debug, Clone)]
pub struct EnclaveRegistration {
    pub id: String,
    pub public_key: Vec<u8>,
    pub platform: String,
    pub measurement: Vec<u8>,
    pub registration_time: u64,
    pub approved_by: Vec<String>,
}

/// Authentication credentials for blockchain
#[derive(Clone)]
pub struct BlockchainCredentials {
    pub address: String,
    pub auth_token: String,
    pub gas_budget: u64,
    pub gas_price: u64,
}

/// Interface between TEE and the Sui blockchain
pub struct TEEBlockchainInterface {
    pub blockchain_client: SuiClient,
    pub command_processor: CommandProcessor,
    pub tee_id: String,
    pub platform_name: String,
    polling_interval: Duration,
    mcp_generator: MCPGenerator,
    polling_active: Arc<Mutex<bool>>,
}

impl TEEBlockchainInterface {
    /// Create a new blockchain interface
    pub fn new(
        blockchain_client: SuiClient,
        platform_name: String,
        polling_interval_ms: u64,
    ) -> Self {
        Self {
            blockchain_client,
            command_processor: CommandProcessor::new(),
            tee_id: uuid::Uuid::new_v4().to_string(),
            platform_name,
            polling_interval: Duration::from_millis(polling_interval_ms),
            mcp_generator: MCPGenerator::new(),
            polling_active: Arc::new(Mutex::new(false)),
        }
    }

    /// Start listening for blockchain commands
    pub async fn start_processing_commands(&self) -> TEEResult<()> {
        let mut active = self.polling_active.lock().await;
        if *active {
            return Ok(());
        }

        *active = true;
        drop(active);

        let polling_active = self.polling_active.clone();
        let tee_id = self.tee_id.clone();
        let client = self.blockchain_client.clone();
        let command_processor = self.command_processor.clone();
        let polling_interval = self.polling_interval;

        async_std::task::spawn(async move {
            while *polling_active.lock().await {
                match client.poll_commands(&tee_id).await {
                    Ok(commands) => {
                        for cmd in commands {
                            if let Err(e) = command_processor.enqueue_command(cmd).await {
                                eprintln!("Failed to enqueue command: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to poll commands: {}", e);
                    }
                }

                async_std::task::sleep(polling_interval).await;
            }
        });

        Ok(())
    }

    /// Stop processing commands
    pub async fn stop_processing_commands(&self) -> TEEResult<()> {
        let mut active = self.polling_active.lock().await;
        *active = false;
        Ok(())
    }

    /// Register TEE with blockchain
    pub async fn register_tee(&self, attestation: &Attestation) -> TEEResult<String> {
        // Create attestation proof
        let attestation_bytes = self.attestation_to_bytes(attestation)?;

        // Submit to blockchain
        let tx_hash = self
            .blockchain_client
            .submit_transaction(
                attestation_bytes,
                &format!("{}::register_tee", TEE_REGISTRY_MODULE),
            )
            .await?;

        Ok(tx_hash)
    }

    /// Convert attestation to blockchain-compatible format
    fn attestation_to_bytes(&self, attestation: &Attestation) -> TEEResult<Vec<u8>> {
        use crate::core::error::TEEError;

        // Create attestation container
        let mut attestation_bytes = Vec::new();

        // Add TEE ID
        attestation_bytes.extend_from_slice(self.tee_id.as_bytes());
        attestation_bytes.push(0); // Null terminator

        // Add platform name
        attestation_bytes.extend_from_slice(self.platform_name.as_bytes());
        attestation_bytes.push(0); // Null terminator

        // Add attestation components
        attestation_bytes.extend_from_slice(&attestation.instance_id.as_bytes());
        attestation_bytes.push(0); // Null terminator

        let report_len = attestation.report.len() as u32;
        attestation_bytes.extend_from_slice(&report_len.to_le_bytes());
        attestation_bytes.extend_from_slice(&attestation.report);

        for signature in &attestation.signatures {
            let sig_len = signature.len() as u32;
            attestation_bytes.extend_from_slice(&sig_len.to_le_bytes());
            attestation_bytes.extend_from_slice(signature);
        }

        // Add metadata
        let metadata_count = attestation.metadata.len() as u32;
        attestation_bytes.extend_from_slice(&metadata_count.to_le_bytes());

        for (key, value) in &attestation.metadata {
            attestation_bytes.extend_from_slice(key.as_bytes());
            attestation_bytes.push(0); // Null terminator

            attestation_bytes.extend_from_slice(value.as_bytes());
            attestation_bytes.push(0); // Null terminator
        }

        Ok(attestation_bytes)
    }

    /// Process execution within TEE and submit result
    pub async fn process_execution(
        &self,
        enclave: Box<dyn SecureEnclave>,
        contract_id: &str,
        function: &str,
        args: &[Vec<u8>],
        callback_tx: &str,
    ) -> TEEResult<String> {
        // Get contract bytecode
        let contract_bytes = self.blockchain_client.get_contract(contract_id).await?;

        // Execute within enclave
        let result = enclave.execute(move || {
            let bytecode = parse_move_contract(&contract_bytes, function)?;
            execute_move_bytecode(bytecode, args.to_vec())
        })?;

        // Generate MCP proof
        let proof = self
            .mcp_generator
            .generate_proof(&result, &contract_bytes, args)?;

        // Submit result to blockchain
        self.blockchain_client
            .submit_result(callback_tx, &result, &proof)
            .await
    }
}
