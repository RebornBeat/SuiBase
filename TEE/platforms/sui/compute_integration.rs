//! Integration with SuiStack0X Compute module

use crate::core::error::{TEEError, TEEResult};
use crate::platforms::SecureEnclave;
use crate::verification::mcp::MCPGenerator;
use async_std::sync::{Arc, Mutex};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};

/// Compute operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputeOperation {
    /// Execute a function
    Execute,
    /// Schedule function execution
    Schedule,
    /// Cancel scheduled execution
    Cancel,
}

/// Function execution context
#[derive(Clone)]
pub struct ExecutionContext {
    /// Environment variables
    environment: HashMap<String, String>,
    /// Maximum execution time
    max_execution_time: Duration,
    /// Maximum memory usage
    max_memory_mb: usize,
    /// Function timeout
    timeout: Duration,
    /// Resource constraints
    constraints: ResourceConstraints,
}

/// Resource constraints
#[derive(Clone)]
pub struct ResourceConstraints {
    /// CPU usage limit (0-100)
    cpu_limit: u8,
    /// Network bandwidth limit in Mbps
    network_bandwidth_mbps: u32,
    /// Storage quota in MB
    storage_quota_mb: u32,
}

/// Function execution result
#[derive(Clone)]
pub struct ExecutionResult {
    /// Output data
    output: Vec<u8>,
    /// Execution status
    status: ExecutionStatus,
    /// Execution metrics
    metrics: ExecutionMetrics,
    /// Computation proof
    proof: Vec<u8>,
}

/// Execution status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// Success
    Success,
    /// Error
    Error,
    /// Timeout
    Timeout,
    /// Canceled
    Canceled,
}

/// Execution metrics
#[derive(Clone)]
pub struct ExecutionMetrics {
    /// Execution time
    execution_time: Duration,
    /// CPU usage (0-100)
    cpu_usage: f32,
    /// Memory usage in MB
    memory_usage_mb: f32,
    /// Network bytes sent
    network_bytes_sent: u64,
    /// Network bytes received
    network_bytes_received: u64,
}

/// Compute TEE client
#[derive(Clone)]
pub struct ComputeTEEClient {
    /// Client endpoint
    endpoint: String,
    /// HTTP client
    client: reqwest::Client,
    /// Authentication token
    auth_token: Option<String>,
    /// TEE ID
    tee_id: Option<String>,
}

impl ComputeTEEClient {
    /// Create a new compute TEE client
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            client: reqwest::Client::new(),
            auth_token: None,
            tee_id: None,
        }
    }

    /// Set authentication token
    pub fn with_auth_token(mut self, token: &str) -> Self {
        self.auth_token = Some(token.to_string());
        self
    }

    /// Set TEE ID
    pub fn with_tee_id(mut self, tee_id: &str) -> Self {
        self.tee_id = Some(tee_id.to_string());
        self
    }

    /// Execute a serverless function
    pub async fn execute_function(
        &self,
        function_id: &str,
        args: &[Vec<u8>],
        environment: &HashMap<String, String>,
    ) -> TEEResult<Vec<u8>> {
        // Build request payload
        let mut payload = Vec::new();

        // Add function ID
        payload.extend_from_slice(function_id.as_bytes());
        payload.push(0); // Null terminator

        // Add arguments
        let arg_count = args.len() as u32;
        payload.extend_from_slice(&arg_count.to_le_bytes());

        for arg in args {
            let arg_size = arg.len() as u32;
            payload.extend_from_slice(&arg_size.to_le_bytes());
            payload.extend_from_slice(arg);
        }

        // Add environment variables
        let env_count = environment.len() as u32;
        payload.extend_from_slice(&env_count.to_le_bytes());

        for (key, value) in environment {
            payload.extend_from_slice(key.as_bytes());
            payload.push(0); // Null terminator
            payload.extend_from_slice(value.as_bytes());
            payload.push(0); // Null terminator
        }

        // Add authentication if available
        if let Some(token) = &self.auth_token {
            payload.extend_from_slice(token.as_bytes());
        }

        // Get TEE ID or use default
        let tee_id = self.tee_id.as_deref().unwrap_or("default");

        // Build request
        let request_url = format!("{}/compute/{}/execute", self.endpoint, tee_id);
        let response = self
            .client
            .post(&request_url)
            .header("Content-Type", "application/octet-stream")
            .body(payload)
            .send()
            .await
            .map_err(|e| TEEError::Generic(format!("Failed to execute function: {}", e)))?;

        // Process response
        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            return Err(TEEError::Generic(format!(
                "Function execution failed: {} - {}",
                response.status(),
                error_text
            )));
        }

        // Return response bytes
        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| TEEError::Generic(format!("Failed to read response: {}", e)))
    }

    /// Schedule a function execution
    pub async fn schedule_function(
        &self,
        function_id: &str,
        args: &[Vec<u8>],
        environment: &HashMap<String, String>,
        schedule_time: SystemTime,
    ) -> TEEResult<String> {
        // Build request payload
        let mut payload = Vec::new();

        // Add function ID
        payload.extend_from_slice(function_id.as_bytes());
        payload.push(0); // Null terminator

        // Add arguments
        let arg_count = args.len() as u32;
        payload.extend_from_slice(&arg_count.to_le_bytes());

        for arg in args {
            let arg_size = arg.len() as u32;
            payload.extend_from_slice(&arg_size.to_le_bytes());
            payload.extend_from_slice(arg);
        }

        // Add environment variables
        let env_count = environment.len() as u32;
        payload.extend_from_slice(&env_count.to_le_bytes());

        for (key, value) in environment {
            payload.extend_from_slice(key.as_bytes());
            payload.push(0); // Null terminator
            payload.extend_from_slice(value.as_bytes());
            payload.push(0); // Null terminator
        }

        // Add schedule time
        let unix_time = schedule_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| TEEError::Generic(format!("Invalid schedule time: {}", e)))?
            .as_secs();

        payload.extend_from_slice(&unix_time.to_le_bytes());

        // Add authentication if available
        if let Some(token) = &self.auth_token {
            payload.extend_from_slice(token.as_bytes());
        }

        // Get TEE ID or use default
        let tee_id = self.tee_id.as_deref().unwrap_or("default");

        // Build request
        let request_url = format!("{}/compute/{}/schedule", self.endpoint, tee_id);
        let response = self
            .client
            .post(&request_url)
            .header("Content-Type", "application/octet-stream")
            .body(payload)
            .send()
            .await
            .map_err(|e| TEEError::Generic(format!("Failed to schedule function: {}", e)))?;

        // Process response
        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            return Err(TEEError::Generic(format!(
                "Function scheduling failed: {} - {}",
                response.status(),
                error_text
            )));
        }

        // Return schedule ID
        response
            .text()
            .await
            .map_err(|e| TEEError::Generic(format!("Failed to read response: {}", e)))
    }
}

/// Integration with compute module
pub struct ComputeTEEIntegration {
    /// Client for TEE communication
    tee_client: ComputeTEEClient,
    /// Function execution cache
    execution_cache: Arc<Mutex<ExecutionCache>>,
    /// Computation proof generator
    mcp_generator: MCPGenerator,
    /// Secure enclave for sensitive processing
    enclave: Option<Box<dyn SecureEnclave>>,
}

/// Execution cache
struct ExecutionCache {
    /// Cached execution results
    entries: HashMap<String, CachedExecution>,
    /// Maximum cache size
    max_entries: usize,
}

/// Cached execution entry
struct CachedExecution {
    /// Execution result
    result: ExecutionResult,
    /// Cache timestamp
    timestamp: Instant,
    /// Expiration time
    expires_at: Instant,
}

impl ComputeTEEIntegration {
    /// Create new compute module integration
    pub fn new(tee_endpoint: &str) -> Self {
        Self {
            tee_client: ComputeTEEClient::new(tee_endpoint),
            execution_cache: Arc::new(Mutex::new(ExecutionCache {
                entries: HashMap::new(),
                max_entries: 1000,
            })),
            mcp_generator: MCPGenerator::new(),
            enclave: None,
        }
    }

    /// Set client configuration
    pub fn with_client(mut self, client: ComputeTEEClient) -> Self {
        self.tee_client = client;
        self
    }

    /// Set secure enclave
    pub fn with_enclave(mut self, enclave: Box<dyn SecureEnclave>) -> Self {
        self.enclave = Some(enclave);
        self
    }

    /// Execute serverless function
    pub async fn execute_serverless_function(
        &self,
        function_id: &str,
        args: Vec<Vec<u8>>,
        environment: HashMap<String, String>,
    ) -> TEEResult<ExecutionResult> {
        // Start execution timer
        let start_time = Instant::now();

        // Generate cache key
        let cache_key = generate_cache_key(function_id, &args, &environment);

        // Check cache
        if let Some(cached) = self.check_cache(&cache_key).await {
            return Ok(cached);
        }

        // Execute function
        let result = if let Some(enclave) = &self.enclave {
            // Use enclave for execution
            self.execute_in_enclave(enclave, function_id, &args, &environment)
                .await?
        } else {
            // Use remote TEE
            self.execute_remote(function_id, &args, &environment)
                .await?
        };

        // Generate execution metrics
        let execution_time = start_time.elapsed();

        // Create proof
        let proof = self
            .generate_execution_proof(function_id, &args, &result)
            .await?;

        // Create execution result
        let execution_result = ExecutionResult {
            output: result,
            status: ExecutionStatus::Success,
            metrics: ExecutionMetrics {
                execution_time,
                cpu_usage: 0.0, // Unknown, would be measured in real implementation
                memory_usage_mb: 0.0, // Unknown, would be measured in real implementation
                network_bytes_sent: 0,
                network_bytes_received: 0,
            },
            proof,
        };

        // Cache result
        self.cache_result(&cache_key, execution_result.clone())
            .await?;

        Ok(execution_result)
    }

    /// Execute function in enclave
    async fn execute_in_enclave(
        &self,
        enclave: &Box<dyn SecureEnclave>,
        function_id: &str,
        args: &[Vec<u8>],
        environment: &HashMap<String, String>,
    ) -> TEEResult<Vec<u8>> {
        // Serialize environment for enclave
        let mut env_data = Vec::new();
        for (key, value) in environment {
            env_data.extend_from_slice(key.as_bytes());
            env_data.push(0); // Null terminator
            env_data.extend_from_slice(value.as_bytes());
            env_data.push(0); // Null terminator
        }

        // Execute within enclave
        let function_id_clone = function_id.to_string();
        let args_clone = args.to_vec();
        let env_data_clone = env_data.clone();

        enclave.execute(move || execute_function(&function_id_clone, &args_clone, &env_data_clone))
    }

    /// Execute function in remote TEE
    async fn execute_remote(
        &self,
        function_id: &str,
        args: &[Vec<u8>],
        environment: &HashMap<String, String>,
    ) -> TEEResult<Vec<u8>> {
        self.tee_client
            .execute_function(function_id, args, environment)
            .await
    }

    /// Generate execution proof
    async fn generate_execution_proof(
        &self,
        function_id: &str,
        args: &[Vec<u8>],
        result: &[u8],
    ) -> TEEResult<Vec<u8>> {
        // Create function data
        let mut function_data = Vec::new();
        function_data.extend_from_slice(function_id.as_bytes());

        // Generate MCP
        self.mcp_generator
            .generate_proof(result, &function_data, args)
    }

    /// Check execution cache
    async fn check_cache(&self, cache_key: &str) -> Option<ExecutionResult> {
        let cache = self.execution_cache.lock().await;

        if let Some(entry) = cache.entries.get(cache_key) {
            // Check if expired
            if Instant::now() < entry.expires_at {
                return Some(entry.result.clone());
            }
        }

        None
    }

    /// Cache execution result
    async fn cache_result(&self, cache_key: &str, result: ExecutionResult) -> TEEResult<()> {
        let mut cache = self.execution_cache.lock().await;

        // Evict if cache is full
        if cache.entries.len() >= cache.max_entries {
            // Find least recently used entry
            let oldest_key = cache
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.timestamp)
                .map(|(key, _)| key.clone());

            if let Some(key) = oldest_key {
                cache.entries.remove(&key);
            }
        }

        // Add new entry to cache
        cache.entries.insert(
            cache_key.to_string(),
            CachedExecution {
                result: result.clone(),
                timestamp: Instant::now(),
                expires_at: Instant::now() + Duration::from_secs(3600), // 1 hour expiration
            },
        );

        Ok(())
    }

    /// Execute function remotely
    async fn execute_remote(
        &self,
        function_id: &str,
        args: &[Vec<u8>],
        environment: &HashMap<String, String>,
    ) -> TEEResult<Vec<u8>> {
        let mut attempts = 0;
        let mut backoff = Duration::from_secs(1);

        loop {
            match self
                .tee_client
                .execute_function(function_id, args, environment)
                .await
            {
                Ok(result) => return Ok(result),
                Err(e) => {
                    attempts += 1;
                    if attempts >= self.config.max_retries {
                        return Err(e);
                    }
                    log::warn!("Remote execution attempt {} failed: {}", attempts, e);
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff * 2, MAX_RETRY_BACKOFF);
                }
            }
        }
    }

    /// Schedule function execution
    pub async fn schedule_execution(
        &self,
        function_id: &str,
        args: Vec<Vec<u8>>,
        environment: HashMap<String, String>,
        schedule_time: SystemTime,
    ) -> TEEResult<String> {
        // Generate schedule ID
        let schedule_id = uuid::Uuid::new_v4().to_string();

        // Submit to TEE client
        self.tee_client
            .schedule_function(function_id, &args, &environment, schedule_time)
            .await?;

        Ok(schedule_id)
    }

    /// Cancel scheduled execution
    pub async fn cancel_scheduled_execution(&self, schedule_id: &str) -> TEEResult<()> {
        self.tee_client.cancel_scheduled_function(schedule_id).await
    }

    /// Get execution metrics
    pub async fn get_metrics(&self) -> TEEResult<ExecutionMetrics> {
        let metrics = self.metrics.lock().await;
        Ok(metrics.clone())
    }

    /// Get cache stats
    pub async fn get_cache_stats(&self) -> TEEResult<(usize, usize)> {
        let stats = self.execution_stats.lock().await;
        Ok((stats.cache_hits as usize, stats.cache_misses as usize))
    }

    /// Update execution stats
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

    /// Update cache stats
    async fn update_cache_stats(&self, hit: bool) {
        let mut stats = self.execution_stats.lock().await;
        if hit {
            stats.cache_hits += 1;
        } else {
            stats.cache_misses += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    #[test]
    async fn test_compute_integration() -> TEEResult<()> {
        let compute = ComputeTEEIntegration::new("http://localhost:9000");

        // Test function execution
        let result = compute
            .execute_serverless_function("test_function", vec![vec![1, 2, 3]], HashMap::new())
            .await?;

        assert!(result.result.len() > 0);
        assert!(result.proof.len() > 0);

        Ok(())
    }

    #[test]
    async fn test_cache() -> TEEResult<()> {
        let compute = ComputeTEEIntegration::new("http://localhost:9000");

        // Execute function twice to test cache
        let args = vec![vec![1, 2, 3]];
        let env = HashMap::new();

        let result1 = compute
            .execute_serverless_function("test_function", args.clone(), env.clone())
            .await?;
        let result2 = compute
            .execute_serverless_function("test_function", args.clone(), env.clone())
            .await?;

        let (hits, misses) = compute.get_cache_stats().await?;
        assert_eq!(hits, 1);
        assert_eq!(misses, 1);

        Ok(())
    }

    #[test]
    async fn test_scheduled_execution() -> TEEResult<()> {
        let compute = ComputeTEEIntegration::new("http://localhost:9000");

        let schedule_time = SystemTime::now() + Duration::from_secs(60);
        let schedule_id = compute
            .schedule_execution(
                "test_function",
                vec![vec![1, 2, 3]],
                HashMap::new(),
                schedule_time,
            )
            .await?;

        assert!(!schedule_id.is_empty());

        // Cancel scheduled execution
        compute.cancel_scheduled_execution(&schedule_id).await?;

        Ok(())
    }
}
