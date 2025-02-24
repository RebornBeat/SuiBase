//! Intel SGX Enclave Implementation

use crate::core::attestation::Attestation;
use crate::core::enclave::SecureEnclave;
use crate::core::error::{TEEError, TEEResult};
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Intel SGX Enclave implementation
pub struct SGXEnclave {
    /// Enclave handle
    enclave: Arc<Mutex<SgxEnclave>>,

    /// Enclave measurement
    measurement: Vec<u8>,

    /// Enclave memory settings
    memory_size: usize,

    /// Enclave metadata
    metadata: HashMap<String, String>,

    /// Enclave ID
    id: String,

    /// Sealing key for data protection
    sealing_key: Vec<u8>,
}

impl SGXEnclave {
    /// Create a new SGX enclave
    pub fn new(memory_size: usize, metadata: HashMap<String, String>) -> TEEResult<Self> {
        // Load enclave from signed binary
        let enclave_path =
            std::env::var("SGX_ENCLAVE_PATH").map_err(|_| TEEError::EnclaveError {
                reason: "SGX_ENCLAVE_PATH not set".to_string(),
                details:
                    "Environment variable SGX_ENCLAVE_PATH must point to signed enclave binary"
                        .to_string(),
                source: None,
            })?;

        let mut launch_token: sgx_launch_token_t = [0; 1024];
        let mut launch_token_updated: i32 = 0;

        // Initialize enclave
        let enclave = SgxEnclave::create(
            &enclave_path,
            SGX_DEBUG_FLAG_FALSE, // No debug mode in production
            &mut launch_token,
            &mut launch_token_updated,
            None,
        )
        .map_err(|e| TEEError::EnclaveError {
            reason: "Failed to create SGX enclave".to_string(),
            details: format!("SGX error: {}", e),
            source: None,
        })?;

        // Generate enclave ID
        let id = uuid::Uuid::new_v4().to_string();

        // Get enclave measurement (MRENCLAVE)
        let measurement = Self::get_enclave_measurement(&enclave)?;

        // Generate sealing key
        let sealing_key = Self::generate_sealing_key(&enclave)?;

        Ok(Self {
            enclave: Arc::new(Mutex::new(enclave)),
            measurement,
            memory_size,
            metadata,
            id,
            sealing_key,
        })
    }

    /// Get enclave measurement (MRENCLAVE)
    fn get_enclave_measurement(enclave: &SgxEnclave) -> TEEResult<Vec<u8>> {
        let mut report = sgx_report_t::default();

        // Get enclave report containing measurement
        unsafe {
            sgx_create_report(std::ptr::null(), std::ptr::null(), &mut report).map_err(|e| {
                TEEError::EnclaveError {
                    reason: "Failed to get enclave report".to_string(),
                    details: format!("SGX error: {}", e),
                    source: None,
                }
            })?;
        }

        Ok(report.body.mr_enclave.m.to_vec())
    }

    /// Generate sealing key for data protection
    fn generate_sealing_key(enclave: &SgxEnclave) -> TEEResult<Vec<u8>> {
        let mut key_request = sgx_key_request_t::default();
        key_request.key_name = SGX_KEYSELECT_SEAL;
        key_request.key_policy = SGX_KEYPOLICY_MRENCLAVE;

        let mut key = sgx_key_128bit_t::default();

        unsafe {
            sgx_get_key(&key_request, &mut key).map_err(|e| TEEError::EnclaveError {
                reason: "Failed to generate sealing key".to_string(),
                details: format!("SGX error: {}", e),
                source: None,
            })?;
        }

        Ok(key.to_vec())
    }
}

impl SecureEnclave for SGXEnclave {
    /// Get enclave identifier
    fn get_id(&self) -> &str {
        &self.id
    }

    /// Execute computation in enclave
    fn execute<F, R>(&self, computation: F) -> TEEResult<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let enclave = self.enclave.lock().map_err(|_| TEEError::EnclaveError {
            reason: "Failed to lock enclave".to_string(),
            details: "Mutex lock failed".to_string(),
            source: None,
        })?;

        // Create secure execution context
        let mut ret = sgx_status_t::SGX_SUCCESS;

        unsafe {
            // Enter enclave to execute computation
            sgx_ecall_execute(
                enclave.geteid(),
                &mut ret,
                Box::into_raw(Box::new(computation)) as *mut _,
            )
            .map_err(|e| TEEError::EnclaveError {
                reason: "Enclave execution failed".to_string(),
                details: format!("SGX error: {}", e),
                source: None,
            })?;
        }

        Ok(computation())
    }

    /// Get attestation for this enclave
    fn get_attestation(&self) -> TEEResult<Attestation> {
        use crate::platforms::intel_sgx::attestation::SGXAttestationUtil;

        // Generate attestation report
        let report = SGXAttestationUtil::generate_report(&self.measurement)?;

        // Create attestation
        let attestation = Attestation::new(
            self.id.clone(),
            "intel_sgx".to_string(),
            report,
            vec![], // Public key added by attestation service
            self.measurement.clone(),
        );

        Ok(attestation)
    }

    /// Get enclave measurement
    fn get_measurement(&self) -> Vec<u8> {
        self.measurement.clone()
    }

    /// Initialize enclave
    fn initialize(&mut self) -> TEEResult<()> {
        let enclave = self.enclave.lock().map_err(|_| TEEError::EnclaveError {
            reason: "Failed to lock enclave".to_string(),
            details: "Mutex lock failed".to_string(),
            source: None,
        })?;

        // Initialize enclave state
        let mut ret = sgx_status_t::SGX_SUCCESS;
        unsafe {
            sgx_ecall_init(enclave.geteid(), &mut ret, self.memory_size as u64).map_err(|e| {
                TEEError::EnclaveError {
                    reason: "Enclave initialization failed".to_string(),
                    details: format!("SGX error: {}", e),
                    source: None,
                }
            })?;
        }

        Ok(())
    }
}

impl Drop for SGXEnclave {
    fn drop(&mut self) {
        if let Ok(enclave) = self.enclave.lock() {
            unsafe {
                enclave.destroy();
            }
        }
    }
}

// External functions defined in enclave
extern "C" {
    fn sgx_ecall_execute(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        computation: *mut libc::c_void,
    ) -> sgx_status_t;

    fn sgx_ecall_init(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        memory_size: u64,
    ) -> sgx_status_t;
}
