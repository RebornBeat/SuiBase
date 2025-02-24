//! Intel SGX Platform Attestation Implementation

use crate::core::attestation::AttestationReportData;
use crate::core::error::{TEEError, TEEResult};
use sgx_quote::{
    QuoteType, sgx_calc_quote_size, sgx_get_quote, sgx_get_quote_size, sgx_init_quote,
};
use sgx_types::{sgx_quote_t, sgx_report_t, sgx_target_info_t};
use sgx_urts::SgxEnclave;

/// Constants for SGX attestation
pub const SGX_QUOTE_MIN_SIZE: usize = 432;
pub const SGX_MEASUREMENT_SIZE: usize = 32;
pub const SGX_MAX_QUOTE_SIZE: usize = 8192;

/// Intel SGX Attestation Utility
pub struct SGXAttestationUtil;

impl SGXAttestationUtil {
    /// Generate a production SGX attestation report
    pub fn generate_report(measurement: &[u8]) -> TEEResult<Vec<u8>> {
        // Check measurement size
        if measurement.len() != SGX_MEASUREMENT_SIZE {
            return Err(TEEError::AttestationError(format!(
                "Invalid measurement size: {}, expected {}",
                measurement.len(),
                SGX_MEASUREMENT_SIZE
            )));
        }

        // Initialize SGX quote
        let mut qe_target_info = sgx_target_info_t::default();
        let mut gid = 0u32;

        let sgx_status = unsafe { sgx_init_quote(&mut qe_target_info, &mut gid) };

        if sgx_status != sgx_types::SGX_SUCCESS {
            return Err(TEEError::AttestationError(format!(
                "Failed to initialize SGX quote: {:#x}",
                sgx_status
            )));
        }

        // Create enclave report
        let report = Self::create_enclave_report(&qe_target_info, measurement)?;

        // Get quote size
        let mut quote_size = 0u32;
        let sgx_status = unsafe { sgx_calc_quote_size(std::ptr::null(), 0, &mut quote_size) };

        if sgx_status != sgx_types::SGX_SUCCESS {
            return Err(TEEError::AttestationError(format!(
                "Failed to calculate quote size: {:#x}",
                sgx_status
            )));
        }

        // Validate quote size
        if quote_size as usize > SGX_MAX_QUOTE_SIZE {
            return Err(TEEError::AttestationError(format!(
                "Quote size too large: {}",
                quote_size
            )));
        }

        // Allocate quote buffer
        let mut quote_buffer = vec![0u8; quote_size as usize];

        // Generate quote
        let sgx_status = unsafe {
            sgx_get_quote(
                &report,
                QuoteType::Linkable,
                &gid,
                std::ptr::null(),
                std::ptr::null(),
                0,
                std::ptr::null(),
                quote_buffer.as_mut_ptr() as *mut sgx_quote_t,
                quote_size,
            )
        };

        if sgx_status != sgx_types::SGX_SUCCESS {
            return Err(TEEError::AttestationError(format!(
                "Failed to generate quote: {:#x}",
                sgx_status
            )));
        }

        Ok(quote_buffer)
    }

    /// Verify SGX attestation report using Intel Attestation Service
    pub fn verify_report(report: &[u8]) -> TEEResult<bool> {
        // Validate report size
        if report.len() < SGX_QUOTE_MIN_SIZE {
            return Err(TEEError::AttestationError(format!(
                "Quote too small: {}, minimum size: {}",
                report.len(),
                SGX_QUOTE_MIN_SIZE
            )));
        }

        // Extract quote from report
        let quote = unsafe { &*(report.as_ptr() as *const sgx_quote_t) };

        // Verify quote signature and certificate chain using IAS
        let ias_client = IasClient::new()?;
        let result = ias_client.verify_quote(&quote)?;

        if !result.isv_enclave_quote_status_valid() {
            return Ok(false);
        }

        // Verify platform attributes
        if !Self::verify_platform_attributes(&quote.report_body) {
            return Ok(false);
        }

        // Verify enclave attributes
        if !Self::verify_enclave_attributes(&quote.report_body) {
            return Ok(false);
        }

        Ok(true)
    }

    /// Parse SGX attestation report
    pub fn parse_report(report: &[u8]) -> TEEResult<AttestationReportData> {
        // Validate report size
        if report.len() < SGX_QUOTE_MIN_SIZE {
            return Err(TEEError::AttestationError(format!(
                "Quote too small: {}, minimum size: {}",
                report.len(),
                SGX_QUOTE_MIN_SIZE
            )));
        }

        // Parse quote structure
        let quote = unsafe { &*(report.as_ptr() as *const sgx_quote_t) };

        // Extract measurement (MRENCLAVE)
        let measurement = quote.report_body.mr_enclave.m.to_vec();

        // Get timestamp from quote
        let timestamp = Self::extract_timestamp(quote)?;

        Ok(AttestationReportData {
            platform: "intel_sgx".to_string(),
            quote: report.to_vec(),
            measurement,
            timestamp,
        })
    }

    /// Create enclave report for attestation
    fn create_enclave_report(
        qe_target_info: &sgx_target_info_t,
        measurement: &[u8],
    ) -> TEEResult<sgx_report_t> {
        // Initialize report data with measurement
        let mut report_data = sgx_types::sgx_report_data_t::default();
        report_data.d[..measurement.len()].copy_from_slice(measurement);

        // Create enclave report
        let mut report = sgx_report_t::default();
        let sgx_status = unsafe { sgx_create_report(qe_target_info, &report_data, &mut report) };

        if sgx_status != sgx_types::SGX_SUCCESS {
            return Err(TEEError::AttestationError(format!(
                "Failed to create enclave report: {:#x}",
                sgx_status
            )));
        }

        Ok(report)
    }

    /// Verify platform security attributes
    fn verify_platform_attributes(report_body: &sgx_report_body_t) -> bool {
        // Check CPU security version
        if report_body.cpu_svn[0] < MIN_CPU_SVN {
            return false;
        }

        // Verify required CPU features
        if !report_body.attributes.flags.contains(SGX_FLAGS_MODE64BIT) {
            return false;
        }

        // Additional platform checks...
        true
    }

    /// Verify enclave security attributes
    fn verify_enclave_attributes(report_body: &sgx_report_body_t) -> bool {
        // Verify enclave flags
        if report_body.attributes.flags.contains(SGX_FLAGS_DEBUG) {
            return false;
        }

        // Verify enclave product ID
        if report_body.isv_prod_id != EXPECTED_PROD_ID {
            return false;
        }

        // Additional enclave checks...
        true
    }

    /// Extract timestamp from quote
    fn extract_timestamp(quote: &sgx_quote_t) -> TEEResult<u64> {
        // Get timestamp from quote
        let timestamp_bytes = &quote.report_body.report_data.d[..8];

        let timestamp = u64::from_le_bytes(
            timestamp_bytes
                .try_into()
                .map_err(|_| TEEError::AttestationError("Invalid timestamp format".to_string()))?,
        );

        Ok(timestamp)
    }
}

/// Intel Attestation Service client
struct IasClient {
    // IAS connection details
    api_key: String,
    endpoint: String,
}

impl IasClient {
    /// Create new IAS client
    fn new() -> TEEResult<Self> {
        // Load IAS credentials from secure configuration
        let config = crate::utils::config::ConfigurationManager::load_config("ias.conf")?;

        Ok(Self {
            api_key: config.get_string("ias_api_key")?,
            endpoint: config.get_string("ias_endpoint")?,
        })
    }

    /// Verify quote with IAS
    fn verify_quote(&self, quote: &sgx_quote_t) -> TEEResult<IasResponse> {
        // Make request to IAS verification endpoint
        let client = reqwest::blocking::Client::new();
        let response = client
            .post(&format!("{}/attestation/v4/report", self.endpoint))
            .header("Ocp-Apim-Subscription-Key", &self.api_key)
            .json(&quote)
            .send()?;

        if !response.status().is_success() {
            return Err(TEEError::AttestationError(format!(
                "IAS request failed: {}",
                response.status()
            )));
        }

        // Parse and validate IAS response
        let ias_response: IasResponse = response.json()?;
        Ok(ias_response)
    }
}

/// Intel Attestation Service response
#[derive(Deserialize)]
struct IasResponse {
    id: String,
    timestamp: String,
    version: u32,
    isv_enclave_quote_status: String,
    isv_enclave_quote_body: String,
}

impl IasResponse {
    /// Check if quote status is valid
    fn isv_enclave_quote_status_valid(&self) -> bool {
        matches!(
            self.isv_enclave_quote_status.as_str(),
            "OK" | "GROUP_OUT_OF_DATE" | "CONFIGURATION_NEEDED"
        )
    }
}
