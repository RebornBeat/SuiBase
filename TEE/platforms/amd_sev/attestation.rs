use crate::core::attestation::AttestationReportData;
use crate::core::error::{TEEError, TEEResult};
use sev::certs::sev::Certificate;
use sev::firmware::Firmware; // AMD SEV API
use sev::launch::Policy;
use sev::measurement::TcbVersion;
use sha2::{Digest, Sha384}; // SEV uses SHA-384

/// AMD SEV-specific constants
const SEV_REPORT_SIZE: usize = 1184; // Size of SEV attestation report
const SEV_MEASUREMENT_SIZE: usize = 48; // SHA-384 measurement size
const SEV_SIGNATURE_SIZE: usize = 512; // SEV signature size

/// AMD SEV Attestation Utility
pub struct SEVAttestationUtil;

impl SEVAttestationUtil {
    /// Generate a SEV attestation report using AMD's SEV API
    pub fn generate_report(measurement: &[u8]) -> TEEResult<Vec<u8>> {
        // Open SEV firmware device
        let fw = Firmware::open().map_err(|e| TEEError::AttestationError {
            reason: "Failed to open SEV firmware".to_string(),
            details: e.to_string(),
            source: None,
        })?;

        // Validate firmware version
        let fw_version = fw
            .get_platform_version()
            .map_err(|e| TEEError::AttestationError {
                reason: "Failed to get SEV firmware version".to_string(),
                details: e.to_string(),
                source: None,
            })?;

        // Check for minimum required version (SEV-SNP for strongest attestation)
        if !fw_version.supports_snp() {
            return Err(TEEError::AttestationError {
                reason: "Insufficient SEV version".to_string(),
                details: "SEV-SNP required for secure attestation".to_string(),
                source: None,
            });
        }

        // Generate launch policy for the SEV guest
        let policy = Policy::default()
            .set_debug(false) // Disable debug mode for production
            .set_migrate(false); // Disable migration for security

        // Get platform certificates
        let chain = fw
            .pdh_cert_export()
            .map_err(|e| TEEError::AttestationError {
                reason: "Failed to export platform certificates".to_string(),
                details: e.to_string(),
                source: None,
            })?;

        // Generate attestation report
        let report = fw
            .get_attestation_report(
                measurement,
                &policy,
                &chain.cek, // Include CEK certificate
                &chain.pdh, // Include platform certificate
            )
            .map_err(|e| TEEError::AttestationError {
                reason: "Failed to generate attestation report".to_string(),
                details: e.to_string(),
                source: None,
            })?;

        // Encode the complete report
        let mut report_data = Vec::with_capacity(SEV_REPORT_SIZE);
        report_data.extend_from_slice(&report.signature); // Add report signature
        report_data.extend_from_slice(&report.measurement); // Add measurement
        report_data.extend_from_slice(&report.host_data); // Add host data
        report_data.extend_from_slice(&report.id_block); // Add ID block
        report_data.extend_from_slice(&report.id_auth); // Add ID auth
        report_data.extend_from_slice(&report.vcek_cert); // Add VCEK certificate

        Ok(report_data)
    }

    /// Verify SEV attestation report
    pub fn verify_report(report: &[u8]) -> TEEResult<bool> {
        // Validate report size
        if report.len() != SEV_REPORT_SIZE {
            return Err(TEEError::AttestationError {
                reason: "Invalid report size".to_string(),
                details: format!("Expected {} bytes, got {}", SEV_REPORT_SIZE, report.len()),
                source: None,
            });
        }

        // Extract components from report
        let (signature, rest) = report.split_at(SEV_SIGNATURE_SIZE);
        let (measurement, rest) = rest.split_at(SEV_MEASUREMENT_SIZE);
        let (host_data, rest) = rest.split_at(64); // Fixed size host data
        let (id_block, rest) = rest.split_at(256); // Fixed size ID block
        let (id_auth, vcek_cert) = rest.split_at(256); // Remaining parts

        // Parse VCEK certificate
        let vcek = Certificate::from_bytes(vcek_cert).map_err(|e| TEEError::AttestationError {
            reason: "Failed to parse VCEK certificate".to_string(),
            details: e.to_string(),
            source: None,
        })?;

        // Verify certificate chain
        vcek.verify().map_err(|e| TEEError::AttestationError {
            reason: "Invalid VCEK certificate".to_string(),
            details: e.to_string(),
            source: None,
        })?;

        // Verify report signature using VCEK public key
        let msg = [measurement, host_data, id_block, id_auth].concat();
        vcek.verify_signature(&msg, signature)
            .map_err(|e| TEEError::AttestationError {
                reason: "Invalid report signature".to_string(),
                details: e.to_string(),
                source: None,
            })?;

        // Verify TCB version is current
        let tcb = TcbVersion::from_bytes(&id_block[224..228]).map_err(|e| {
            TEEError::AttestationError {
                reason: "Invalid TCB version".to_string(),
                details: e.to_string(),
                source: None,
            }
        })?;

        if !tcb.is_current() {
            return Err(TEEError::AttestationError {
                reason: "Outdated TCB version".to_string(),
                details: "Platform firmware requires update".to_string(),
                source: None,
            });
        }

        Ok(true)
    }

    /// Parse SEV attestation report into standard format
    pub fn parse_report(report: &[u8]) -> TEEResult<AttestationReportData> {
        if report.len() != SEV_REPORT_SIZE {
            return Err(TEEError::AttestationError {
                reason: "Invalid report size".to_string(),
                details: format!("Expected {} bytes, got {}", SEV_REPORT_SIZE, report.len()),
                source: None,
            });
        }

        // Extract measurement from report (fixed offset in SEV report)
        let measurement =
            report[SEV_SIGNATURE_SIZE..SEV_SIGNATURE_SIZE + SEV_MEASUREMENT_SIZE].to_vec();

        // Get timestamp from report ID block (fixed position in SEV format)
        let timestamp_bytes = &report[SEV_SIGNATURE_SIZE + SEV_MEASUREMENT_SIZE + 64 + 216..][..8];
        let timestamp = u64::from_le_bytes(timestamp_bytes.try_into().unwrap());

        Ok(AttestationReportData {
            platform: "amd_sev".to_string(),
            quote: report.to_vec(),
            measurement,
            timestamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sev_platform_availability() {
        // Verify SEV hardware is available
        let fw = Firmware::open();
        assert!(fw.is_ok(), "SEV firmware not available");

        if let Ok(fw) = fw {
            let version = fw.get_platform_version();
            assert!(version.is_ok(), "Failed to get SEV version");

            if let Ok(version) = version {
                assert!(version.supports_snp(), "SEV-SNP not supported");
            }
        }
    }
}
