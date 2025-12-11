use crate::types::Certificate;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};
use x509_cert::{
    der::Decode,
    Certificate as X509Certificate,
};

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn add_error(&mut self, error: String) {
        self.is_valid = false;
        self.errors.push(error);
    }

    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    pub fn is_valid(&self) -> bool {
        self.is_valid
    }
}

#[derive(Debug, Clone)]
pub struct ChainValidationResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub chain_length: usize,
    pub trust_anchor_found: bool,
}

pub struct CertificateValidator;

impl CertificateValidator {
    pub fn validate_certificate(cert: &Certificate) -> Result<ValidationResult> {
        let mut result = ValidationResult::new();

        if let Err(e) = Self::validate_expiration(cert, &mut result) {
            result.add_error(format!("Expiration validation failed: {}", e));
        }

        if let Err(e) = Self::validate_signature(cert, &mut result) {
            result.add_error(format!("Signature validation failed: {}", e));
        }

        if let Err(e) = Self::validate_key_usage(cert, &mut result) {
            result.add_error(format!("Key usage validation failed: {}", e));
        }

        if let Err(e) = Self::validate_basic_constraints(cert, &mut result) {
            result.add_error(format!("Basic constraints validation failed: {}", e));
        }

        Ok(result)
    }

    fn validate_expiration(cert: &Certificate, result: &mut ValidationResult) -> Result<()> {
        let now = Utc::now();

        if now < cert.not_before {
            result.add_error(format!(
                "Certificate is not yet valid. Valid from: {}",
                cert.not_before
            ));
        }

        if now > cert.not_after {
            result.add_error(format!(
                "Certificate has expired. Expired on: {}",
                cert.not_after
            ));
        } else {
            let days_remaining = (cert.not_after - now).num_days();
            if days_remaining <= 30 {
                result.add_warning(format!(
                    "Certificate will expire soon ({} days remaining)",
                    days_remaining
                ));
            }
        }

        Ok(())
    }

    fn validate_signature(cert: &Certificate, result: &mut ValidationResult) -> Result<()> {
        let cert_pem = cert.certificate_pem.as_bytes();
        let parsed_cert = Self::parse_pem_certificate(cert_pem)?;

        let calculated_fingerprint = Self::calculate_fingerprint(&parsed_cert)?;

        if calculated_fingerprint != cert.fingerprint_sha256 {
            result.add_error(format!(
                "Certificate fingerprint mismatch. Expected: {}, Got: {}",
                cert.fingerprint_sha256, calculated_fingerprint
            ));
        }

        Ok(())
    }

    fn validate_key_usage(cert: &Certificate, _result: &mut ValidationResult) -> Result<()> {
        let cert_pem = cert.certificate_pem.as_bytes();
        let parsed_cert = Self::parse_pem_certificate(cert_pem)?;

        if parsed_cert.tbs_certificate.extensions.is_some() {
        }

        Ok(())
    }

    fn validate_basic_constraints(cert: &Certificate, result: &mut ValidationResult) -> Result<()> {
        let cert_pem = cert.certificate_pem.as_bytes();
        let parsed_cert = Self::parse_pem_certificate(cert_pem)?;

        if let Some(extensions) = &parsed_cert.tbs_certificate.extensions {
            for ext in extensions.iter() {
                if ext.extn_id.to_string() == "2.5.29.19" {
                    if let Ok(basic_constraints) = x509_cert::ext::pkix::BasicConstraints::from_der(ext.extn_value.as_bytes()) {
                        match cert.purpose {
                            crate::types::CertificatePurpose::RootCa
                            | crate::types::CertificatePurpose::IntermediateCa => {
                                if !basic_constraints.ca {
                                    result.add_error(
                                        "Certificate is marked as CA but basicConstraints.ca is false".to_string()
                                    );
                                }
                            }
                            _ => {
                                if basic_constraints.ca {
                                    result.add_warning(
                                        "Non-CA certificate has basicConstraints.ca set to true".to_string()
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn validate_chain(
        cert: &Certificate,
        intermediate_certs: &[&Certificate],
        root_cert: Option<&Certificate>,
    ) -> Result<ChainValidationResult> {
        let mut result = ChainValidationResult {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            chain_length: 1 + intermediate_certs.len() + if root_cert.is_some() { 1 } else { 0 },
            trust_anchor_found: root_cert.is_some(),
        };

        let parsed_cert = Self::parse_pem_certificate(cert.certificate_pem.as_bytes())?;
        let mut parsed_intermediates = Vec::new();
        for intermediate in intermediate_certs {
            parsed_intermediates.push(Self::parse_pem_certificate(intermediate.certificate_pem.as_bytes())?);
        }
        let parsed_root = if let Some(root) = root_cert {
            Some(Self::parse_pem_certificate(root.certificate_pem.as_bytes())?)
        } else {
            None
        };

        if cert.issuer == cert.subject {
            if intermediate_certs.is_empty() && root_cert.is_none() {
                result.warnings.push("Self-signed certificate without explicit root CA".to_string());
                return Ok(result);
            }
        }

        let mut current_issuer = cert.issuer.clone();

        for (i, intermediate) in intermediate_certs.iter().enumerate() {
            if intermediate.subject != current_issuer {
                result.is_valid = false;
                result.errors.push(format!(
                    "Chain break at intermediate certificate {}: expected issuer '{}', found '{}'",
                    i, current_issuer, intermediate.subject
                ));
                return Ok(result);
            }

            if intermediate.is_expired() {
                result.is_valid = false;
                result.errors.push(format!(
                    "Intermediate certificate {} has expired",
                    intermediate.name
                ));
            }

            let subject_idx = if i == 0 { None } else { Some(i - 1) };
            if let Err(e) = Self::verify_signature_by_index(&parsed_cert, &parsed_intermediates, subject_idx, i) {
                result.is_valid = false;
                result.errors.push(format!(
                    "Signature verification failed for intermediate certificate {}: {}",
                    i, e
                ));
            }

            current_issuer = intermediate.issuer.clone();
        }

        if let Some(root) = root_cert {
            if root.subject != current_issuer {
                result.is_valid = false;
                result.errors.push(format!(
                    "Chain break at root certificate: expected issuer '{}', found '{}'",
                    current_issuer, root.subject
                ));
                return Ok(result);
            }

            if root.is_expired() {
                result.is_valid = false;
                result.errors.push(format!("Root certificate has expired"));
            }

            if let Some(parsed_root_cert) = &parsed_root {
                let subject_idx = if intermediate_certs.is_empty() {
                    None
                } else {
                    Some(intermediate_certs.len() - 1)
                };
                if let Err(e) = Self::verify_root_signature(&parsed_cert, &parsed_intermediates, subject_idx, parsed_root_cert) {
                    result.is_valid = false;
                    result.errors.push(format!("Signature verification failed for root certificate: {}", e));
                }
            }

            if root.subject != root.issuer {
                result.warnings.push("Root certificate is not self-signed".to_string());
            }
        } else {
            result.warnings.push("No root certificate provided for chain validation".to_string());
        }

        Ok(result)
    }

    fn verify_signature_by_index(
        _leaf_cert: &X509Certificate,
        _intermediates: &[X509Certificate],
        _subject_idx: Option<usize>,
        _issuer_idx: usize,
    ) -> Result<()> {
        Ok(())
    }

    fn verify_root_signature(
        _leaf_cert: &X509Certificate,
        _intermediates: &[X509Certificate],
        _subject_idx: Option<usize>,
        _root_cert: &X509Certificate,
    ) -> Result<()> {
        Ok(())
    }

    fn parse_pem_certificate(pem_data: &[u8]) -> Result<X509Certificate> {
        let pem_str = std::str::from_utf8(pem_data)?;
        let pem_lines: Vec<&str> = pem_str.lines().collect();

        let mut cert_lines = Vec::new();
        let mut in_cert = false;

        for line in pem_lines {
            if line.contains("BEGIN CERTIFICATE") {
                in_cert = true;
                continue;
            }
            if line.contains("END CERTIFICATE") {
                break;
            }
            if in_cert {
                cert_lines.push(line);
            }
        }

        let cert_base64 = cert_lines.join("");
        let cert_der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &cert_base64)?;

        X509Certificate::from_der(&cert_der).map_err(|e| anyhow!("Failed to parse certificate: {}", e))
    }

    fn calculate_fingerprint(cert: &X509Certificate) -> Result<String> {
        use x509_cert::der::Encode;
        let der_bytes = cert.to_der()?;
        let mut hasher = Sha256::new();
        hasher.update(&der_bytes);
        let hash = hasher.finalize();
        Ok(hex::encode(hash))
    }

    pub fn check_expiration_batch(certs: &[Certificate]) -> Vec<(String, ExpirationStatus)> {
        certs
            .iter()
            .map(|cert| {
                let status = if cert.is_expired() {
                    ExpirationStatus::Expired
                } else {
                    let days = cert.days_until_expiration();
                    if days <= 7 {
                        ExpirationStatus::Critical(days)
                    } else if days <= 30 {
                        ExpirationStatus::Warning(days)
                    } else {
                        ExpirationStatus::Valid(days)
                    }
                };
                (cert.name.clone(), status)
            })
            .collect()
    }

    pub fn find_certificates_needing_renewal(
        certs: &[Certificate],
        days_threshold: i64,
    ) -> Vec<String> {
        certs
            .iter()
            .filter(|cert| cert.needs_renewal(days_threshold))
            .map(|cert| cert.name.clone())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExpirationStatus {
    Expired,
    Critical(i64),
    Warning(i64),
    Valid(i64),
}

impl ExpirationStatus {
    pub fn days_remaining(&self) -> Option<i64> {
        match self {
            ExpirationStatus::Expired => None,
            ExpirationStatus::Critical(days)
            | ExpirationStatus::Warning(days)
            | ExpirationStatus::Valid(days) => Some(*days),
        }
    }

    pub fn is_expired(&self) -> bool {
        matches!(self, ExpirationStatus::Expired)
    }

    pub fn is_critical(&self) -> bool {
        matches!(self, ExpirationStatus::Critical(_))
    }

    pub fn is_warning(&self) -> bool {
        matches!(self, ExpirationStatus::Warning(_))
    }
}
