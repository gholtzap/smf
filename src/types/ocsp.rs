use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspRequest {
    pub cert_ids: Vec<CertId>,
    pub nonce: Option<Vec<u8>>,
    pub requestor_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CertId {
    pub hash_algorithm: HashAlgorithm,
    pub issuer_name_hash: Vec<u8>,
    pub issuer_key_hash: Vec<u8>,
    pub serial_number: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub fn oid(&self) -> &'static [u8] {
        match self {
            HashAlgorithm::Sha1 => &[0x2B, 0x0E, 0x03, 0x02, 0x1A],
            HashAlgorithm::Sha256 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            HashAlgorithm::Sha384 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02],
            HashAlgorithm::Sha512 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
        }
    }

    pub fn hash_size(&self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 20,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspResponse {
    pub response_status: OcspResponseStatus,
    pub response_bytes: Option<OcspResponseBytes>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OcspResponseStatus {
    Successful,
    MalformedRequest,
    InternalError,
    TryLater,
    SigRequired,
    Unauthorized,
}

impl OcspResponseStatus {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(OcspResponseStatus::Successful),
            1 => Some(OcspResponseStatus::MalformedRequest),
            2 => Some(OcspResponseStatus::InternalError),
            3 => Some(OcspResponseStatus::TryLater),
            5 => Some(OcspResponseStatus::SigRequired),
            6 => Some(OcspResponseStatus::Unauthorized),
            _ => None,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            OcspResponseStatus::Successful => 0,
            OcspResponseStatus::MalformedRequest => 1,
            OcspResponseStatus::InternalError => 2,
            OcspResponseStatus::TryLater => 3,
            OcspResponseStatus::SigRequired => 5,
            OcspResponseStatus::Unauthorized => 6,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspResponseBytes {
    pub response_type: String,
    pub response: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicOcspResponse {
    pub tbs_response_data: ResponseData,
    pub signature_algorithm: String,
    pub signature: Vec<u8>,
    pub certs: Option<Vec<Vec<u8>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseData {
    pub version: u8,
    pub responder_id: ResponderId,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub produced_at: DateTime<Utc>,
    pub responses: Vec<SingleResponse>,
    pub response_extensions: Option<Vec<Extension>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ResponderId {
    ByName { name: String },
    ByKey { key_hash: Vec<u8> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleResponse {
    pub cert_id: CertId,
    pub cert_status: CertStatus,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub this_update: DateTime<Utc>,
    #[serde(with = "crate::utils::serde_helpers::optional_datetime")]
    pub next_update: Option<DateTime<Utc>>,
    pub single_extensions: Option<Vec<Extension>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertStatus {
    Good,
    Revoked {
        revocation_time: i64,
        revocation_reason: Option<u8>,
    },
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extension {
    pub extn_id: Vec<u8>,
    pub critical: bool,
    pub extn_value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspCacheEntry {
    #[serde(rename = "_id")]
    pub id: String,
    pub cert_id: CertId,
    pub cert_status: CertStatus,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub this_update: DateTime<Utc>,
    #[serde(with = "crate::utils::serde_helpers::optional_datetime")]
    pub next_update: Option<DateTime<Utc>>,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub produced_at: DateTime<Utc>,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub cached_at: DateTime<Utc>,
    pub responder_url: String,
}

impl OcspCacheEntry {
    pub fn new(
        cert_id: CertId,
        cert_status: CertStatus,
        this_update: DateTime<Utc>,
        next_update: Option<DateTime<Utc>>,
        produced_at: DateTime<Utc>,
        responder_url: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            cert_id,
            cert_status,
            this_update,
            next_update,
            produced_at,
            cached_at: Utc::now(),
            responder_url,
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(next_update) = self.next_update {
            Utc::now() > next_update
        } else {
            false
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }

    pub fn needs_refresh(&self) -> bool {
        self.is_expired()
    }

    pub fn time_until_expiration(&self) -> Option<chrono::Duration> {
        self.next_update
            .map(|next_update| next_update - Utc::now())
    }
}

#[derive(Debug)]
pub struct OcspRequestBuilder {
    cert_ids: Vec<CertId>,
    nonce: Option<Vec<u8>>,
    requestor_name: Option<String>,
}

impl OcspRequestBuilder {
    pub fn new() -> Self {
        Self {
            cert_ids: Vec::new(),
            nonce: None,
            requestor_name: None,
        }
    }

    pub fn add_cert_id(mut self, cert_id: CertId) -> Self {
        self.cert_ids.push(cert_id);
        self
    }

    pub fn with_nonce(mut self, nonce: Vec<u8>) -> Self {
        self.nonce = Some(nonce);
        self
    }

    pub fn with_requestor_name(mut self, name: String) -> Self {
        self.requestor_name = Some(name);
        self
    }

    pub fn build(self) -> Result<OcspRequest, String> {
        if self.cert_ids.is_empty() {
            return Err("At least one certificate ID is required".to_string());
        }

        Ok(OcspRequest {
            cert_ids: self.cert_ids,
            nonce: self.nonce,
            requestor_name: self.requestor_name,
        })
    }
}

impl Default for OcspRequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct CertIdBuilder {
    hash_algorithm: HashAlgorithm,
    issuer_name_hash: Option<Vec<u8>>,
    issuer_key_hash: Option<Vec<u8>>,
    serial_number: Option<Vec<u8>>,
}

impl CertIdBuilder {
    pub fn new(hash_algorithm: HashAlgorithm) -> Self {
        Self {
            hash_algorithm,
            issuer_name_hash: None,
            issuer_key_hash: None,
            serial_number: None,
        }
    }

    pub fn with_issuer_name_hash(mut self, hash: Vec<u8>) -> Self {
        self.issuer_name_hash = Some(hash);
        self
    }

    pub fn with_issuer_key_hash(mut self, hash: Vec<u8>) -> Self {
        self.issuer_key_hash = Some(hash);
        self
    }

    pub fn with_serial_number(mut self, serial: Vec<u8>) -> Self {
        self.serial_number = Some(serial);
        self
    }

    pub fn build(self) -> Result<CertId, String> {
        let issuer_name_hash = self.issuer_name_hash
            .ok_or_else(|| "Issuer name hash is required".to_string())?;
        let issuer_key_hash = self.issuer_key_hash
            .ok_or_else(|| "Issuer key hash is required".to_string())?;
        let serial_number = self.serial_number
            .ok_or_else(|| "Serial number is required".to_string())?;

        if issuer_name_hash.len() != self.hash_algorithm.hash_size() {
            return Err(format!(
                "Issuer name hash size {} does not match expected size {} for {:?}",
                issuer_name_hash.len(),
                self.hash_algorithm.hash_size(),
                self.hash_algorithm
            ));
        }

        if issuer_key_hash.len() != self.hash_algorithm.hash_size() {
            return Err(format!(
                "Issuer key hash size {} does not match expected size {} for {:?}",
                issuer_key_hash.len(),
                self.hash_algorithm.hash_size(),
                self.hash_algorithm
            ));
        }

        Ok(CertId {
            hash_algorithm: self.hash_algorithm,
            issuer_name_hash,
            issuer_key_hash,
            serial_number,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_id_builder_valid() {
        let issuer_name_hash = vec![0u8; 32];
        let issuer_key_hash = vec![1u8; 32];
        let serial_number = vec![0x01, 0x02, 0x03];

        let cert_id = CertIdBuilder::new(HashAlgorithm::Sha256)
            .with_issuer_name_hash(issuer_name_hash.clone())
            .with_issuer_key_hash(issuer_key_hash.clone())
            .with_serial_number(serial_number.clone())
            .build();

        assert!(cert_id.is_ok());
        let cert_id = cert_id.unwrap();
        assert_eq!(cert_id.hash_algorithm, HashAlgorithm::Sha256);
        assert_eq!(cert_id.issuer_name_hash, issuer_name_hash);
        assert_eq!(cert_id.issuer_key_hash, issuer_key_hash);
        assert_eq!(cert_id.serial_number, serial_number);
    }

    #[test]
    fn test_cert_id_builder_missing_fields() {
        let result = CertIdBuilder::new(HashAlgorithm::Sha256)
            .with_issuer_name_hash(vec![0u8; 32])
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Issuer key hash is required"));
    }

    #[test]
    fn test_cert_id_builder_invalid_hash_size() {
        let result = CertIdBuilder::new(HashAlgorithm::Sha256)
            .with_issuer_name_hash(vec![0u8; 16])
            .with_issuer_key_hash(vec![1u8; 32])
            .with_serial_number(vec![0x01])
            .build();

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not match expected size"));
    }

    #[test]
    fn test_ocsp_request_builder_valid() {
        let cert_id = CertIdBuilder::new(HashAlgorithm::Sha256)
            .with_issuer_name_hash(vec![0u8; 32])
            .with_issuer_key_hash(vec![1u8; 32])
            .with_serial_number(vec![0x01, 0x02, 0x03])
            .build()
            .unwrap();

        let request = OcspRequestBuilder::new()
            .add_cert_id(cert_id)
            .with_nonce(vec![0xFF; 16])
            .with_requestor_name("SMF".to_string())
            .build();

        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.cert_ids.len(), 1);
        assert!(request.nonce.is_some());
        let nonce = request.nonce.as_ref().unwrap();
        assert_eq!(nonce.len(), 16);
        assert_eq!(request.requestor_name, Some("SMF".to_string()));
    }

    #[test]
    fn test_ocsp_request_builder_empty() {
        let result = OcspRequestBuilder::new().build();

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("At least one certificate ID is required"));
    }

    #[test]
    fn test_ocsp_request_builder_multiple_cert_ids() {
        let cert_id1 = CertIdBuilder::new(HashAlgorithm::Sha256)
            .with_issuer_name_hash(vec![0u8; 32])
            .with_issuer_key_hash(vec![1u8; 32])
            .with_serial_number(vec![0x01])
            .build()
            .unwrap();

        let cert_id2 = CertIdBuilder::new(HashAlgorithm::Sha256)
            .with_issuer_name_hash(vec![2u8; 32])
            .with_issuer_key_hash(vec![3u8; 32])
            .with_serial_number(vec![0x02])
            .build()
            .unwrap();

        let request = OcspRequestBuilder::new()
            .add_cert_id(cert_id1)
            .add_cert_id(cert_id2)
            .build();

        assert!(request.is_ok());
        let request = request.unwrap();
        assert_eq!(request.cert_ids.len(), 2);
    }

    #[test]
    fn test_hash_algorithm_oid() {
        assert_eq!(HashAlgorithm::Sha1.oid(), &[0x2B, 0x0E, 0x03, 0x02, 0x1A]);
        assert_eq!(HashAlgorithm::Sha256.oid(), &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);
    }

    #[test]
    fn test_hash_algorithm_size() {
        assert_eq!(HashAlgorithm::Sha1.hash_size(), 20);
        assert_eq!(HashAlgorithm::Sha256.hash_size(), 32);
        assert_eq!(HashAlgorithm::Sha384.hash_size(), 48);
        assert_eq!(HashAlgorithm::Sha512.hash_size(), 64);
    }

    #[test]
    fn test_ocsp_response_status_conversion() {
        assert_eq!(OcspResponseStatus::Successful.to_u8(), 0);
        assert_eq!(OcspResponseStatus::MalformedRequest.to_u8(), 1);
        assert_eq!(OcspResponseStatus::InternalError.to_u8(), 2);
        assert_eq!(OcspResponseStatus::TryLater.to_u8(), 3);
        assert_eq!(OcspResponseStatus::SigRequired.to_u8(), 5);
        assert_eq!(OcspResponseStatus::Unauthorized.to_u8(), 6);

        assert_eq!(OcspResponseStatus::from_u8(0), Some(OcspResponseStatus::Successful));
        assert_eq!(OcspResponseStatus::from_u8(1), Some(OcspResponseStatus::MalformedRequest));
        assert_eq!(OcspResponseStatus::from_u8(4), None);
    }

    #[test]
    fn test_ocsp_cache_entry_expiration() {
        let cert_id = CertIdBuilder::new(HashAlgorithm::Sha256)
            .with_issuer_name_hash(vec![0u8; 32])
            .with_issuer_key_hash(vec![1u8; 32])
            .with_serial_number(vec![0x01])
            .build()
            .unwrap();

        let this_update = Utc::now() - chrono::Duration::hours(1);
        let next_update = Utc::now() + chrono::Duration::hours(1);

        let cache_entry = OcspCacheEntry::new(
            cert_id,
            CertStatus::Good,
            this_update,
            Some(next_update),
            Utc::now(),
            "http://ocsp.example.com".to_string(),
        );

        assert!(!cache_entry.is_expired());
        assert!(cache_entry.is_valid());
        assert!(!cache_entry.needs_refresh());
    }

    #[test]
    fn test_ocsp_cache_entry_expired() {
        let cert_id = CertIdBuilder::new(HashAlgorithm::Sha256)
            .with_issuer_name_hash(vec![0u8; 32])
            .with_issuer_key_hash(vec![1u8; 32])
            .with_serial_number(vec![0x01])
            .build()
            .unwrap();

        let this_update = Utc::now() - chrono::Duration::hours(2);
        let next_update = Utc::now() - chrono::Duration::hours(1);

        let cache_entry = OcspCacheEntry::new(
            cert_id,
            CertStatus::Good,
            this_update,
            Some(next_update),
            Utc::now(),
            "http://ocsp.example.com".to_string(),
        );

        assert!(cache_entry.is_expired());
        assert!(!cache_entry.is_valid());
        assert!(cache_entry.needs_refresh());
    }
}
