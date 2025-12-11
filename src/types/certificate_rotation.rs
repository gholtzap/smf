use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRotationRequest {
    pub certificate_pem: String,
    pub private_key_pem: Option<String>,
    pub certificate_chain_pem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRotationResponse {
    pub success: bool,
    pub message: String,
    pub rotation_id: String,
    pub old_certificate_id: String,
    pub new_certificate_id: String,
    pub requires_restart: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRotationRecord {
    #[serde(rename = "_id")]
    pub id: String,
    pub certificate_name: String,
    pub certificate_purpose: String,
    pub old_certificate_id: String,
    pub new_certificate_id: String,
    pub rotated_at: DateTime<Utc>,
    pub rotated_by: Option<String>,
    pub rotation_reason: Option<String>,
    pub status: RotationStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RotationStatus {
    Completed,
    RolledBack,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRollbackRequest {
    pub rotation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRollbackResponse {
    pub success: bool,
    pub message: String,
    pub restored_certificate_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationHistoryResponse {
    pub rotations: Vec<CertificateRotationRecord>,
    pub total_count: usize,
}
