use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::types::CertificatePurpose;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateAuditLog {
    #[serde(rename = "_id")]
    pub id: String,
    pub certificate_id: String,
    pub certificate_name: String,
    pub certificate_purpose: CertificatePurpose,
    pub event_type: AuditEventType,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub timestamp: DateTime<Utc>,
    pub actor: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub details: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditEventType {
    CertificateCreated,
    CertificateUpdated,
    CertificateDeleted,
    CertificateAccessed,
    CertificateValidated,
    CertificateRotated,
    CertificateRolledBack,
    CertificateExported,
    PrivateKeyAccessed,
    ChainValidated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateUsageRecord {
    #[serde(rename = "_id")]
    pub id: String,
    pub certificate_id: String,
    pub certificate_name: String,
    pub certificate_purpose: CertificatePurpose,
    pub usage_type: CertificateUsageType,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub timestamp: DateTime<Utc>,
    pub service: Option<String>,
    pub endpoint: Option<String>,
    pub connection_id: Option<String>,
    pub remote_address: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificateUsageType {
    TlsHandshake,
    MtlsValidation,
    SignatureVerification,
    SignatureGeneration,
    Encryption,
    Decryption,
}

impl CertificateAuditLog {
    pub fn new(
        certificate_id: String,
        certificate_name: String,
        certificate_purpose: CertificatePurpose,
        event_type: AuditEventType,
        success: bool,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            certificate_id,
            certificate_name,
            certificate_purpose,
            event_type,
            timestamp: Utc::now(),
            actor: None,
            ip_address: None,
            user_agent: None,
            details: None,
            success,
            error_message: None,
        }
    }

    pub fn with_actor(mut self, actor: String) -> Self {
        self.actor = Some(actor);
        self
    }

    pub fn with_ip_address(mut self, ip_address: String) -> Self {
        self.ip_address = Some(ip_address);
        self
    }

    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }

    pub fn with_error(mut self, error_message: String) -> Self {
        self.error_message = Some(error_message);
        self.success = false;
        self
    }
}

impl CertificateUsageRecord {
    pub fn new(
        certificate_id: String,
        certificate_name: String,
        certificate_purpose: CertificatePurpose,
        usage_type: CertificateUsageType,
        success: bool,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            certificate_id,
            certificate_name,
            certificate_purpose,
            usage_type,
            timestamp: Utc::now(),
            service: None,
            endpoint: None,
            connection_id: None,
            remote_address: None,
            success,
            error_message: None,
        }
    }

    pub fn with_service(mut self, service: String) -> Self {
        self.service = Some(service);
        self
    }

    pub fn with_endpoint(mut self, endpoint: String) -> Self {
        self.endpoint = Some(endpoint);
        self
    }

    pub fn with_connection_id(mut self, connection_id: String) -> Self {
        self.connection_id = Some(connection_id);
        self
    }

    pub fn with_remote_address(mut self, remote_address: String) -> Self {
        self.remote_address = Some(remote_address);
        self
    }

    pub fn with_error(mut self, error_message: String) -> Self {
        self.error_message = Some(error_message);
        self.success = false;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogQuery {
    pub certificate_id: Option<String>,
    pub certificate_name: Option<String>,
    pub event_type: Option<AuditEventType>,
    #[serde(with = "crate::utils::serde_helpers::optional_datetime")]
    pub start_time: Option<DateTime<Utc>>,
    #[serde(with = "crate::utils::serde_helpers::optional_datetime")]
    pub end_time: Option<DateTime<Utc>>,
    pub actor: Option<String>,
    pub success: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecordQuery {
    pub certificate_id: Option<String>,
    pub certificate_name: Option<String>,
    pub usage_type: Option<CertificateUsageType>,
    #[serde(with = "crate::utils::serde_helpers::optional_datetime")]
    pub start_time: Option<DateTime<Utc>>,
    #[serde(with = "crate::utils::serde_helpers::optional_datetime")]
    pub end_time: Option<DateTime<Utc>>,
    pub service: Option<String>,
    pub success: Option<bool>,
    pub limit: Option<i64>,
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogSummary {
    pub total_events: i64,
    pub events_by_type: Vec<EventTypeCount>,
    pub recent_events: Vec<CertificateAuditLog>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventTypeCount {
    pub event_type: AuditEventType,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecordSummary {
    pub total_usage: i64,
    pub usage_by_type: Vec<UsageTypeCount>,
    pub recent_usage: Vec<CertificateUsageRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageTypeCount {
    pub usage_type: CertificateUsageType,
    pub count: i64,
}
