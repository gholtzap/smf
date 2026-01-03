use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Crl {
    #[serde(rename = "_id")]
    pub id: String,
    pub issuer: String,
    pub distribution_point_url: String,
    pub crl_der: Vec<u8>,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub this_update: DateTime<Utc>,
    #[serde(with = "crate::utils::serde_helpers::optional_datetime")]
    pub next_update: Option<DateTime<Utc>>,
    pub revoked_certificate_count: usize,
    pub status: CrlStatus,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub last_fetch_attempt: DateTime<Utc>,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub last_successful_fetch: DateTime<Utc>,
    pub fetch_failure_count: u32,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CrlStatus {
    Valid,
    Expired,
    FailedToFetch,
    Invalid,
}

impl Crl {
    pub fn new(
        issuer: String,
        distribution_point_url: String,
        crl_der: Vec<u8>,
        this_update: DateTime<Utc>,
        next_update: Option<DateTime<Utc>>,
        revoked_certificate_count: usize,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            issuer,
            distribution_point_url,
            crl_der,
            this_update,
            next_update,
            revoked_certificate_count,
            status: CrlStatus::Valid,
            last_fetch_attempt: now,
            last_successful_fetch: now,
            fetch_failure_count: 0,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(next_update) = self.next_update {
            Utc::now() > next_update
        } else {
            false
        }
    }

    pub fn needs_refresh(&self) -> bool {
        self.is_expired() || self.status != CrlStatus::Valid
    }

    pub fn days_until_expiration(&self) -> Option<i64> {
        self.next_update
            .map(|next_update| (next_update - Utc::now()).num_days())
    }

    pub fn is_valid(&self) -> bool {
        !self.is_expired() && self.status == CrlStatus::Valid
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedCertificate {
    #[serde(rename = "_id")]
    pub id: String,
    pub crl_id: String,
    pub serial_number: String,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub revocation_date: DateTime<Utc>,
    pub revocation_reason: Option<RevocationReason>,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
}

impl RevokedCertificate {
    pub fn new(
        crl_id: String,
        serial_number: String,
        revocation_date: DateTime<Utc>,
        revocation_reason: Option<RevocationReason>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            crl_id,
            serial_number,
            revocation_date,
            revocation_reason,
            created_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlFetchAttempt {
    #[serde(rename = "_id")]
    pub id: String,
    pub distribution_point_url: String,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub attempt_time: DateTime<Utc>,
    pub success: bool,
    pub error_message: Option<String>,
    pub http_status_code: Option<u16>,
    pub response_size_bytes: Option<usize>,
    pub duration_ms: u64,
}

impl CrlFetchAttempt {
    pub fn new(distribution_point_url: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            distribution_point_url,
            attempt_time: Utc::now(),
            success: false,
            error_message: None,
            http_status_code: None,
            response_size_bytes: None,
            duration_ms: 0,
        }
    }

    pub fn mark_success(mut self, status_code: u16, size: usize, duration_ms: u64) -> Self {
        self.success = true;
        self.http_status_code = Some(status_code);
        self.response_size_bytes = Some(size);
        self.duration_ms = duration_ms;
        self
    }

    pub fn mark_failure(mut self, error: String, duration_ms: u64) -> Self {
        self.success = false;
        self.error_message = Some(error);
        self.duration_ms = duration_ms;
        self
    }
}
