use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use super::{CertificatePurpose};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoRotationConfig {
    #[serde(rename = "_id")]
    pub id: String,
    pub certificate_name: String,
    pub certificate_purpose: CertificatePurpose,
    pub enabled: bool,
    pub rotation_threshold_days: i64,
    pub provider_type: CertificateProviderType,
    pub provider_config: serde_json::Value,
    #[serde(with = "crate::utils::serde_helpers::optional_datetime")]
    pub last_rotation_attempt: Option<DateTime<Utc>>,
    #[serde(with = "crate::utils::serde_helpers::optional_datetime")]
    pub last_rotation_success: Option<DateTime<Utc>>,
    pub last_rotation_error: Option<String>,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub updated_at: DateTime<Utc>,
}

impl AutoRotationConfig {
    pub fn new(
        certificate_name: String,
        certificate_purpose: CertificatePurpose,
        rotation_threshold_days: i64,
        provider_type: CertificateProviderType,
        provider_config: serde_json::Value,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            certificate_name,
            certificate_purpose,
            enabled: true,
            rotation_threshold_days,
            provider_type,
            provider_config,
            last_rotation_attempt: None,
            last_rotation_success: None,
            last_rotation_error: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn should_rotate(&self, days_until_expiration: i64) -> bool {
        self.enabled && days_until_expiration <= self.rotation_threshold_days
    }

    pub fn update_attempt(&mut self, success: bool, error: Option<String>) {
        let now = Utc::now();
        self.last_rotation_attempt = Some(now);
        if success {
            self.last_rotation_success = Some(now);
            self.last_rotation_error = None;
        } else {
            self.last_rotation_error = error;
        }
        self.updated_at = now;
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificateProviderType {
    Acme,
    Manual,
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoRotationStatus {
    pub config_id: String,
    pub certificate_name: String,
    pub certificate_purpose: CertificatePurpose,
    pub enabled: bool,
    pub rotation_threshold_days: i64,
    pub days_until_expiration: i64,
    pub should_rotate: bool,
    pub last_rotation_attempt: Option<DateTime<Utc>>,
    pub last_rotation_success: Option<DateTime<Utc>>,
    pub last_rotation_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAutoRotationConfigRequest {
    pub certificate_name: String,
    pub certificate_purpose: CertificatePurpose,
    pub rotation_threshold_days: i64,
    pub provider_type: CertificateProviderType,
    pub provider_config: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateAutoRotationConfigRequest {
    pub enabled: Option<bool>,
    pub rotation_threshold_days: Option<i64>,
    pub provider_config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoRotationAttempt {
    #[serde(rename = "_id")]
    pub id: String,
    pub config_id: String,
    pub certificate_name: String,
    pub certificate_purpose: CertificatePurpose,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub attempted_at: DateTime<Utc>,
    pub success: bool,
    pub error_message: Option<String>,
    pub old_certificate_id: Option<String>,
    pub new_certificate_id: Option<String>,
    pub rotation_id: Option<String>,
}

impl AutoRotationAttempt {
    pub fn new(
        config_id: String,
        certificate_name: String,
        certificate_purpose: CertificatePurpose,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            config_id,
            certificate_name,
            certificate_purpose,
            attempted_at: Utc::now(),
            success: false,
            error_message: None,
            old_certificate_id: None,
            new_certificate_id: None,
            rotation_id: None,
        }
    }

    pub fn mark_success(
        &mut self,
        old_certificate_id: String,
        new_certificate_id: String,
        rotation_id: String,
    ) {
        self.success = true;
        self.old_certificate_id = Some(old_certificate_id);
        self.new_certificate_id = Some(new_certificate_id);
        self.rotation_id = Some(rotation_id);
        self.error_message = None;
    }

    pub fn mark_failure(&mut self, error: String) {
        self.success = false;
        self.error_message = Some(error);
    }
}
