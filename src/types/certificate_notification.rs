use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRenewalNotification {
    #[serde(rename = "_id")]
    pub id: String,
    pub certificate_id: String,
    pub certificate_name: String,
    pub severity: NotificationSeverity,
    pub days_until_expiration: i64,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub expiration_date: DateTime<Utc>,
    pub message: String,
    pub acknowledged: bool,
    #[serde(with = "crate::utils::serde_helpers::optional_datetime")]
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<String>,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NotificationSeverity {
    Info,
    Warning,
    Critical,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalThresholds {
    pub critical_days: i64,
    pub warning_days: i64,
    pub info_days: i64,
}

impl Default for RenewalThresholds {
    fn default() -> Self {
        Self {
            critical_days: 7,
            warning_days: 30,
            info_days: 60,
        }
    }
}

impl RenewalThresholds {
    pub fn new(critical_days: i64, warning_days: i64, info_days: i64) -> Self {
        Self {
            critical_days,
            warning_days,
            info_days,
        }
    }

    pub fn get_severity(&self, days_until_expiration: i64) -> NotificationSeverity {
        if days_until_expiration <= 0 {
            NotificationSeverity::Expired
        } else if days_until_expiration <= self.critical_days {
            NotificationSeverity::Critical
        } else if days_until_expiration <= self.warning_days {
            NotificationSeverity::Warning
        } else if days_until_expiration <= self.info_days {
            NotificationSeverity::Info
        } else {
            NotificationSeverity::Info
        }
    }
}

impl CertificateRenewalNotification {
    pub fn new(
        certificate_id: String,
        certificate_name: String,
        severity: NotificationSeverity,
        days_until_expiration: i64,
        expiration_date: DateTime<Utc>,
    ) -> Self {
        let message = Self::generate_message(&certificate_name, severity, days_until_expiration, &expiration_date);
        let now = Utc::now();

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            certificate_id,
            certificate_name,
            severity,
            days_until_expiration,
            expiration_date,
            message,
            acknowledged: false,
            acknowledged_at: None,
            acknowledged_by: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn generate_message(
        cert_name: &str,
        severity: NotificationSeverity,
        days: i64,
        expiration_date: &DateTime<Utc>,
    ) -> String {
        match severity {
            NotificationSeverity::Expired => {
                format!(
                    "Certificate '{}' has EXPIRED on {}",
                    cert_name,
                    expiration_date.format("%Y-%m-%d %H:%M:%S UTC")
                )
            }
            NotificationSeverity::Critical => {
                format!(
                    "CRITICAL: Certificate '{}' expires in {} day(s) on {}",
                    cert_name,
                    days,
                    expiration_date.format("%Y-%m-%d %H:%M:%S UTC")
                )
            }
            NotificationSeverity::Warning => {
                format!(
                    "WARNING: Certificate '{}' expires in {} day(s) on {}",
                    cert_name,
                    days,
                    expiration_date.format("%Y-%m-%d %H:%M:%S UTC")
                )
            }
            NotificationSeverity::Info => {
                format!(
                    "INFO: Certificate '{}' expires in {} day(s) on {}",
                    cert_name,
                    days,
                    expiration_date.format("%Y-%m-%d %H:%M:%S UTC")
                )
            }
        }
    }

    pub fn acknowledge(&mut self, acknowledged_by: Option<String>) {
        self.acknowledged = true;
        self.acknowledged_at = Some(Utc::now());
        self.acknowledged_by = acknowledged_by;
        self.updated_at = Utc::now();
    }

    pub fn is_stale(&self, max_age_hours: i64) -> bool {
        let now = Utc::now();
        let age = now.signed_duration_since(self.created_at);
        age.num_hours() > max_age_hours
    }
}
