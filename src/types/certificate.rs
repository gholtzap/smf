use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: String,
    pub purpose: CertificatePurpose,
    pub certificate_pem: String,
    pub private_key_pem: Option<String>,
    pub certificate_chain_pem: Option<String>,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub not_before: DateTime<Utc>,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub not_after: DateTime<Utc>,
    pub fingerprint_sha256: String,
    pub key_type: KeyType,
    pub key_size_bits: u32,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificatePurpose {
    ServerTls,
    ClientTls,
    ClientAuth,
    RootCa,
    IntermediateCa,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyType {
    Rsa,
    Ecdsa,
    Ed25519,
}

impl Certificate {
    pub fn new(
        name: String,
        purpose: CertificatePurpose,
        certificate_pem: String,
        private_key_pem: Option<String>,
        certificate_chain_pem: Option<String>,
        subject: String,
        issuer: String,
        serial_number: String,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
        fingerprint_sha256: String,
        key_type: KeyType,
        key_size_bits: u32,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            purpose,
            certificate_pem,
            private_key_pem,
            certificate_chain_pem,
            subject,
            issuer,
            serial_number,
            not_before,
            not_after,
            fingerprint_sha256,
            key_type,
            key_size_bits,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.not_after
    }

    pub fn is_valid_now(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now <= self.not_after
    }

    pub fn days_until_expiration(&self) -> i64 {
        let now = Utc::now();
        (self.not_after - now).num_days()
    }

    pub fn needs_renewal(&self, days_threshold: i64) -> bool {
        self.days_until_expiration() <= days_threshold
    }
}
