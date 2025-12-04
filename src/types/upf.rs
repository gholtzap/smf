use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpfNode {
    #[serde(rename = "_id")]
    pub id: String,
    pub address: String,
    pub status: UpfStatus,
    pub last_heartbeat: Option<DateTime<Utc>>,
    pub last_heartbeat_response: Option<DateTime<Utc>>,
    pub association_established: bool,
    pub consecutive_failures: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpfStatus {
    Active,
    Inactive,
    Unknown,
}

impl UpfNode {
    pub fn new(address: String) -> Self {
        Self {
            id: address.clone(),
            address,
            status: UpfStatus::Unknown,
            last_heartbeat: None,
            last_heartbeat_response: None,
            association_established: false,
            consecutive_failures: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}
