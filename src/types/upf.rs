use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

mod datetime_rfc3339 {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(dt: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&dt.to_rfc3339())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        DateTime::parse_from_rfc3339(&s)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(serde::de::Error::custom)
    }
}

mod datetime_rfc3339_option {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(opt: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(dt) => serializer.serialize_some(&dt.to_rfc3339()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        opt.map(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(serde::de::Error::custom)
        })
        .transpose()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpfNode {
    #[serde(rename = "_id")]
    pub id: String,
    pub address: String,
    pub status: UpfStatus,
    #[serde(with = "datetime_rfc3339_option")]
    pub last_heartbeat: Option<DateTime<Utc>>,
    #[serde(with = "datetime_rfc3339_option")]
    pub last_heartbeat_response: Option<DateTime<Utc>>,
    pub association_established: bool,
    pub consecutive_failures: u32,
    #[serde(with = "datetime_rfc3339")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "datetime_rfc3339")]
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
