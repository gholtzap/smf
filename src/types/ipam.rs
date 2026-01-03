use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpPool {
    #[serde(rename = "_id")]
    pub id: String,
    pub name: String,
    pub cidr: String,
    pub gateway: String,
    pub dns_primary: Option<String>,
    pub dns_secondary: Option<String>,
    pub mtu: Option<u16>,
    pub allocated_ips: Vec<String>,
    pub ipv6_cidr: Option<String>,
    pub ipv6_gateway: Option<String>,
    pub ipv6_dns_primary: Option<String>,
    pub ipv6_dns_secondary: Option<String>,
    pub allocated_ipv6_prefixes: Vec<String>,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub created_at: DateTime<Utc>,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAllocation {
    #[serde(rename = "_id")]
    pub id: String,
    pub ip_address: String,
    pub ipv6_prefix: Option<String>,
    pub pool_id: String,
    pub sm_context_ref: String,
    pub supi: String,
    #[serde(with = "mongodb::bson::serde_helpers::chrono_datetime_as_bson_datetime")]
    pub allocated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct IpAllocationResult {
    pub ip_address: String,
    pub gateway: String,
    pub dns_primary: Option<String>,
    pub dns_secondary: Option<String>,
    pub mtu: Option<u16>,
    pub ipv6_prefix: Option<String>,
    pub ipv6_gateway: Option<String>,
    pub ipv6_dns_primary: Option<String>,
    pub ipv6_dns_secondary: Option<String>,
}
