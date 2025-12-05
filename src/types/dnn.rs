use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnnConfiguration {
    pub dnn: String,
    pub description: String,
    pub allowed: bool,
    pub ip_pool_name: String,
    pub default_session_ambr_uplink: String,
    pub default_session_ambr_downlink: String,
    pub default_5qi: Option<u8>,
    pub mtu: Option<u16>,
    pub priority: u8,
}

impl DnnConfiguration {
    pub fn new_default() -> Vec<Self> {
        vec![
            DnnConfiguration {
                dnn: "internet".to_string(),
                description: "Public Internet access".to_string(),
                allowed: true,
                ip_pool_name: "default".to_string(),
                default_session_ambr_uplink: "100 Mbps".to_string(),
                default_session_ambr_downlink: "100 Mbps".to_string(),
                default_5qi: Some(9),
                mtu: Some(1500),
                priority: 10,
            },
            DnnConfiguration {
                dnn: "ims".to_string(),
                description: "IP Multimedia Subsystem".to_string(),
                allowed: true,
                ip_pool_name: "default".to_string(),
                default_session_ambr_uplink: "50 Mbps".to_string(),
                default_session_ambr_downlink: "50 Mbps".to_string(),
                default_5qi: Some(5),
                mtu: Some(1500),
                priority: 5,
            },
            DnnConfiguration {
                dnn: "edge".to_string(),
                description: "Mobile Edge Computing".to_string(),
                allowed: true,
                ip_pool_name: "default".to_string(),
                default_session_ambr_uplink: "500 Mbps".to_string(),
                default_session_ambr_downlink: "1000 Mbps".to_string(),
                default_5qi: Some(7),
                mtu: Some(1500),
                priority: 1,
            },
        ]
    }

    pub fn matches(&self, dnn: &str) -> bool {
        self.dnn == dnn
    }
}
