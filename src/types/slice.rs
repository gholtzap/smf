use serde::{Deserialize, Serialize};
use crate::types::Snssai;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SliceConfiguration {
    pub s_nssai: Snssai,
    pub slice_name: String,
    pub allowed: bool,
    pub default_session_ambr_uplink: String,
    pub default_session_ambr_downlink: String,
    pub ip_pool_name: Option<String>,
    pub default_5qi: Option<u8>,
}

impl SliceConfiguration {
    pub fn new_default() -> Vec<Self> {
        vec![
            SliceConfiguration {
                s_nssai: Snssai {
                    sst: 1,
                    sd: None,
                },
                slice_name: "eMBB".to_string(),
                allowed: true,
                default_session_ambr_uplink: "100 Mbps".to_string(),
                default_session_ambr_downlink: "100 Mbps".to_string(),
                ip_pool_name: Some("default".to_string()),
                default_5qi: Some(9),
            },
            SliceConfiguration {
                s_nssai: Snssai {
                    sst: 2,
                    sd: None,
                },
                slice_name: "URLLC".to_string(),
                allowed: true,
                default_session_ambr_uplink: "50 Mbps".to_string(),
                default_session_ambr_downlink: "50 Mbps".to_string(),
                ip_pool_name: Some("default".to_string()),
                default_5qi: Some(1),
            },
            SliceConfiguration {
                s_nssai: Snssai {
                    sst: 3,
                    sd: None,
                },
                slice_name: "MIoT".to_string(),
                allowed: true,
                default_session_ambr_uplink: "10 Mbps".to_string(),
                default_session_ambr_downlink: "10 Mbps".to_string(),
                ip_pool_name: Some("default".to_string()),
                default_5qi: Some(9),
            },
            SliceConfiguration {
                s_nssai: Snssai {
                    sst: 1,
                    sd: Some("000001".to_string()),
                },
                slice_name: "eMBB-Premium".to_string(),
                allowed: true,
                default_session_ambr_uplink: "500 Mbps".to_string(),
                default_session_ambr_downlink: "1000 Mbps".to_string(),
                ip_pool_name: Some("default".to_string()),
                default_5qi: Some(5),
            },
        ]
    }

    pub fn matches(&self, s_nssai: &Snssai) -> bool {
        self.s_nssai.sst == s_nssai.sst && self.s_nssai.sd == s_nssai.sd
    }
}
