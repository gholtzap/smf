use serde::{Deserialize, Serialize};
use super::{Guami, PlmnId, Snssai};
use super::nrf::{Tai, TaiRange};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmfInfo {
    pub amf_set_id: String,
    pub amf_region_id: String,
    pub guami_list: Vec<Guami>,
    pub tai_list: Option<Vec<Tai>>,
    pub tai_range_list: Option<Vec<TaiRange>>,
    pub backup_info_amf_failure: Option<Vec<BackupAmfInfo>>,
    pub backup_info_amf_removal: Option<Vec<BackupAmfInfo>>,
    pub n2_interface_amf_info: Option<N2InterfaceAmfInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupAmfInfo {
    pub backup_amf: String,
    pub guami_list: Option<Vec<Guami>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N2InterfaceAmfInfo {
    pub ipv4_endpoint_addresses: Option<Vec<String>>,
    pub ipv6_endpoint_addresses: Option<Vec<String>>,
    pub amf_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AmfSelectionCriteria {
    pub snssai: Option<Snssai>,
    pub plmn_id: Option<PlmnId>,
    pub tai: Option<Tai>,
    pub guami: Option<Guami>,
    pub prefer_local: bool,
}

impl Default for AmfSelectionCriteria {
    fn default() -> Self {
        Self {
            snssai: None,
            plmn_id: None,
            tai: None,
            guami: None,
            prefer_local: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AmfSelectionResult {
    pub nf_instance_id: String,
    pub uri: String,
    pub priority: u16,
    pub capacity: u16,
    pub load: u16,
    pub score: f64,
}
