use serde::{Deserialize, Serialize};
use crate::models::SmContext;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SmContextType {
    EpsPdnConnection,
    SmContext,
    AfCoordinationInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextRetrieveData {
    pub sm_context_type: Option<SmContextType>,
    pub target_mme_cap: Option<MmeCapabilities>,
    pub serving_network: Option<PlmnId>,
    #[serde(default)]
    pub ran_unchanged_ind: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MmeCapabilities {
    #[serde(default)]
    pub non_ip_supported: bool,
    #[serde(default)]
    pub ethernet_supported: bool,
    #[serde(default)]
    pub upip_supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlmnId {
    pub mcc: String,
    pub mnc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextRetrievedData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_eps_pdn_connection: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sm_context: Option<SmContext>,
}
