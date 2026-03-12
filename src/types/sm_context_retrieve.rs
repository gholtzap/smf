use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextRetrieveData {
    pub target_mme_cap: Option<MmeCapabilities>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MmeCapabilities {
    #[serde(default)]
    pub non_ip_supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextRetrievedData {
    pub ue_eps_pdn_connection: String,
}
