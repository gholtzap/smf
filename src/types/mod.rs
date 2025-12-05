pub mod event_exposure;
pub mod pfcp;
pub mod ipam;
pub mod upf;
pub mod nrf;
pub mod qos;
pub mod packet_filter;
pub mod qos_rule;
pub mod slice;
pub mod dnn;
pub mod amf;
pub mod udm;

use serde::{Deserialize, Serialize};

pub use event_exposure::*;
pub use pfcp::*;
pub use ipam::*;
pub use upf::*;
pub use nrf::*;
pub use qos::*;
pub use packet_filter::*;
pub use qos_rule::*;
pub use slice::*;
pub use dnn::*;
pub use amf::*;
pub use udm::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snssai {
    pub sst: u8,
    pub sd: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PduSessionType {
    Ipv4,
    Ipv6,
    Ipv4v6,
    Unstructured,
    Ethernet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlmnId {
    pub mcc: String,
    pub mnc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Guami {
    pub plmn_id: PlmnId,
    pub amf_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N2SmInfo {
    pub content_id: String,
    pub n2_info_content: N2InfoContent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct N2InfoContent {
    pub ngap_ie_type: NgapIeType,
    pub ngap_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NgapIeType {
    PduResSetupReq,
    PduResSetupRsp,
    PduResRelCmd,
    PduResRelRsp,
    PduResModifyReq,
    PduResModifyRsp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefToBinaryData {
    pub content_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduAddress {
    pub pdu_session_type: PduSessionType,
    pub ipv4_addr: Option<String>,
    pub ipv6_addr: Option<String>,
    pub dns_primary: Option<String>,
    pub dns_secondary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SmContextState {
    Idle,
    ActivePending,
    Active,
    InactivePending,
    Inactive,
    ModificationPending,
}
