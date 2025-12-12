use serde::{Deserialize, Serialize};
use super::{N2SmInfo, PlmnId, RefToBinaryData};
use super::nrf::Tai;
use crate::models::{TunnelInfo, UserLocation};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandoverRequiredData {
    pub target_id: TargetId,
    pub direct_forwarding_path_availability: Option<DirectForwardingPathAvailability>,
    pub n2_sm_info: Option<N2SmInfo>,
    pub pdu_session_id: u8,
    pub ho_state: Option<HoState>,
    pub source_to_target_data: Option<RefToBinaryData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetId {
    pub ran_node_id: RanNodeId,
    pub tai: Option<Tai>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RanNodeId {
    pub plmn_id: PlmnId,
    pub n3_iwf_id: Option<String>,
    pub gnb_id: Option<GnbId>,
    pub nge_nb_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GnbId {
    pub bit_length: u32,
    pub gnb_value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DirectForwardingPathAvailability {
    DirectPathAvailable,
    DirectPathNotAvailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HoState {
    None,
    Preparing,
    Prepared,
    Completed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandoverRequiredResponse {
    pub n2_sm_info: Option<N2SmInfo>,
    pub n2_sm_info_ext1: Option<N2SmInfo>,
    pub ho_state: Option<HoState>,
    pub cn_tunnel_info: Option<TunnelInfo>,
    pub additional_cn_tunnel_info: Option<TunnelInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandoverRequestAckData {
    pub n2_sm_info: Option<N2SmInfo>,
    pub pdu_session_id: u8,
    pub target_to_source_data: Option<RefToBinaryData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandoverNotifyData {
    pub n2_sm_info: Option<N2SmInfo>,
    pub pdu_session_id: u8,
    pub ho_state: HoState,
    pub an_tunnel_info: Option<TunnelInfo>,
    pub ue_location: Option<UserLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandoverCancelData {
    pub pdu_session_id: u8,
    pub cause: HandoverCancelCause,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandoverCancelCause {
    HoTargetNotAllowed,
    HoTargetBecomingRich,
    HoTargetNotReachable,
    HoFailureInTargetSystem,
    HoCancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllocatedHandoverResources {
    pub target_tunnel_info: TunnelInfo,
    pub allocated_qos_flow_ids: Vec<u8>,
    pub failed_qos_flow_ids: Vec<u8>,
    pub security_activated: bool,
}
