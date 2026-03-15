use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::models::{Ambr, RequestType, TunnelInfo, UserLocation};
use crate::types::{
    Guami, HoState, PacketFilter, PduAddress, PduSessionType, QosFlow, QosRule,
    SmContextState, Snssai, SscMode, UpSecurityContext, UeSecurityCapabilities,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextData {
    pub supi: String,
    pub pdu_session_id: u8,
    pub dnn: String,
    pub s_nssai: Snssai,
    pub pdu_session_type: PduSessionType,
    pub ssc_mode: SscMode,
    pub state: SmContextState,
    pub pdu_address: Option<PduAddress>,
    pub pfcp_session_id: Option<u64>,
    pub pcf_policy_id: Option<String>,
    pub chf_charging_ref: Option<String>,
    pub qos_flows: Vec<QosFlow>,
    pub packet_filters: Vec<PacketFilter>,
    pub qos_rules: Vec<QosRule>,
    pub mtu: Option<u16>,
    pub an_tunnel_info: Option<TunnelInfo>,
    pub ue_location: Option<UserLocation>,
    pub handover_state: Option<HoState>,
    pub is_emergency: bool,
    pub request_type: Option<RequestType>,
    pub up_security_context: Option<UpSecurityContext>,
    pub ue_security_capabilities: Option<UeSecurityCapabilities>,
    pub session_ambr: Option<Ambr>,
    pub upf_address: Option<String>,
    pub created_at: DateTime<Utc>,
    pub pcf_id: Option<String>,
    pub pcf_group_id: Option<String>,
    pub pcf_set_id: Option<String>,
    pub guami: Option<Guami>,
    pub serving_network: Option<String>,
    pub rat_type: Option<String>,
    pub subscription_data: Option<TransferredSubscriptionData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferredSubscriptionData {
    pub allowed_dnns: Vec<String>,
    pub allowed_s_nssais: Vec<Snssai>,
    pub subscribed_ue_ambr: Option<Ambr>,
    pub default_5qi: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TransferCause {
    InterSmfHandover,
    SmfRelocation,
    LoadBalancing,
    NetworkOptimization,
    UeMovedToTargetArea,
    SourceSmfFailure,
    PolicyChange,
}
