use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::types::{Guami, HoState, N2SmInfo, PacketFilter, PduAddress, PduSessionType, QosFlow, QosRule, RefToBinaryData, SmContextState, Snssai, SscMode};
use crate::types::up_security::UpSecurityContext;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduSessionCreateData {
    pub supi: String,
    pub unauthenticated_supi: Option<bool>,
    pub pei: Option<String>,
    pub gpsi: Option<String>,
    pub pdu_session_id: u8,
    pub dnn: String,
    pub selected_dnn: Option<String>,
    pub s_nssai: Snssai,
    pub serving_network: Option<String>,
    pub request_type: Option<RequestType>,
    pub eps_bearer_id: Option<Vec<u8>>,
    pub pgw_s8c_fteid: Option<String>,
    pub vsmf_pdu_session_uri: Option<String>,
    pub ismf_pdu_session_uri: Option<String>,
    pub vcn_tunnel_info: Option<TunnelInfo>,
    pub icn_tunnel_info: Option<TunnelInfo>,
    pub n9_forwarding_tunnel_info: Option<TunnelInfo>,
    pub additional_cn_tunnel_info: Option<TunnelInfo>,
    pub an_type: AnType,
    pub additional_an_type: Option<AnType>,
    pub rat_type: Option<RatType>,
    pub ue_location: Option<UserLocation>,
    pub ue_time_zone: Option<String>,
    pub add_ue_location: Option<UserLocation>,
    pub gpsi_list: Option<Vec<String>>,
    pub n1_sm_msg: Option<RefToBinaryData>,
    pub guami: Option<Guami>,
    pub service_name: Option<String>,
    pub pcf_id: Option<String>,
    pub pcf_group_id: Option<String>,
    pub pcf_set_id: Option<String>,
    pub ho_preparation_indication: Option<bool>,
    pub sel_mode: Option<DnnSelectionMode>,
    pub always_on_requested: Option<bool>,
    pub ssc_mode: Option<String>,
    pub pdu_session_type: Option<PduSessionType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestType {
    InitialRequest,
    ExistingPduSession,
    InitialEmergencyRequest,
    ExistingEmergencyPduSession,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelInfo {
    pub ipv4_addr: Option<String>,
    pub ipv6_addr: Option<String>,
    pub gtp_teid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AnType {
    #[serde(rename = "3GPP_ACCESS")]
    ThreeGppAccess,
    #[serde(rename = "NON_3GPP_ACCESS")]
    NonThreeGppAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RatType {
    Nr,
    EutraWb,
    Wlan,
    VirtualNr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserLocation {
    pub nr_location: Option<NrLocation>,
    pub eutra_location: Option<EutraLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NrLocation {
    pub tai: Tai,
    pub ncgi: Ncgi,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tai {
    pub plmn_id: String,
    pub tac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ncgi {
    pub plmn_id: String,
    pub nr_cell_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EutraLocation {
    pub tai: Tai,
    pub ecgi: Ecgi,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ecgi {
    pub plmn_id: String,
    pub eutra_cell_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DnnSelectionMode {
    Verified,
    UeProvidedNotVerified,
    NetworkProvided,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduSessionCreatedData {
    pub pdu_session_type: PduSessionType,
    pub ssc_mode: String,
    pub h_smf_uri: Option<String>,
    pub smf_uri: Option<String>,
    pub pdu_session_id: u8,
    pub s_nssai: Snssai,
    pub enable_pause_charging: Option<bool>,
    pub ue_ipv4_address: Option<String>,
    pub ue_ipv6_prefix: Option<String>,
    pub dns_primary: Option<String>,
    pub dns_secondary: Option<String>,
    pub mtu: Option<u16>,
    pub n1_sm_info_to_ue: Option<RefToBinaryData>,
    pub eps_pdn_cnx_info: Option<EpsPdnCnxInfo>,
    pub supported_features: Option<String>,
    pub session_ambr: Option<Ambr>,
    pub cn_tunnel_info: Option<TunnelInfo>,
    pub additional_cn_tunnel_info: Option<TunnelInfo>,
    pub dnai_list: Option<Vec<String>>,
    pub n2_sm_info: Option<N2SmInfo>,
    pub n2_sm_info_type: Option<N2SmInfoType>,
    pub sm_context_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpsPdnCnxInfo {
    pub pgw_s8c_fteid: String,
    pub pgw_node_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ambr {
    pub uplink: String,
    pub downlink: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum N2SmInfoType {
    PduResSetupReq,
    PduResSetupRsp,
    PduResRelCmd,
    PathSwitchReq,
    PathSwitchSetupFail,
    PathSwitchReqAck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmContext {
    #[serde(rename = "_id")]
    pub id: String,
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl SmContext {
    pub fn new(create_data: &PduSessionCreateData) -> Self {
        let is_emergency = matches!(
            create_data.request_type,
            Some(RequestType::InitialEmergencyRequest) | Some(RequestType::ExistingEmergencyPduSession)
        );

        Self {
            id: Uuid::new_v4().to_string(),
            supi: create_data.supi.clone(),
            pdu_session_id: create_data.pdu_session_id,
            dnn: create_data.dnn.clone(),
            s_nssai: create_data.s_nssai.clone(),
            pdu_session_type: create_data.pdu_session_type.clone().unwrap_or(PduSessionType::Ipv4),
            ssc_mode: SscMode::default(),
            state: SmContextState::ActivePending,
            pdu_address: None,
            pfcp_session_id: None,
            pcf_policy_id: None,
            chf_charging_ref: None,
            qos_flows: vec![QosFlow::new_default(1)],
            packet_filters: vec![],
            qos_rules: vec![QosRule::new_default(1, 1)],
            mtu: None,
            an_tunnel_info: None,
            ue_location: create_data.ue_location.clone(),
            handover_state: None,
            is_emergency,
            request_type: create_data.request_type.clone(),
            up_security_context: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduSessionUpdateData {
    pub n1_sm_msg: Option<RefToBinaryData>,
    pub n2_sm_info: Option<N2SmInfo>,
    pub n2_sm_info_type: Option<N2SmInfoType>,
    pub an_type: Option<AnType>,
    pub rat_type: Option<RatType>,
    pub ue_location: Option<UserLocation>,
    pub ue_time_zone: Option<String>,
    pub add_ue_location: Option<UserLocation>,
    pub session_ambr: Option<Ambr>,
    pub qos_flows_add_mod_request_list: Option<Vec<QosFlowItem>>,
    pub qos_flows_rel_request_list: Option<Vec<QosFlowItem>>,
    pub up_cnx_state: Option<UpCnxState>,
    pub ho_preparation_indication: Option<bool>,
    pub pcf_id: Option<String>,
    pub pcf_group_id: Option<String>,
    pub pcf_set_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduSessionUpdatedData {
    pub n1_sm_info_to_ue: Option<RefToBinaryData>,
    pub n2_sm_info: Option<N2SmInfo>,
    pub n2_sm_info_type: Option<N2SmInfoType>,
    pub eps_bearer_info: Option<Vec<EpsBearerInfo>>,
    pub supported_features: Option<String>,
    pub session_ambr: Option<Ambr>,
    pub cn_tunnel_info: Option<TunnelInfo>,
    pub additional_cn_tunnel_info: Option<TunnelInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosFlowItem {
    pub qfi: u8,
    pub qos_profile: Option<QosProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosProfile {
    #[serde(rename = "5qi")]
    pub five_qi: u8,
    pub priority_level: Option<u8>,
    pub arp: Option<Arp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Arp {
    pub priority_level: u8,
    pub preempt_cap: PreemptionCapability,
    pub preempt_vuln: PreemptionVulnerability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PreemptionCapability {
    MayPreempt,
    NotPreempt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PreemptionVulnerability {
    Preemptable,
    NotPreemptable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpCnxState {
    Activated,
    Deactivated,
    Activating,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpsBearerInfo {
    pub ebi: u8,
    pub pgw_s8u_fteid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduSessionReleaseData {
    pub n2_sm_info: Option<N2SmInfo>,
    pub n2_sm_info_type: Option<N2SmInfoType>,
    pub cause: Option<ReleaseCause>,
    pub ng_ap_cause: Option<NgApCause>,
    pub five_g_mm_cause_value: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseCause {
    NwInitiated,
    UeInitiated,
    DdnFailure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NgApCause {
    pub group: u8,
    pub value: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduSessionReleasedData {
    pub n1_sm_info_to_ue: Option<RefToBinaryData>,
    pub n2_sm_info: Option<N2SmInfo>,
    pub n2_sm_info_type: Option<N2SmInfoType>,
}
