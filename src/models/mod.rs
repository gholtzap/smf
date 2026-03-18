use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use crate::types::{Guami, HoState, N2SmInfo, PacketFilter, PduAddress, PduSessionType, PlmnId, QosFlow, QosRule, RefToBinaryData, SmContextState, Snssai, SscMode, TargetId};
use crate::types::up_security::{UpSecurityContext, UeSecurityCapabilities};
use crate::types::sm_context_transfer::{SmContextData, TransferCause};

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
    #[serde(default)]
    pub serving_nf_id: Option<String>,
    pub serving_network: Option<PlmnId>,
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
    #[serde(default)]
    pub sm_context_status_uri: Option<String>,
    pub pcf_id: Option<String>,
    pub pcf_group_id: Option<String>,
    pub pcf_set_id: Option<String>,
    pub ho_preparation_indication: Option<bool>,
    pub sel_mode: Option<DnnSelectionMode>,
    pub always_on_requested: Option<bool>,
    pub ssc_mode: Option<String>,
    pub pdu_session_type: Option<PduSessionType>,
    pub ho_state: Option<HoState>,
    pub sm_context_ref: Option<String>,
    pub smf_uri: Option<String>,
    #[serde(default)]
    pub smf_transfer_ind: Option<bool>,
    pub target_id: Option<TargetId>,
    pub source_sm_context: Option<SmContextData>,
    pub source_smf_id: Option<String>,
    pub transfer_cause: Option<TransferCause>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_cnx_state: Option<UpCnxState>,
    pub enable_pause_charging: Option<bool>,
    pub ue_ipv4_address: Option<String>,
    pub ue_ipv6_prefix: Option<String>,
    pub dns_primary: Option<String>,
    pub dns_secondary: Option<String>,
    pub mtu: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n1_sm_info_to_ue: Option<RefToBinaryData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n1_sm_msg: Option<String>,
    pub eps_pdn_cnx_info: Option<EpsPdnCnxInfo>,
    pub supported_features: Option<String>,
    pub session_ambr: Option<Ambr>,
    pub cn_tunnel_info: Option<TunnelInfo>,
    pub additional_cn_tunnel_info: Option<TunnelInfo>,
    pub dnai_list: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n2_sm_info: Option<String>,
    pub n2_sm_info_type: Option<N2SmInfoType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ho_state: Option<HoState>,
    pub sm_context_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upf_tunnel_info: Option<UpfTunnelInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qos_flow_list: Option<Vec<QosFlowInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_ambr_downlink: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_ambr_uplink: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpfTunnelInfo {
    pub teid: u32,
    pub ipv4_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosFlowInfo {
    pub qfi: u8,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum N2SmInfoType {
    PduResSetupReq,
    PduResSetupRsp,
    PduResSetupFail,
    PduResRelCmd,
    PduResRelRsp,
    #[serde(rename = "PDU_RES_MOD_REQ")]
    PduResModReq,
    #[serde(rename = "PDU_RES_MOD_RSP")]
    PduResModRsp,
    #[serde(rename = "PDU_RES_MOD_FAIL")]
    PduResModFail,
    PduResNty,
    PduResNtyRel,
    #[serde(rename = "PDU_RES_MOD_IND")]
    PduResModInd,
    #[serde(rename = "PDU_RES_MOD_CFM")]
    PduResModCfm,
    PathSwitchReq,
    PathSwitchSetupFail,
    PathSwitchReqAck,
    PathSwitchReqFail,
    HandoverRequired,
    HandoverCmd,
    HandoverPrepFail,
    HandoverReqAck,
    HandoverResAllocFail,
    SecondaryRatUsage,
    #[serde(rename = "PDU_RES_MOD_IND_FAIL")]
    PduResModIndFail,
    UeContextResumeReq,
    UeContextResumeRsp,
    UeContextSuspendReq,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmContext {
    #[serde(rename = "_id")]
    pub id: String,
    pub supi: String,
    #[serde(default)]
    pub gpsi: Option<String>,
    #[serde(default)]
    pub pei: Option<String>,
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
    pub an_type: AnType,
    pub rat_type: Option<RatType>,
    pub an_tunnel_info: Option<TunnelInfo>,
    #[serde(default)]
    pub source_an_tunnel_info: Option<TunnelInfo>,
    pub ue_location: Option<UserLocation>,
    pub handover_state: Option<HoState>,
    pub is_emergency: bool,
    pub request_type: Option<RequestType>,
    pub up_security_context: Option<UpSecurityContext>,
    pub ue_security_capabilities: Option<UeSecurityCapabilities>,
    pub session_ambr: Option<Ambr>,
    pub upf_address: Option<String>,
    #[serde(default)]
    pub upf_teid: Option<u32>,
    #[serde(default)]
    pub upf_tunnel_ipv4: Option<String>,
    #[serde(default)]
    pub serving_nf_id: Option<String>,
    #[serde(default)]
    pub sm_context_status_uri: Option<String>,
    #[serde(default)]
    pub guami: Option<Guami>,
    #[serde(default)]
    pub serving_network: Option<PlmnId>,
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
            gpsi: create_data.gpsi.clone(),
            pei: create_data.pei.clone(),
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
            an_type: create_data.an_type.clone(),
            rat_type: create_data.rat_type.clone(),
            an_tunnel_info: None,
            source_an_tunnel_info: None,
            ue_location: create_data.ue_location.clone(),
            handover_state: None,
            is_emergency,
            request_type: create_data.request_type.clone(),
            up_security_context: None,
            ue_security_capabilities: None,
            session_ambr: None,
            upf_address: None,
            upf_teid: None,
            upf_tunnel_ipv4: None,
            serving_nf_id: create_data.serving_nf_id.clone(),
            sm_context_status_uri: create_data.sm_context_status_uri.clone(),
            guami: create_data.guami.clone(),
            serving_network: create_data.serving_network.clone(),
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
    pub ho_state: Option<HoState>,
    pub target_id: Option<TargetId>,
    pub ho_preparation_indication: Option<bool>,
    pub data_forwarding: Option<bool>,
    pub n9_forwarding_tunnel: Option<TunnelInfo>,
    pub cause: Option<SmContextUpdateCause>,
    pub an_tunnel_info: Option<TunnelInfo>,
    pub pcf_id: Option<String>,
    pub pcf_group_id: Option<String>,
    pub pcf_set_id: Option<String>,
    #[serde(default)]
    pub release: Option<bool>,
    pub serving_nf_id: Option<String>,
    pub sm_context_status_uri: Option<String>,
    pub ng_ap_cause: Option<NgApCause>,
    #[serde(rename = "5gMmCauseValue")]
    pub five_g_mm_cause_value: Option<u32>,
    pub pei: Option<String>,
    pub guami: Option<Guami>,
    pub serving_network: Option<PlmnId>,
    pub to_be_switched: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PduSessionUpdatedData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n1_sm_info_to_ue: Option<RefToBinaryData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n1_sm_msg: Option<RefToBinaryData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n2_sm_info: Option<N2SmInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n2_sm_info_type: Option<N2SmInfoType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eps_bearer_info: Option<Vec<EpsBearerInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_features: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ho_state: Option<HoState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_ambr: Option<Ambr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cn_tunnel_info: Option<TunnelInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_cn_tunnel_info: Option<TunnelInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qos_flows_add_mod_list: Option<Vec<QosFlowItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qos_flows_rel_list: Option<Vec<QosFlowItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_cnx_state: Option<UpCnxState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_forwarding: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<SmContextUpdateCause>,
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
    Suspended,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SmContextUpdateCause {
    RelDueToHo,
    EpsFallback,
    #[serde(rename = "REL_DUE_TO_UP_SEC")]
    RelDueToUpSec,
    DnnCongestion,
    #[serde(rename = "S_NSSAI_CONGESTION")]
    SNssaiCongestion,
    RelDueToReactivation,
    #[serde(rename = "5G_AN_NOT_RESPONDING")]
    FiveGAnNotResponding,
    RelDueToSliceNotAvailable,
    RelDueToDuplicateSessionId,
    PduSessionStatusMismatch,
    HoFailure,
    InsufficientUpResources,
    PduSessionHandedOver,
    PduSessionResumed,
    CnAssistedRanParameterTuning,
    IsmfContextTransfer,
    SmfContextTransfer,
    RelDueToPsToCs,
    RelDueToSubscriptionChange,
    HoCancel,
    RelDueToSliceNotAuthorized,
    PduSessionHandOverFailure,
    DdnFailureStatus,
    RelDueToCpOnlyNotApplicable,
    NotSupportedWithIsmf,
    ChangedAnchorSmf,
    ChangedIntermediateSmf,
    TargetDnaiNotification,
    RelDueToVplmnQosFailure,
    RelDueToUnspecifiedReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpsBearerInfo {
    pub ebi: u8,
    pub pgw_s8u_fteid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextReleaseData {
    pub cause: Option<String>,
    pub ng_ap_cause: Option<NgApCause>,
    #[serde(rename = "5gMmCauseValue")]
    pub five_g_mm_cause_value: Option<u32>,
    pub ue_location: Option<UserLocation>,
    pub ue_time_zone: Option<String>,
    pub vsmf_release_only: Option<bool>,
    pub n2_sm_info: Option<N2SmInfo>,
    pub n2_sm_info_type: Option<N2SmInfoType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NgApCause {
    pub group: u32,
    pub value: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextReleasedData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub small_data_rate_status: Option<SmallDataRateStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apn_rate_status: Option<ApnRateStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmallDataRateStatus {
    pub remain_packets_ul: Option<u32>,
    pub remain_packets_dl: Option<u32>,
    pub validity_time: Option<String>,
    pub remain_ex_reports_ul: Option<u32>,
    pub remain_ex_reports_dl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApnRateStatus {
    pub remain_packets_ul: Option<u32>,
    pub remain_packets_dl: Option<u32>,
    pub validity_time: Option<String>,
    pub remain_ex_reports_ul: Option<u32>,
    pub remain_ex_reports_dl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextStatusNotification {
    pub status_info: SmContextStatusInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SmContextStatusInfo {
    pub resource_status: ResourceStatus,
    pub cause: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceStatus {
    Released,
}
