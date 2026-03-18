use serde::{Deserialize, Serialize};
use crate::models::{UserLocation, NgApCause, SmallDataRateStatus, ApnRateStatus, SmContext, TunnelInfo, AnType, RatType, Ambr, QosFlowItem, EpsBearerInfo};
use crate::types::{PlmnId, RefToBinaryData, Snssai};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HsmfReleaseData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ng_ap_cause: Option<NgApCause>,
    #[serde(rename = "5gMmCauseValue", skip_serializing_if = "Option::is_none")]
    pub five_g_mm_cause_value: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_location: Option<UserLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HsmfReleasedData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub small_data_rate_status: Option<SmallDataRateStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apn_rate_status: Option<ApnRateStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PduSessionContextType {
    AfCoordinationInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HsmfRetrieveData {
    #[serde(default)]
    pub small_data_rate_status_req: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdu_session_context_type: Option<PduSessionContextType>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HsmfRetrievedData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub small_data_rate_status: Option<SmallDataRateStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub af_coordination_info: Option<AfCoordinationInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AfCoordinationInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_dnai: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ue_ipv4_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ue_ipv6_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_info_list: Option<Vec<NotificationInfo>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotificationInfo {
    pub notif_id: String,
    pub notif_uri: String,
    #[serde(default)]
    pub up_buffer_ind: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RequestIndication {
    #[serde(rename = "UE_REQ_PDU_SES_MOD")]
    UeReqPduSesMod,
    #[serde(rename = "UE_REQ_PDU_SES_REL")]
    UeReqPduSesRel,
    #[serde(rename = "PDU_SES_MOB")]
    PduSesMob,
    #[serde(rename = "NW_REQ_PDU_SES_AUTH")]
    NwReqPduSesAuth,
    #[serde(rename = "NW_REQ_PDU_SES_MOD")]
    NwReqPduSesMod,
    #[serde(rename = "NW_REQ_PDU_SES_REL")]
    NwReqPduSesRel,
    #[serde(rename = "EBI_ASSIGNMENT_REQ")]
    EbiAssignmentReq,
    #[serde(rename = "REL_DUE_TO_5G_AN_REQUEST")]
    RelDueTo5gAnRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HsmfUpdateData {
    pub request_indication: RequestIndication,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pei: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcn_tunnel_info: Option<TunnelInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icn_tunnel_info: Option<TunnelInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_cn_tunnel_info: Option<TunnelInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serving_network: Option<PlmnId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub an_type: Option<AnType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_an_type: Option<AnType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rat_type: Option<RatType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_location: Option<UserLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_time_zone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n1_sm_info_from_ue: Option<RefToBinaryData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unknown_n1_sm_info: Option<RefToBinaryData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qos_flows_rel_notify_list: Option<Vec<QosFlowItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qos_flows_notify_list: Option<Vec<QosFlowNotifyItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eps_bearer_info: Option<Vec<EpsBearerInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assign_ebi_list: Option<Vec<Arp5qi>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoke_ebi_list: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ng_ap_cause: Option<NgApCause>,
    #[serde(rename = "5gMmCauseValue", skip_serializing_if = "Option::is_none")]
    pub five_g_mm_cause_value: Option<u32>,
    #[serde(default)]
    pub always_on_requested: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eps_interworking_ind: Option<EpsInterworkingIndication>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secondary_rat_usage_report: Option<Vec<SecondaryRatUsageReport>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secondary_rat_usage_info: Option<Vec<SecondaryRatUsageInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_features: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s_nssai: Option<Snssai>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosFlowNotifyItem {
    pub qfi: u8,
    pub notification_cause: QosFlowNotifyCause,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QosFlowNotifyCause {
    #[serde(rename = "FULFILLED")]
    Fulfilled,
    #[serde(rename = "NOT_FULFILLED")]
    NotFulfilled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Arp5qi {
    #[serde(rename = "5qi")]
    pub five_qi: u8,
    pub arp: Option<ArpHsmf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArpHsmf {
    pub priority_level: u8,
    pub preempt_cap: String,
    pub preempt_vuln: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EpsInterworkingIndication {
    #[serde(rename = "NONE")]
    None,
    #[serde(rename = "WITH_N26")]
    WithN26,
    #[serde(rename = "WITHOUT_N26")]
    WithoutN26,
    #[serde(rename = "IWK_NON_3GPP")]
    IwkNon3gpp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecondaryRatUsageReport {
    pub secondary_rat_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qos_flows_usage_data: Option<Vec<QosFlowUsageReport>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosFlowUsageReport {
    pub qfi: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time_stamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time_stamp: Option<String>,
    #[serde(default)]
    pub downlink_volume: u64,
    #[serde(default)]
    pub uplink_volume: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecondaryRatUsageInfo {
    pub secondary_rat_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qos_flows_usage_data: Option<Vec<QosFlowUsageReport>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdu_session_usage_data: Option<VolumeTimedReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VolumeTimedReport {
    pub start_time_stamp: String,
    pub end_time_stamp: String,
    pub downlink_volume: u64,
    pub uplink_volume: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HsmfUpdatedData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n1_sm_info_to_ue: Option<RefToBinaryData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_features: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_ambr: Option<Ambr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eps_bearer_info: Option<Vec<EpsBearerInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_provided_charging_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qos_flows_setup_list: Option<Vec<QosFlowSetupItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qos_flows_rel_list: Option<Vec<QosFlowItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up_security: Option<UpSecurityResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_integrity_protected_data_rate_ul: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_integrity_protected_data_rate_dl: Option<String>,
    #[serde(rename = "pti", skip_serializing_if = "Option::is_none")]
    pub pti: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inter_plmn_api_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intra_plmn_api_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roaming_charging_profile: Option<RoamingChargingProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnai_list: Option<Vec<String>>,
    #[serde(default)]
    pub ipv6_multi_homing_ind: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QosFlowSetupItem {
    pub qfi: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qos_rules: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ebi: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpSecurityResult {
    pub up_integr: String,
    pub up_confid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoamingChargingProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggers: Option<Vec<RoamingChargingTrigger>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_record_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoamingChargingTrigger {
    pub trigger_type: String,
    pub trigger_category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HsmfUpdateError {
    pub error: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n1_sm_info_to_ue: Option<RefToBinaryData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_time: Option<String>,
}

impl HsmfUpdateError {
    pub fn from_problem(status: u16, title: &str, detail: &str, cause: &str) -> Self {
        Self {
            error: serde_json::json!({
                "type": format!("https://httpstatuses.io/{}", status),
                "title": title,
                "status": status,
                "detail": detail,
                "cause": cause,
            }),
            n1_sm_info_to_ue: None,
            recovery_time: None,
        }
    }
}

impl HsmfRetrievedData {
    pub fn from_context(ctx: &SmContext, req: &HsmfRetrieveData) -> Self {
        let small_data_rate_status = if req.small_data_rate_status_req {
            ctx.small_data_rate_status.clone()
        } else {
            None
        };

        let af_coordination_info = match req.pdu_session_context_type {
            Some(PduSessionContextType::AfCoordinationInfo) => {
                let ipv4 = ctx.pdu_address.as_ref().and_then(|a| a.ipv4_addr.clone());
                let ipv6 = ctx.pdu_address.as_ref().and_then(|a| a.ipv6_addr.clone());
                Some(AfCoordinationInfo {
                    source_dnai: ctx.dnai.clone(),
                    source_ue_ipv4_addr: ipv4,
                    source_ue_ipv6_prefix: ipv6,
                    notification_info_list: ctx.notification_info_list.clone(),
                })
            }
            None => None,
        };

        Self {
            small_data_rate_status,
            af_coordination_info,
        }
    }
}
