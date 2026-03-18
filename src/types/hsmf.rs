use serde::{Deserialize, Serialize};
use crate::models::{UserLocation, NgApCause, SmallDataRateStatus, ApnRateStatus, SmContext};

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
