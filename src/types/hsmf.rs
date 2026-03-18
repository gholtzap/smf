use serde::{Deserialize, Serialize};
use crate::models::{UserLocation, NgApCause, SmallDataRateStatus, ApnRateStatus};

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
