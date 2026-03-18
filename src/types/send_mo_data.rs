use serde::{Deserialize, Serialize};
use super::RefToBinaryData;
use crate::models::UserLocation;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendMoDataReqData {
    pub mo_data: RefToBinaryData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mo_exp_data_counter: Option<MoExpDataCounter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ue_location: Option<UserLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoExpDataCounter {
    pub counter: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_stamp: Option<String>,
}
