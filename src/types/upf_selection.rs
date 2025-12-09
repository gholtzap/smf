use serde::{Deserialize, Serialize};
use super::{UpfNode, Snssai};
use crate::models::UserLocation;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpfSelectionCriteria {
    pub ue_location: Option<UserLocation>,
    pub s_nssai: Snssai,
    pub dnn: String,
    pub current_upf_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpfSelectionResult {
    pub selected_upf: UpfNode,
    pub score: u32,
    pub relocation_required: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpfRelocationReason {
    LocationChange,
    UpfFailure,
    LoadBalancing,
    PolicyChange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpfRelocationDecision {
    pub should_relocate: bool,
    pub reason: Option<UpfRelocationReason>,
    pub target_upf_address: Option<String>,
}
