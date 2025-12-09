use serde::{Deserialize, Serialize};
use super::QosFlow;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosFlowMappingResult {
    pub allocated_flows: Vec<QosFlow>,
    pub failed_flows: Vec<QosFlowFailure>,
    pub mapping_status: QosFlowMappingStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosFlowFailure {
    pub qfi: u8,
    pub five_qi: u8,
    pub is_critical: bool,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum QosFlowMappingStatus {
    AllAllocated,
    PartiallyAllocated,
    CriticalFlowsFailed,
    AllFailed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosFlowContinuityCheck {
    pub supi: String,
    pub pdu_session_id: u8,
    pub source_qos_flows: Vec<QosFlow>,
    pub target_qos_flows: Vec<QosFlow>,
    pub continuity_status: QosFlowContinuityStatus,
    pub missing_flows: Vec<u8>,
    pub added_flows: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum QosFlowContinuityStatus {
    Maintained,
    PartiallyMaintained,
    Interrupted,
}

impl QosFlowMappingStatus {
    pub fn is_acceptable(&self) -> bool {
        matches!(self, QosFlowMappingStatus::AllAllocated | QosFlowMappingStatus::PartiallyAllocated)
    }
}

impl QosFlowContinuityStatus {
    pub fn is_acceptable(&self) -> bool {
        matches!(self, QosFlowContinuityStatus::Maintained | QosFlowContinuityStatus::PartiallyMaintained)
    }
}
