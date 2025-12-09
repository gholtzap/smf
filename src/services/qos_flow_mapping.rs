use crate::types::{
    QosFlow, QosFlowMappingResult, QosFlowMappingStatus, QosFlowFailure,
    QosFlowContinuityCheck, QosFlowContinuityStatus, QosFlowType,
};
use std::collections::{HashMap, HashSet};
use tracing::{info, warn};

pub struct QosFlowMappingService;

impl QosFlowMappingService {
    pub fn map_qos_flows_to_target(
        source_flows: &[QosFlow],
        allocated_qfis: &[u8],
        failed_qfis: &[u8],
    ) -> QosFlowMappingResult {
        let source_map: HashMap<u8, &QosFlow> = source_flows
            .iter()
            .map(|qf| (qf.qfi, qf))
            .collect();

        let allocated_flows: Vec<QosFlow> = allocated_qfis
            .iter()
            .filter_map(|qfi| source_map.get(qfi).map(|&qf| qf.clone()))
            .collect();

        let failed_flows: Vec<QosFlowFailure> = failed_qfis
            .iter()
            .filter_map(|qfi| {
                source_map.get(qfi).map(|qf| {
                    let is_critical = Self::is_critical_qos_flow(qf);
                    QosFlowFailure {
                        qfi: *qfi,
                        five_qi: qf.five_qi,
                        is_critical,
                        failure_reason: Some("Failed to allocate at target".to_string()),
                    }
                })
            })
            .collect();

        let mapping_status = Self::determine_mapping_status(
            source_flows.len(),
            allocated_flows.len(),
            &failed_flows,
        );

        info!(
            "QoS flow mapping completed: {} source flows, {} allocated, {} failed, status: {:?}",
            source_flows.len(),
            allocated_flows.len(),
            failed_flows.len(),
            mapping_status
        );

        if !failed_flows.is_empty() {
            for failure in &failed_flows {
                let severity = if failure.is_critical { "ERROR" } else { "WARN" };
                warn!(
                    "[{}] QoS flow allocation failed: QFI={}, 5QI={}, Critical={}",
                    severity, failure.qfi, failure.five_qi, failure.is_critical
                );
            }
        }

        QosFlowMappingResult {
            allocated_flows,
            failed_flows,
            mapping_status,
        }
    }

    pub fn check_qos_flow_continuity(
        supi: &str,
        pdu_session_id: u8,
        source_flows: &[QosFlow],
        target_flows: &[QosFlow],
    ) -> QosFlowContinuityCheck {
        let source_qfis: HashSet<u8> = source_flows.iter().map(|qf| qf.qfi).collect();
        let target_qfis: HashSet<u8> = target_flows.iter().map(|qf| qf.qfi).collect();

        let missing_flows: Vec<u8> = source_qfis
            .difference(&target_qfis)
            .copied()
            .collect();

        let added_flows: Vec<u8> = target_qfis
            .difference(&source_qfis)
            .copied()
            .collect();

        let continuity_status = Self::determine_continuity_status(
            source_flows,
            &missing_flows,
        );

        info!(
            "QoS flow continuity check for SUPI: {}, PDU Session ID: {}: {} source flows, {} target flows, {} missing, {} added, status: {:?}",
            supi,
            pdu_session_id,
            source_flows.len(),
            target_flows.len(),
            missing_flows.len(),
            added_flows.len(),
            continuity_status
        );

        if !missing_flows.is_empty() {
            let critical_missing = missing_flows.iter().filter(|qfi| {
                source_flows.iter()
                    .find(|qf| qf.qfi == **qfi)
                    .map(Self::is_critical_qos_flow)
                    .unwrap_or(false)
            }).count();

            if critical_missing > 0 {
                warn!(
                    "QoS flow continuity interrupted: {} critical flows missing for SUPI: {}, PDU Session ID: {}, Missing QFIs: {:?}",
                    critical_missing, supi, pdu_session_id, missing_flows
                );
            } else {
                warn!(
                    "QoS flow continuity partially maintained: {} non-critical flows missing for SUPI: {}, PDU Session ID: {}, Missing QFIs: {:?}",
                    missing_flows.len(), supi, pdu_session_id, missing_flows
                );
            }
        }

        if !added_flows.is_empty() {
            info!(
                "New QoS flows added during handover for SUPI: {}, PDU Session ID: {}, Added QFIs: {:?}",
                supi, pdu_session_id, added_flows
            );
        }

        QosFlowContinuityCheck {
            supi: supi.to_string(),
            pdu_session_id,
            source_qos_flows: source_flows.to_vec(),
            target_qos_flows: target_flows.to_vec(),
            continuity_status,
            missing_flows,
            added_flows,
        }
    }

    pub fn validate_mandatory_qos_flows(
        qos_flows: &[QosFlow],
    ) -> Result<(), String> {
        let has_default_flow = qos_flows.iter().any(|qf| qf.five_qi == 9);

        if !has_default_flow {
            return Err("No default QoS flow (5QI 9) present".to_string());
        }

        let critical_flows: Vec<&QosFlow> = qos_flows
            .iter()
            .filter(|qf| Self::is_critical_qos_flow(qf))
            .collect();

        if !critical_flows.is_empty() {
            info!(
                "Validated {} critical QoS flows: {:?}",
                critical_flows.len(),
                critical_flows.iter().map(|qf| (qf.qfi, qf.five_qi)).collect::<Vec<_>>()
            );
        }

        Ok(())
    }

    pub fn filter_critical_qos_flows(qos_flows: &[QosFlow]) -> Vec<QosFlow> {
        qos_flows
            .iter()
            .filter(|qf| Self::is_critical_qos_flow(qf))
            .cloned()
            .collect()
    }

    fn is_critical_qos_flow(qos_flow: &QosFlow) -> bool {
        matches!(qos_flow.qos_flow_type, QosFlowType::GBR)
            || qos_flow.five_qi <= 5
            || qos_flow.priority_level <= 20
    }

    fn determine_mapping_status(
        source_count: usize,
        allocated_count: usize,
        failed_flows: &[QosFlowFailure],
    ) -> QosFlowMappingStatus {
        if allocated_count == 0 {
            return QosFlowMappingStatus::AllFailed;
        }

        let has_critical_failure = failed_flows.iter().any(|f| f.is_critical);
        if has_critical_failure {
            return QosFlowMappingStatus::CriticalFlowsFailed;
        }

        if allocated_count == source_count {
            QosFlowMappingStatus::AllAllocated
        } else {
            QosFlowMappingStatus::PartiallyAllocated
        }
    }

    fn determine_continuity_status(
        source_flows: &[QosFlow],
        missing_qfis: &[u8],
    ) -> QosFlowContinuityStatus {
        if missing_qfis.is_empty() {
            return QosFlowContinuityStatus::Maintained;
        }

        let critical_missing = missing_qfis.iter().any(|qfi| {
            source_flows
                .iter()
                .find(|qf| qf.qfi == *qfi)
                .map(Self::is_critical_qos_flow)
                .unwrap_or(false)
        });

        if critical_missing {
            QosFlowContinuityStatus::Interrupted
        } else {
            QosFlowContinuityStatus::PartiallyMaintained
        }
    }

    pub fn get_qos_flow_summary(qos_flows: &[QosFlow]) -> String {
        let gbr_count = qos_flows.iter().filter(|qf| matches!(qf.qos_flow_type, QosFlowType::GBR)).count();
        let non_gbr_count = qos_flows.iter().filter(|qf| matches!(qf.qos_flow_type, QosFlowType::NonGBR)).count();
        let delay_gbr_count = qos_flows.iter().filter(|qf| matches!(qf.qos_flow_type, QosFlowType::DelayGBR)).count();
        let critical_count = qos_flows.iter().filter(|qf| Self::is_critical_qos_flow(qf)).count();

        format!(
            "Total: {}, GBR: {}, Non-GBR: {}, Delay-GBR: {}, Critical: {}",
            qos_flows.len(),
            gbr_count,
            non_gbr_count,
            delay_gbr_count,
            critical_count
        )
    }
}
