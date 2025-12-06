use serde::{Deserialize, Serialize};
use crate::types::{QosFlowType, Snssai};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SliceQosPolicy {
    pub s_nssai: Snssai,
    pub default_qos_flow_config: QosFlowConfig,
    pub additional_qos_flows: Vec<QosFlowConfig>,
    pub max_qos_flows: u8,
    pub priority_level: u8,
    pub preemption_capability: PreemptionCapability,
    pub preemption_vulnerability: PreemptionVulnerability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosFlowConfig {
    pub five_qi: u8,
    pub priority_level: u8,
    pub qos_flow_type: QosFlowType,
    pub packet_delay_budget: u32,
    pub packet_error_rate: String,
    pub averaging_window: Option<u32>,
    pub max_data_burst_volume: Option<u32>,
    pub gfbr_uplink: Option<u64>,
    pub gfbr_downlink: Option<u64>,
    pub mfbr_uplink: Option<u64>,
    pub mfbr_downlink: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreemptionCapability {
    MayPreempt,
    NotPreempt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreemptionVulnerability {
    Preemptable,
    NotPreemptable,
}

impl SliceQosPolicy {
    pub fn new_default_for_slice(s_nssai: Snssai) -> Self {
        let (five_qi, priority_level, packet_delay_budget, packet_error_rate, preemption_capability, preemption_vulnerability) = match s_nssai.sst {
            1 => (9, 90, 300, "1E-6".to_string(), PreemptionCapability::NotPreempt, PreemptionVulnerability::Preemptable),
            2 => (1, 20, 100, "1E-2".to_string(), PreemptionCapability::MayPreempt, PreemptionVulnerability::NotPreemptable),
            3 => (9, 90, 300, "1E-6".to_string(), PreemptionCapability::NotPreempt, PreemptionVulnerability::Preemptable),
            _ => (9, 90, 300, "1E-6".to_string(), PreemptionCapability::NotPreempt, PreemptionVulnerability::Preemptable),
        };

        let qos_flow_type = if five_qi <= 4 || five_qi == 65 || five_qi == 66 || five_qi == 67 {
            QosFlowType::GBR
        } else {
            QosFlowType::NonGBR
        };

        Self {
            s_nssai,
            default_qos_flow_config: QosFlowConfig {
                five_qi,
                priority_level,
                qos_flow_type: qos_flow_type.clone(),
                packet_delay_budget,
                packet_error_rate,
                averaging_window: None,
                max_data_burst_volume: None,
                gfbr_uplink: None,
                gfbr_downlink: None,
                mfbr_uplink: None,
                mfbr_downlink: None,
            },
            additional_qos_flows: vec![],
            max_qos_flows: 8,
            priority_level,
            preemption_capability,
            preemption_vulnerability,
        }
    }

    pub fn get_qos_flow_config(&self, qfi: u8) -> &QosFlowConfig {
        if qfi == 1 {
            &self.default_qos_flow_config
        } else {
            self.additional_qos_flows
                .get((qfi - 2) as usize)
                .unwrap_or(&self.default_qos_flow_config)
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.default_qos_flow_config.five_qi == 0 || self.default_qos_flow_config.five_qi > 127 {
            return Err(format!("Invalid 5QI: {}", self.default_qos_flow_config.five_qi));
        }

        if self.max_qos_flows == 0 || self.max_qos_flows > 64 {
            return Err(format!("Invalid max QoS flows: {}", self.max_qos_flows));
        }

        Ok(())
    }
}

impl QosFlowConfig {
    pub fn from_5qi(five_qi: u8) -> Self {
        let (priority_level, packet_delay_budget, packet_error_rate, averaging_window) = match five_qi {
            1 => (20, 100, "1E-2".to_string(), Some(2000)),
            2 => (40, 150, "1E-3".to_string(), Some(2000)),
            3 => (30, 50, "1E-3".to_string(), Some(2000)),
            4 => (50, 300, "1E-6".to_string(), Some(2000)),
            5 => (10, 100, "1E-6".to_string(), None),
            6 => (60, 300, "1E-6".to_string(), None),
            7 => (70, 100, "1E-3".to_string(), None),
            8 => (80, 300, "1E-6".to_string(), None),
            9 => (90, 300, "1E-6".to_string(), None),
            65 => (7, 75, "1E-2".to_string(), Some(2000)),
            66 => (20, 100, "1E-2".to_string(), Some(2000)),
            67 => (15, 100, "1E-3".to_string(), Some(2000)),
            69 => (5, 60, "1E-6".to_string(), None),
            70 => (55, 200, "1E-6".to_string(), None),
            79 => (65, 50, "1E-2".to_string(), Some(2000)),
            80 => (68, 10, "1E-6".to_string(), None),
            _ => (50, 300, "1E-6".to_string(), None),
        };

        let qos_flow_type = if five_qi <= 4 || five_qi == 65 || five_qi == 66 || five_qi == 67 {
            QosFlowType::GBR
        } else if five_qi == 82 || five_qi == 83 || five_qi == 84 || five_qi == 85 {
            QosFlowType::DelayGBR
        } else {
            QosFlowType::NonGBR
        };

        Self {
            five_qi,
            priority_level,
            qos_flow_type,
            packet_delay_budget,
            packet_error_rate,
            averaging_window,
            max_data_burst_volume: if five_qi == 80 { Some(255) } else { None },
            gfbr_uplink: None,
            gfbr_downlink: None,
            mfbr_uplink: None,
            mfbr_downlink: None,
        }
    }
}
