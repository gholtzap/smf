use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosRule {
    pub qos_rule_id: u8,
    pub precedence: u8,
    pub segregation: bool,
    pub qfi: u8,
    pub packet_filter_ids: Vec<u8>,
    pub rule_operation_code: RuleOperationCode,
    pub default_qos_rule: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleOperationCode {
    CreateNewQosRule,
    DeleteExistingQosRule,
    ModifyExistingQosRuleAndAddPacketFilters,
    ModifyExistingQosRuleAndReplaceAllPacketFilters,
    ModifyExistingQosRuleAndDeletePacketFilters,
    ModifyExistingQosRuleWithoutModifyingPacketFilters,
}

impl QosRule {
    pub fn new(
        qos_rule_id: u8,
        precedence: u8,
        segregation: bool,
        qfi: u8,
        packet_filter_ids: Vec<u8>,
        default_qos_rule: bool,
    ) -> Self {
        QosRule {
            qos_rule_id,
            precedence,
            segregation,
            qfi,
            packet_filter_ids,
            rule_operation_code: RuleOperationCode::CreateNewQosRule,
            default_qos_rule,
        }
    }

    pub fn new_default(qos_rule_id: u8, qfi: u8) -> Self {
        QosRule {
            qos_rule_id,
            precedence: 255,
            segregation: false,
            qfi,
            packet_filter_ids: vec![],
            rule_operation_code: RuleOperationCode::CreateNewQosRule,
            default_qos_rule: true,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.precedence == 0 {
            return Err("Precedence value 0 is reserved".to_string());
        }

        if self.qfi > 63 {
            return Err(format!("QFI must be between 0 and 63, got {}", self.qfi));
        }

        if !self.default_qos_rule && self.packet_filter_ids.is_empty() {
            return Err("Non-default QoS rules must have at least one packet filter".to_string());
        }

        if self.default_qos_rule && !self.packet_filter_ids.is_empty() {
            return Err("Default QoS rules cannot have packet filters".to_string());
        }

        Ok(())
    }

    pub fn is_applicable_for_packet(&self, packet_filter_id: u8) -> bool {
        if self.default_qos_rule {
            return true;
        }
        self.packet_filter_ids.contains(&packet_filter_id)
    }
}
