use crate::types::{BitRate, QosFlow, QosFlowType, SliceQosPolicy, Snssai};

pub struct SliceQosPolicyService {
    policies: Vec<SliceQosPolicy>,
}

impl SliceQosPolicyService {
    pub fn new() -> Self {
        Self {
            policies: Self::default_policies(),
        }
    }

    pub fn new_with_policies(policies: Vec<SliceQosPolicy>) -> Self {
        Self { policies }
    }

    fn default_policies() -> Vec<SliceQosPolicy> {
        vec![
            SliceQosPolicy::new_default_for_slice(Snssai { sst: 1, sd: None }),
            SliceQosPolicy::new_default_for_slice(Snssai { sst: 2, sd: None }),
            SliceQosPolicy::new_default_for_slice(Snssai { sst: 3, sd: None }),
            SliceQosPolicy::new_default_for_slice(Snssai {
                sst: 1,
                sd: Some("000001".to_string()),
            }),
        ]
    }

    pub fn get_policy(&self, s_nssai: &Snssai) -> Option<&SliceQosPolicy> {
        self.policies.iter().find(|p| {
            p.s_nssai.sst == s_nssai.sst && p.s_nssai.sd == s_nssai.sd
        })
    }

    pub fn create_default_qos_flow(&self, s_nssai: &Snssai, qfi: u8) -> QosFlow {
        if let Some(policy) = self.get_policy(s_nssai) {
            let config = &policy.default_qos_flow_config;
            QosFlow {
                qfi,
                five_qi: config.five_qi,
                priority_level: config.priority_level,
                qos_flow_type: config.qos_flow_type.clone(),
                gfbr: if config.gfbr_uplink.is_some() || config.gfbr_downlink.is_some() {
                    Some(BitRate {
                        uplink: config.gfbr_uplink.unwrap_or(0),
                        downlink: config.gfbr_downlink.unwrap_or(0),
                    })
                } else {
                    None
                },
                mfbr: if config.mfbr_uplink.is_some() || config.mfbr_downlink.is_some() {
                    Some(BitRate {
                        uplink: config.mfbr_uplink.unwrap_or(0),
                        downlink: config.mfbr_downlink.unwrap_or(0),
                    })
                } else {
                    None
                },
                packet_delay_budget: Some(config.packet_delay_budget),
                packet_error_rate: Some(config.packet_error_rate.clone()),
                averaging_window: config.averaging_window,
                max_data_burst_volume: config.max_data_burst_volume,
            }
        } else {
            QosFlow::new_default(qfi)
        }
    }

    pub fn create_qos_flow_with_5qi(&self, s_nssai: &Snssai, qfi: u8, five_qi: u8) -> QosFlow {
        if let Some(policy) = self.get_policy(s_nssai) {
            let config = policy.get_qos_flow_config(qfi);
            QosFlow {
                qfi,
                five_qi,
                priority_level: config.priority_level,
                qos_flow_type: config.qos_flow_type.clone(),
                gfbr: if config.gfbr_uplink.is_some() || config.gfbr_downlink.is_some() {
                    Some(BitRate {
                        uplink: config.gfbr_uplink.unwrap_or(0),
                        downlink: config.gfbr_downlink.unwrap_or(0),
                    })
                } else {
                    None
                },
                mfbr: if config.mfbr_uplink.is_some() || config.mfbr_downlink.is_some() {
                    Some(BitRate {
                        uplink: config.mfbr_uplink.unwrap_or(0),
                        downlink: config.mfbr_downlink.unwrap_or(0),
                    })
                } else {
                    None
                },
                packet_delay_budget: Some(config.packet_delay_budget),
                packet_error_rate: Some(config.packet_error_rate.clone()),
                averaging_window: config.averaging_window,
                max_data_burst_volume: config.max_data_burst_volume,
            }
        } else {
            QosFlow::new_with_5qi(qfi, five_qi)
        }
    }

    pub fn get_priority_level(&self, s_nssai: &Snssai) -> u8 {
        self.get_policy(s_nssai)
            .map(|p| p.priority_level)
            .unwrap_or(50)
    }

    pub fn validate_qos_flow(&self, s_nssai: &Snssai, qfi: u8) -> Result<(), String> {
        if let Some(policy) = self.get_policy(s_nssai) {
            if qfi == 0 || qfi > policy.max_qos_flows {
                return Err(format!(
                    "QFI {} exceeds maximum QoS flows for slice (max: {})",
                    qfi, policy.max_qos_flows
                ));
            }
        }
        Ok(())
    }

    pub fn add_policy(&mut self, policy: SliceQosPolicy) -> Result<(), String> {
        policy.validate()?;

        if let Some(existing_idx) = self.policies.iter().position(|p| {
            p.s_nssai.sst == policy.s_nssai.sst && p.s_nssai.sd == policy.s_nssai.sd
        }) {
            self.policies[existing_idx] = policy;
        } else {
            self.policies.push(policy);
        }

        Ok(())
    }

    pub fn list_policies(&self) -> &[SliceQosPolicy] {
        &self.policies
    }
}

impl Default for SliceQosPolicyService {
    fn default() -> Self {
        Self::new()
    }
}
