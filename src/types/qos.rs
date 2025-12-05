use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosFlow {
    pub qfi: u8,
    pub five_qi: u8,
    pub priority_level: u8,
    pub qos_flow_type: QosFlowType,
    pub gfbr: Option<BitRate>,
    pub mfbr: Option<BitRate>,
    pub packet_delay_budget: Option<u32>,
    pub packet_error_rate: Option<String>,
    pub averaging_window: Option<u32>,
    pub max_data_burst_volume: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QosFlowType {
    GBR,
    NonGBR,
    DelayGBR,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitRate {
    pub uplink: u64,
    pub downlink: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosProfile {
    pub five_qi: u8,
    pub priority_level: u8,
    pub packet_delay_budget: u32,
    pub packet_error_rate: String,
    pub default_averaging_window: Option<u32>,
    pub default_max_data_burst_volume: Option<u32>,
}

impl QosProfile {
    pub fn from_5qi(five_qi: u8) -> Self {
        match five_qi {
            1 => QosProfile {
                five_qi: 1,
                priority_level: 20,
                packet_delay_budget: 100,
                packet_error_rate: "1E-2".to_string(),
                default_averaging_window: Some(2000),
                default_max_data_burst_volume: None,
            },
            2 => QosProfile {
                five_qi: 2,
                priority_level: 40,
                packet_delay_budget: 150,
                packet_error_rate: "1E-3".to_string(),
                default_averaging_window: Some(2000),
                default_max_data_burst_volume: None,
            },
            3 => QosProfile {
                five_qi: 3,
                priority_level: 30,
                packet_delay_budget: 50,
                packet_error_rate: "1E-3".to_string(),
                default_averaging_window: Some(2000),
                default_max_data_burst_volume: None,
            },
            4 => QosProfile {
                five_qi: 4,
                priority_level: 50,
                packet_delay_budget: 300,
                packet_error_rate: "1E-6".to_string(),
                default_averaging_window: Some(2000),
                default_max_data_burst_volume: None,
            },
            5 => QosProfile {
                five_qi: 5,
                priority_level: 10,
                packet_delay_budget: 100,
                packet_error_rate: "1E-6".to_string(),
                default_averaging_window: None,
                default_max_data_burst_volume: None,
            },
            6 => QosProfile {
                five_qi: 6,
                priority_level: 60,
                packet_delay_budget: 300,
                packet_error_rate: "1E-6".to_string(),
                default_averaging_window: None,
                default_max_data_burst_volume: None,
            },
            7 => QosProfile {
                five_qi: 7,
                priority_level: 70,
                packet_delay_budget: 100,
                packet_error_rate: "1E-3".to_string(),
                default_averaging_window: None,
                default_max_data_burst_volume: None,
            },
            8 => QosProfile {
                five_qi: 8,
                priority_level: 80,
                packet_delay_budget: 300,
                packet_error_rate: "1E-6".to_string(),
                default_averaging_window: None,
                default_max_data_burst_volume: None,
            },
            9 => QosProfile {
                five_qi: 9,
                priority_level: 90,
                packet_delay_budget: 300,
                packet_error_rate: "1E-6".to_string(),
                default_averaging_window: None,
                default_max_data_burst_volume: None,
            },
            65 => QosProfile {
                five_qi: 65,
                priority_level: 7,
                packet_delay_budget: 75,
                packet_error_rate: "1E-2".to_string(),
                default_averaging_window: Some(2000),
                default_max_data_burst_volume: None,
            },
            66 => QosProfile {
                five_qi: 66,
                priority_level: 20,
                packet_delay_budget: 100,
                packet_error_rate: "1E-2".to_string(),
                default_averaging_window: Some(2000),
                default_max_data_burst_volume: None,
            },
            67 => QosProfile {
                five_qi: 67,
                priority_level: 15,
                packet_delay_budget: 100,
                packet_error_rate: "1E-3".to_string(),
                default_averaging_window: Some(2000),
                default_max_data_burst_volume: None,
            },
            69 => QosProfile {
                five_qi: 69,
                priority_level: 5,
                packet_delay_budget: 60,
                packet_error_rate: "1E-6".to_string(),
                default_averaging_window: None,
                default_max_data_burst_volume: None,
            },
            70 => QosProfile {
                five_qi: 70,
                priority_level: 55,
                packet_delay_budget: 200,
                packet_error_rate: "1E-6".to_string(),
                default_averaging_window: None,
                default_max_data_burst_volume: None,
            },
            79 => QosProfile {
                five_qi: 79,
                priority_level: 65,
                packet_delay_budget: 50,
                packet_error_rate: "1E-2".to_string(),
                default_averaging_window: Some(2000),
                default_max_data_burst_volume: None,
            },
            80 => QosProfile {
                five_qi: 80,
                priority_level: 68,
                packet_delay_budget: 10,
                packet_error_rate: "1E-6".to_string(),
                default_averaging_window: None,
                default_max_data_burst_volume: Some(255),
            },
            _ => QosProfile {
                five_qi,
                priority_level: 50,
                packet_delay_budget: 300,
                packet_error_rate: "1E-6".to_string(),
                default_averaging_window: None,
                default_max_data_burst_volume: None,
            },
        }
    }
}

impl QosFlow {
    pub fn new_default(qfi: u8) -> Self {
        let profile = QosProfile::from_5qi(9);
        QosFlow {
            qfi,
            five_qi: 9,
            priority_level: profile.priority_level,
            qos_flow_type: QosFlowType::NonGBR,
            gfbr: None,
            mfbr: None,
            packet_delay_budget: Some(profile.packet_delay_budget),
            packet_error_rate: Some(profile.packet_error_rate),
            averaging_window: profile.default_averaging_window,
            max_data_burst_volume: profile.default_max_data_burst_volume,
        }
    }

    pub fn new_with_5qi(qfi: u8, five_qi: u8) -> Self {
        let profile = QosProfile::from_5qi(five_qi);
        let qos_flow_type = if five_qi <= 4 || five_qi == 65 || five_qi == 66 || five_qi == 67 {
            QosFlowType::GBR
        } else if five_qi == 82 || five_qi == 83 || five_qi == 84 || five_qi == 85 {
            QosFlowType::DelayGBR
        } else {
            QosFlowType::NonGBR
        };

        QosFlow {
            qfi,
            five_qi,
            priority_level: profile.priority_level,
            qos_flow_type,
            gfbr: None,
            mfbr: None,
            packet_delay_budget: Some(profile.packet_delay_budget),
            packet_error_rate: Some(profile.packet_error_rate),
            averaging_window: profile.default_averaging_window,
            max_data_burst_volume: profile.default_max_data_burst_volume,
        }
    }
}
