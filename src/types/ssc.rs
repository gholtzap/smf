use serde::{Deserialize, Serialize};
use super::udm;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SscMode {
    #[serde(rename = "SSC_MODE_1")]
    Mode1,
    #[serde(rename = "SSC_MODE_2")]
    Mode2,
    #[serde(rename = "SSC_MODE_3")]
    Mode3,
}

impl SscMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            SscMode::Mode1 => "SSC_MODE_1",
            SscMode::Mode2 => "SSC_MODE_2",
            SscMode::Mode3 => "SSC_MODE_3",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "SSC_MODE_1" | "1" => Some(SscMode::Mode1),
            "SSC_MODE_2" | "2" => Some(SscMode::Mode2),
            "SSC_MODE_3" | "3" => Some(SscMode::Mode3),
            _ => None,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        match self {
            SscMode::Mode1 | SscMode::Mode2 | SscMode::Mode3 => Ok(()),
        }
    }
}

impl Default for SscMode {
    fn default() -> Self {
        SscMode::Mode1
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SscModeConfig {
    pub allowed_modes: Vec<SscMode>,
    pub default_mode: SscMode,
}

impl Default for SscModeConfig {
    fn default() -> Self {
        Self {
            allowed_modes: vec![SscMode::Mode1, SscMode::Mode2, SscMode::Mode3],
            default_mode: SscMode::Mode1,
        }
    }
}

impl From<udm::SscMode> for SscMode {
    fn from(udm_mode: udm::SscMode) -> Self {
        match udm_mode {
            udm::SscMode::SscMode1 => SscMode::Mode1,
            udm::SscMode::SscMode2 => SscMode::Mode2,
            udm::SscMode::SscMode3 => SscMode::Mode3,
        }
    }
}
