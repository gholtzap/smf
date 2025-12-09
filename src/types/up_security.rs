use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipheringAlgorithm {
    Nea0,
    Nea1,
    Nea2,
    Nea3,
}

impl CipheringAlgorithm {
    pub fn to_u8(&self) -> u8 {
        match self {
            CipheringAlgorithm::Nea0 => 0,
            CipheringAlgorithm::Nea1 => 1,
            CipheringAlgorithm::Nea2 => 2,
            CipheringAlgorithm::Nea3 => 3,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(CipheringAlgorithm::Nea0),
            1 => Some(CipheringAlgorithm::Nea1),
            2 => Some(CipheringAlgorithm::Nea2),
            3 => Some(CipheringAlgorithm::Nea3),
            _ => None,
        }
    }

    pub fn is_null_algorithm(&self) -> bool {
        matches!(self, CipheringAlgorithm::Nea0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityAlgorithm {
    Nia0,
    Nia1,
    Nia2,
    Nia3,
}

impl IntegrityAlgorithm {
    pub fn to_u8(&self) -> u8 {
        match self {
            IntegrityAlgorithm::Nia0 => 0,
            IntegrityAlgorithm::Nia1 => 1,
            IntegrityAlgorithm::Nia2 => 2,
            IntegrityAlgorithm::Nia3 => 3,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(IntegrityAlgorithm::Nia0),
            1 => Some(IntegrityAlgorithm::Nia1),
            2 => Some(IntegrityAlgorithm::Nia2),
            3 => Some(IntegrityAlgorithm::Nia3),
            _ => None,
        }
    }

    pub fn is_null_algorithm(&self) -> bool {
        matches!(self, IntegrityAlgorithm::Nia0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpSecurityContext {
    pub integrity_protection_algorithm: Option<IntegrityAlgorithm>,
    pub ciphering_algorithm: Option<CipheringAlgorithm>,
    pub integrity_protection_activated: bool,
    pub confidentiality_protection_activated: bool,
    pub maximum_integrity_protected_data_rate_ul: Option<MaximumIntegrityProtectedDataRate>,
    pub maximum_integrity_protected_data_rate_dl: Option<MaximumIntegrityProtectedDataRate>,
}

impl Default for UpSecurityContext {
    fn default() -> Self {
        Self {
            integrity_protection_algorithm: None,
            ciphering_algorithm: None,
            integrity_protection_activated: false,
            confidentiality_protection_activated: false,
            maximum_integrity_protected_data_rate_ul: None,
            maximum_integrity_protected_data_rate_dl: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaximumIntegrityProtectedDataRate {
    Bitrate64kbs,
    MaximumUeRate,
}

impl MaximumIntegrityProtectedDataRate {
    pub fn to_kbps(&self) -> Option<u64> {
        match self {
            MaximumIntegrityProtectedDataRate::Bitrate64kbs => Some(64),
            MaximumIntegrityProtectedDataRate::MaximumUeRate => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UeSecurityCapabilities {
    pub nr_encryption_algorithms: Vec<CipheringAlgorithm>,
    pub nr_integrity_algorithms: Vec<IntegrityAlgorithm>,
    pub eutra_encryption_algorithms: Option<Vec<CipheringAlgorithm>>,
    pub eutra_integrity_algorithms: Option<Vec<IntegrityAlgorithm>>,
}

impl Default for UeSecurityCapabilities {
    fn default() -> Self {
        Self {
            nr_encryption_algorithms: vec![
                CipheringAlgorithm::Nea0,
                CipheringAlgorithm::Nea1,
                CipheringAlgorithm::Nea2,
            ],
            nr_integrity_algorithms: vec![
                IntegrityAlgorithm::Nia0,
                IntegrityAlgorithm::Nia1,
                IntegrityAlgorithm::Nia2,
            ],
            eutra_encryption_algorithms: None,
            eutra_integrity_algorithms: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpSecurityPolicy {
    pub preferred_integrity_algorithms: Vec<IntegrityAlgorithm>,
    pub preferred_ciphering_algorithms: Vec<CipheringAlgorithm>,
    pub integrity_protection_required: bool,
    pub confidentiality_protection_required: bool,
    pub maximum_integrity_protected_data_rate_ul: MaximumIntegrityProtectedDataRate,
    pub maximum_integrity_protected_data_rate_dl: MaximumIntegrityProtectedDataRate,
}

impl Default for UpSecurityPolicy {
    fn default() -> Self {
        Self {
            preferred_integrity_algorithms: vec![
                IntegrityAlgorithm::Nia2,
                IntegrityAlgorithm::Nia1,
                IntegrityAlgorithm::Nia0,
            ],
            preferred_ciphering_algorithms: vec![
                CipheringAlgorithm::Nea2,
                CipheringAlgorithm::Nea1,
                CipheringAlgorithm::Nea0,
            ],
            integrity_protection_required: false,
            confidentiality_protection_required: false,
            maximum_integrity_protected_data_rate_ul: MaximumIntegrityProtectedDataRate::MaximumUeRate,
            maximum_integrity_protected_data_rate_dl: MaximumIntegrityProtectedDataRate::MaximumUeRate,
        }
    }
}
