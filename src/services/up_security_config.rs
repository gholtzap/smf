use crate::types::up_security::{
    CipheringAlgorithm, IntegrityAlgorithm, MaximumIntegrityProtectedDataRate, UpSecurityPolicy,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpSecurityConfiguration {
    pub name: String,
    pub description: String,
    pub policy: UpSecurityPolicy,
}

impl UpSecurityConfiguration {
    pub fn get_default_configurations() -> Vec<Self> {
        vec![
            UpSecurityConfiguration {
                name: "high-security".to_string(),
                description: "High security with mandatory encryption and integrity protection using strong algorithms".to_string(),
                policy: UpSecurityPolicy {
                    preferred_integrity_algorithms: vec![
                        IntegrityAlgorithm::Nia3,
                        IntegrityAlgorithm::Nia2,
                        IntegrityAlgorithm::Nia1,
                    ],
                    preferred_ciphering_algorithms: vec![
                        CipheringAlgorithm::Nea3,
                        CipheringAlgorithm::Nea2,
                        CipheringAlgorithm::Nea1,
                    ],
                    integrity_protection_required: true,
                    confidentiality_protection_required: true,
                    maximum_integrity_protected_data_rate_ul: MaximumIntegrityProtectedDataRate::MaximumUeRate,
                    maximum_integrity_protected_data_rate_dl: MaximumIntegrityProtectedDataRate::MaximumUeRate,
                },
            },
            UpSecurityConfiguration {
                name: "standard-security".to_string(),
                description: "Standard security with preferred encryption and integrity protection".to_string(),
                policy: UpSecurityPolicy::default(),
            },
            UpSecurityConfiguration {
                name: "low-security".to_string(),
                description: "Low security allowing null algorithms if no other option is available".to_string(),
                policy: UpSecurityPolicy {
                    preferred_integrity_algorithms: vec![
                        IntegrityAlgorithm::Nia1,
                        IntegrityAlgorithm::Nia2,
                        IntegrityAlgorithm::Nia0,
                    ],
                    preferred_ciphering_algorithms: vec![
                        CipheringAlgorithm::Nea1,
                        CipheringAlgorithm::Nea2,
                        CipheringAlgorithm::Nea0,
                    ],
                    integrity_protection_required: false,
                    confidentiality_protection_required: false,
                    maximum_integrity_protected_data_rate_ul: MaximumIntegrityProtectedDataRate::MaximumUeRate,
                    maximum_integrity_protected_data_rate_dl: MaximumIntegrityProtectedDataRate::MaximumUeRate,
                },
            },
            UpSecurityConfiguration {
                name: "no-security".to_string(),
                description: "No security - uses null algorithms only (for testing purposes)".to_string(),
                policy: UpSecurityPolicy {
                    preferred_integrity_algorithms: vec![IntegrityAlgorithm::Nia0],
                    preferred_ciphering_algorithms: vec![CipheringAlgorithm::Nea0],
                    integrity_protection_required: false,
                    confidentiality_protection_required: false,
                    maximum_integrity_protected_data_rate_ul: MaximumIntegrityProtectedDataRate::MaximumUeRate,
                    maximum_integrity_protected_data_rate_dl: MaximumIntegrityProtectedDataRate::MaximumUeRate,
                },
            },
        ]
    }

    pub fn get_policy_by_name(name: &str) -> Option<UpSecurityPolicy> {
        Self::get_default_configurations()
            .into_iter()
            .find(|config| config.name == name)
            .map(|config| config.policy)
    }

    pub fn get_default_policy() -> UpSecurityPolicy {
        Self::get_policy_by_name("standard-security")
            .unwrap_or_else(UpSecurityPolicy::default)
    }
}

pub struct UpSecurityConfigService;

impl UpSecurityConfigService {
    pub fn get_policy_for_slice(slice_sst: u8, slice_sd: Option<&str>) -> UpSecurityPolicy {
        match slice_sst {
            1 => {
                tracing::debug!(
                    "Using standard security policy for eMBB slice (SST=1, SD={:?})",
                    slice_sd
                );
                UpSecurityConfiguration::get_default_policy()
            }
            2 => {
                tracing::debug!(
                    "Using high security policy for URLLC slice (SST=2, SD={:?})",
                    slice_sd
                );
                UpSecurityConfiguration::get_policy_by_name("high-security")
                    .unwrap_or_else(UpSecurityPolicy::default)
            }
            3 => {
                tracing::debug!(
                    "Using low security policy for MIoT slice (SST=3, SD={:?})",
                    slice_sd
                );
                UpSecurityConfiguration::get_policy_by_name("low-security")
                    .unwrap_or_else(UpSecurityPolicy::default)
            }
            _ => {
                tracing::debug!(
                    "Using default security policy for unknown slice (SST={}, SD={:?})",
                    slice_sst,
                    slice_sd
                );
                UpSecurityConfiguration::get_default_policy()
            }
        }
    }

    pub fn get_policy_for_emergency() -> UpSecurityPolicy {
        tracing::debug!("Using low security policy for emergency session");
        UpSecurityConfiguration::get_policy_by_name("low-security")
            .unwrap_or_else(UpSecurityPolicy::default)
    }

    pub fn validate_policy(policy: &UpSecurityPolicy) -> Result<(), String> {
        if policy.preferred_integrity_algorithms.is_empty() {
            return Err("UP security policy must include at least one preferred integrity algorithm".to_string());
        }

        if policy.preferred_ciphering_algorithms.is_empty() {
            return Err("UP security policy must include at least one preferred ciphering algorithm".to_string());
        }

        if policy.integrity_protection_required {
            let has_non_null = policy.preferred_integrity_algorithms
                .iter()
                .any(|alg| !alg.is_null_algorithm());

            if !has_non_null {
                return Err("Integrity protection is required but only null algorithm (NIA0) is in preferred list".to_string());
            }
        }

        if policy.confidentiality_protection_required {
            let has_non_null = policy.preferred_ciphering_algorithms
                .iter()
                .any(|alg| !alg.is_null_algorithm());

            if !has_non_null {
                return Err("Confidentiality protection is required but only null algorithm (NEA0) is in preferred list".to_string());
            }
        }

        tracing::debug!("UP security policy validated successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_default_configurations() {
        let configs = UpSecurityConfiguration::get_default_configurations();
        assert_eq!(configs.len(), 4);
        assert_eq!(configs[0].name, "high-security");
        assert_eq!(configs[1].name, "standard-security");
        assert_eq!(configs[2].name, "low-security");
        assert_eq!(configs[3].name, "no-security");
    }

    #[test]
    fn test_get_policy_by_name() {
        let policy = UpSecurityConfiguration::get_policy_by_name("high-security").unwrap();
        assert!(policy.integrity_protection_required);
        assert!(policy.confidentiality_protection_required);
        assert_eq!(policy.preferred_integrity_algorithms[0], IntegrityAlgorithm::Nia3);
    }

    #[test]
    fn test_get_policy_for_slice_urllc() {
        let policy = UpSecurityConfigService::get_policy_for_slice(2, None);
        assert!(policy.integrity_protection_required);
        assert!(policy.confidentiality_protection_required);
    }

    #[test]
    fn test_get_policy_for_slice_miot() {
        let policy = UpSecurityConfigService::get_policy_for_slice(3, None);
        assert!(!policy.integrity_protection_required);
        assert!(!policy.confidentiality_protection_required);
    }

    #[test]
    fn test_get_policy_for_emergency() {
        let policy = UpSecurityConfigService::get_policy_for_emergency();
        assert!(!policy.integrity_protection_required);
        assert!(!policy.confidentiality_protection_required);
    }

    #[test]
    fn test_validate_policy_valid() {
        let policy = UpSecurityPolicy::default();
        let result = UpSecurityConfigService::validate_policy(&policy);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_policy_empty_algorithms() {
        let policy = UpSecurityPolicy {
            preferred_integrity_algorithms: vec![],
            preferred_ciphering_algorithms: vec![CipheringAlgorithm::Nea2],
            integrity_protection_required: false,
            confidentiality_protection_required: false,
            maximum_integrity_protected_data_rate_ul: MaximumIntegrityProtectedDataRate::MaximumUeRate,
            maximum_integrity_protected_data_rate_dl: MaximumIntegrityProtectedDataRate::MaximumUeRate,
        };

        let result = UpSecurityConfigService::validate_policy(&policy);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_policy_required_but_only_null() {
        let policy = UpSecurityPolicy {
            preferred_integrity_algorithms: vec![IntegrityAlgorithm::Nia0],
            preferred_ciphering_algorithms: vec![CipheringAlgorithm::Nea0],
            integrity_protection_required: true,
            confidentiality_protection_required: false,
            maximum_integrity_protected_data_rate_ul: MaximumIntegrityProtectedDataRate::MaximumUeRate,
            maximum_integrity_protected_data_rate_dl: MaximumIntegrityProtectedDataRate::MaximumUeRate,
        };

        let result = UpSecurityConfigService::validate_policy(&policy);
        assert!(result.is_err());
    }
}
