use crate::types::up_security::{
    CipheringAlgorithm, IntegrityAlgorithm, UeSecurityCapabilities,
    UpSecurityContext, UpSecurityPolicy, MaximumIntegrityProtectedDataRate
};

pub struct UpSecuritySelector;

impl UpSecuritySelector {
    pub fn select_algorithms(
        ue_capabilities: &UeSecurityCapabilities,
        network_policy: &UpSecurityPolicy,
    ) -> Result<UpSecurityContext, String> {
        let integrity_algorithm = Self::select_integrity_algorithm(
            &ue_capabilities.nr_integrity_algorithms,
            &network_policy.preferred_integrity_algorithms,
            network_policy.integrity_protection_required,
        )?;

        let ciphering_algorithm = Self::select_ciphering_algorithm(
            &ue_capabilities.nr_encryption_algorithms,
            &network_policy.preferred_ciphering_algorithms,
            network_policy.confidentiality_protection_required,
        )?;

        let integrity_activated = integrity_algorithm.is_some()
            && !integrity_algorithm.as_ref().map(|a| a.is_null_algorithm()).unwrap_or(false);

        let confidentiality_activated = ciphering_algorithm.is_some()
            && !ciphering_algorithm.as_ref().map(|a| a.is_null_algorithm()).unwrap_or(false);

        tracing::info!(
            "UP Security algorithm selection: Integrity={:?} (activated={}), Ciphering={:?} (activated={})",
            integrity_algorithm,
            integrity_activated,
            ciphering_algorithm,
            confidentiality_activated
        );

        Ok(UpSecurityContext {
            integrity_protection_algorithm: integrity_algorithm,
            ciphering_algorithm,
            integrity_protection_activated: integrity_activated,
            confidentiality_protection_activated: confidentiality_activated,
            maximum_integrity_protected_data_rate_ul: Some(network_policy.maximum_integrity_protected_data_rate_ul),
            maximum_integrity_protected_data_rate_dl: Some(network_policy.maximum_integrity_protected_data_rate_dl),
        })
    }

    fn select_integrity_algorithm(
        ue_algorithms: &[IntegrityAlgorithm],
        preferred_algorithms: &[IntegrityAlgorithm],
        required: bool,
    ) -> Result<Option<IntegrityAlgorithm>, String> {
        for preferred in preferred_algorithms {
            if ue_algorithms.contains(preferred) {
                tracing::debug!(
                    "Selected integrity algorithm: {:?} (UE supports it, network prefers it)",
                    preferred
                );
                return Ok(Some(*preferred));
            }
        }

        if required {
            return Err(format!(
                "No mutually supported integrity algorithm found. UE supports: {:?}, Network requires one of: {:?}",
                ue_algorithms,
                preferred_algorithms
            ));
        }

        if ue_algorithms.contains(&IntegrityAlgorithm::Nia0) {
            tracing::debug!("No matching integrity algorithm found, using NIA0 (null algorithm)");
            return Ok(Some(IntegrityAlgorithm::Nia0));
        }

        tracing::debug!("No integrity protection selected");
        Ok(None)
    }

    fn select_ciphering_algorithm(
        ue_algorithms: &[CipheringAlgorithm],
        preferred_algorithms: &[CipheringAlgorithm],
        required: bool,
    ) -> Result<Option<CipheringAlgorithm>, String> {
        for preferred in preferred_algorithms {
            if ue_algorithms.contains(preferred) {
                tracing::debug!(
                    "Selected ciphering algorithm: {:?} (UE supports it, network prefers it)",
                    preferred
                );
                return Ok(Some(*preferred));
            }
        }

        if required {
            return Err(format!(
                "No mutually supported ciphering algorithm found. UE supports: {:?}, Network requires one of: {:?}",
                ue_algorithms,
                preferred_algorithms
            ));
        }

        if ue_algorithms.contains(&CipheringAlgorithm::Nea0) {
            tracing::debug!("No matching ciphering algorithm found, using NEA0 (null algorithm)");
            return Ok(Some(CipheringAlgorithm::Nea0));
        }

        tracing::debug!("No ciphering protection selected");
        Ok(None)
    }

    pub fn validate_security_capabilities(
        capabilities: &UeSecurityCapabilities,
    ) -> Result<(), String> {
        if capabilities.nr_encryption_algorithms.is_empty() {
            return Err("UE must support at least one NR encryption algorithm".to_string());
        }

        if capabilities.nr_integrity_algorithms.is_empty() {
            return Err("UE must support at least one NR integrity algorithm".to_string());
        }

        tracing::debug!(
            "UE security capabilities validated: NR encryption={:?}, NR integrity={:?}",
            capabilities.nr_encryption_algorithms,
            capabilities.nr_integrity_algorithms
        );

        Ok(())
    }

    pub fn should_activate_security(context: &UpSecurityContext) -> bool {
        context.integrity_protection_activated || context.confidentiality_protection_activated
    }

    pub fn get_security_level(context: &UpSecurityContext) -> SecurityLevel {
        let has_strong_integrity = context.integrity_protection_algorithm
            .as_ref()
            .map(|alg| matches!(alg, IntegrityAlgorithm::Nia2 | IntegrityAlgorithm::Nia3))
            .unwrap_or(false);

        let has_strong_ciphering = context.ciphering_algorithm
            .as_ref()
            .map(|alg| matches!(alg, CipheringAlgorithm::Nea2 | CipheringAlgorithm::Nea3))
            .unwrap_or(false);

        match (has_strong_integrity, has_strong_ciphering) {
            (true, true) => SecurityLevel::High,
            (true, false) | (false, true) => SecurityLevel::Medium,
            (false, false) if context.integrity_protection_activated || context.confidentiality_protection_activated => SecurityLevel::Low,
            _ => SecurityLevel::None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    None,
    Low,
    Medium,
    High,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_algorithms_with_common_support() {
        let ue_caps = UeSecurityCapabilities {
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
        };

        let policy = UpSecurityPolicy::default();

        let result = UpSecuritySelector::select_algorithms(&ue_caps, &policy).unwrap();

        assert_eq!(result.integrity_protection_algorithm, Some(IntegrityAlgorithm::Nia2));
        assert_eq!(result.ciphering_algorithm, Some(CipheringAlgorithm::Nea2));
        assert!(result.integrity_protection_activated);
        assert!(result.confidentiality_protection_activated);
    }

    #[test]
    fn test_select_algorithms_with_required_but_no_match() {
        let ue_caps = UeSecurityCapabilities {
            nr_encryption_algorithms: vec![CipheringAlgorithm::Nea0],
            nr_integrity_algorithms: vec![IntegrityAlgorithm::Nia0],
            eutra_encryption_algorithms: None,
            eutra_integrity_algorithms: None,
        };

        let mut policy = UpSecurityPolicy::default();
        policy.integrity_protection_required = true;
        policy.preferred_integrity_algorithms = vec![IntegrityAlgorithm::Nia2, IntegrityAlgorithm::Nia3];

        let result = UpSecuritySelector::select_algorithms(&ue_caps, &policy);

        assert!(result.is_err());
    }

    #[test]
    fn test_select_algorithms_fallback_to_null() {
        let ue_caps = UeSecurityCapabilities {
            nr_encryption_algorithms: vec![CipheringAlgorithm::Nea0],
            nr_integrity_algorithms: vec![IntegrityAlgorithm::Nia0],
            eutra_encryption_algorithms: None,
            eutra_integrity_algorithms: None,
        };

        let policy = UpSecurityPolicy::default();

        let result = UpSecuritySelector::select_algorithms(&ue_caps, &policy).unwrap();

        assert_eq!(result.integrity_protection_algorithm, Some(IntegrityAlgorithm::Nia0));
        assert_eq!(result.ciphering_algorithm, Some(CipheringAlgorithm::Nea0));
        assert!(!result.integrity_protection_activated);
        assert!(!result.confidentiality_protection_activated);
    }

    #[test]
    fn test_validate_security_capabilities_valid() {
        let caps = UeSecurityCapabilities::default();
        let result = UpSecuritySelector::validate_security_capabilities(&caps);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_security_capabilities_no_encryption() {
        let caps = UeSecurityCapabilities {
            nr_encryption_algorithms: vec![],
            nr_integrity_algorithms: vec![IntegrityAlgorithm::Nia0],
            eutra_encryption_algorithms: None,
            eutra_integrity_algorithms: None,
        };

        let result = UpSecuritySelector::validate_security_capabilities(&caps);
        assert!(result.is_err());
    }

    #[test]
    fn test_security_level_high() {
        let context = UpSecurityContext {
            integrity_protection_algorithm: Some(IntegrityAlgorithm::Nia2),
            ciphering_algorithm: Some(CipheringAlgorithm::Nea2),
            integrity_protection_activated: true,
            confidentiality_protection_activated: true,
            maximum_integrity_protected_data_rate_ul: Some(MaximumIntegrityProtectedDataRate::MaximumUeRate),
            maximum_integrity_protected_data_rate_dl: Some(MaximumIntegrityProtectedDataRate::MaximumUeRate),
        };

        assert_eq!(UpSecuritySelector::get_security_level(&context), SecurityLevel::High);
    }

    #[test]
    fn test_security_level_none() {
        let context = UpSecurityContext::default();
        assert_eq!(UpSecuritySelector::get_security_level(&context), SecurityLevel::None);
    }
}
