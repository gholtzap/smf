use crate::models::SmContext;
use crate::types::{SscMode, PduAddress};

type SscResult<T> = Result<T, String>;

pub struct SscBehaviorService;

impl SscBehaviorService {
    pub fn validate_ip_preservation_on_handover(
        sm_context: &SmContext,
        new_pdu_address: Option<&PduAddress>,
    ) -> SscResult<()> {
        if sm_context.ssc_mode != SscMode::Mode1 {
            return Ok(());
        }

        let existing_addr = sm_context.pdu_address.as_ref()
            .ok_or_else(|| "No existing PDU address in SM context".to_string())?;

        if let Some(new_addr) = new_pdu_address {
            if !Self::addresses_match(existing_addr, new_addr) {
                return Err(format!(
                    "SSC Mode 1 violation: IP address must be preserved during handover. Existing: {:?}, New: {:?}",
                    existing_addr, new_addr
                ));
            }
        }

        Ok(())
    }

    pub fn should_preserve_ip_on_mobility(ssc_mode: &SscMode) -> bool {
        matches!(ssc_mode, SscMode::Mode1)
    }

    pub fn should_release_ip_on_mobility(ssc_mode: &SscMode) -> bool {
        !Self::should_preserve_ip_on_mobility(ssc_mode)
    }

    pub fn validate_ip_allocation_for_mode(
        ssc_mode: &SscMode,
        pdu_address: Option<&PduAddress>,
    ) -> SscResult<()> {
        match ssc_mode {
            SscMode::Mode1 => {
                if pdu_address.is_none() {
                    return Err("SSC Mode 1 requires IP address allocation".to_string());
                }
                Ok(())
            }
            SscMode::Mode2 | SscMode::Mode3 => Ok(()),
        }
    }

    pub fn can_modify_ip_during_handover(ssc_mode: &SscMode) -> bool {
        match ssc_mode {
            SscMode::Mode1 => false,
            SscMode::Mode2 | SscMode::Mode3 => true,
        }
    }

    fn addresses_match(addr1: &PduAddress, addr2: &PduAddress) -> bool {
        if addr1.ipv4_addr != addr2.ipv4_addr {
            return false;
        }
        if addr1.ipv6_addr != addr2.ipv6_addr {
            return false;
        }
        true
    }

    pub fn get_handover_ip_behavior(ssc_mode: &SscMode) -> HandoverIpBehavior {
        match ssc_mode {
            SscMode::Mode1 => HandoverIpBehavior::Preserve,
            SscMode::Mode2 => HandoverIpBehavior::ReleaseAndAllocate,
            SscMode::Mode3 => HandoverIpBehavior::MakeBeforeBreak,
        }
    }

    pub fn validate_handover_ip_behavior(
        ssc_mode: &SscMode,
        existing_pdu_address: &PduAddress,
        target_pdu_address: Option<&PduAddress>,
    ) -> SscResult<()> {
        let behavior = Self::get_handover_ip_behavior(ssc_mode);

        match behavior {
            HandoverIpBehavior::Preserve => {
                if let Some(target_addr) = target_pdu_address {
                    if !Self::addresses_match(existing_pdu_address, target_addr) {
                        return Err(format!(
                            "SSC Mode 1: IP address must be preserved. Cannot change from {:?} to {:?}",
                            existing_pdu_address, target_addr
                        ));
                    }
                }
                Ok(())
            }
            HandoverIpBehavior::ReleaseAndAllocate => {
                Ok(())
            }
            HandoverIpBehavior::MakeBeforeBreak => {
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoverIpBehavior {
    Preserve,
    ReleaseAndAllocate,
    MakeBeforeBreak,
}
