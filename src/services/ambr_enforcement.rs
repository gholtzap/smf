use crate::models::Ambr;

type AmbrResult<T> = Result<T, String>;

pub struct AmbrEnforcementService;

impl AmbrEnforcementService {
    pub fn validate_ambr_preservation(
        original_ambr: &Option<Ambr>,
        handover_ambr: &Option<Ambr>,
    ) -> AmbrResult<()> {
        match (original_ambr, handover_ambr) {
            (Some(original), Some(handover)) => {
                if original.uplink != handover.uplink || original.downlink != handover.downlink {
                    tracing::warn!(
                        "AMBR changed during handover: Original UL={}, DL={} -> New UL={}, DL={}",
                        original.uplink,
                        original.downlink,
                        handover.uplink,
                        handover.downlink
                    );
                }
                Ok(())
            }
            (Some(original), None) => {
                tracing::info!(
                    "AMBR preserved during handover: UL={}, DL={}",
                    original.uplink,
                    original.downlink
                );
                Ok(())
            }
            (None, Some(handover)) => {
                tracing::info!(
                    "New AMBR applied during handover: UL={}, DL={}",
                    handover.uplink,
                    handover.downlink
                );
                Ok(())
            }
            (None, None) => {
                tracing::debug!("No AMBR configured for session during handover");
                Ok(())
            }
        }
    }

    pub fn get_effective_ambr(
        session_ambr: &Option<Ambr>,
        update_ambr: &Option<Ambr>,
    ) -> Option<Ambr> {
        update_ambr.clone().or_else(|| session_ambr.clone())
    }

    pub fn log_ambr_enforcement(
        supi: &str,
        pdu_session_id: u8,
        ambr: &Option<Ambr>,
        operation: &str,
    ) {
        if let Some(session_ambr) = ambr {
            tracing::info!(
                "AMBR enforcement during {} for SUPI: {}, PDU Session ID: {}, UL: {}, DL: {}",
                operation,
                supi,
                pdu_session_id,
                session_ambr.uplink,
                session_ambr.downlink
            );
        } else {
            tracing::debug!(
                "No AMBR to enforce during {} for SUPI: {}, PDU Session ID: {}",
                operation,
                supi,
                pdu_session_id
            );
        }
    }

    pub fn parse_ambr_bitrate(bitrate_str: &str) -> AmbrResult<u64> {
        let bitrate_str = bitrate_str.trim().to_uppercase();

        let (numeric_part, unit) = if bitrate_str.ends_with("GBPS") {
            (bitrate_str.trim_end_matches("GBPS").trim(), 1_000_000_000)
        } else if bitrate_str.ends_with("MBPS") {
            (bitrate_str.trim_end_matches("MBPS").trim(), 1_000_000)
        } else if bitrate_str.ends_with("KBPS") {
            (bitrate_str.trim_end_matches("KBPS").trim(), 1_000)
        } else if bitrate_str.ends_with("BPS") {
            (bitrate_str.trim_end_matches("BPS").trim(), 1)
        } else {
            return Err(format!("Invalid AMBR bitrate format: {}", bitrate_str));
        };

        let value: f64 = numeric_part.parse().map_err(|_| {
            format!("Failed to parse AMBR bitrate value: {}", numeric_part)
        })?;

        Ok((value * unit as f64) as u64)
    }

    pub fn validate_ambr_limits(ambr: &Ambr) -> AmbrResult<()> {
        let uplink_bps = Self::parse_ambr_bitrate(&ambr.uplink)?;
        let downlink_bps = Self::parse_ambr_bitrate(&ambr.downlink)?;

        if uplink_bps == 0 {
            return Err("Uplink AMBR cannot be zero".to_string());
        }

        if downlink_bps == 0 {
            return Err("Downlink AMBR cannot be zero".to_string());
        }

        tracing::debug!(
            "AMBR limits validated: UL={} bps, DL={} bps",
            uplink_bps,
            downlink_bps
        );

        Ok(())
    }
}
