use crate::models::SmContext;
use crate::services::ipam::IpamService;
use crate::services::pfcp_session::PfcpSessionManager;
use crate::services::pfcp::PfcpClient;
use crate::types::PduAddress;
use crate::types::SscMode;
use mongodb::Database;

type SscMode3Result<T> = Result<T, String>;

pub struct SscMode3Service;

impl SscMode3Service {
    pub async fn handle_mobility_event(
        sm_context: &mut SmContext,
        db: &Database,
        pfcp_client: Option<&PfcpClient>,
        ip_pool_name: &str,
    ) -> SscMode3Result<(PduAddress, Option<PduAddress>)> {
        if sm_context.ssc_mode != SscMode::Mode3 {
            return Err("SSC Mode 3 handler called for non-Mode3 session".to_string());
        }

        tracing::info!(
            "SSC Mode 3: Handling mobility event (make-before-break) for SUPI: {}, PDU Session ID: {}",
            sm_context.supi,
            sm_context.pdu_session_id
        );

        let old_address = sm_context.pdu_address.clone();

        let new_address = Self::establish_new_session(sm_context, db, ip_pool_name).await?;

        tracing::info!(
            "SSC Mode 3: New address allocated before releasing old session. Old: {:?}, New: {:?}",
            old_address,
            new_address
        );

        Self::release_old_session(sm_context, db, pfcp_client, &old_address).await?;

        tracing::info!(
            "SSC Mode 3: Mobility complete (make-before-break). New address: {:?}",
            new_address
        );

        Ok((new_address, old_address))
    }

    async fn establish_new_session(
        sm_context: &SmContext,
        db: &Database,
        ip_pool_name: &str,
    ) -> SscMode3Result<PduAddress> {
        tracing::info!(
            "SSC Mode 3: Establishing new PDU session (make-before-break) for SUPI: {}, PDU Session ID: {}",
            sm_context.supi,
            sm_context.pdu_session_id
        );

        let allocation = IpamService::allocate_ip(
            db,
            ip_pool_name,
            &format!("{}_new", sm_context.id),
            &sm_context.supi,
            &sm_context.pdu_session_type,
        ).await.map_err(|e| format!("Failed to allocate new IP: {}", e))?;

        tracing::info!(
            "SSC Mode 3: New address allocated (make-before-break): IPv4={:?}, IPv6={:?}",
            allocation.ip_address,
            allocation.ipv6_prefix
        );

        Ok(PduAddress {
            pdu_session_type: sm_context.pdu_session_type.clone(),
            ipv4_addr: if !allocation.ip_address.is_empty() {
                Some(allocation.ip_address)
            } else {
                None
            },
            ipv6_addr: allocation.ipv6_prefix,
            dns_primary: allocation.dns_primary,
            dns_secondary: allocation.dns_secondary,
        })
    }

    async fn release_old_session(
        sm_context: &SmContext,
        db: &Database,
        pfcp_client: Option<&PfcpClient>,
        old_address: &Option<PduAddress>,
    ) -> SscMode3Result<()> {
        tracing::info!(
            "SSC Mode 3: Releasing old PDU session for SUPI: {}, PDU Session ID: {}",
            sm_context.supi,
            sm_context.pdu_session_id
        );

        if old_address.is_some() {
            IpamService::release_ip(db, &sm_context.id).await
                .map_err(|e| format!("Failed to release old IP addresses: {}", e))?;

            tracing::info!(
                "SSC Mode 3: Released old IP addresses for SM context: {}",
                sm_context.id
            );
        }

        if let Some(pfcp_session_id) = sm_context.pfcp_session_id {
            if let Some(client) = pfcp_client {
                tracing::info!(
                    "SSC Mode 3: Deleting old PFCP session: {}",
                    pfcp_session_id
                );
                PfcpSessionManager::delete_session(client, pfcp_session_id).await
                    .map_err(|e| format!("Failed to delete old PFCP session: {}", e))?;
            }
        }

        tracing::info!(
            "SSC Mode 3: Old session released successfully"
        );

        Ok(())
    }

    pub fn should_trigger_make_before_break(ssc_mode: &SscMode) -> bool {
        matches!(ssc_mode, SscMode::Mode3)
    }

    pub async fn validate_mobility_for_mode3(
        sm_context: &SmContext,
    ) -> SscMode3Result<()> {
        if sm_context.ssc_mode != SscMode::Mode3 {
            return Ok(());
        }

        tracing::info!(
            "SSC Mode 3: Validating mobility (make-before-break) for SUPI: {}, PDU Session ID: {}",
            sm_context.supi,
            sm_context.pdu_session_id
        );

        Ok(())
    }

    pub async fn prepare_handover(
        sm_context: &SmContext,
        db: &Database,
        ip_pool_name: &str,
    ) -> SscMode3Result<PduAddress> {
        if sm_context.ssc_mode != SscMode::Mode3 {
            return Err("Prepare handover called for non-Mode3 session".to_string());
        }

        tracing::info!(
            "SSC Mode 3: Preparing handover (allocating new address) for SUPI: {}, PDU Session ID: {}",
            sm_context.supi,
            sm_context.pdu_session_id
        );

        Self::establish_new_session(sm_context, db, ip_pool_name).await
    }

    pub async fn complete_handover(
        sm_context: &SmContext,
        db: &Database,
        pfcp_client: Option<&PfcpClient>,
        old_address: &Option<PduAddress>,
    ) -> SscMode3Result<()> {
        if sm_context.ssc_mode != SscMode::Mode3 {
            return Err("Complete handover called for non-Mode3 session".to_string());
        }

        tracing::info!(
            "SSC Mode 3: Completing handover (releasing old address) for SUPI: {}, PDU Session ID: {}",
            sm_context.supi,
            sm_context.pdu_session_id
        );

        Self::release_old_session(sm_context, db, pfcp_client, old_address).await
    }
}
