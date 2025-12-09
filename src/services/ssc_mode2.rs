use crate::models::SmContext;
use crate::services::ipam::IpamService;
use crate::services::pfcp_session::PfcpSessionManager;
use crate::services::pfcp::PfcpClient;
use crate::types::PduAddress;
use crate::types::SscMode;
use mongodb::Database;

type SscMode2Result<T> = Result<T, String>;

pub struct SscMode2Service;

impl SscMode2Service {
    pub async fn handle_mobility_event(
        sm_context: &mut SmContext,
        db: &Database,
        pfcp_client: Option<&PfcpClient>,
        ip_pool_name: &str,
    ) -> SscMode2Result<PduAddress> {
        if sm_context.ssc_mode != SscMode::Mode2 {
            return Err("SSC Mode 2 handler called for non-Mode2 session".to_string());
        }

        tracing::info!(
            "SSC Mode 2: Handling mobility event for SUPI: {}, PDU Session ID: {}",
            sm_context.supi,
            sm_context.pdu_session_id
        );

        Self::release_old_session(sm_context, db, pfcp_client).await?;

        let new_address = Self::establish_new_session(sm_context, db, ip_pool_name).await?;

        tracing::info!(
            "SSC Mode 2: Mobility complete. New address allocated: {:?}",
            new_address
        );

        Ok(new_address)
    }

    async fn release_old_session(
        sm_context: &SmContext,
        db: &Database,
        pfcp_client: Option<&PfcpClient>,
    ) -> SscMode2Result<()> {
        tracing::info!(
            "SSC Mode 2: Releasing old PDU session for SUPI: {}, PDU Session ID: {}",
            sm_context.supi,
            sm_context.pdu_session_id
        );

        IpamService::release_ip(db, &sm_context.id).await
            .map_err(|e| format!("Failed to release IP addresses: {}", e))?;

        tracing::info!(
            "SSC Mode 2: Released IP addresses for SM context: {}",
            sm_context.id
        );

        if let Some(pfcp_session_id) = sm_context.pfcp_session_id {
            if let Some(client) = pfcp_client {
                tracing::info!(
                    "SSC Mode 2: Releasing PFCP session: {}",
                    pfcp_session_id
                );
                PfcpSessionManager::delete_session(client, pfcp_session_id).await
                    .map_err(|e| format!("Failed to delete PFCP session: {}", e))?;
            }
        }

        Ok(())
    }

    async fn establish_new_session(
        sm_context: &SmContext,
        db: &Database,
        ip_pool_name: &str,
    ) -> SscMode2Result<PduAddress> {
        tracing::info!(
            "SSC Mode 2: Establishing new PDU session for SUPI: {}, PDU Session ID: {}",
            sm_context.supi,
            sm_context.pdu_session_id
        );

        let allocation = IpamService::allocate_ip(
            db,
            ip_pool_name,
            &sm_context.id,
            &sm_context.supi,
            &sm_context.pdu_session_type,
        ).await.map_err(|e| format!("Failed to allocate IP: {}", e))?;

        tracing::info!(
            "SSC Mode 2: New address allocated: IPv4={:?}, IPv6={:?}",
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

    pub fn should_trigger_session_reestablishment(ssc_mode: &SscMode) -> bool {
        matches!(ssc_mode, SscMode::Mode2)
    }

    pub async fn validate_mobility_for_mode2(
        sm_context: &SmContext,
    ) -> SscMode2Result<()> {
        if sm_context.ssc_mode != SscMode::Mode2 {
            return Ok(());
        }

        tracing::info!(
            "SSC Mode 2: Validating mobility for SUPI: {}, PDU Session ID: {}",
            sm_context.supi,
            sm_context.pdu_session_id
        );

        Ok(())
    }
}
