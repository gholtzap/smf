use mongodb::{Client, Database};
use std::sync::Arc;
use crate::services::notification::NotificationService;
use crate::services::pfcp::PfcpClient;
use crate::services::nrf::NrfClient;
use crate::services::nrf_registration::NrfRegistrationService;
use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub notification_service: Arc<NotificationService>,
    pub pfcp_client: Option<PfcpClient>,
    pub nrf_registration: Option<Arc<NrfRegistrationService>>,
}

pub async fn init(config: &Config) -> anyhow::Result<AppState> {
    let client = Client::with_uri_str(&config.mongodb_uri).await?;
    let db = client.database("smf");

    tracing::info!("Connected to MongoDB");

    crate::services::ipam::IpamService::init_default_pool(&db).await?;

    let notification_service = Arc::new(NotificationService::new());

    let pfcp_bind_addr = format!("{}:{}", config.pfcp_bind_addr, config.pfcp_bind_port)
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid PFCP bind address: {}", e))?;

    let pfcp_client = match crate::services::pfcp::PfcpClientInner::new(
        config.upf_host.clone(),
        config.upf_port,
        pfcp_bind_addr,
    )
    .await
    {
        Ok(client) => {
            tracing::info!("PFCP client initialized successfully");

            let upf_address = format!("{}:{}", config.upf_host, config.upf_port);
            let health_monitor = crate::services::upf_health::UpfHealthMonitor::new(
                client.clone(),
                db.clone(),
                upf_address,
            );

            tokio::spawn(async move {
                health_monitor.start().await;
            });

            Some(client)
        }
        Err(e) => {
            tracing::warn!("Failed to initialize PFCP client: {}. PDU sessions will be created without UPF integration.", e);
            None
        }
    };

    let nrf_registration = if let Some(nrf_uri) = &config.nrf_uri {
        let nrf_client = Arc::new(NrfClient::new(
            nrf_uri.clone(),
            config.nf_instance_id.clone(),
        ));

        let registration_service = Arc::new(NrfRegistrationService::new(
            nrf_client,
            config.clone(),
        ));

        Some(registration_service)
    } else {
        tracing::warn!("NRF_URI not configured. SMF will not register with NRF.");
        None
    };

    Ok(AppState {
        db,
        notification_service,
        pfcp_client,
        nrf_registration,
    })
}
