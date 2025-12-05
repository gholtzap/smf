use mongodb::{Client, Database, IndexModel};
use mongodb::bson::doc;
use mongodb::options::IndexOptions;
use std::sync::Arc;
use crate::services::notification::NotificationService;
use crate::services::pfcp::PfcpClient;
use crate::services::nrf::NrfClient;
use crate::services::nrf_registration::NrfRegistrationService;
use crate::services::nrf_discovery::NrfDiscoveryService;
use crate::services::slice_selection::SliceSelector;
use crate::services::dnn_selector::DnnSelector;
use crate::services::pcf::PcfClient;
use crate::services::udm::UdmClient;
use crate::config::Config;
use crate::models::SmContext;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub notification_service: Arc<NotificationService>,
    pub pfcp_client: Option<PfcpClient>,
    pub pcf_client: Option<Arc<PcfClient>>,
    pub udm_client: Option<Arc<UdmClient>>,
    pub nrf_registration: Option<Arc<NrfRegistrationService>>,
    pub nrf_discovery: Option<Arc<NrfDiscoveryService>>,
    pub slice_selector: Arc<SliceSelector>,
    pub dnn_selector: Arc<DnnSelector>,
}

pub async fn init(config: &Config) -> anyhow::Result<AppState> {
    let client = Client::with_uri_str(&config.mongodb_uri).await?;
    let db = client.database("smf");

    tracing::info!("Connected to MongoDB");

    init_indexes(&db).await?;

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

    let (nrf_registration, nrf_discovery) = if let Some(nrf_uri) = &config.nrf_uri {
        let nrf_client = Arc::new(NrfClient::new(
            nrf_uri.clone(),
            config.nf_instance_id.clone(),
        ));

        let registration_service = Arc::new(NrfRegistrationService::new(
            nrf_client.clone(),
            config.clone(),
        ));

        let discovery_service = Arc::new(NrfDiscoveryService::new(
            nrf_client,
            config.smf_host.clone(),
            config.port,
        ));

        (Some(registration_service), Some(discovery_service))
    } else {
        tracing::warn!("NRF_URI not configured. SMF will not register with NRF.");
        (None, None)
    };

    let pcf_client = if let Some(pcf_uri) = &config.pcf_uri {
        tracing::info!("PCF client initialized with URI: {}", pcf_uri);
        Some(Arc::new(PcfClient::new()))
    } else {
        tracing::warn!("PCF_URI not configured. SM policy control will be disabled.");
        None
    };

    let udm_client = if let Some(udm_uri) = &config.udm_uri {
        tracing::info!("UDM client initialized with URI: {}", udm_uri);
        Some(Arc::new(UdmClient::new()))
    } else {
        tracing::warn!("UDM_URI not configured. Subscriber data validation will be disabled.");
        None
    };

    let slice_selector = Arc::new(SliceSelector::new());
    tracing::info!("Slice selector initialized with {} configured slices", slice_selector.list_allowed_slices().len());

    let dnn_selector = Arc::new(DnnSelector::new());
    tracing::info!("DNN selector initialized with {} configured DNNs", dnn_selector.list_allowed_dnns().len());

    Ok(AppState {
        db,
        notification_service,
        pfcp_client,
        pcf_client,
        udm_client,
        nrf_registration,
        nrf_discovery,
        slice_selector,
        dnn_selector,
    })
}

async fn init_indexes(db: &Database) -> anyhow::Result<()> {
    let collection = db.collection::<SmContext>("sm_contexts");

    let index = IndexModel::builder()
        .keys(doc! { "supi": 1, "pdu_session_id": 1 })
        .options(IndexOptions::builder().unique(true).build())
        .build();

    collection.create_index(index).await?;

    tracing::info!("Created unique index on (supi, pdu_session_id)");

    Ok(())
}
