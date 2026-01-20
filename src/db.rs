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
use crate::services::slice_qos_policy::SliceQosPolicyService;
use crate::services::dnn_selector::DnnSelector;
use crate::services::ssc_selector::SscModeSelector;
use crate::services::pcf::PcfClient;
use crate::services::udm::UdmClient;
use crate::services::udr::UdrClient;
use crate::services::chf::ChfClient;
use crate::services::upf_selection::UpfSelectionService;
use crate::services::inter_smf_handover::InterSmfHandoverService;
use crate::services::n16_client::N16Client;
use crate::config::Config;
use crate::models::SmContext;
use crate::utils::http_client::build_mtls_client;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub notification_service: Arc<NotificationService>,
    pub pfcp_client: Option<PfcpClient>,
    pub pcf_client: Option<Arc<PcfClient>>,
    pub udm_client: Option<Arc<UdmClient>>,
    pub udr_client: Option<Arc<UdrClient>>,
    pub chf_client: Option<Arc<ChfClient>>,
    pub nrf_registration: Option<Arc<NrfRegistrationService>>,
    pub nrf_discovery: Option<Arc<NrfDiscoveryService>>,
    pub slice_selector: Arc<SliceSelector>,
    pub slice_qos_policy_service: Arc<SliceQosPolicyService>,
    pub dnn_selector: Arc<DnnSelector>,
    pub ssc_selector: Arc<SscModeSelector>,
    pub upf_selection_service: Arc<UpfSelectionService>,
    pub inter_smf_handover_service: Option<Arc<InterSmfHandoverService>>,
}

pub async fn init(config: &Config) -> anyhow::Result<AppState> {
    let client = Client::with_uri_str(&config.mongodb_uri).await?;
    let db = client.database("smf");

    tracing::info!("Connected to MongoDB");

    init_indexes(&db).await?;

    cleanup_stale_sessions(&db).await?;

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
            tracing::info!("UPF health monitoring disabled for testing");
            Some(client)
        }
        Err(e) => {
            tracing::warn!("Failed to initialize PFCP client: {}. PDU sessions will be created without UPF integration.", e);
            None
        }
    };

    let http_client = if let (Some(cert_path), Some(key_path)) =
        (&config.tls.client_cert_path, &config.tls.client_key_path) {
        match build_mtls_client(cert_path, key_path) {
            Ok(client) => {
                tracing::info!("mTLS client initialized for outbound requests");
                Some(client)
            }
            Err(e) => {
                tracing::warn!("Failed to initialize mTLS client: {}. Using default HTTP client.", e);
                None
            }
        }
    } else {
        None
    };

    let (nrf_registration, nrf_discovery) = if let Some(nrf_uri) = &config.nrf_uri {
        let mut nrf_client = NrfClient::new(
            nrf_uri.clone(),
            config.nf_instance_id.clone(),
        );

        if let Some(client) = http_client.clone() {
            nrf_client = nrf_client.with_client(client);
        }

        let nrf_client = Arc::new(nrf_client);

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
        let mut client = PcfClient::new();
        if let Some(http_client) = http_client.clone() {
            client = client.with_client(http_client);
        }
        Some(Arc::new(client))
    } else {
        tracing::warn!("PCF_URI not configured. SM policy control will be disabled.");
        None
    };

    let udm_client = if let Some(udm_uri) = &config.udm_uri {
        tracing::info!("UDM client initialized with URI: {}", udm_uri);
        let mut client = UdmClient::new();
        if let Some(http_client) = http_client.clone() {
            client = client.with_client(http_client);
        }
        Some(Arc::new(client))
    } else {
        tracing::warn!("UDM_URI not configured. Subscriber data validation will be disabled.");
        None
    };

    let udr_client = if nrf_discovery.is_some() {
        tracing::info!("UDR client initialized with NRF discovery");
        let mut client = UdrClient::new();
        if let Some(http_client) = http_client.clone() {
            client = client.with_client(http_client);
        }
        Some(Arc::new(client))
    } else {
        tracing::warn!("UDR client not initialized. NRF discovery required for UDR access.");
        None
    };

    let chf_client = if let Some(chf_uri) = &config.chf_uri {
        tracing::info!("CHF client initialized with URI: {}", chf_uri);
        let mut client = ChfClient::new();
        if let Some(http_client) = http_client.clone() {
            client = client.with_client(http_client);
        }
        Some(Arc::new(client))
    } else {
        tracing::warn!("CHF_URI not configured. Charging will be disabled.");
        None
    };

    let slice_selector = Arc::new(SliceSelector::new());
    tracing::info!("Slice selector initialized with {} configured slices", slice_selector.list_allowed_slices().len());

    let slice_qos_policy_service = Arc::new(SliceQosPolicyService::new());
    tracing::info!("Slice QoS policy service initialized with {} slice policies", slice_qos_policy_service.list_policies().len());

    let dnn_selector = Arc::new(DnnSelector::new());
    tracing::info!("DNN selector initialized with {} configured DNNs", dnn_selector.list_allowed_dnns().len());

    let ssc_selector = Arc::new(SscModeSelector::new());
    tracing::info!("SSC mode selector initialized with {} allowed modes", ssc_selector.get_allowed_modes().len());

    let upf_selection_service = Arc::new(UpfSelectionService::new(db.clone()));
    tracing::info!("UPF selection service initialized");

    tracing::info!("Certificate renewal monitoring service disabled for testing");
    tracing::info!("Certificate auto-rotation service disabled for testing");

    let inter_smf_handover_service = if let Some(ref pfcp) = pfcp_client {
        let n16_client = Arc::new(N16Client::new(config.nf_instance_id.clone()));
        let service = Arc::new(InterSmfHandoverService::new(
            n16_client,
            pfcp.clone(),
            db.clone(),
            config.nf_instance_id.clone(),
        ));
        tracing::info!("Inter-SMF handover service initialized");
        Some(service)
    } else {
        tracing::warn!("Inter-SMF handover service not initialized. PFCP client required.");
        None
    };

    Ok(AppState {
        db,
        notification_service,
        pfcp_client,
        pcf_client,
        udm_client,
        udr_client,
        chf_client,
        nrf_registration,
        nrf_discovery,
        slice_selector,
        slice_qos_policy_service,
        dnn_selector,
        ssc_selector,
        upf_selection_service,
        inter_smf_handover_service,
    })
}

async fn cleanup_stale_sessions(db: &Database) -> anyhow::Result<()> {
    let sm_contexts_collection = db.collection::<SmContext>("sm_contexts");

    let result = sm_contexts_collection.delete_many(doc! {}).await?;

    if result.deleted_count > 0 {
        tracing::info!(
            "Cleaned up {} stale PDU sessions from previous SMF instance",
            result.deleted_count
        );
    } else {
        tracing::info!("No stale PDU sessions found");
    }

    let ip_allocations_collection = db.collection::<mongodb::bson::Document>("ip_allocations");
    let ip_result = ip_allocations_collection.delete_many(doc! {}).await?;

    if ip_result.deleted_count > 0 {
        tracing::info!(
            "Cleaned up {} stale IP allocations from previous SMF instance",
            ip_result.deleted_count
        );
    }

    Ok(())
}

async fn init_indexes(db: &Database) -> anyhow::Result<()> {
    let sm_contexts_collection = db.collection::<SmContext>("sm_contexts");

    let sm_index = IndexModel::builder()
        .keys(doc! { "supi": 1, "pdu_session_id": 1 })
        .options(IndexOptions::builder().unique(true).build())
        .build();

    sm_contexts_collection.create_index(sm_index).await?;

    tracing::info!("Created unique index on (supi, pdu_session_id)");

    let certificates_collection = db.collection::<crate::types::Certificate>("certificates");

    let cert_name_purpose_index = IndexModel::builder()
        .keys(doc! { "name": 1, "purpose": 1 })
        .options(IndexOptions::builder().unique(true).build())
        .build();

    certificates_collection.create_index(cert_name_purpose_index).await?;

    tracing::info!("Created unique index on (name, purpose) for certificates");

    let cert_expiration_index = IndexModel::builder()
        .keys(doc! { "not_after": 1 })
        .build();

    certificates_collection.create_index(cert_expiration_index).await?;

    tracing::info!("Created index on not_after for certificates");

    let renewal_notifications_collection = db.collection::<crate::types::CertificateRenewalNotification>("certificate_renewal_notifications");

    let renewal_cert_id_index = IndexModel::builder()
        .keys(doc! { "certificate_id": 1, "acknowledged": 1 })
        .build();

    renewal_notifications_collection.create_index(renewal_cert_id_index).await?;

    tracing::info!("Created index on (certificate_id, acknowledged) for renewal notifications");

    let renewal_severity_index = IndexModel::builder()
        .keys(doc! { "severity": -1, "created_at": 1 })
        .build();

    renewal_notifications_collection.create_index(renewal_severity_index).await?;

    tracing::info!("Created index on (severity, created_at) for renewal notifications");

    crate::services::certificate_audit::CertificateAuditService::initialize_indexes(db).await?;

    Ok(())
}
