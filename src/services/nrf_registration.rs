use crate::config::Config;
use crate::services::nrf::NrfClient;
use crate::types::{
    NFProfile, NFService, NFServiceVersion, NfType, NfStatus, NfServiceStatus,
    SmfInfo, SnssaiSmfInfoItem, DnnSmfInfoItem, Snssai, PlmnId,
};
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};

pub struct NrfRegistrationService {
    nrf_client: Arc<NrfClient>,
    config: Config,
    heartbeat_interval: Duration,
}

impl NrfRegistrationService {
    pub fn new(nrf_client: Arc<NrfClient>, config: Config) -> Self {
        Self {
            nrf_client,
            config,
            heartbeat_interval: Duration::from_secs(60),
        }
    }

    pub fn build_smf_profile(&self) -> NFProfile {
        let service_base_url = format!("http://{}:{}", self.config.smf_host, self.config.port);

        let nf_services = vec![
            NFService {
                service_instance_id: format!("{}-nsmf-pdusession", self.config.nf_instance_id),
                service_name: "nsmf-pdusession".to_string(),
                versions: vec![NFServiceVersion {
                    api_version_in_uri: "v1".to_string(),
                    api_full_version: "1.0.0".to_string(),
                }],
                scheme: "http".to_string(),
                nf_service_status: NfServiceStatus::Registered,
                fqdn: None,
                ipv4_addresses: Some(vec![self.config.smf_host.clone()]),
                ipv6_addresses: None,
                api_prefix: Some(service_base_url.clone()),
                default_notification_subscriptions: None,
                allowed_plmns: None,
                allowed_nf_types: Some(vec![NfType::Amf]),
                allowed_nf_domains: None,
                allowed_nssais: None,
                priority: Some(1),
                capacity: Some(100),
                load: Some(0),
                supported_features: None,
            },
            NFService {
                service_instance_id: format!("{}-nsmf-event-exposure", self.config.nf_instance_id),
                service_name: "nsmf-event-exposure".to_string(),
                versions: vec![NFServiceVersion {
                    api_version_in_uri: "v1".to_string(),
                    api_full_version: "1.0.0".to_string(),
                }],
                scheme: "http".to_string(),
                nf_service_status: NfServiceStatus::Registered,
                fqdn: None,
                ipv4_addresses: Some(vec![self.config.smf_host.clone()]),
                ipv6_addresses: None,
                api_prefix: Some(service_base_url.clone()),
                default_notification_subscriptions: None,
                allowed_plmns: None,
                allowed_nf_types: Some(vec![NfType::Amf, NfType::Pcf, NfType::Af]),
                allowed_nf_domains: None,
                allowed_nssais: None,
                priority: Some(1),
                capacity: Some(100),
                load: Some(0),
                supported_features: None,
            },
        ];

        let smf_info = SmfInfo {
            s_nssai_smf_info_list: vec![
                SnssaiSmfInfoItem {
                    s_nssai: Snssai {
                        sst: 1,
                        sd: None,
                    },
                    dnn_smf_info_list: vec![
                        DnnSmfInfoItem {
                            dnn: "internet".to_string(),
                        },
                    ],
                },
            ],
            tai_list: None,
            tai_range_list: None,
            pgw_fqdn: None,
            access_type: None,
            priority: Some(1),
            vsmf_support_ind: Some(false),
        };

        NFProfile {
            nf_instance_id: self.config.nf_instance_id.clone(),
            nf_type: NfType::Smf,
            nf_status: NfStatus::Registered,
            plmn_list: vec![PlmnId {
                mcc: "001".to_string(),
                mnc: "01".to_string(),
            }],
            s_nssai_list: Some(vec![Snssai {
                sst: 1,
                sd: None,
            }]),
            nsi_list: None,
            fqdn: None,
            ipv4_addresses: Some(vec![self.config.smf_host.clone()]),
            ipv6_addresses: None,
            allowed_plmns: None,
            allowed_nf_types: None,
            allowed_nf_domains: None,
            allowed_nssais: None,
            priority: Some(1),
            capacity: Some(100),
            load: Some(0),
            locality: None,
            nf_services: Some(nf_services),
            smf_info: Some(smf_info),
            amf_info: None,
            heart_beat_timer: Some(60),
        }
    }

    pub async fn register(&self) -> Result<()> {
        let profile = self.build_smf_profile();
        self.nrf_client.register(profile).await?;
        tracing::info!("SMF registered with NRF successfully");
        Ok(())
    }

    pub async fn deregister(&self) -> Result<()> {
        self.nrf_client.deregister().await?;
        tracing::info!("SMF deregistered from NRF successfully");
        Ok(())
    }

    pub async fn start_heartbeat(&self) {
        let nrf_client = self.nrf_client.clone();
        let heartbeat_interval = self.heartbeat_interval;

        tokio::spawn(async move {
            let mut interval_timer = interval(heartbeat_interval);
            loop {
                interval_timer.tick().await;
                match nrf_client.heartbeat().await {
                    Ok(_) => {
                        tracing::debug!("NRF heartbeat sent successfully");
                    }
                    Err(e) => {
                        tracing::error!("Failed to send NRF heartbeat: {}", e);
                    }
                }
            }
        });

        tracing::info!("NRF heartbeat task started with interval of {:?}", self.heartbeat_interval);
    }
}
