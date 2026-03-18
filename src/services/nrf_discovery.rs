use crate::services::nrf::NrfClient;
use crate::types::{
    NFProfile, NfType, QueryParams, SubscriptionData, NotificationEventType, NotificationData,
};
use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct NrfDiscoveryService {
    nrf_client: Arc<NrfClient>,
    discovered_nfs: Arc<RwLock<HashMap<NfType, Vec<NFProfile>>>>,
    subscriptions: Arc<RwLock<HashMap<NfType, String>>>,
    notification_uri: String,
}

impl NrfDiscoveryService {
    pub fn new(nrf_client: Arc<NrfClient>, smf_host: String, smf_port: u16) -> Self {
        let notification_uri = format!("http://{}:{}/nnrf-nfm/v1/nf-status-notify", smf_host, smf_port);

        Self {
            nrf_client,
            discovered_nfs: Arc::new(RwLock::new(HashMap::new())),
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            notification_uri,
        }
    }

    pub async fn discover_amf(&self, query_params: Option<QueryParams>) -> Result<Vec<NFProfile>> {
        self.discover_and_cache(NfType::Amf, query_params).await
    }

    pub async fn discover_pcf(&self, query_params: Option<QueryParams>) -> Result<Vec<NFProfile>> {
        self.discover_and_cache(NfType::Pcf, query_params).await
    }

    pub async fn discover_udm(&self, query_params: Option<QueryParams>) -> Result<Vec<NFProfile>> {
        self.discover_and_cache(NfType::Udm, query_params).await
    }

    pub async fn discover_upf(&self, query_params: Option<QueryParams>) -> Result<Vec<NFProfile>> {
        self.discover_and_cache(NfType::Upf, query_params).await
    }

    pub async fn discover_udr(&self, query_params: Option<QueryParams>) -> Result<Vec<NFProfile>> {
        self.discover_and_cache(NfType::Udr, query_params).await
    }

    pub async fn discover_chf(&self, query_params: Option<QueryParams>) -> Result<Vec<NFProfile>> {
        self.discover_and_cache(NfType::Chf, query_params).await
    }

    pub async fn discover_nf(&self, nf_type: NfType, query_params: Option<QueryParams>) -> Result<Vec<NFProfile>> {
        self.discover_and_cache(nf_type, query_params).await
    }

    async fn discover_and_cache(&self, nf_type: NfType, query_params: Option<QueryParams>) -> Result<Vec<NFProfile>> {
        let search_result = self.nrf_client.discover(nf_type.clone(), query_params).await?;

        let mut cache = self.discovered_nfs.write().await;
        cache.insert(nf_type.clone(), search_result.nf_instances.clone());

        tracing::info!("Discovered and cached {} instances of {:?}", search_result.nf_instances.len(), nf_type);

        Ok(search_result.nf_instances)
    }

    pub async fn get_cached_nfs(&self, nf_type: &NfType) -> Option<Vec<NFProfile>> {
        let cache = self.discovered_nfs.read().await;
        cache.get(nf_type).cloned()
    }

    pub async fn subscribe_to_nf_status(&self, nf_type: NfType) -> Result<String> {
        let subscription = SubscriptionData {
            nf_status_notification_uri: self.notification_uri.clone(),
            req_nf_instance_id: None,
            subscription_id: None,
            validity_time: None,
            req_notif_events: Some(vec![
                NotificationEventType::NfRegistered,
                NotificationEventType::NfDeregistered,
                NotificationEventType::NfProfileChanged,
            ]),
            plmn_id: None,
            nf_type: Some(nf_type.clone()),
        };

        let created_sub = self.nrf_client.subscribe(subscription).await?;

        if let Some(sub_id) = &created_sub.subscription_id {
            let mut subs = self.subscriptions.write().await;
            subs.insert(nf_type.clone(), sub_id.clone());

            tracing::info!("Subscribed to {:?} status notifications with subscription ID: {}", nf_type, sub_id);

            Ok(sub_id.clone())
        } else {
            Err(anyhow::anyhow!("Subscription created but no subscription ID returned"))
        }
    }

    pub async fn unsubscribe_from_nf_status(&self, nf_type: &NfType) -> Result<()> {
        let mut subs = self.subscriptions.write().await;

        if let Some(sub_id) = subs.remove(nf_type) {
            self.nrf_client.unsubscribe(&sub_id).await?;
            tracing::info!("Unsubscribed from {:?} status notifications", nf_type);
            Ok(())
        } else {
            Err(anyhow::anyhow!("No subscription found for {:?}", nf_type))
        }
    }

    fn extract_nf_instance_id(nf_instance_uri: &str) -> Option<&str> {
        nf_instance_uri.rsplit('/').next().filter(|s| !s.is_empty())
    }

    pub async fn handle_nf_status_notification(&self, notification: NotificationData) -> Result<()> {
        tracing::info!(
            "NF status notification: event={:?}, uri={}",
            notification.event,
            notification.nf_instance_uri
        );

        match notification.event {
            NotificationEventType::NfRegistered => {
                let profile = notification.nf_profile
                    .ok_or_else(|| anyhow::anyhow!("NF_REGISTERED requires nfProfile"))?;
                let nf_type = profile.nf_type.clone();
                let mut cache = self.discovered_nfs.write().await;
                let nf_list = cache.entry(nf_type.clone()).or_default();
                if let Some(index) = nf_list.iter().position(|nf| nf.nf_instance_id == profile.nf_instance_id) {
                    nf_list[index] = profile.clone();
                    tracing::info!("Updated cached {:?} instance: {}", nf_type, profile.nf_instance_id);
                } else {
                    nf_list.push(profile.clone());
                    tracing::info!("Added new cached {:?} instance: {}", nf_type, profile.nf_instance_id);
                }
            }
            NotificationEventType::NfProfileChanged => {
                if let Some(profile) = &notification.nf_profile {
                    let nf_type = profile.nf_type.clone();
                    let mut cache = self.discovered_nfs.write().await;
                    let nf_list = cache.entry(nf_type.clone()).or_default();
                    if let Some(index) = nf_list.iter().position(|nf| nf.nf_instance_id == profile.nf_instance_id) {
                        nf_list[index] = profile.clone();
                        tracing::info!("Updated cached {:?} instance via full profile: {}", nf_type, profile.nf_instance_id);
                    } else {
                        nf_list.push(profile.clone());
                        tracing::info!("Added new cached {:?} instance via profile change: {}", nf_type, profile.nf_instance_id);
                    }
                } else if let Some(ref changes) = notification.profile_changes {
                    let nf_id = Self::extract_nf_instance_id(&notification.nf_instance_uri);
                    if let Some(nf_id) = nf_id {
                        let mut cache = self.discovered_nfs.write().await;
                        let mut found = false;
                        for nf_list in cache.values_mut() {
                            if let Some(profile) = nf_list.iter_mut().find(|nf| nf.nf_instance_id == nf_id) {
                                Self::apply_profile_changes(profile, changes);
                                found = true;
                                tracing::info!("Applied {} profile changes to NF instance: {}", changes.len(), nf_id);
                                break;
                            }
                        }
                        if !found {
                            tracing::warn!("NF_PROFILE_CHANGED with profileChanges for unknown NF: {}", nf_id);
                        }
                    }
                } else {
                    tracing::warn!(
                        "NF_PROFILE_CHANGED without nfProfile or profileChanges for: {}",
                        notification.nf_instance_uri
                    );
                }
            }
            NotificationEventType::NfDeregistered => {
                if let Some(profile) = &notification.nf_profile {
                    let nf_type = profile.nf_type.clone();
                    let mut cache = self.discovered_nfs.write().await;
                    if let Some(nf_list) = cache.get_mut(&nf_type) {
                        nf_list.retain(|nf| nf.nf_instance_id != profile.nf_instance_id);
                        tracing::info!("Removed cached {:?} instance: {}", nf_type, profile.nf_instance_id);
                    }
                } else if let Some(nf_id) = Self::extract_nf_instance_id(&notification.nf_instance_uri) {
                    let mut cache = self.discovered_nfs.write().await;
                    let mut removed = false;
                    for (nf_type, nf_list) in cache.iter_mut() {
                        let before = nf_list.len();
                        nf_list.retain(|nf| nf.nf_instance_id != nf_id);
                        if nf_list.len() < before {
                            tracing::info!("Removed cached {:?} instance via URI: {}", nf_type, nf_id);
                            removed = true;
                        }
                    }
                    if !removed {
                        tracing::debug!("NF_DEREGISTERED for NF not in cache: {}", nf_id);
                    }
                }
            }
            NotificationEventType::SharedDataChanged => {
                tracing::debug!(
                    "Received SHARED_DATA_CHANGED notification (not applicable to SMF): {}",
                    notification.nf_instance_uri
                );
            }
            NotificationEventType::Unknown => {
                tracing::warn!(
                    "Received unknown NF status notification event type for: {}",
                    notification.nf_instance_uri
                );
            }
        }

        Ok(())
    }

    fn apply_profile_changes(profile: &mut NFProfile, changes: &[crate::types::ChangeItem]) {
        for change in changes {
            match change.op {
                crate::types::ChangeOp::Replace => {
                    if change.path == "/nfStatus" || change.path == "nfStatus" {
                        if let Some(ref val) = change.new_value {
                            if let Ok(status) = serde_json::from_value(val.clone()) {
                                profile.nf_status = status;
                            }
                        }
                    } else if change.path == "/load" || change.path == "load" {
                        if let Some(ref val) = change.new_value {
                            if let Some(load) = val.as_u64() {
                                profile.load = Some(load as u16);
                            }
                        }
                    } else if change.path == "/capacity" || change.path == "capacity" {
                        if let Some(ref val) = change.new_value {
                            if let Some(cap) = val.as_u64() {
                                profile.capacity = Some(cap as u16);
                            }
                        }
                    } else if change.path == "/priority" || change.path == "priority" {
                        if let Some(ref val) = change.new_value {
                            if let Some(pri) = val.as_u64() {
                                profile.priority = Some(pri as u16);
                            }
                        }
                    }
                }
                _ => {
                    tracing::debug!("Unhandled profile change op {:?} for path: {}", change.op, change.path);
                }
            }
        }
    }

    pub async fn get_all_cached_nfs(&self) -> HashMap<NfType, Vec<NFProfile>> {
        self.discovered_nfs.read().await.clone()
    }

    pub async fn clear_cache(&self) {
        let mut cache = self.discovered_nfs.write().await;
        cache.clear();
        tracing::info!("Cleared NF discovery cache");
    }

    pub async fn clear_cache_for_nf_type(&self, nf_type: &NfType) {
        let mut cache = self.discovered_nfs.write().await;
        cache.remove(nf_type);
        tracing::info!("Cleared NF discovery cache for {:?}", nf_type);
    }

    pub async fn get_subscription_id(&self, nf_type: &NfType) -> Option<String> {
        let subs = self.subscriptions.read().await;
        subs.get(nf_type).cloned()
    }
}
