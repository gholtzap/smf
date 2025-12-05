use crate::services::nrf_discovery::NrfDiscoveryService;
use crate::types::{
    AmfSelectionCriteria, AmfSelectionResult, NFProfile, NfStatus, QueryParams, Snssai, PlmnId,
    Tai,
};
use anyhow::{anyhow, Result};
use std::sync::Arc;

pub struct AmfSelector {
    nrf_discovery: Arc<NrfDiscoveryService>,
}

impl AmfSelector {
    pub fn new(nrf_discovery: Arc<NrfDiscoveryService>) -> Self {
        Self { nrf_discovery }
    }

    pub async fn select_amf(
        &self,
        criteria: AmfSelectionCriteria,
    ) -> Result<AmfSelectionResult> {
        let amfs = self.select_amfs(criteria, 1).await?;
        amfs.into_iter()
            .next()
            .ok_or_else(|| anyhow!("No suitable AMF found"))
    }

    pub async fn select_amfs(
        &self,
        criteria: AmfSelectionCriteria,
        count: usize,
    ) -> Result<Vec<AmfSelectionResult>> {
        let mut query_params = QueryParams::new();

        if let Some(ref snssai) = criteria.snssai {
            let snssai_str = if let Some(ref sd) = snssai.sd {
                format!("{}-{}", snssai.sst, sd)
            } else {
                snssai.sst.to_string()
            };
            query_params.insert("snssai".to_string(), snssai_str);
        }

        if let Some(ref plmn_id) = criteria.plmn_id {
            query_params.insert("plmn-id".to_string(), format!("{}-{}", plmn_id.mcc, plmn_id.mnc));
        }

        if let Some(ref tai) = criteria.tai {
            query_params.insert(
                "tai".to_string(),
                format!("{}-{}-{}", tai.plmn_id.mcc, tai.plmn_id.mnc, tai.tac),
            );
        }

        let amf_profiles = self
            .nrf_discovery
            .discover_amf(Some(query_params))
            .await?;

        if amf_profiles.is_empty() {
            return Err(anyhow!("No AMF instances discovered"));
        }

        let mut scored_amfs: Vec<(NFProfile, f64)> = amf_profiles
            .into_iter()
            .filter(|profile| self.matches_criteria(profile, &criteria))
            .map(|profile| {
                let score = self.calculate_score(&profile, &criteria);
                (profile, score)
            })
            .collect();

        scored_amfs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let results: Vec<AmfSelectionResult> = scored_amfs
            .into_iter()
            .take(count)
            .filter_map(|(profile, score)| self.profile_to_result(profile, score))
            .collect();

        if results.is_empty() {
            return Err(anyhow!("No suitable AMF found matching criteria"));
        }

        Ok(results)
    }

    fn matches_criteria(&self, profile: &NFProfile, criteria: &AmfSelectionCriteria) -> bool {
        if !matches!(profile.nf_status, NfStatus::Registered) {
            return false;
        }

        if let Some(ref snssai) = criteria.snssai {
            if let Some(ref snssai_list) = profile.s_nssai_list {
                if !snssai_list.iter().any(|s| self.snssai_matches(s, snssai)) {
                    return false;
                }
            }
        }

        if let Some(ref plmn_id) = criteria.plmn_id {
            if !profile.plmn_list.iter().any(|p| self.plmn_matches(p, plmn_id)) {
                return false;
            }
        }

        if let Some(ref tai) = criteria.tai {
            if let Some(ref amf_info) = profile.amf_info {
                if let Some(ref tai_list) = amf_info.tai_list {
                    if !tai_list.iter().any(|t| self.tai_matches(t, tai)) {
                        if let Some(ref tai_range_list) = amf_info.tai_range_list {
                            if !tai_range_list.iter().any(|r| self.tai_in_range(tai, r)) {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                }
            }
        }

        true
    }

    fn calculate_score(&self, profile: &NFProfile, criteria: &AmfSelectionCriteria) -> f64 {
        let mut score = 100.0;

        let priority = profile.priority.unwrap_or(128) as f64;
        let capacity = profile.capacity.unwrap_or(100) as f64;
        let load = profile.load.unwrap_or(0) as f64;

        score += (256.0 - priority) * 0.5;

        score += capacity * 0.3;

        score -= load * 0.4;

        if criteria.prefer_local {
            if let Some(ref locality) = profile.locality {
                if locality == "local" {
                    score += 20.0;
                }
            }
        }

        if let Some(ref snssai) = criteria.snssai {
            if let Some(ref allowed_nssais) = profile.allowed_nssais {
                if allowed_nssais.iter().any(|s| self.snssai_matches(s, snssai)) {
                    score += 10.0;
                }
            }
        }

        score.max(0.0)
    }

    fn profile_to_result(&self, profile: NFProfile, score: f64) -> Option<AmfSelectionResult> {
        let uri = self.get_service_uri(&profile)?;

        Some(AmfSelectionResult {
            nf_instance_id: profile.nf_instance_id,
            uri,
            priority: profile.priority.unwrap_or(128),
            capacity: profile.capacity.unwrap_or(100),
            load: profile.load.unwrap_or(0),
            score,
        })
    }

    fn get_service_uri(&self, profile: &NFProfile) -> Option<String> {
        if let Some(ref services) = profile.nf_services {
            if let Some(service) = services.iter().find(|s| s.service_name == "namf-comm") {
                if let Some(ref fqdn) = service.fqdn {
                    return Some(format!(
                        "{}://{}{}",
                        service.scheme,
                        fqdn,
                        service.api_prefix.as_deref().unwrap_or("")
                    ));
                } else if let Some(ref ipv4_addrs) = service.ipv4_addresses {
                    if let Some(addr) = ipv4_addrs.first() {
                        return Some(format!(
                            "{}://{}{}",
                            service.scheme,
                            addr,
                            service.api_prefix.as_deref().unwrap_or("")
                        ));
                    }
                }
            }
        }

        if let Some(ref fqdn) = profile.fqdn {
            return Some(format!("http://{}", fqdn));
        }

        if let Some(ref ipv4_addrs) = profile.ipv4_addresses {
            if let Some(addr) = ipv4_addrs.first() {
                return Some(format!("http://{}", addr));
            }
        }

        None
    }

    fn snssai_matches(&self, a: &Snssai, b: &Snssai) -> bool {
        a.sst == b.sst && a.sd == b.sd
    }

    fn plmn_matches(&self, a: &PlmnId, b: &PlmnId) -> bool {
        a.mcc == b.mcc && a.mnc == b.mnc
    }

    fn tai_matches(&self, a: &Tai, b: &Tai) -> bool {
        self.plmn_matches(&a.plmn_id, &b.plmn_id) && a.tac == b.tac
    }

    fn tai_in_range(&self, tai: &Tai, range: &crate::types::nrf::TaiRange) -> bool {
        if !self.plmn_matches(&tai.plmn_id, &range.plmn_id) {
            return false;
        }

        for tac_range in &range.tac_range_list {
            if let Ok(tac_num) = u32::from_str_radix(&tai.tac, 16) {
                if let Ok(start) = u32::from_str_radix(&tac_range.start, 16) {
                    if let Some(ref end_str) = tac_range.end {
                        if let Ok(end) = u32::from_str_radix(end_str, 16) {
                            if tac_num >= start && tac_num <= end {
                                return true;
                            }
                        }
                    } else if tac_num == start {
                        return true;
                    }
                }
            }
        }

        false
    }
}
