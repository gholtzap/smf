use crate::types::{
    UpfNode, UpfStatus, UpfSelectionCriteria, UpfSelectionResult,
    UpfRelocationDecision, UpfRelocationReason,
};
use crate::models::UserLocation;
use anyhow::{Result, anyhow};
use mongodb::Database;
use mongodb::bson::doc;
use tracing::{debug, info, warn};
use futures::TryStreamExt;

const LOCATION_MATCH_SCORE: u32 = 100;
const ACTIVE_STATUS_SCORE: u32 = 50;
const CURRENT_UPF_BONUS: u32 = 30;
const BASE_SCORE: u32 = 10;

pub struct UpfSelectionService {
    db: Database,
}

impl UpfSelectionService {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    pub async fn select_upf(&self, criteria: &UpfSelectionCriteria) -> Result<UpfSelectionResult> {
        let available_upfs = self.get_available_upfs().await?;

        if available_upfs.is_empty() {
            return Err(anyhow!("No UPF nodes available"));
        }

        let mut best_upf: Option<(UpfNode, u32)> = None;

        for upf in available_upfs {
            let score = self.calculate_upf_score(&upf, criteria);

            debug!(
                "UPF {} score: {} (status: {:?})",
                upf.address, score, upf.status
            );

            match &best_upf {
                Some((_, best_score)) if score > *best_score => {
                    best_upf = Some((upf, score));
                }
                None => {
                    best_upf = Some((upf, score));
                }
                _ => {}
            }
        }

        let (selected_upf, final_score) = best_upf
            .ok_or_else(|| anyhow!("Failed to select UPF"))?;

        let relocation_required = criteria.current_upf_address.as_ref()
            .map(|current| current != &selected_upf.address)
            .unwrap_or(false);

        info!(
            "Selected UPF: {} (score: {}, relocation_required: {})",
            selected_upf.address, final_score, relocation_required
        );

        Ok(UpfSelectionResult {
            selected_upf,
            score: final_score,
            relocation_required,
        })
    }

    pub async fn evaluate_upf_relocation(
        &self,
        current_upf_address: &str,
        new_location: Option<UserLocation>,
    ) -> Result<UpfRelocationDecision> {
        let current_upf = self.get_upf_by_address(current_upf_address).await?;

        if current_upf.status == UpfStatus::Inactive {
            warn!("Current UPF {} is inactive, relocation required", current_upf_address);
            return Ok(UpfRelocationDecision {
                should_relocate: true,
                reason: Some(UpfRelocationReason::UpfFailure),
                target_upf_address: None,
            });
        }

        if let Some(location) = new_location {
            let tai = Self::extract_tai_from_location(&location);
            if let Some(tai) = tai {
                debug!(
                    "Evaluating UPF relocation for location change to TAI: PLMN={}, TAC={}",
                    tai.plmn_id, tai.tac
                );

                let available_upfs = self.get_available_upfs().await?;

                let mut better_upf_found = false;
                let mut target_upf_address = None;

                for upf in available_upfs {
                    if upf.address == current_upf_address {
                        continue;
                    }

                    if upf.status == UpfStatus::Active {
                        better_upf_found = true;
                        target_upf_address = Some(upf.address.clone());
                        break;
                    }
                }

                if better_upf_found {
                    info!(
                        "Better UPF found for location change: {:?}",
                        target_upf_address
                    );
                    return Ok(UpfRelocationDecision {
                        should_relocate: true,
                        reason: Some(UpfRelocationReason::LocationChange),
                        target_upf_address,
                    });
                }
            }
        }

        Ok(UpfRelocationDecision {
            should_relocate: false,
            reason: None,
            target_upf_address: None,
        })
    }

    async fn get_available_upfs(&self) -> Result<Vec<UpfNode>> {
        let collection = self.db.collection::<UpfNode>("upf_nodes");

        let cursor = collection
            .find(doc! {
                "association_established": true
            })
            .await?;

        let upfs: Vec<UpfNode> = cursor.try_collect().await?;

        Ok(upfs)
    }

    async fn get_upf_by_address(&self, address: &str) -> Result<UpfNode> {
        let collection = self.db.collection::<UpfNode>("upf_nodes");

        collection
            .find_one(doc! { "_id": address })
            .await?
            .ok_or_else(|| anyhow!("UPF node not found: {}", address))
    }

    fn calculate_upf_score(&self, upf: &UpfNode, criteria: &UpfSelectionCriteria) -> u32 {
        let mut score = BASE_SCORE;

        if upf.status == UpfStatus::Active {
            score += ACTIVE_STATUS_SCORE;
        }

        if let Some(current_upf) = &criteria.current_upf_address {
            if &upf.address == current_upf {
                score += CURRENT_UPF_BONUS;
            }
        }

        if let Some(location) = &criteria.ue_location {
            if Self::is_upf_suitable_for_location(upf, location) {
                score += LOCATION_MATCH_SCORE;
            }
        }

        score
    }

    fn is_upf_suitable_for_location(_upf: &UpfNode, _location: &UserLocation) -> bool {
        true
    }

    fn extract_tai_from_location(location: &UserLocation) -> Option<crate::models::Tai> {
        location
            .nr_location
            .as_ref()
            .map(|nr_loc| nr_loc.tai.clone())
    }
}
