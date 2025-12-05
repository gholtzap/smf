use crate::models::SmContext;
use crate::types::QosRule;
use mongodb::{Collection, Database};
use mongodb::bson::doc;
use std::sync::Arc;
use tracing::{info, warn};

pub struct QosRuleManager {
    db: Arc<Database>,
}

impl QosRuleManager {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub async fn add_qos_rules(
        &self,
        sm_context_id: &str,
        qos_rules: Vec<QosRule>,
    ) -> Result<(), String> {
        let collection: Collection<SmContext> = self.db.collection("sm_contexts");

        for qos_rule in &qos_rules {
            if let Err(e) = qos_rule.validate() {
                warn!("Invalid QoS rule with ID {}: {}", qos_rule.qos_rule_id, e);
                return Err(e);
            }
        }

        let update = doc! {
            "$push": {
                "qos_rules": {
                    "$each": mongodb::bson::to_bson(&qos_rules)
                        .map_err(|e| format!("Failed to serialize QoS rules: {}", e))?
                }
            },
            "$set": {
                "updated_at": mongodb::bson::DateTime::now()
            }
        };

        collection
            .update_one(doc! { "_id": sm_context_id }, update)
            .await
            .map_err(|e| format!("Failed to add QoS rules: {}", e))?;

        info!("Added {} QoS rules to SM context {}", qos_rules.len(), sm_context_id);
        Ok(())
    }

    pub async fn modify_qos_rule(
        &self,
        sm_context_id: &str,
        qos_rule: QosRule,
    ) -> Result<(), String> {
        if let Err(e) = qos_rule.validate() {
            warn!("Invalid QoS rule with ID {}: {}", qos_rule.qos_rule_id, e);
            return Err(e);
        }

        let collection: Collection<SmContext> = self.db.collection("sm_contexts");

        let filter = doc! {
            "_id": sm_context_id,
            "qos_rules.qos_rule_id": qos_rule.qos_rule_id as i32
        };

        let update = doc! {
            "$set": {
                "qos_rules.$": mongodb::bson::to_bson(&qos_rule)
                    .map_err(|e| format!("Failed to serialize QoS rule: {}", e))?,
                "updated_at": mongodb::bson::DateTime::now()
            }
        };

        let result = collection
            .update_one(filter, update)
            .await
            .map_err(|e| format!("Failed to modify QoS rule: {}", e))?;

        if result.matched_count == 0 {
            return Err(format!("QoS rule with ID {} not found in SM context {}", qos_rule.qos_rule_id, sm_context_id));
        }

        info!("Modified QoS rule with ID {} in SM context {}", qos_rule.qos_rule_id, sm_context_id);
        Ok(())
    }

    pub async fn remove_qos_rules(
        &self,
        sm_context_id: &str,
        qos_rule_ids: Vec<u8>,
    ) -> Result<(), String> {
        let collection: Collection<SmContext> = self.db.collection("sm_contexts");

        let qos_rule_ids_i32: Vec<i32> = qos_rule_ids.iter().map(|&id| id as i32).collect();

        let update = doc! {
            "$pull": {
                "qos_rules": {
                    "qos_rule_id": { "$in": qos_rule_ids_i32 }
                }
            },
            "$set": {
                "updated_at": mongodb::bson::DateTime::now()
            }
        };

        collection
            .update_one(doc! { "_id": sm_context_id }, update)
            .await
            .map_err(|e| format!("Failed to remove QoS rules: {}", e))?;

        info!("Removed {} QoS rules from SM context {}", qos_rule_ids.len(), sm_context_id);
        Ok(())
    }

    pub async fn get_qos_rules(&self, sm_context_id: &str) -> Result<Vec<QosRule>, String> {
        let collection: Collection<SmContext> = self.db.collection("sm_contexts");

        let sm_context = collection
            .find_one(doc! { "_id": sm_context_id })
            .await
            .map_err(|e| format!("Failed to get SM context: {}", e))?
            .ok_or_else(|| format!("SM context {} not found", sm_context_id))?;

        Ok(sm_context.qos_rules)
    }

    pub async fn apply_qos_rules(
        &self,
        sm_context_id: &str,
    ) -> Result<(), String> {
        let collection: Collection<SmContext> = self.db.collection("sm_contexts");

        let sm_context = collection
            .find_one(doc! { "_id": sm_context_id })
            .await
            .map_err(|e| format!("Failed to get SM context: {}", e))?
            .ok_or_else(|| format!("SM context {} not found", sm_context_id))?;

        for qos_rule in &sm_context.qos_rules {
            for packet_filter_id in &qos_rule.packet_filter_ids {
                if !sm_context.packet_filters.iter().any(|pf| pf.packet_filter_id == *packet_filter_id) {
                    warn!(
                        "QoS rule {} references non-existent packet filter {}",
                        qos_rule.qos_rule_id, packet_filter_id
                    );
                }
            }

            if !sm_context.qos_flows.iter().any(|qf| qf.qfi == qos_rule.qfi) {
                return Err(format!(
                    "QoS rule {} references non-existent QoS flow with QFI {}",
                    qos_rule.qos_rule_id, qos_rule.qfi
                ));
            }
        }

        info!("Applied QoS rules to SM context {}", sm_context_id);
        Ok(())
    }

    pub fn allocate_qos_rule_id(&self, existing_qos_rules: &[QosRule]) -> Option<u8> {
        for id in 1..=255 {
            if !existing_qos_rules.iter().any(|qr| qr.qos_rule_id == id) {
                return Some(id);
            }
        }
        None
    }
}
