use crate::models::SmContext;
use crate::types::{BitRate, QosFlow, QosFlowType};
use mongodb::{Collection, Database};
use mongodb::bson::doc;
use std::sync::Arc;
use tracing::{info, warn};

pub struct QosFlowManager {
    db: Arc<Database>,
}

impl QosFlowManager {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub async fn add_qos_flows(
        &self,
        sm_context_id: &str,
        qos_flows: Vec<QosFlow>,
    ) -> Result<(), String> {
        let collection: Collection<SmContext> = self.db.collection("sm_contexts");

        for qos_flow in &qos_flows {
            if let Err(e) = self.validate_qos_flow(qos_flow) {
                warn!("Invalid QoS flow with QFI {}: {}", qos_flow.qfi, e);
                return Err(e);
            }
        }

        let update = doc! {
            "$push": {
                "qos_flows": {
                    "$each": mongodb::bson::to_bson(&qos_flows)
                        .map_err(|e| format!("Failed to serialize QoS flows: {}", e))?
                }
            },
            "$set": {
                "updated_at": mongodb::bson::DateTime::now()
            }
        };

        collection
            .update_one(doc! { "_id": sm_context_id }, update)
            .await
            .map_err(|e| format!("Failed to add QoS flows: {}", e))?;

        info!("Added {} QoS flows to SM context {}", qos_flows.len(), sm_context_id);
        Ok(())
    }

    pub async fn modify_qos_flow(
        &self,
        sm_context_id: &str,
        qos_flow: QosFlow,
    ) -> Result<(), String> {
        if let Err(e) = self.validate_qos_flow(&qos_flow) {
            warn!("Invalid QoS flow with QFI {}: {}", qos_flow.qfi, e);
            return Err(e);
        }

        let collection: Collection<SmContext> = self.db.collection("sm_contexts");

        let filter = doc! {
            "_id": sm_context_id,
            "qos_flows.qfi": qos_flow.qfi as i32
        };

        let update = doc! {
            "$set": {
                "qos_flows.$": mongodb::bson::to_bson(&qos_flow)
                    .map_err(|e| format!("Failed to serialize QoS flow: {}", e))?,
                "updated_at": mongodb::bson::DateTime::now()
            }
        };

        let result = collection
            .update_one(filter, update)
            .await
            .map_err(|e| format!("Failed to modify QoS flow: {}", e))?;

        if result.matched_count == 0 {
            return Err(format!("QoS flow with QFI {} not found in SM context {}", qos_flow.qfi, sm_context_id));
        }

        info!("Modified QoS flow with QFI {} in SM context {}", qos_flow.qfi, sm_context_id);
        Ok(())
    }

    pub async fn remove_qos_flows(
        &self,
        sm_context_id: &str,
        qfis: Vec<u8>,
    ) -> Result<(), String> {
        let collection: Collection<SmContext> = self.db.collection("sm_contexts");

        let qfis_i32: Vec<i32> = qfis.iter().map(|&qfi| qfi as i32).collect();

        let update = doc! {
            "$pull": {
                "qos_flows": {
                    "qfi": { "$in": qfis_i32 }
                }
            },
            "$set": {
                "updated_at": mongodb::bson::DateTime::now()
            }
        };

        collection
            .update_one(doc! { "_id": sm_context_id }, update)
            .await
            .map_err(|e| format!("Failed to remove QoS flows: {}", e))?;

        info!("Removed {} QoS flows from SM context {}", qfis.len(), sm_context_id);
        Ok(())
    }

    pub async fn get_qos_flows(&self, sm_context_id: &str) -> Result<Vec<QosFlow>, String> {
        let collection: Collection<SmContext> = self.db.collection("sm_contexts");

        let sm_context = collection
            .find_one(doc! { "_id": sm_context_id })
            .await
            .map_err(|e| format!("Failed to get SM context: {}", e))?
            .ok_or_else(|| format!("SM context {} not found", sm_context_id))?;

        Ok(sm_context.qos_flows)
    }

    fn validate_qos_flow(&self, qos_flow: &QosFlow) -> Result<(), String> {
        if qos_flow.qfi > 63 {
            return Err(format!("QFI must be between 0 and 63, got {}", qos_flow.qfi));
        }

        if qos_flow.five_qi == 0 || qos_flow.five_qi > 255 {
            return Err(format!("Invalid 5QI value: {}", qos_flow.five_qi));
        }

        match &qos_flow.qos_flow_type {
            QosFlowType::GBR | QosFlowType::DelayGBR => {
                if qos_flow.gfbr.is_none() {
                    return Err("GBR flows must have GFBR set".to_string());
                }
                if qos_flow.mfbr.is_none() {
                    return Err("GBR flows must have MFBR set".to_string());
                }
                self.validate_bit_rate(qos_flow.gfbr.as_ref().unwrap())?;
                self.validate_bit_rate(qos_flow.mfbr.as_ref().unwrap())?;
            }
            QosFlowType::NonGBR => {
                if qos_flow.gfbr.is_some() || qos_flow.mfbr.is_some() {
                    warn!("Non-GBR flow has GFBR/MFBR set, which will be ignored");
                }
            }
        }

        Ok(())
    }

    fn validate_bit_rate(&self, bit_rate: &BitRate) -> Result<(), String> {
        if bit_rate.uplink == 0 || bit_rate.downlink == 0 {
            return Err("Bit rate must be greater than 0".to_string());
        }
        Ok(())
    }

    pub fn allocate_qfi(&self, existing_qos_flows: &[QosFlow]) -> Option<u8> {
        for qfi in 1..=63 {
            if !existing_qos_flows.iter().any(|qf| qf.qfi == qfi) {
                return Some(qfi);
            }
        }
        None
    }
}
