use crate::services::pfcp::PfcpClient;
use crate::types::{NodeId, UpfNode, UpfStatus};
use anyhow::Result;
use mongodb::{bson::doc, Database};
use std::time::Duration;
use tokio::time;
use tracing::{debug, error, info, warn};

const HEARTBEAT_INTERVAL_SECS: u64 = 30;
const HEARTBEAT_TIMEOUT_SECS: u64 = 5;
const MAX_CONSECUTIVE_FAILURES: u32 = 3;

pub struct UpfHealthMonitor {
    pfcp_client: PfcpClient,
    db: Database,
    upf_address: String,
}

impl UpfHealthMonitor {
    pub fn new(pfcp_client: PfcpClient, db: Database, upf_address: String) -> Self {
        Self {
            pfcp_client,
            db,
            upf_address,
        }
    }

    pub async fn start(self) {
        info!("Starting UPF health monitor for {}", self.upf_address);

        if let Err(e) = self.initialize_upf_node().await {
            error!("Failed to initialize UPF node in database: {}", e);
        }

        if let Err(e) = self.setup_association().await {
            warn!("Failed to setup PFCP association with UPF: {}", e);
        } else {
            time::sleep(Duration::from_millis(500)).await;
        }

        let mut interval = time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            if let Err(e) = self.send_heartbeat().await {
                error!("Heartbeat check failed: {}", e);
            }
        }
    }

    async fn initialize_upf_node(&self) -> Result<()> {
        let collection = self.db.collection::<UpfNode>("upf_nodes");

        let existing = collection
            .find_one(doc! { "_id": &self.upf_address })
            .await?;

        if existing.is_none() {
            let upf_node = UpfNode::new(self.upf_address.clone());
            collection.insert_one(&upf_node).await?;
            info!("Initialized UPF node {} in database", self.upf_address);
        }

        Ok(())
    }

    async fn setup_association(&self) -> Result<()> {
        let node_id = NodeId {
            node_id_type: crate::types::NodeIdType::Ipv4Address,
            node_id_value: self.pfcp_client.local_address()?.ip().to_string(),
        };

        self.pfcp_client
            .send_association_setup_request(node_id.clone())
            .await?;

        info!("Sent PFCP Association Setup Request to {}", self.upf_address);

        match self.pfcp_client
            .receive_message_with_timeout(Duration::from_secs(HEARTBEAT_TIMEOUT_SECS))
            .await
        {
            Ok(response) => {
                if response.message_type == crate::services::pfcp::PfcpMessageType::AssociationSetupResponse {
                    self.update_association_status(true).await?;
                    info!("PFCP Association established with {}", self.upf_address);
                    Ok(())
                } else if response.message_type == crate::services::pfcp::PfcpMessageType::AssociationSetupRequest {
                    info!("Received Association Setup Request from UPF, sending response");
                    self.pfcp_client.send_association_setup_response(response.sequence_number, node_id).await?;
                    self.update_association_status(true).await?;
                    info!("PFCP Association established with {} (UPF initiated)", self.upf_address);
                    Ok(())
                } else {
                    warn!(
                        "Unexpected response to Association Setup Request: received {:?}, expected AssociationSetupResponse",
                        response.message_type
                    );
                    Err(anyhow::anyhow!("Unexpected message type: {:?}", response.message_type))
                }
            }
            Err(e) => {
                warn!("Failed to receive Association Setup Response: {}", e);
                Err(e)
            }
        }
    }

    async fn send_heartbeat(&self) -> Result<()> {
        let association_established = self.is_association_established().await?;

        if !association_established {
            info!("PFCP association not established, attempting setup before heartbeat");
            if let Err(e) = self.setup_association().await {
                warn!("Failed to establish PFCP association: {}", e);
                self.increment_failure_count().await?;
                return Err(e);
            }
        }

        let now = chrono::Utc::now();

        self.update_heartbeat_sent(now).await?;

        if let Err(e) = self.pfcp_client.send_heartbeat_request().await {
            error!("Failed to send heartbeat request: {}", e);
            self.increment_failure_count().await?;
            return Err(e);
        }

        debug!("Sent heartbeat to {}", self.upf_address);

        match self.pfcp_client
            .receive_message_with_timeout(Duration::from_secs(HEARTBEAT_TIMEOUT_SECS))
            .await
        {
            Ok(response) => {
                if response.message_type == crate::services::pfcp::PfcpMessageType::HeartbeatResponse {
                    let response_time = chrono::Utc::now();
                    self.update_heartbeat_success(response_time).await?;
                    debug!("Received heartbeat response from {}", self.upf_address);
                    Ok(())
                } else if response.message_type == crate::services::pfcp::PfcpMessageType::HeartbeatRequest {
                    debug!("Received Heartbeat Request from UPF, sending response");
                    self.pfcp_client.send_heartbeat_response(response.sequence_number).await?;
                    let response_time = chrono::Utc::now();
                    self.update_heartbeat_success(response_time).await?;
                    Ok(())
                } else if response.message_type == crate::services::pfcp::PfcpMessageType::AssociationSetupResponse {
                    info!("Received delayed Association Setup Response during heartbeat, updating association status");
                    self.update_association_status(true).await?;
                    let response_time = chrono::Utc::now();
                    self.update_heartbeat_success(response_time).await?;
                    Ok(())
                } else if response.message_type == crate::services::pfcp::PfcpMessageType::AssociationSetupRequest {
                    info!("Received Association Setup Request from UPF during heartbeat, sending response");
                    let node_id = NodeId {
                        node_id_type: crate::types::NodeIdType::Ipv4Address,
                        node_id_value: self.pfcp_client.local_address()?.ip().to_string(),
                    };
                    self.pfcp_client.send_association_setup_response(response.sequence_number, node_id).await?;
                    self.update_association_status(true).await?;
                    let response_time = chrono::Utc::now();
                    self.update_heartbeat_success(response_time).await?;
                    Ok(())
                } else {
                    warn!(
                        "Unexpected response to heartbeat request: received {:?}, expected HeartbeatResponse",
                        response.message_type
                    );
                    self.increment_failure_count().await?;
                    Err(anyhow::anyhow!("Unexpected message type: {:?}", response.message_type))
                }
            }
            Err(e) => {
                warn!("Heartbeat timeout for {}: {}", self.upf_address, e);
                self.increment_failure_count().await?;
                Err(e)
            }
        }
    }

    async fn is_association_established(&self) -> Result<bool> {
        let collection = self.db.collection::<UpfNode>("upf_nodes");

        let upf_node = collection
            .find_one(doc! { "_id": &self.upf_address })
            .await?
            .ok_or_else(|| anyhow::anyhow!("UPF node not found"))?;

        Ok(upf_node.association_established)
    }

    async fn update_heartbeat_sent(&self, timestamp: chrono::DateTime<chrono::Utc>) -> Result<()> {
        let collection = self.db.collection::<UpfNode>("upf_nodes");

        collection
            .update_one(
                doc! { "_id": &self.upf_address },
                doc! {
                    "$set": {
                        "last_heartbeat": mongodb::bson::DateTime::from_millis(timestamp.timestamp_millis()),
                        "updated_at": mongodb::bson::DateTime::now()
                    }
                },
            )
            .await?;

        Ok(())
    }

    async fn update_heartbeat_success(
        &self,
        timestamp: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        let collection = self.db.collection::<UpfNode>("upf_nodes");

        collection
            .update_one(
                doc! { "_id": &self.upf_address },
                doc! {
                    "$set": {
                        "last_heartbeat_response": mongodb::bson::DateTime::from_millis(timestamp.timestamp_millis()),
                        "status": "ACTIVE",
                        "consecutive_failures": 0,
                        "updated_at": mongodb::bson::DateTime::now()
                    }
                },
            )
            .await?;

        Ok(())
    }

    async fn increment_failure_count(&self) -> Result<()> {
        let collection = self.db.collection::<UpfNode>("upf_nodes");

        let upf_node = collection
            .find_one(doc! { "_id": &self.upf_address })
            .await?
            .ok_or_else(|| anyhow::anyhow!("UPF node not found"))?;

        let new_failure_count = upf_node.consecutive_failures + 1;

        let new_status = if new_failure_count >= MAX_CONSECUTIVE_FAILURES {
            UpfStatus::Inactive
        } else {
            upf_node.status
        };

        let status_str = match new_status {
            UpfStatus::Active => "ACTIVE",
            UpfStatus::Inactive => "INACTIVE",
            UpfStatus::Unknown => "UNKNOWN",
        };

        collection
            .update_one(
                doc! { "_id": &self.upf_address },
                doc! {
                    "$set": {
                        "consecutive_failures": new_failure_count,
                        "status": status_str,
                        "updated_at": mongodb::bson::DateTime::now()
                    }
                },
            )
            .await?;

        if new_status == UpfStatus::Inactive && upf_node.status != UpfStatus::Inactive {
            error!("UPF {} marked as INACTIVE after {} consecutive failures", self.upf_address, new_failure_count);
        }

        Ok(())
    }

    async fn update_association_status(&self, established: bool) -> Result<()> {
        let collection = self.db.collection::<UpfNode>("upf_nodes");

        collection
            .update_one(
                doc! { "_id": &self.upf_address },
                doc! {
                    "$set": {
                        "association_established": established,
                        "updated_at": mongodb::bson::DateTime::now()
                    }
                },
            )
            .await?;

        Ok(())
    }

    pub async fn get_upf_status(db: &Database, upf_address: &str) -> Result<Option<UpfNode>> {
        let collection = db.collection::<UpfNode>("upf_nodes");

        collection
            .find_one(doc! { "_id": upf_address })
            .await
            .map_err(|e| anyhow::anyhow!("Database error: {}", e))
    }

    pub async fn list_upf_nodes(db: &Database) -> Result<Vec<UpfNode>> {
        use futures::TryStreamExt;

        let collection = db.collection::<UpfNode>("upf_nodes");

        let cursor = collection.find(doc! {}).await?;

        cursor
            .try_collect()
            .await
            .map_err(|e| anyhow::anyhow!("Database error: {}", e))
    }
}
