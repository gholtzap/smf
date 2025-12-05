use crate::models::SmContext;
use crate::types::{PacketFilter, PacketFilterComponent, PacketFilterDirection};
use mongodb::{Collection, Database};
use mongodb::bson::doc;
use std::sync::Arc;
use tracing::{info, warn};

pub struct PacketFilterManager {
    db: Arc<Database>,
}

impl PacketFilterManager {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    pub async fn add_packet_filters(
        &self,
        sm_context_id: &str,
        packet_filters: Vec<PacketFilter>,
    ) -> Result<(), String> {
        let collection: Collection<SmContext> = self.db.collection("sm_contexts");

        for packet_filter in &packet_filters {
            if let Err(e) = self.validate_packet_filter(packet_filter) {
                warn!(
                    "Invalid packet filter with ID {}: {}",
                    packet_filter.packet_filter_id, e
                );
                return Err(e);
            }
        }

        let existing_context = collection
            .find_one(doc! { "_id": sm_context_id })
            .await
            .map_err(|e| format!("Failed to fetch SM context: {}", e))?
            .ok_or_else(|| format!("SM context {} not found", sm_context_id))?;

        for packet_filter in &packet_filters {
            if existing_context
                .packet_filters
                .iter()
                .any(|pf| pf.packet_filter_id == packet_filter.packet_filter_id)
            {
                return Err(format!(
                    "Packet filter with ID {} already exists",
                    packet_filter.packet_filter_id
                ));
            }
        }

        let update = doc! {
            "$push": {
                "packet_filters": {
                    "$each": mongodb::bson::to_bson(&packet_filters)
                        .map_err(|e| format!("Failed to serialize packet filters: {}", e))?
                }
            },
            "$set": {
                "updated_at": mongodb::bson::DateTime::now()
            }
        };

        collection
            .update_one(doc! { "_id": sm_context_id }, update)
            .await
            .map_err(|e| format!("Failed to add packet filters: {}", e))?;

        info!(
            "Added {} packet filters to SM context {}",
            packet_filters.len(),
            sm_context_id
        );
        Ok(())
    }

    pub async fn modify_packet_filter(
        &self,
        sm_context_id: &str,
        packet_filter: PacketFilter,
    ) -> Result<(), String> {
        if let Err(e) = self.validate_packet_filter(&packet_filter) {
            warn!(
                "Invalid packet filter with ID {}: {}",
                packet_filter.packet_filter_id, e
            );
            return Err(e);
        }

        let collection: Collection<SmContext> = self.db.collection("sm_contexts");

        let filter = doc! {
            "_id": sm_context_id,
            "packet_filters.packet_filter_id": packet_filter.packet_filter_id as i32
        };

        let update = doc! {
            "$set": {
                "packet_filters.$": mongodb::bson::to_bson(&packet_filter)
                    .map_err(|e| format!("Failed to serialize packet filter: {}", e))?,
                "updated_at": mongodb::bson::DateTime::now()
            }
        };

        let result = collection
            .update_one(filter, update)
            .await
            .map_err(|e| format!("Failed to modify packet filter: {}", e))?;

        if result.matched_count == 0 {
            return Err(format!(
                "Packet filter with ID {} not found in SM context {}",
                packet_filter.packet_filter_id, sm_context_id
            ));
        }

        info!(
            "Modified packet filter with ID {} in SM context {}",
            packet_filter.packet_filter_id, sm_context_id
        );
        Ok(())
    }

    pub async fn remove_packet_filters(
        &self,
        sm_context_id: &str,
        packet_filter_ids: Vec<u8>,
    ) -> Result<(), String> {
        let collection: Collection<SmContext> = self.db.collection("sm_contexts");

        let ids_i32: Vec<i32> = packet_filter_ids
            .iter()
            .map(|&id| id as i32)
            .collect();

        let update = doc! {
            "$pull": {
                "packet_filters": {
                    "packet_filter_id": { "$in": ids_i32 }
                }
            },
            "$set": {
                "updated_at": mongodb::bson::DateTime::now()
            }
        };

        collection
            .update_one(doc! { "_id": sm_context_id }, update)
            .await
            .map_err(|e| format!("Failed to remove packet filters: {}", e))?;

        info!(
            "Removed {} packet filters from SM context {}",
            packet_filter_ids.len(),
            sm_context_id
        );
        Ok(())
    }

    pub async fn get_packet_filters(
        &self,
        sm_context_id: &str,
    ) -> Result<Vec<PacketFilter>, String> {
        let collection: Collection<SmContext> = self.db.collection("sm_contexts");

        let sm_context = collection
            .find_one(doc! { "_id": sm_context_id })
            .await
            .map_err(|e| format!("Failed to get SM context: {}", e))?
            .ok_or_else(|| format!("SM context {} not found", sm_context_id))?;

        Ok(sm_context.packet_filters)
    }

    fn validate_packet_filter(&self, packet_filter: &PacketFilter) -> Result<(), String> {
        if packet_filter.packet_filter_id == 0 {
            return Err("Packet filter ID must be greater than 0".to_string());
        }

        if packet_filter.precedence == 0 {
            return Err("Packet filter precedence must be greater than 0".to_string());
        }

        if packet_filter.components.is_empty() {
            return Err("Packet filter must have at least one component".to_string());
        }

        if let Some(qfi) = packet_filter.qfi {
            if qfi > 63 {
                return Err(format!(
                    "QFI must be between 0 and 63, got {}",
                    qfi
                ));
            }
        }

        for component in &packet_filter.components {
            self.validate_packet_filter_component(component)?;
        }

        Ok(())
    }

    fn validate_packet_filter_component(
        &self,
        component: &PacketFilterComponent,
    ) -> Result<(), String> {
        match component {
            PacketFilterComponent::LocalPortRange { low, high }
            | PacketFilterComponent::RemotePortRange { low, high } => {
                if low > high {
                    return Err(format!(
                        "Invalid port range: low ({}) must be <= high ({})",
                        low, high
                    ));
                }
            }
            PacketFilterComponent::TypeOfService { tos, mask } => {
                if tos & !mask != 0 {
                    return Err(format!(
                        "TOS value ({}) has bits set outside mask ({})",
                        tos, mask
                    ));
                }
            }
            PacketFilterComponent::FlowLabel(label) => {
                if *label > 0xFFFFF {
                    return Err(format!(
                        "Flow label ({}) exceeds maximum value (0xFFFFF)",
                        label
                    ));
                }
            }
            PacketFilterComponent::LocalIpv6Address { prefix_length, .. }
            | PacketFilterComponent::RemoteIpv6Address { prefix_length, .. } => {
                if *prefix_length > 128 {
                    return Err(format!(
                        "IPv6 prefix length ({}) exceeds maximum (128)",
                        prefix_length
                    ));
                }
            }
            _ => {}
        }

        Ok(())
    }

    pub fn allocate_packet_filter_id(
        &self,
        existing_packet_filters: &[PacketFilter],
    ) -> Option<u8> {
        for id in 1..=255 {
            if !existing_packet_filters
                .iter()
                .any(|pf| pf.packet_filter_id == id)
            {
                return Some(id);
            }
        }
        None
    }

    pub fn get_filters_by_direction(
        &self,
        packet_filters: &[PacketFilter],
        direction: PacketFilterDirection,
    ) -> Vec<PacketFilter> {
        packet_filters
            .iter()
            .filter(|pf| {
                pf.direction == direction || pf.direction == PacketFilterDirection::Bidirectional
            })
            .cloned()
            .collect()
    }

    pub fn get_filters_by_qfi(
        &self,
        packet_filters: &[PacketFilter],
        qfi: u8,
    ) -> Vec<PacketFilter> {
        packet_filters
            .iter()
            .filter(|pf| pf.qfi == Some(qfi))
            .cloned()
            .collect()
    }
}
