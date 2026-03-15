use crate::models::SmContext;
use crate::types::{PacketFilter, PacketFilterComponent, PacketFilterDirection, QosRule};
use crate::types::nas::{NasQosRule, QosRuleOperationCode};
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
        if packet_filter.packet_filter_id > 15 {
            return Err(format!(
                "Packet filter ID must be 0-15, got {}",
                packet_filter.packet_filter_id
            ));
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
        for id in 0..=15 {
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

    pub async fn process_nas_qos_rules(
        &self,
        sm_context_id: &str,
        nas_rules: &[NasQosRule],
    ) -> Result<NasQosRuleResult, String> {
        let collection: Collection<SmContext> = self.db.collection("sm_contexts");
        let sm_context = collection
            .find_one(doc! { "_id": sm_context_id })
            .await
            .map_err(|e| format!("Failed to fetch SM context: {}", e))?
            .ok_or_else(|| format!("SM context {} not found", sm_context_id))?;

        let mut packet_filters = sm_context.packet_filters.clone();
        let mut qos_rules = sm_context.qos_rules.clone();
        let mut added_pf_ids: Vec<u8> = Vec::new();
        let mut removed_pf_ids: Vec<u8> = Vec::new();

        for nas_rule in nas_rules {
            match nas_rule.operation_code {
                QosRuleOperationCode::CreateNewQosRule => {
                    if qos_rules.iter().any(|r| r.qos_rule_id == nas_rule.rule_id) {
                        return Err(format!("QoS rule {} already exists", nas_rule.rule_id));
                    }
                    let mut pf_ids = Vec::new();
                    for nas_pf in &nas_rule.packet_filters {
                        if nas_pf.identifier > 15 {
                            return Err(format!("Packet filter ID {} exceeds maximum 15", nas_pf.identifier));
                        }
                        if packet_filters.iter().any(|pf| pf.packet_filter_id == nas_pf.identifier) {
                            return Err(format!("Packet filter {} already exists", nas_pf.identifier));
                        }
                        let components = PacketFilterComponent::parse_nas_content(&nas_pf.content)?;
                        let pf = PacketFilter::new(
                            nas_pf.identifier,
                            nas_pf.direction,
                            nas_rule.precedence,
                            components,
                            Some(nas_rule.qfi),
                        );
                        packet_filters.push(pf);
                        pf_ids.push(nas_pf.identifier);
                        added_pf_ids.push(nas_pf.identifier);
                    }
                    let qos_rule = QosRule::new(
                        nas_rule.rule_id,
                        nas_rule.precedence,
                        false,
                        nas_rule.qfi,
                        pf_ids,
                        nas_rule.dqr,
                    );
                    qos_rules.push(qos_rule);
                }
                QosRuleOperationCode::DeleteExistingQosRule => {
                    let rule_idx = qos_rules
                        .iter()
                        .position(|r| r.qos_rule_id == nas_rule.rule_id)
                        .ok_or_else(|| format!("QoS rule {} not found", nas_rule.rule_id))?;
                    let removed_rule = qos_rules.remove(rule_idx);
                    for pf_id in &removed_rule.packet_filter_ids {
                        packet_filters.retain(|pf| pf.packet_filter_id != *pf_id);
                        removed_pf_ids.push(*pf_id);
                    }
                }
                QosRuleOperationCode::ModifyAndAddPacketFilters => {
                    let rule = qos_rules
                        .iter_mut()
                        .find(|r| r.qos_rule_id == nas_rule.rule_id)
                        .ok_or_else(|| format!("QoS rule {} not found", nas_rule.rule_id))?;
                    for nas_pf in &nas_rule.packet_filters {
                        if nas_pf.identifier > 15 {
                            return Err(format!("Packet filter ID {} exceeds maximum 15", nas_pf.identifier));
                        }
                        if packet_filters.iter().any(|pf| pf.packet_filter_id == nas_pf.identifier) {
                            return Err(format!("Packet filter {} already exists", nas_pf.identifier));
                        }
                        let components = PacketFilterComponent::parse_nas_content(&nas_pf.content)?;
                        let pf = PacketFilter::new(
                            nas_pf.identifier,
                            nas_pf.direction,
                            nas_rule.precedence,
                            components,
                            Some(nas_rule.qfi),
                        );
                        packet_filters.push(pf);
                        rule.packet_filter_ids.push(nas_pf.identifier);
                        added_pf_ids.push(nas_pf.identifier);
                    }
                    rule.precedence = nas_rule.precedence;
                    rule.qfi = nas_rule.qfi;
                }
                QosRuleOperationCode::ModifyAndReplaceAllPacketFilters => {
                    let rule = qos_rules
                        .iter_mut()
                        .find(|r| r.qos_rule_id == nas_rule.rule_id)
                        .ok_or_else(|| format!("QoS rule {} not found", nas_rule.rule_id))?;
                    for old_pf_id in &rule.packet_filter_ids {
                        packet_filters.retain(|pf| pf.packet_filter_id != *old_pf_id);
                        removed_pf_ids.push(*old_pf_id);
                    }
                    rule.packet_filter_ids.clear();
                    for nas_pf in &nas_rule.packet_filters {
                        if nas_pf.identifier > 15 {
                            return Err(format!("Packet filter ID {} exceeds maximum 15", nas_pf.identifier));
                        }
                        let components = PacketFilterComponent::parse_nas_content(&nas_pf.content)?;
                        let pf = PacketFilter::new(
                            nas_pf.identifier,
                            nas_pf.direction,
                            nas_rule.precedence,
                            components,
                            Some(nas_rule.qfi),
                        );
                        packet_filters.push(pf);
                        rule.packet_filter_ids.push(nas_pf.identifier);
                        added_pf_ids.push(nas_pf.identifier);
                    }
                    rule.precedence = nas_rule.precedence;
                    rule.qfi = nas_rule.qfi;
                }
                QosRuleOperationCode::ModifyAndDeletePacketFilters => {
                    let rule = qos_rules
                        .iter_mut()
                        .find(|r| r.qos_rule_id == nas_rule.rule_id)
                        .ok_or_else(|| format!("QoS rule {} not found", nas_rule.rule_id))?;
                    for nas_pf in &nas_rule.packet_filters {
                        rule.packet_filter_ids.retain(|id| *id != nas_pf.identifier);
                        packet_filters.retain(|pf| pf.packet_filter_id != nas_pf.identifier);
                        removed_pf_ids.push(nas_pf.identifier);
                    }
                    rule.precedence = nas_rule.precedence;
                    rule.qfi = nas_rule.qfi;
                }
                QosRuleOperationCode::ModifyWithoutChangingPacketFilters => {
                    let rule = qos_rules
                        .iter_mut()
                        .find(|r| r.qos_rule_id == nas_rule.rule_id)
                        .ok_or_else(|| format!("QoS rule {} not found", nas_rule.rule_id))?;
                    rule.precedence = nas_rule.precedence;
                    rule.qfi = nas_rule.qfi;
                }
            }
        }

        let pf_bson = mongodb::bson::to_bson(&packet_filters)
            .map_err(|e| format!("Failed to serialize packet filters: {}", e))?;
        let qr_bson = mongodb::bson::to_bson(&qos_rules)
            .map_err(|e| format!("Failed to serialize QoS rules: {}", e))?;

        collection
            .update_one(
                doc! { "_id": sm_context_id },
                doc! {
                    "$set": {
                        "packet_filters": pf_bson,
                        "qos_rules": qr_bson,
                        "updated_at": mongodb::bson::DateTime::now()
                    }
                },
            )
            .await
            .map_err(|e| format!("Failed to update SM context: {}", e))?;

        info!(
            "Processed {} NAS QoS rules for SM context {}: added {} PFs, removed {} PFs",
            nas_rules.len(),
            sm_context_id,
            added_pf_ids.len(),
            removed_pf_ids.len()
        );

        Ok(NasQosRuleResult {
            added_pf_ids,
            removed_pf_ids,
        })
    }
}

pub struct NasQosRuleResult {
    pub added_pf_ids: Vec<u8>,
    pub removed_pf_ids: Vec<u8>,
}
