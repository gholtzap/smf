use mongodb::{bson::doc, Database};
use std::net::{Ipv4Addr, Ipv6Addr};
use uuid::Uuid;
use chrono::Utc;
use crate::types::{IpAllocation, IpAllocationResult, IpPool, PduSessionType};

pub struct IpamService;

impl IpamService {
    pub async fn init_default_pool(db: &Database) -> anyhow::Result<()> {
        let pools_collection: mongodb::Collection<IpPool> = db.collection("ip_pools");

        let existing_pool = pools_collection
            .find_one(doc! { "name": "default" })
            .await?;

        if existing_pool.is_none() {
            let default_pool = IpPool {
                id: Uuid::new_v4().to_string(),
                name: "default".to_string(),
                cidr: "10.60.0.0/16".to_string(),
                gateway: "10.60.0.1".to_string(),
                dns_primary: Some("8.8.8.8".to_string()),
                dns_secondary: Some("8.8.4.4".to_string()),
                mtu: Some(1500),
                allocated_ips: Vec::new(),
                ipv6_cidr: Some("2001:db8::/32".to_string()),
                ipv6_gateway: Some("2001:db8::1".to_string()),
                ipv6_dns_primary: Some("2001:4860:4860::8888".to_string()),
                ipv6_dns_secondary: Some("2001:4860:4860::8844".to_string()),
                allocated_ipv6_prefixes: Vec::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            pools_collection.insert_one(&default_pool).await?;
            tracing::info!("Created default IP pool: 10.60.0.0/16 (IPv4) and 2001:db8::/32 (IPv6)");
        }

        Ok(())
    }

    pub async fn allocate_ip(
        db: &Database,
        pool_name: &str,
        sm_context_ref: &str,
        supi: &str,
        pdu_session_type: &PduSessionType,
    ) -> anyhow::Result<IpAllocationResult> {
        let pools_collection: mongodb::Collection<IpPool> = db.collection("ip_pools");
        let allocations_collection: mongodb::Collection<IpAllocation> = db.collection("ip_allocations");

        let pool = pools_collection
            .find_one(doc! { "name": pool_name })
            .await?
            .ok_or_else(|| anyhow::anyhow!("IP pool '{}' not found", pool_name))?;

        let mut ipv4_addr = None;
        let mut ipv6_prefix = None;

        match pdu_session_type {
            PduSessionType::Ipv4 | PduSessionType::Ipv4v6 => {
                let (network, prefix_len) = Self::parse_cidr(&pool.cidr)?;
                let total_ips = Self::calculate_pool_size(prefix_len);

                for offset in 2..total_ips {
                    let ip = Self::offset_to_ip(network, offset);
                    let ip_str = ip.to_string();

                    if !pool.allocated_ips.contains(&ip_str) {
                        ipv4_addr = Some(ip_str.clone());

                        pools_collection
                            .update_one(
                                doc! { "_id": &pool.id },
                                doc! {
                                    "$push": { "allocated_ips": &ip_str },
                                    "$set": { "updated_at": mongodb::bson::DateTime::now() }
                                },
                            )
                            .await?;

                        tracing::info!(
                            "Allocated IPv4 {} from pool '{}' to SUPI: {}",
                            ip_str,
                            pool_name,
                            supi
                        );
                        break;
                    }
                }

                if ipv4_addr.is_none() {
                    return Err(anyhow::anyhow!("No available IPv4 addresses in pool '{}'", pool_name));
                }
            }
            _ => {}
        }

        match pdu_session_type {
            PduSessionType::Ipv6 | PduSessionType::Ipv4v6 => {
                if let Some(ref ipv6_cidr) = pool.ipv6_cidr {
                    let (network, prefix_len) = Self::parse_ipv6_cidr(ipv6_cidr)?;
                    let subnet_prefix_len = 64;
                    let total_subnets = Self::calculate_ipv6_subnet_count(prefix_len, subnet_prefix_len);

                    for offset in 1..total_subnets {
                        let subnet = Self::offset_to_ipv6_subnet(network, offset, subnet_prefix_len);
                        let subnet_str = format!("{}/{}", subnet, subnet_prefix_len);

                        if !pool.allocated_ipv6_prefixes.contains(&subnet_str) {
                            ipv6_prefix = Some(subnet_str.clone());

                            pools_collection
                                .update_one(
                                    doc! { "_id": &pool.id },
                                    doc! {
                                        "$push": { "allocated_ipv6_prefixes": &subnet_str },
                                        "$set": { "updated_at": mongodb::bson::DateTime::now() }
                                    },
                                )
                                .await?;

                            tracing::info!(
                                "Allocated IPv6 prefix {} from pool '{}' to SUPI: {}",
                                subnet_str,
                                pool_name,
                                supi
                            );
                            break;
                        }
                    }

                    if ipv6_prefix.is_none() {
                        return Err(anyhow::anyhow!("No available IPv6 prefixes in pool '{}'", pool_name));
                    }
                } else {
                    return Err(anyhow::anyhow!("Pool '{}' does not support IPv6", pool_name));
                }
            }
            _ => {}
        }

        let allocation = IpAllocation {
            id: Uuid::new_v4().to_string(),
            ip_address: ipv4_addr.clone().unwrap_or_default(),
            ipv6_prefix: ipv6_prefix.clone(),
            pool_id: pool.id.clone(),
            sm_context_ref: sm_context_ref.to_string(),
            supi: supi.to_string(),
            allocated_at: Utc::now(),
        };

        allocations_collection.insert_one(&allocation).await?;

        Ok(IpAllocationResult {
            ip_address: allocation.ip_address,
            gateway: pool.gateway.clone(),
            dns_primary: pool.dns_primary.clone(),
            dns_secondary: pool.dns_secondary.clone(),
            mtu: pool.mtu,
            ipv6_prefix,
            ipv6_gateway: pool.ipv6_gateway.clone(),
            ipv6_dns_primary: pool.ipv6_dns_primary.clone(),
            ipv6_dns_secondary: pool.ipv6_dns_secondary.clone(),
        })
    }

    pub async fn release_ip(
        db: &Database,
        sm_context_ref: &str,
    ) -> anyhow::Result<()> {
        let pools_collection: mongodb::Collection<IpPool> = db.collection("ip_pools");
        let allocations_collection: mongodb::Collection<IpAllocation> = db.collection("ip_allocations");

        if let Some(allocation) = allocations_collection
            .find_one(doc! { "sm_context_ref": sm_context_ref })
            .await?
        {
            allocations_collection
                .delete_one(doc! { "_id": &allocation.id })
                .await?;

            let mut update_doc = doc! {
                "$set": { "updated_at": mongodb::bson::DateTime::now() }
            };

            if !allocation.ip_address.is_empty() {
                update_doc.insert("$pull", doc! { "allocated_ips": &allocation.ip_address });
                tracing::info!(
                    "Released IPv4 {} for SM Context: {}",
                    allocation.ip_address,
                    sm_context_ref
                );
            }

            if let Some(ref ipv6_prefix) = allocation.ipv6_prefix {
                if let Some(pull_doc) = update_doc.get_document_mut("$pull").ok() {
                    pull_doc.insert("allocated_ipv6_prefixes", ipv6_prefix);
                } else {
                    update_doc.insert("$pull", doc! { "allocated_ipv6_prefixes": ipv6_prefix });
                }
                tracing::info!(
                    "Released IPv6 prefix {} for SM Context: {}",
                    ipv6_prefix,
                    sm_context_ref
                );
            }

            pools_collection
                .update_one(
                    doc! { "_id": &allocation.pool_id },
                    update_doc,
                )
                .await?;
        }

        Ok(())
    }

    fn parse_cidr(cidr: &str) -> anyhow::Result<(Ipv4Addr, u8)> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid CIDR format"));
        }

        let network: Ipv4Addr = parts[0].parse()?;
        let prefix_len: u8 = parts[1].parse()?;

        Ok((network, prefix_len))
    }

    fn calculate_pool_size(prefix_len: u8) -> u32 {
        2u32.pow((32 - prefix_len) as u32)
    }

    fn offset_to_ip(network: Ipv4Addr, offset: u32) -> Ipv4Addr {
        let network_int = u32::from(network);
        let new_ip = network_int + offset;
        Ipv4Addr::from(new_ip)
    }

    fn parse_ipv6_cidr(cidr: &str) -> anyhow::Result<(Ipv6Addr, u8)> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid IPv6 CIDR format"));
        }

        let network: Ipv6Addr = parts[0].parse()?;
        let prefix_len: u8 = parts[1].parse()?;

        Ok((network, prefix_len))
    }

    fn calculate_ipv6_subnet_count(prefix_len: u8, subnet_prefix_len: u8) -> u64 {
        if subnet_prefix_len <= prefix_len {
            return 1;
        }
        let bits = subnet_prefix_len - prefix_len;
        if bits >= 64 {
            return u64::MAX;
        }
        2u64.pow(bits as u32)
    }

    fn offset_to_ipv6_subnet(network: Ipv6Addr, offset: u64, subnet_prefix_len: u8) -> Ipv6Addr {
        let network_int = u128::from(network);
        let shift = 128 - subnet_prefix_len;
        let subnet_int = network_int + (offset as u128) * (1u128 << shift);
        Ipv6Addr::from(subnet_int)
    }
}
