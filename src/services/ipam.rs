use mongodb::{bson::doc, Database};
use std::net::Ipv4Addr;
use uuid::Uuid;
use chrono::Utc;
use crate::types::{IpAllocation, IpPool};

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
                allocated_ips: Vec::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            pools_collection.insert_one(&default_pool).await?;
            tracing::info!("Created default IP pool: 10.60.0.0/16");
        }

        Ok(())
    }

    pub async fn allocate_ip(
        db: &Database,
        pool_name: &str,
        sm_context_ref: &str,
        supi: &str,
    ) -> anyhow::Result<String> {
        let pools_collection: mongodb::Collection<IpPool> = db.collection("ip_pools");
        let allocations_collection: mongodb::Collection<IpAllocation> = db.collection("ip_allocations");

        let pool = pools_collection
            .find_one(doc! { "name": pool_name })
            .await?
            .ok_or_else(|| anyhow::anyhow!("IP pool '{}' not found", pool_name))?;

        let (network, prefix_len) = Self::parse_cidr(&pool.cidr)?;
        let total_ips = Self::calculate_pool_size(prefix_len);

        for offset in 2..total_ips {
            let ip = Self::offset_to_ip(network, offset);
            let ip_str = ip.to_string();

            if !pool.allocated_ips.contains(&ip_str) {
                let allocation = IpAllocation {
                    id: Uuid::new_v4().to_string(),
                    ip_address: ip_str.clone(),
                    pool_id: pool.id.clone(),
                    sm_context_ref: sm_context_ref.to_string(),
                    supi: supi.to_string(),
                    allocated_at: Utc::now(),
                };

                allocations_collection.insert_one(&allocation).await?;

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
                    "Allocated IP {} from pool '{}' to SUPI: {}",
                    ip_str,
                    pool_name,
                    supi
                );

                return Ok(ip_str);
            }
        }

        Err(anyhow::anyhow!("No available IPs in pool '{}'", pool_name))
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

            pools_collection
                .update_one(
                    doc! { "_id": &allocation.pool_id },
                    doc! {
                        "$pull": { "allocated_ips": &allocation.ip_address },
                        "$set": { "updated_at": mongodb::bson::DateTime::now() }
                    },
                )
                .await?;

            tracing::info!(
                "Released IP {} from pool for SM Context: {}",
                allocation.ip_address,
                sm_context_ref
            );
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
}
