use mongodb::{bson::doc, Database, IndexModel, options::IndexOptions};
use crate::types::{
    CertificateAuditLog, CertificateUsageRecord, AuditLogQuery, UsageRecordQuery,
    AuditLogSummary, UsageRecordSummary, EventTypeCount, UsageTypeCount, AuditEventType,
    CertificateUsageType,
};

pub struct CertificateAuditService;

impl CertificateAuditService {
    pub async fn initialize_indexes(db: &Database) -> anyhow::Result<()> {
        let audit_collection: mongodb::Collection<CertificateAuditLog> = db.collection("certificate_audit_logs");
        let usage_collection: mongodb::Collection<CertificateUsageRecord> = db.collection("certificate_usage_records");

        let audit_indexes = vec![
            IndexModel::builder()
                .keys(doc! { "certificate_id": 1, "timestamp": -1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "event_type": 1, "timestamp": -1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "timestamp": -1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "actor": 1, "timestamp": -1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "timestamp": 1 })
                .options(IndexOptions::builder()
                    .expire_after(std::time::Duration::from_secs(90 * 24 * 3600))
                    .build())
                .build(),
        ];

        audit_collection.create_indexes(audit_indexes).await?;

        let usage_indexes = vec![
            IndexModel::builder()
                .keys(doc! { "certificate_id": 1, "timestamp": -1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "usage_type": 1, "timestamp": -1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "service": 1, "timestamp": -1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "timestamp": -1 })
                .build(),
            IndexModel::builder()
                .keys(doc! { "timestamp": 1 })
                .options(IndexOptions::builder()
                    .expire_after(std::time::Duration::from_secs(90 * 24 * 3600))
                    .build())
                .build(),
        ];

        usage_collection.create_indexes(usage_indexes).await?;

        tracing::info!("Certificate audit indexes created successfully");
        Ok(())
    }

    pub async fn log_audit_event(
        db: &Database,
        audit_log: CertificateAuditLog,
    ) -> anyhow::Result<()> {
        let collection: mongodb::Collection<CertificateAuditLog> = db.collection("certificate_audit_logs");
        collection.insert_one(&audit_log).await?;

        tracing::debug!(
            "Audit event logged: {:?} for certificate '{}' ({})",
            audit_log.event_type,
            audit_log.certificate_name,
            audit_log.certificate_id
        );

        Ok(())
    }

    pub async fn log_usage_record(
        db: &Database,
        usage_record: CertificateUsageRecord,
    ) -> anyhow::Result<()> {
        let collection: mongodb::Collection<CertificateUsageRecord> = db.collection("certificate_usage_records");
        collection.insert_one(&usage_record).await?;

        tracing::debug!(
            "Usage record logged: {:?} for certificate '{}' ({})",
            usage_record.usage_type,
            usage_record.certificate_name,
            usage_record.certificate_id
        );

        Ok(())
    }

    pub async fn query_audit_logs(
        db: &Database,
        query: &AuditLogQuery,
    ) -> anyhow::Result<Vec<CertificateAuditLog>> {
        let collection: mongodb::Collection<CertificateAuditLog> = db.collection("certificate_audit_logs");

        let mut filter = doc! {};

        if let Some(ref cert_id) = query.certificate_id {
            filter.insert("certificate_id", cert_id);
        }

        if let Some(ref cert_name) = query.certificate_name {
            filter.insert("certificate_name", cert_name);
        }

        if let Some(event_type) = query.event_type {
            filter.insert("event_type", mongodb::bson::to_bson(&event_type)?);
        }

        if let Some(ref actor) = query.actor {
            filter.insert("actor", actor);
        }

        if let Some(success) = query.success {
            filter.insert("success", success);
        }

        if query.start_time.is_some() || query.end_time.is_some() {
            let mut time_filter = doc! {};
            if let Some(start) = query.start_time {
                let start_millis = start.timestamp_millis();
                let start_bson = mongodb::bson::DateTime::from_millis(start_millis);
                time_filter.insert("$gte", start_bson);
            }
            if let Some(end) = query.end_time {
                let end_millis = end.timestamp_millis();
                let end_bson = mongodb::bson::DateTime::from_millis(end_millis);
                time_filter.insert("$lte", end_bson);
            }
            filter.insert("timestamp", time_filter);
        }

        let mut find_options = mongodb::options::FindOptions::builder()
            .sort(doc! { "timestamp": -1 })
            .build();

        if let Some(limit) = query.limit {
            find_options.limit = Some(limit);
        }

        if let Some(offset) = query.offset {
            find_options.skip = Some(offset);
        }

        let mut cursor = collection.find(filter).with_options(find_options).await?;

        let mut logs = Vec::new();
        while cursor.advance().await? {
            logs.push(cursor.deserialize_current()?);
        }

        Ok(logs)
    }

    pub async fn query_usage_records(
        db: &Database,
        query: &UsageRecordQuery,
    ) -> anyhow::Result<Vec<CertificateUsageRecord>> {
        let collection: mongodb::Collection<CertificateUsageRecord> = db.collection("certificate_usage_records");

        let mut filter = doc! {};

        if let Some(ref cert_id) = query.certificate_id {
            filter.insert("certificate_id", cert_id);
        }

        if let Some(ref cert_name) = query.certificate_name {
            filter.insert("certificate_name", cert_name);
        }

        if let Some(usage_type) = query.usage_type {
            filter.insert("usage_type", mongodb::bson::to_bson(&usage_type)?);
        }

        if let Some(ref service) = query.service {
            filter.insert("service", service);
        }

        if let Some(success) = query.success {
            filter.insert("success", success);
        }

        if query.start_time.is_some() || query.end_time.is_some() {
            let mut time_filter = doc! {};
            if let Some(start) = query.start_time {
                let start_millis = start.timestamp_millis();
                let start_bson = mongodb::bson::DateTime::from_millis(start_millis);
                time_filter.insert("$gte", start_bson);
            }
            if let Some(end) = query.end_time {
                let end_millis = end.timestamp_millis();
                let end_bson = mongodb::bson::DateTime::from_millis(end_millis);
                time_filter.insert("$lte", end_bson);
            }
            filter.insert("timestamp", time_filter);
        }

        let mut find_options = mongodb::options::FindOptions::builder()
            .sort(doc! { "timestamp": -1 })
            .build();

        if let Some(limit) = query.limit {
            find_options.limit = Some(limit);
        }

        if let Some(offset) = query.offset {
            find_options.skip = Some(offset);
        }

        let mut cursor = collection.find(filter).with_options(find_options).await?;

        let mut records = Vec::new();
        while cursor.advance().await? {
            records.push(cursor.deserialize_current()?);
        }

        Ok(records)
    }

    pub async fn get_audit_summary(db: &Database) -> anyhow::Result<AuditLogSummary> {
        let collection: mongodb::Collection<CertificateAuditLog> = db.collection("certificate_audit_logs");

        let total_events = collection.count_documents(doc! {}).await?;

        let pipeline = vec![
            doc! { "$group": {
                "_id": "$event_type",
                "count": { "$sum": 1 }
            }},
            doc! { "$sort": { "count": -1 }},
        ];

        let mut cursor = collection.aggregate(pipeline).await?;
        let mut events_by_type = Vec::new();

        while cursor.advance().await? {
            let doc = cursor.current();
            if let Ok(Some(event_type_ref)) = doc.get("_id") {
                if let Some(event_type_str) = event_type_ref.as_str() {
                    if let Ok(event_type) = serde_json::from_str::<AuditEventType>(&format!("\"{}\"", event_type_str)) {
                        let count = doc.get_i64("count").unwrap_or(0);
                        events_by_type.push(EventTypeCount {
                            event_type,
                            count,
                        });
                    }
                }
            }
        }

        let recent_query = AuditLogQuery {
            certificate_id: None,
            certificate_name: None,
            event_type: None,
            start_time: None,
            end_time: None,
            actor: None,
            success: None,
            limit: Some(10),
            offset: None,
        };

        let recent_events = Self::query_audit_logs(db, &recent_query).await?;

        Ok(AuditLogSummary {
            total_events: total_events as i64,
            events_by_type,
            recent_events,
        })
    }

    pub async fn get_usage_summary(db: &Database) -> anyhow::Result<UsageRecordSummary> {
        let collection: mongodb::Collection<CertificateUsageRecord> = db.collection("certificate_usage_records");

        let total_usage = collection.count_documents(doc! {}).await?;

        let pipeline = vec![
            doc! { "$group": {
                "_id": "$usage_type",
                "count": { "$sum": 1 }
            }},
            doc! { "$sort": { "count": -1 }},
        ];

        let mut cursor = collection.aggregate(pipeline).await?;
        let mut usage_by_type = Vec::new();

        while cursor.advance().await? {
            let doc = cursor.current();
            if let Ok(Some(usage_type_ref)) = doc.get("_id") {
                if let Some(usage_type_str) = usage_type_ref.as_str() {
                    if let Ok(usage_type) = serde_json::from_str::<CertificateUsageType>(&format!("\"{}\"", usage_type_str)) {
                        let count = doc.get_i64("count").unwrap_or(0);
                        usage_by_type.push(UsageTypeCount {
                            usage_type,
                            count,
                        });
                    }
                }
            }
        }

        let recent_query = UsageRecordQuery {
            certificate_id: None,
            certificate_name: None,
            usage_type: None,
            start_time: None,
            end_time: None,
            service: None,
            success: None,
            limit: Some(10),
            offset: None,
        };

        let recent_usage = Self::query_usage_records(db, &recent_query).await?;

        Ok(UsageRecordSummary {
            total_usage: total_usage as i64,
            usage_by_type,
            recent_usage,
        })
    }

    pub async fn delete_logs_for_certificate(
        db: &Database,
        certificate_id: &str,
    ) -> anyhow::Result<u64> {
        let audit_collection: mongodb::Collection<CertificateAuditLog> = db.collection("certificate_audit_logs");
        let usage_collection: mongodb::Collection<CertificateUsageRecord> = db.collection("certificate_usage_records");

        let audit_result = audit_collection
            .delete_many(doc! { "certificate_id": certificate_id })
            .await?;

        let usage_result = usage_collection
            .delete_many(doc! { "certificate_id": certificate_id })
            .await?;

        let total_deleted = audit_result.deleted_count + usage_result.deleted_count;

        tracing::info!(
            "Deleted {} audit logs and usage records for certificate '{}'",
            total_deleted,
            certificate_id
        );

        Ok(total_deleted)
    }
}
