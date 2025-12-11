use crate::types::{CertificateRenewalNotification, NotificationSeverity, RenewalThresholds};
use crate::services::certificate::CertificateService;
use mongodb::{bson::doc, Database};
use std::sync::Arc;
use tokio::time::{Duration, interval};

pub struct CertificateRenewalService {
    db: Arc<Database>,
    thresholds: RenewalThresholds,
    check_interval_hours: u64,
}

impl CertificateRenewalService {
    pub fn new(db: Arc<Database>, thresholds: RenewalThresholds, check_interval_hours: u64) -> Self {
        Self {
            db,
            thresholds,
            check_interval_hours,
        }
    }

    pub fn with_defaults(db: Arc<Database>) -> Self {
        Self::new(db, RenewalThresholds::default(), 24)
    }

    pub async fn start_monitoring(self: Arc<Self>) {
        let mut check_interval = interval(Duration::from_secs(self.check_interval_hours * 3600));

        tracing::info!(
            "Starting certificate renewal monitoring service (checking every {} hours)",
            self.check_interval_hours
        );
        tracing::info!(
            "Renewal thresholds - Critical: {} days, Warning: {} days, Info: {} days",
            self.thresholds.critical_days,
            self.thresholds.warning_days,
            self.thresholds.info_days
        );

        loop {
            check_interval.tick().await;

            if let Err(e) = self.check_certificates().await {
                tracing::error!("Error checking certificates for renewal: {}", e);
            }
        }
    }

    async fn check_certificates(&self) -> anyhow::Result<()> {
        tracing::debug!("Running certificate renewal check");

        let certificates = CertificateService::list_all(&self.db).await?;

        let mut notifications_created = 0;
        let mut critical_count = 0;
        let mut warning_count = 0;
        let mut info_count = 0;
        let mut expired_count = 0;

        for cert in certificates {
            let days_until_expiration = cert.days_until_expiration();
            let severity = self.thresholds.get_severity(days_until_expiration);

            if days_until_expiration <= self.thresholds.info_days {
                let existing = self.get_active_notification(&cert.id).await?;

                if existing.is_none() {
                    let notification = CertificateRenewalNotification::new(
                        cert.id.clone(),
                        cert.name.clone(),
                        severity,
                        days_until_expiration,
                        cert.not_after,
                    );

                    self.create_notification(notification).await?;
                    notifications_created += 1;

                    match severity {
                        NotificationSeverity::Expired => expired_count += 1,
                        NotificationSeverity::Critical => critical_count += 1,
                        NotificationSeverity::Warning => warning_count += 1,
                        NotificationSeverity::Info => info_count += 1,
                    }

                    tracing::warn!(
                        "Certificate renewal notification created: {} (expires in {} days)",
                        cert.name,
                        days_until_expiration
                    );
                }
            }
        }

        if notifications_created > 0 {
            tracing::info!(
                "Created {} renewal notification(s) - Expired: {}, Critical: {}, Warning: {}, Info: {}",
                notifications_created,
                expired_count,
                critical_count,
                warning_count,
                info_count
            );
        } else {
            tracing::debug!("No new renewal notifications created");
        }

        self.cleanup_stale_notifications().await?;

        Ok(())
    }

    async fn get_active_notification(
        &self,
        certificate_id: &str,
    ) -> anyhow::Result<Option<CertificateRenewalNotification>> {
        let collection: mongodb::Collection<CertificateRenewalNotification> =
            self.db.collection("certificate_renewal_notifications");

        Ok(collection
            .find_one(doc! {
                "certificate_id": certificate_id,
                "acknowledged": false
            })
            .await?)
    }

    async fn create_notification(
        &self,
        notification: CertificateRenewalNotification,
    ) -> anyhow::Result<()> {
        let collection: mongodb::Collection<CertificateRenewalNotification> =
            self.db.collection("certificate_renewal_notifications");

        collection.insert_one(&notification).await?;

        Ok(())
    }

    async fn cleanup_stale_notifications(&self) -> anyhow::Result<()> {
        let collection: mongodb::Collection<CertificateRenewalNotification> =
            self.db.collection("certificate_renewal_notifications");

        let result = collection
            .delete_many(doc! {
                "acknowledged": true,
                "acknowledged_at": {
                    "$lt": mongodb::bson::DateTime::from_millis(
                        (chrono::Utc::now() - chrono::Duration::days(30)).timestamp_millis()
                    )
                }
            })
            .await?;

        if result.deleted_count > 0 {
            tracing::info!(
                "Cleaned up {} acknowledged renewal notification(s)",
                result.deleted_count
            );
        }

        Ok(())
    }

    pub async fn get_all_notifications(
        db: &Database,
    ) -> anyhow::Result<Vec<CertificateRenewalNotification>> {
        let collection: mongodb::Collection<CertificateRenewalNotification> =
            db.collection("certificate_renewal_notifications");

        let mut cursor = collection
            .find(doc! {})
            .sort(doc! { "severity": -1, "created_at": 1 })
            .await?;

        let mut notifications = Vec::new();
        while cursor.advance().await? {
            notifications.push(cursor.deserialize_current()?);
        }

        Ok(notifications)
    }

    pub async fn get_unacknowledged_notifications(
        db: &Database,
    ) -> anyhow::Result<Vec<CertificateRenewalNotification>> {
        let collection: mongodb::Collection<CertificateRenewalNotification> =
            db.collection("certificate_renewal_notifications");

        let mut cursor = collection
            .find(doc! { "acknowledged": false })
            .sort(doc! { "severity": -1, "created_at": 1 })
            .await?;

        let mut notifications = Vec::new();
        while cursor.advance().await? {
            notifications.push(cursor.deserialize_current()?);
        }

        Ok(notifications)
    }

    pub async fn get_notifications_by_severity(
        db: &Database,
        severity: NotificationSeverity,
    ) -> anyhow::Result<Vec<CertificateRenewalNotification>> {
        let collection: mongodb::Collection<CertificateRenewalNotification> =
            db.collection("certificate_renewal_notifications");

        let mut cursor = collection
            .find(doc! { "severity": mongodb::bson::to_bson(&severity)? })
            .sort(doc! { "created_at": 1 })
            .await?;

        let mut notifications = Vec::new();
        while cursor.advance().await? {
            notifications.push(cursor.deserialize_current()?);
        }

        Ok(notifications)
    }

    pub async fn acknowledge_notification(
        db: &Database,
        notification_id: &str,
        acknowledged_by: Option<String>,
    ) -> anyhow::Result<()> {
        let collection: mongodb::Collection<CertificateRenewalNotification> =
            db.collection("certificate_renewal_notifications");

        let mut notification = collection
            .find_one(doc! { "_id": notification_id })
            .await?
            .ok_or_else(|| anyhow::anyhow!("Notification not found"))?;

        notification.acknowledge(acknowledged_by);

        collection
            .replace_one(doc! { "_id": notification_id }, &notification)
            .await?;

        tracing::info!("Acknowledged renewal notification: {}", notification_id);

        Ok(())
    }

    pub async fn delete_notification(db: &Database, notification_id: &str) -> anyhow::Result<()> {
        let collection: mongodb::Collection<CertificateRenewalNotification> =
            db.collection("certificate_renewal_notifications");

        let result = collection.delete_one(doc! { "_id": notification_id }).await?;

        if result.deleted_count == 0 {
            return Err(anyhow::anyhow!("Notification not found"));
        }

        tracing::info!("Deleted renewal notification: {}", notification_id);

        Ok(())
    }

    pub async fn get_notification_summary(db: &Database) -> anyhow::Result<NotificationSummary> {
        let notifications = Self::get_all_notifications(db).await?;

        let mut summary = NotificationSummary::default();

        for notification in notifications {
            summary.total += 1;
            if !notification.acknowledged {
                summary.unacknowledged += 1;
            }

            match notification.severity {
                NotificationSeverity::Expired => summary.expired += 1,
                NotificationSeverity::Critical => summary.critical += 1,
                NotificationSeverity::Warning => summary.warning += 1,
                NotificationSeverity::Info => summary.info += 1,
            }
        }

        Ok(summary)
    }
}

#[derive(Debug, Clone, Default)]
pub struct NotificationSummary {
    pub total: usize,
    pub unacknowledged: usize,
    pub expired: usize,
    pub critical: usize,
    pub warning: usize,
    pub info: usize,
}
