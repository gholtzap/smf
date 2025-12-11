use crate::types::{
    AutoRotationConfig, AutoRotationAttempt, CertificatePurpose, CertificateProviderType,
};
use crate::services::{
    certificate::CertificateService,
    certificate_rotation::CertificateRotationService,
    certificate_provider,
};
use mongodb::{bson::doc, Database};
use std::sync::Arc;
use tokio::time::{Duration, interval};

pub struct CertificateAutoRotationService {
    db: Arc<Database>,
    check_interval_hours: u64,
}

impl CertificateAutoRotationService {
    pub fn new(db: Arc<Database>, check_interval_hours: u64) -> Self {
        Self {
            db,
            check_interval_hours,
        }
    }

    pub fn with_defaults(db: Arc<Database>) -> Self {
        Self::new(db, 6)
    }

    pub async fn start_monitoring(self: Arc<Self>) {
        let mut check_interval = interval(Duration::from_secs(self.check_interval_hours * 3600));

        tracing::info!(
            "Starting certificate auto-rotation service (checking every {} hours)",
            self.check_interval_hours
        );

        loop {
            check_interval.tick().await;

            if let Err(e) = self.check_and_rotate_certificates().await {
                tracing::error!("Error in auto-rotation check: {}", e);
            }
        }
    }

    async fn check_and_rotate_certificates(&self) -> anyhow::Result<()> {
        tracing::debug!("Running certificate auto-rotation check");

        let configs = self.get_enabled_configs().await?;

        if configs.is_empty() {
            tracing::debug!("No enabled auto-rotation configs found");
            return Ok(());
        }

        tracing::info!("Checking {} auto-rotation config(s)", configs.len());

        for config in configs {
            if let Err(e) = self.process_config(config).await {
                tracing::error!("Failed to process auto-rotation config: {}", e);
            }
        }

        Ok(())
    }

    async fn process_config(&self, mut config: AutoRotationConfig) -> anyhow::Result<()> {
        let cert = CertificateService::get_by_name_and_purpose(
            &self.db,
            &config.certificate_name,
            config.certificate_purpose,
        )
        .await?;

        let cert = match cert {
            Some(c) => c,
            None => {
                tracing::warn!(
                    "Certificate '{}' ({:?}) not found for auto-rotation config {}",
                    config.certificate_name,
                    config.certificate_purpose,
                    config.id
                );
                return Ok(());
            }
        };

        let days_until_expiration = cert.days_until_expiration();

        if !config.should_rotate(days_until_expiration) {
            tracing::debug!(
                "Certificate '{}' ({:?}) does not need rotation yet ({} days remaining, threshold: {})",
                config.certificate_name,
                config.certificate_purpose,
                days_until_expiration,
                config.rotation_threshold_days
            );
            return Ok(());
        }

        tracing::info!(
            "Certificate '{}' ({:?}) needs auto-rotation ({} days remaining, threshold: {})",
            config.certificate_name,
            config.certificate_purpose,
            days_until_expiration,
            config.rotation_threshold_days
        );

        let mut attempt = AutoRotationAttempt::new(
            config.id.clone(),
            config.certificate_name.clone(),
            config.certificate_purpose,
        );

        match self.perform_rotation(&config, &cert.id).await {
            Ok((old_id, new_id, rotation_id)) => {
                attempt.mark_success(old_id, new_id, rotation_id);
                config.update_attempt(true, None);
                tracing::info!(
                    "Successfully auto-rotated certificate '{}' ({:?})",
                    config.certificate_name,
                    config.certificate_purpose
                );
            }
            Err(e) => {
                let error_msg = format!("Auto-rotation failed: {}", e);
                attempt.mark_failure(error_msg.clone());
                config.update_attempt(false, Some(error_msg.clone()));
                tracing::error!(
                    "Failed to auto-rotate certificate '{}' ({:?}): {}",
                    config.certificate_name,
                    config.certificate_purpose,
                    e
                );
            }
        }

        self.save_attempt(attempt).await?;
        self.save_config(&config).await?;

        Ok(())
    }

    async fn perform_rotation(
        &self,
        config: &AutoRotationConfig,
        old_cert_id: &str,
    ) -> anyhow::Result<(String, String, String)> {
        let provider = certificate_provider::create_provider(
            config.provider_type,
            &config.provider_config,
        )?;

        let cert_request = provider
            .get_certificate(&config.certificate_name, config.certificate_purpose)
            .await?;

        let response = CertificateRotationService::rotate_certificate(
            &self.db,
            &config.certificate_name,
            config.certificate_purpose,
            cert_request,
            Some("auto-rotation-service".to_string()),
            Some(format!(
                "Automatic rotation (threshold: {} days)",
                config.rotation_threshold_days
            )),
        )
        .await?;

        if !response.success {
            return Err(anyhow::anyhow!("Rotation failed: {}", response.message));
        }

        Ok((
            response.old_certificate_id,
            response.new_certificate_id,
            response.rotation_id,
        ))
    }

    async fn get_enabled_configs(&self) -> anyhow::Result<Vec<AutoRotationConfig>> {
        let collection: mongodb::Collection<AutoRotationConfig> =
            self.db.collection("certificate_auto_rotation_configs");

        let mut cursor = collection
            .find(doc! { "enabled": true })
            .await?;

        let mut configs = Vec::new();
        while cursor.advance().await? {
            configs.push(cursor.deserialize_current()?);
        }

        Ok(configs)
    }

    async fn save_attempt(&self, attempt: AutoRotationAttempt) -> anyhow::Result<()> {
        let collection: mongodb::Collection<AutoRotationAttempt> =
            self.db.collection("certificate_auto_rotation_attempts");

        collection.insert_one(&attempt).await?;

        Ok(())
    }

    async fn save_config(&self, config: &AutoRotationConfig) -> anyhow::Result<()> {
        let collection: mongodb::Collection<AutoRotationConfig> =
            self.db.collection("certificate_auto_rotation_configs");

        collection
            .replace_one(doc! { "_id": &config.id }, config)
            .await?;

        Ok(())
    }

    pub async fn create_config(
        db: &Database,
        certificate_name: String,
        certificate_purpose: CertificatePurpose,
        rotation_threshold_days: i64,
        provider_type: CertificateProviderType,
        provider_config: serde_json::Value,
    ) -> anyhow::Result<AutoRotationConfig> {
        let collection: mongodb::Collection<AutoRotationConfig> =
            db.collection("certificate_auto_rotation_configs");

        let existing = collection
            .find_one(doc! {
                "certificate_name": &certificate_name,
                "certificate_purpose": mongodb::bson::to_bson(&certificate_purpose)?
            })
            .await?;

        if existing.is_some() {
            return Err(anyhow::anyhow!(
                "Auto-rotation config already exists for certificate '{}' ({:?})",
                certificate_name,
                certificate_purpose
            ));
        }

        let config = AutoRotationConfig::new(
            certificate_name,
            certificate_purpose,
            rotation_threshold_days,
            provider_type,
            provider_config,
        );

        collection.insert_one(&config).await?;

        tracing::info!(
            "Created auto-rotation config for '{}' ({:?})",
            config.certificate_name,
            config.certificate_purpose
        );

        Ok(config)
    }

    pub async fn get_config(
        db: &Database,
        config_id: &str,
    ) -> anyhow::Result<Option<AutoRotationConfig>> {
        let collection: mongodb::Collection<AutoRotationConfig> =
            db.collection("certificate_auto_rotation_configs");

        Ok(collection.find_one(doc! { "_id": config_id }).await?)
    }

    pub async fn get_config_by_certificate(
        db: &Database,
        certificate_name: &str,
        certificate_purpose: CertificatePurpose,
    ) -> anyhow::Result<Option<AutoRotationConfig>> {
        let collection: mongodb::Collection<AutoRotationConfig> =
            db.collection("certificate_auto_rotation_configs");

        Ok(collection
            .find_one(doc! {
                "certificate_name": certificate_name,
                "certificate_purpose": mongodb::bson::to_bson(&certificate_purpose)?
            })
            .await?)
    }

    pub async fn list_all_configs(db: &Database) -> anyhow::Result<Vec<AutoRotationConfig>> {
        let collection: mongodb::Collection<AutoRotationConfig> =
            db.collection("certificate_auto_rotation_configs");

        let mut cursor = collection
            .find(doc! {})
            .sort(doc! { "certificate_name": 1 })
            .await?;

        let mut configs = Vec::new();
        while cursor.advance().await? {
            configs.push(cursor.deserialize_current()?);
        }

        Ok(configs)
    }

    pub async fn update_config(
        db: &Database,
        config_id: &str,
        enabled: Option<bool>,
        rotation_threshold_days: Option<i64>,
        provider_config: Option<serde_json::Value>,
    ) -> anyhow::Result<AutoRotationConfig> {
        let collection: mongodb::Collection<AutoRotationConfig> =
            db.collection("certificate_auto_rotation_configs");

        let mut config = collection
            .find_one(doc! { "_id": config_id })
            .await?
            .ok_or_else(|| anyhow::anyhow!("Auto-rotation config not found"))?;

        if let Some(enabled_val) = enabled {
            config.enabled = enabled_val;
        }
        if let Some(threshold) = rotation_threshold_days {
            config.rotation_threshold_days = threshold;
        }
        if let Some(provider_cfg) = provider_config {
            config.provider_config = provider_cfg;
        }

        config.updated_at = chrono::Utc::now();

        collection
            .replace_one(doc! { "_id": config_id }, &config)
            .await?;

        tracing::info!(
            "Updated auto-rotation config {} for '{}' ({:?})",
            config_id,
            config.certificate_name,
            config.certificate_purpose
        );

        Ok(config)
    }

    pub async fn delete_config(db: &Database, config_id: &str) -> anyhow::Result<()> {
        let collection: mongodb::Collection<AutoRotationConfig> =
            db.collection("certificate_auto_rotation_configs");

        let result = collection.delete_one(doc! { "_id": config_id }).await?;

        if result.deleted_count == 0 {
            return Err(anyhow::anyhow!("Auto-rotation config not found"));
        }

        tracing::info!("Deleted auto-rotation config: {}", config_id);

        Ok(())
    }

    pub async fn get_attempts_for_config(
        db: &Database,
        config_id: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<AutoRotationAttempt>> {
        let collection: mongodb::Collection<AutoRotationAttempt> =
            db.collection("certificate_auto_rotation_attempts");

        let mut cursor = collection
            .find(doc! { "config_id": config_id })
            .sort(doc! { "attempted_at": -1 })
            .limit(limit)
            .await?;

        let mut attempts = Vec::new();
        while cursor.advance().await? {
            attempts.push(cursor.deserialize_current()?);
        }

        Ok(attempts)
    }

    pub async fn get_recent_attempts(
        db: &Database,
        limit: i64,
    ) -> anyhow::Result<Vec<AutoRotationAttempt>> {
        let collection: mongodb::Collection<AutoRotationAttempt> =
            db.collection("certificate_auto_rotation_attempts");

        let mut cursor = collection
            .find(doc! {})
            .sort(doc! { "attempted_at": -1 })
            .limit(limit)
            .await?;

        let mut attempts = Vec::new();
        while cursor.advance().await? {
            attempts.push(cursor.deserialize_current()?);
        }

        Ok(attempts)
    }
}
