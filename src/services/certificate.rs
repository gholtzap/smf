use mongodb::{bson::doc, Database};
use crate::types::{Certificate, CertificatePurpose};
use crate::services::certificate_validation::{CertificateValidator, ValidationResult, ChainValidationResult};
use chrono::Utc;

pub struct CertificateService;

impl CertificateService {
    pub async fn create(db: &Database, certificate: Certificate) -> anyhow::Result<Certificate> {
        let collection: mongodb::Collection<Certificate> = db.collection("certificates");

        let existing = collection
            .find_one(doc! { "name": &certificate.name, "purpose": mongodb::bson::to_bson(&certificate.purpose)? })
            .await?;

        if existing.is_some() {
            return Err(anyhow::anyhow!(
                "Certificate with name '{}' and purpose '{:?}' already exists",
                certificate.name,
                certificate.purpose
            ));
        }

        collection.insert_one(&certificate).await?;

        tracing::info!(
            "Created certificate '{}' ({:?}) with expiration: {}",
            certificate.name,
            certificate.purpose,
            certificate.not_after
        );

        Ok(certificate)
    }

    pub async fn get_by_id(db: &Database, id: &str) -> anyhow::Result<Option<Certificate>> {
        let collection: mongodb::Collection<Certificate> = db.collection("certificates");
        Ok(collection.find_one(doc! { "_id": id }).await?)
    }

    pub async fn get_by_name_and_purpose(
        db: &Database,
        name: &str,
        purpose: CertificatePurpose,
    ) -> anyhow::Result<Option<Certificate>> {
        let collection: mongodb::Collection<Certificate> = db.collection("certificates");
        Ok(collection
            .find_one(doc! {
                "name": name,
                "purpose": mongodb::bson::to_bson(&purpose)?
            })
            .await?)
    }

    pub async fn list_by_purpose(
        db: &Database,
        purpose: CertificatePurpose,
    ) -> anyhow::Result<Vec<Certificate>> {
        let collection: mongodb::Collection<Certificate> = db.collection("certificates");
        let mut cursor = collection
            .find(doc! { "purpose": mongodb::bson::to_bson(&purpose)? })
            .await?;

        let mut certificates = Vec::new();
        while cursor.advance().await? {
            certificates.push(cursor.deserialize_current()?);
        }

        Ok(certificates)
    }

    pub async fn list_all(db: &Database) -> anyhow::Result<Vec<Certificate>> {
        let collection: mongodb::Collection<Certificate> = db.collection("certificates");
        let mut cursor = collection.find(doc! {}).await?;

        let mut certificates = Vec::new();
        while cursor.advance().await? {
            certificates.push(cursor.deserialize_current()?);
        }

        Ok(certificates)
    }

    pub async fn list_expired(db: &Database) -> anyhow::Result<Vec<Certificate>> {
        let collection: mongodb::Collection<Certificate> = db.collection("certificates");
        let now = Utc::now();
        let now_millis = now.timestamp_millis();
        let now_bson = mongodb::bson::DateTime::from_millis(now_millis);

        let mut cursor = collection
            .find(doc! { "not_after": { "$lt": now_bson } })
            .await?;

        let mut certificates = Vec::new();
        while cursor.advance().await? {
            certificates.push(cursor.deserialize_current()?);
        }

        Ok(certificates)
    }

    pub async fn list_expiring_soon(
        db: &Database,
        days_threshold: i64,
    ) -> anyhow::Result<Vec<Certificate>> {
        let collection: mongodb::Collection<Certificate> = db.collection("certificates");
        let now = Utc::now();
        let threshold = now + chrono::Duration::days(days_threshold);

        let now_millis = now.timestamp_millis();
        let threshold_millis = threshold.timestamp_millis();
        let now_bson = mongodb::bson::DateTime::from_millis(now_millis);
        let threshold_bson = mongodb::bson::DateTime::from_millis(threshold_millis);

        let mut cursor = collection
            .find(doc! {
                "not_after": {
                    "$gte": now_bson,
                    "$lte": threshold_bson
                }
            })
            .await?;

        let mut certificates = Vec::new();
        while cursor.advance().await? {
            certificates.push(cursor.deserialize_current()?);
        }

        Ok(certificates)
    }

    pub async fn update(db: &Database, certificate: &Certificate) -> anyhow::Result<()> {
        let collection: mongodb::Collection<Certificate> = db.collection("certificates");

        let mut updated_cert = certificate.clone();
        updated_cert.updated_at = Utc::now();

        collection
            .replace_one(doc! { "_id": &certificate.id }, &updated_cert)
            .await?;

        tracing::info!("Updated certificate '{}'", certificate.name);

        Ok(())
    }

    pub async fn delete(db: &Database, id: &str) -> anyhow::Result<()> {
        let collection: mongodb::Collection<Certificate> = db.collection("certificates");

        let result = collection.delete_one(doc! { "_id": id }).await?;

        if result.deleted_count == 0 {
            return Err(anyhow::anyhow!("Certificate with ID '{}' not found", id));
        }

        tracing::info!("Deleted certificate with ID '{}'", id);

        Ok(())
    }

    pub async fn delete_by_name(db: &Database, name: &str) -> anyhow::Result<u64> {
        let collection: mongodb::Collection<Certificate> = db.collection("certificates");

        let result = collection.delete_many(doc! { "name": name }).await?;

        tracing::info!(
            "Deleted {} certificate(s) with name '{}'",
            result.deleted_count,
            name
        );

        Ok(result.deleted_count)
    }

    pub async fn validate_certificate(
        db: &Database,
        cert_id: &str,
    ) -> anyhow::Result<ValidationResult> {
        let cert = Self::get_by_id(db, cert_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Certificate not found"))?;

        CertificateValidator::validate_certificate(&cert)
    }

    pub async fn validate_certificate_chain(
        db: &Database,
        cert_id: &str,
        intermediate_cert_ids: &[String],
        root_cert_id: Option<String>,
    ) -> anyhow::Result<ChainValidationResult> {
        let cert = Self::get_by_id(db, cert_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Certificate not found"))?;

        let mut intermediates = Vec::new();
        for int_id in intermediate_cert_ids {
            let int_cert = Self::get_by_id(db, int_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Intermediate certificate not found: {}", int_id))?;
            intermediates.push(int_cert);
        }

        let root = if let Some(root_id) = root_cert_id {
            Some(
                Self::get_by_id(db, &root_id)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("Root certificate not found"))?,
            )
        } else {
            None
        };

        let intermediate_refs: Vec<&Certificate> = intermediates.iter().collect();
        let root_ref = root.as_ref();

        CertificateValidator::validate_chain(&cert, &intermediate_refs, root_ref)
    }

    pub async fn check_all_expirations(db: &Database) -> anyhow::Result<Vec<(String, crate::services::certificate_validation::ExpirationStatus)>> {
        let certs = Self::list_all(db).await?;
        Ok(CertificateValidator::check_expiration_batch(&certs))
    }

    pub async fn find_certificates_needing_renewal(
        db: &Database,
        days_threshold: i64,
    ) -> anyhow::Result<Vec<String>> {
        let certs = Self::list_all(db).await?;
        Ok(CertificateValidator::find_certificates_needing_renewal(&certs, days_threshold))
    }
}
