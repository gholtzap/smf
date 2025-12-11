use mongodb::{bson::doc, Database};
use crate::types::{
    Certificate, CertificatePurpose, CertificateRotationRecord, RotationStatus,
    CertificateRotationRequest, CertificateRotationResponse, CertificateRollbackRequest,
    CertificateRollbackResponse, RotationHistoryResponse,
};
use crate::services::{certificate::CertificateService, certificate_validation::CertificateValidator};
use chrono::Utc;
use x509_cert::Certificate as X509Certificate;
use x509_cert::der::Decode;
use base64::Engine;

pub struct CertificateRotationService;

impl CertificateRotationService {
    pub async fn rotate_certificate(
        db: &Database,
        name: &str,
        purpose: CertificatePurpose,
        request: CertificateRotationRequest,
        rotated_by: Option<String>,
        rotation_reason: Option<String>,
    ) -> anyhow::Result<CertificateRotationResponse> {
        let old_cert = CertificateService::get_by_name_and_purpose(db, name, purpose)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Certificate '{}' with purpose {:?} not found", name, purpose))?;

        let pem = request.certificate_pem.trim();
        let pem_data = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");

        let der_bytes = base64::engine::general_purpose::STANDARD
            .decode(&pem_data)
            .map_err(|e| anyhow::anyhow!("Failed to decode base64 certificate: {}", e))?;

        let cert_der = X509Certificate::from_der(&der_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {}", e))?;

        let subject = cert_der.tbs_certificate.subject.to_string();
        let issuer = cert_der.tbs_certificate.issuer.to_string();
        let serial_number = hex::encode(cert_der.tbs_certificate.serial_number.as_bytes());

        let validity = &cert_der.tbs_certificate.validity;
        let not_before = validity.not_before.to_unix_duration().as_secs() as i64;
        let not_after = validity.not_after.to_unix_duration().as_secs() as i64;

        let not_before = chrono::DateTime::from_timestamp(not_before, 0)
            .ok_or_else(|| anyhow::anyhow!("Invalid not_before timestamp"))?;
        let not_after = chrono::DateTime::from_timestamp(not_after, 0)
            .ok_or_else(|| anyhow::anyhow!("Invalid not_after timestamp"))?;

        let fingerprint_sha256 = {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&der_bytes);
            hex::encode(hasher.finalize())
        };

        let (key_type, key_size_bits) = Self::extract_key_info(&cert_der)?;

        let new_cert = Certificate::new(
            name.to_string(),
            purpose,
            request.certificate_pem.clone(),
            request.private_key_pem.clone(),
            request.certificate_chain_pem.clone(),
            subject,
            issuer,
            serial_number,
            not_before,
            not_after,
            fingerprint_sha256,
            key_type,
            key_size_bits,
        );

        let validation_result = CertificateValidator::validate_certificate(&new_cert)?;
        if !validation_result.is_valid {
            return Err(anyhow::anyhow!(
                "New certificate validation failed: {:?}",
                validation_result.errors
            ));
        }

        let rotation_id = uuid::Uuid::new_v4().to_string();
        let rotation_record = CertificateRotationRecord {
            id: rotation_id.clone(),
            certificate_name: name.to_string(),
            certificate_purpose: format!("{:?}", purpose),
            old_certificate_id: old_cert.id.clone(),
            new_certificate_id: new_cert.id.clone(),
            rotated_at: Utc::now(),
            rotated_by,
            rotation_reason,
            status: RotationStatus::Completed,
        };

        let rotation_collection: mongodb::Collection<CertificateRotationRecord> =
            db.collection("certificate_rotations");
        rotation_collection.insert_one(&rotation_record).await?;

        CertificateService::delete(db, &old_cert.id).await?;
        let created_cert = CertificateService::create(db, new_cert).await?;

        tracing::info!(
            "Certificate '{}' ({:?}) rotated successfully. Old ID: {}, New ID: {}",
            name,
            purpose,
            old_cert.id,
            created_cert.id
        );

        Ok(CertificateRotationResponse {
            success: true,
            message: format!("Certificate '{}' rotated successfully", name),
            rotation_id,
            old_certificate_id: old_cert.id,
            new_certificate_id: created_cert.id,
            requires_restart: matches!(purpose, CertificatePurpose::ServerTls),
        })
    }

    pub async fn rollback_rotation(
        db: &Database,
        request: CertificateRollbackRequest,
    ) -> anyhow::Result<CertificateRollbackResponse> {
        let rotation_collection: mongodb::Collection<CertificateRotationRecord> =
            db.collection("certificate_rotations");

        let rotation = rotation_collection
            .find_one(doc! { "_id": &request.rotation_id })
            .await?
            .ok_or_else(|| anyhow::anyhow!("Rotation record not found"))?;

        if rotation.status == RotationStatus::RolledBack {
            return Err(anyhow::anyhow!("Rotation has already been rolled back"));
        }

        let current_cert_purpose: CertificatePurpose = serde_json::from_str(&format!("\"{}\"", rotation.certificate_purpose))?;

        let current_cert = CertificateService::get_by_name_and_purpose(
            db,
            &rotation.certificate_name,
            current_cert_purpose,
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("Current certificate not found"))?;

        if current_cert.id != rotation.new_certificate_id {
            return Err(anyhow::anyhow!(
                "Certificate has been modified since rotation, cannot rollback safely"
            ));
        }

        CertificateService::delete(db, &current_cert.id).await?;

        let mut updated_rotation = rotation.clone();
        updated_rotation.status = RotationStatus::RolledBack;
        rotation_collection
            .replace_one(doc! { "_id": &request.rotation_id }, &updated_rotation)
            .await?;

        tracing::info!(
            "Rotation {} rolled back for certificate '{}'. Restored certificate ID: {}",
            request.rotation_id,
            rotation.certificate_name,
            rotation.old_certificate_id
        );

        Ok(CertificateRollbackResponse {
            success: true,
            message: format!("Certificate '{}' rolled back successfully", rotation.certificate_name),
            restored_certificate_id: rotation.old_certificate_id,
        })
    }

    pub async fn get_rotation_history(
        db: &Database,
        name: Option<String>,
        purpose: Option<CertificatePurpose>,
    ) -> anyhow::Result<RotationHistoryResponse> {
        let rotation_collection: mongodb::Collection<CertificateRotationRecord> =
            db.collection("certificate_rotations");

        let mut filter = doc! {};
        if let Some(cert_name) = name {
            filter.insert("certificate_name", cert_name);
        }
        if let Some(cert_purpose) = purpose {
            filter.insert("certificate_purpose", format!("{:?}", cert_purpose));
        }

        let mut cursor = rotation_collection
            .find(filter)
            .sort(doc! { "rotated_at": -1 })
            .await?;

        let mut rotations = Vec::new();
        while cursor.advance().await? {
            rotations.push(cursor.deserialize_current()?);
        }

        let total_count = rotations.len();

        Ok(RotationHistoryResponse {
            rotations,
            total_count,
        })
    }

    fn extract_key_info(cert: &X509Certificate) -> anyhow::Result<(crate::types::KeyType, u32)> {
        use crate::types::KeyType;

        let algorithm_oid = &cert.tbs_certificate.subject_public_key_info.algorithm.oid;
        let algorithm_str = algorithm_oid.to_string();

        let key_type = if algorithm_str == "1.2.840.113549.1.1.1" {
            KeyType::Rsa
        } else if algorithm_str.starts_with("1.2.840.10045.2.1") {
            KeyType::Ecdsa
        } else if algorithm_str == "1.3.101.112" {
            KeyType::Ed25519
        } else {
            return Err(anyhow::anyhow!("Unsupported key type: {}", algorithm_str));
        };

        let key_size = match key_type {
            KeyType::Rsa => {
                let spki_bits = cert.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
                (spki_bits.len() * 8) as u32
            }
            KeyType::Ecdsa => 256,
            KeyType::Ed25519 => 256,
        };

        Ok((key_type, key_size))
    }
}
