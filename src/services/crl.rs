use mongodb::{bson::doc, Database};
use crate::types::{Crl, CrlStatus, RevokedCertificate, RevocationReason, CrlFetchAttempt};
use chrono::{Utc, Duration};
use x509_cert::crl::CertificateList;
use x509_cert::der::Decode;
use reqwest::Client;
use std::time::Instant;

pub struct CrlService;

impl CrlService {
    pub async fn fetch_and_store(
        db: &Database,
        distribution_point_url: String,
    ) -> anyhow::Result<Crl> {
        let start = Instant::now();
        let mut fetch_attempt = CrlFetchAttempt::new(distribution_point_url.clone());

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()?;

        let response = match client.get(&distribution_point_url).send().await {
            Ok(resp) => resp,
            Err(e) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                fetch_attempt = fetch_attempt.mark_failure(e.to_string(), duration_ms);
                let _ = Self::record_fetch_attempt(db, fetch_attempt).await;

                if let Some(existing) = Self::get_by_url(db, &distribution_point_url).await? {
                    let _ = Self::increment_failure_count(db, &existing.id).await;
                }

                return Err(anyhow::anyhow!("Failed to fetch CRL: {}", e));
            }
        };

        let status_code = response.status().as_u16();
        if !response.status().is_success() {
            let duration_ms = start.elapsed().as_millis() as u64;
            let error_msg = format!("HTTP error: {}", status_code);
            fetch_attempt = fetch_attempt.mark_failure(error_msg.clone(), duration_ms);
            let _ = Self::record_fetch_attempt(db, fetch_attempt).await;

            if let Some(existing) = Self::get_by_url(db, &distribution_point_url).await? {
                let _ = Self::increment_failure_count(db, &existing.id).await;
            }

            return Err(anyhow::anyhow!("HTTP error {}", status_code));
        }

        let crl_der = match response.bytes().await {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                fetch_attempt = fetch_attempt.mark_failure(e.to_string(), duration_ms);
                let _ = Self::record_fetch_attempt(db, fetch_attempt).await;
                return Err(anyhow::anyhow!("Failed to read response body: {}", e));
            }
        };

        let crl = match CertificateList::from_der(&crl_der) {
            Ok(crl) => crl,
            Err(e) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let error_msg = format!("Failed to parse CRL: {}", e);
                fetch_attempt = fetch_attempt.mark_failure(error_msg.clone(), duration_ms);
                let _ = Self::record_fetch_attempt(db, fetch_attempt).await;
                return Err(anyhow::anyhow!("Failed to parse CRL: {}", e));
            }
        };

        let issuer = format!("{:?}", crl.tbs_cert_list.issuer);
        let this_update = Self::parse_time(&crl.tbs_cert_list.this_update)?;
        let next_update = crl.tbs_cert_list.next_update
            .as_ref()
            .and_then(|t| Self::parse_time(t).ok());

        let revoked_count = crl.tbs_cert_list.revoked_certificates
            .as_ref()
            .map(|certs| certs.len())
            .unwrap_or(0);

        let duration_ms = start.elapsed().as_millis() as u64;
        fetch_attempt = fetch_attempt.mark_success(status_code, crl_der.len(), duration_ms);
        let _ = Self::record_fetch_attempt(db, fetch_attempt).await;

        let existing = Self::get_by_url(db, &distribution_point_url).await?;

        let crl_record = if let Some(mut existing_crl) = existing {
            existing_crl.crl_der = crl_der.clone();
            existing_crl.this_update = this_update;
            existing_crl.next_update = next_update;
            existing_crl.revoked_certificate_count = revoked_count;
            existing_crl.status = CrlStatus::Valid;
            existing_crl.last_fetch_attempt = Utc::now();
            existing_crl.last_successful_fetch = Utc::now();
            existing_crl.fetch_failure_count = 0;
            existing_crl.updated_at = Utc::now();

            Self::update(db, &existing_crl).await?;
            existing_crl
        } else {
            let new_crl = Crl::new(
                issuer,
                distribution_point_url.clone(),
                crl_der.clone(),
                this_update,
                next_update,
                revoked_count,
            );

            Self::create(db, new_crl).await?
        };

        if let Some(revoked_certs) = crl.tbs_cert_list.revoked_certificates {
            let _ = Self::delete_revoked_certs_for_crl(db, &crl_record.id).await;

            for revoked in revoked_certs {
                use x509_cert::der::Encode;
                let serial_der = revoked.serial_number.to_der()?;
                let serial_number = hex::encode(&serial_der);
                let revocation_date = Self::parse_time(&revoked.revocation_date)?;

                let revocation_reason = revoked.crl_entry_extensions
                    .as_ref()
                    .and_then(|exts| {
                        exts.iter().find(|ext| {
                            ext.extn_id.to_string() == "2.5.29.21"
                        })
                    })
                    .and_then(|_| Some(RevocationReason::Unspecified));

                let revoked_cert = RevokedCertificate::new(
                    crl_record.id.clone(),
                    serial_number,
                    revocation_date,
                    revocation_reason,
                );

                let _ = Self::store_revoked_cert(db, revoked_cert).await;
            }
        }

        tracing::info!(
            "Fetched and stored CRL from {} with {} revoked certificates",
            distribution_point_url,
            revoked_count
        );

        Ok(crl_record)
    }

    pub async fn create(db: &Database, crl: Crl) -> anyhow::Result<Crl> {
        let collection: mongodb::Collection<Crl> = db.collection("crls");
        collection.insert_one(&crl).await?;
        tracing::info!("Created CRL for issuer '{}' from URL: {}", crl.issuer, crl.distribution_point_url);
        Ok(crl)
    }

    pub async fn update(db: &Database, crl: &Crl) -> anyhow::Result<()> {
        let collection: mongodb::Collection<Crl> = db.collection("crls");
        collection
            .replace_one(doc! { "_id": &crl.id }, crl)
            .await?;
        tracing::info!("Updated CRL {}", crl.id);
        Ok(())
    }

    pub async fn get_by_id(db: &Database, id: &str) -> anyhow::Result<Option<Crl>> {
        let collection: mongodb::Collection<Crl> = db.collection("crls");
        Ok(collection.find_one(doc! { "_id": id }).await?)
    }

    pub async fn get_by_url(db: &Database, url: &str) -> anyhow::Result<Option<Crl>> {
        let collection: mongodb::Collection<Crl> = db.collection("crls");
        Ok(collection.find_one(doc! { "distribution_point_url": url }).await?)
    }

    pub async fn list_all(db: &Database) -> anyhow::Result<Vec<Crl>> {
        let collection: mongodb::Collection<Crl> = db.collection("crls");
        let mut cursor = collection.find(doc! {}).await?;

        let mut crls = Vec::new();
        while let Ok(true) = cursor.advance().await {
            if let Ok(crl) = cursor.deserialize_current() {
                crls.push(crl);
            }
        }

        Ok(crls)
    }

    pub async fn list_expired(db: &Database) -> anyhow::Result<Vec<Crl>> {
        let collection: mongodb::Collection<Crl> = db.collection("crls");
        let now_millis = Utc::now().timestamp_millis();
        let now = mongodb::bson::DateTime::from_millis(now_millis);

        let mut cursor = collection
            .find(doc! { "next_update": { "$lt": now } })
            .await?;

        let mut crls = Vec::new();
        while let Ok(true) = cursor.advance().await {
            if let Ok(crl) = cursor.deserialize_current() {
                crls.push(crl);
            }
        }

        Ok(crls)
    }

    pub async fn list_needs_refresh(db: &Database, hours_threshold: i64) -> anyhow::Result<Vec<Crl>> {
        let threshold_time = Utc::now() + Duration::hours(hours_threshold);
        let threshold_millis = threshold_time.timestamp_millis();
        let threshold_bson = mongodb::bson::DateTime::from_millis(threshold_millis);

        let collection: mongodb::Collection<Crl> = db.collection("crls");
        let mut cursor = collection
            .find(doc! {
                "$or": [
                    { "next_update": { "$lt": threshold_bson } },
                    { "status": { "$ne": mongodb::bson::to_bson(&CrlStatus::Valid)? } }
                ]
            })
            .await?;

        let mut crls = Vec::new();
        while let Ok(true) = cursor.advance().await {
            if let Ok(crl) = cursor.deserialize_current() {
                crls.push(crl);
            }
        }

        Ok(crls)
    }

    pub async fn delete(db: &Database, id: &str) -> anyhow::Result<()> {
        let collection: mongodb::Collection<Crl> = db.collection("crls");
        let _ = Self::delete_revoked_certs_for_crl(db, id).await;
        collection.delete_one(doc! { "_id": id }).await?;
        tracing::info!("Deleted CRL {}", id);
        Ok(())
    }

    pub async fn is_certificate_revoked(
        db: &Database,
        serial_number: &str,
        issuer: &str,
    ) -> anyhow::Result<bool> {
        let crl = match Self::get_by_issuer(db, issuer).await? {
            Some(crl) => crl,
            None => return Ok(false),
        };

        if !crl.is_valid() {
            tracing::warn!("CRL for issuer {} is not valid, cannot check revocation status", issuer);
            return Ok(false);
        }

        let collection: mongodb::Collection<RevokedCertificate> = db.collection("revoked_certificates");
        let result = collection
            .find_one(doc! {
                "crl_id": &crl.id,
                "serial_number": serial_number
            })
            .await?;

        Ok(result.is_some())
    }

    async fn get_by_issuer(db: &Database, issuer: &str) -> anyhow::Result<Option<Crl>> {
        let collection: mongodb::Collection<Crl> = db.collection("crls");
        Ok(collection.find_one(doc! { "issuer": issuer }).await?)
    }

    async fn store_revoked_cert(db: &Database, cert: RevokedCertificate) -> anyhow::Result<()> {
        let collection: mongodb::Collection<RevokedCertificate> = db.collection("revoked_certificates");
        collection.insert_one(&cert).await?;
        Ok(())
    }

    async fn delete_revoked_certs_for_crl(db: &Database, crl_id: &str) -> anyhow::Result<()> {
        let collection: mongodb::Collection<RevokedCertificate> = db.collection("revoked_certificates");
        collection.delete_many(doc! { "crl_id": crl_id }).await?;
        Ok(())
    }

    async fn increment_failure_count(db: &Database, crl_id: &str) -> anyhow::Result<()> {
        let collection: mongodb::Collection<Crl> = db.collection("crls");
        collection
            .update_one(
                doc! { "_id": crl_id },
                doc! {
                    "$inc": { "fetch_failure_count": 1 },
                    "$set": {
                        "last_fetch_attempt": mongodb::bson::DateTime::from_millis(Utc::now().timestamp_millis()),
                        "status": mongodb::bson::to_bson(&CrlStatus::FailedToFetch)?
                    }
                }
            )
            .await?;
        Ok(())
    }

    async fn record_fetch_attempt(db: &Database, attempt: CrlFetchAttempt) -> anyhow::Result<()> {
        let collection: mongodb::Collection<CrlFetchAttempt> = db.collection("crl_fetch_attempts");
        collection.insert_one(&attempt).await?;
        Ok(())
    }

    pub async fn get_fetch_attempts(
        db: &Database,
        url: &str,
        limit: i64,
    ) -> anyhow::Result<Vec<CrlFetchAttempt>> {
        use mongodb::options::FindOptions;

        let collection: mongodb::Collection<CrlFetchAttempt> = db.collection("crl_fetch_attempts");
        let options = FindOptions::builder()
            .sort(doc! { "attempt_time": -1 })
            .limit(limit)
            .build();

        let mut cursor = collection
            .find(doc! { "distribution_point_url": url })
            .with_options(options)
            .await?;

        let mut attempts = Vec::new();
        while let Ok(true) = cursor.advance().await {
            if let Ok(attempt) = cursor.deserialize_current() {
                attempts.push(attempt);
            }
        }

        Ok(attempts)
    }

    fn parse_time(time: &x509_cert::time::Time) -> anyhow::Result<chrono::DateTime<Utc>> {
        match time {
            x509_cert::time::Time::UtcTime(utc) => {
                let datetime = utc.to_date_time();
                let year = datetime.year() as i32;
                let month = datetime.month();
                let day = datetime.day();
                let hour = datetime.hour();
                let minute = datetime.minutes();
                let second = datetime.seconds();

                chrono::NaiveDate::from_ymd_opt(year, month.into(), day.into())
                    .and_then(|date| date.and_hms_opt(hour.into(), minute.into(), second.into()))
                    .map(|naive| chrono::DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
                    .ok_or_else(|| anyhow::anyhow!("Invalid datetime"))
            }
            x509_cert::time::Time::GeneralTime(gen) => {
                let datetime = gen.to_date_time();
                let year = datetime.year() as i32;
                let month = datetime.month();
                let day = datetime.day();
                let hour = datetime.hour();
                let minute = datetime.minutes();
                let second = datetime.seconds();

                chrono::NaiveDate::from_ymd_opt(year, month.into(), day.into())
                    .and_then(|date| date.and_hms_opt(hour.into(), minute.into(), second.into()))
                    .map(|naive| chrono::DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc))
                    .ok_or_else(|| anyhow::anyhow!("Invalid datetime"))
            }
        }
    }
}
