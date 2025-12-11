use crate::services::ocsp_codec::OcspCodec;
use crate::types::ocsp::{
    OcspRequest, OcspResponse, OcspResponseStatus,
    BasicOcspResponse, CertId, CertStatus, OcspCacheEntry,
};
use crate::types::Certificate;
use anyhow::{anyhow, Result};
use mongodb::{bson::{self, doc}, Database};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::time::Instant;
use chrono::Utc;
use x509_cert::{
    der::Decode,
    Certificate as X509Certificate,
};

pub struct OcspClient {
    http_client: Client,
    db: Database,
}

impl OcspClient {
    pub fn new(db: Database) -> Self {
        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self { http_client, db }
    }

    pub async fn check_certificate(
        &self,
        cert: &Certificate,
        issuer: &Certificate,
        responder_url: &str,
    ) -> Result<CertStatus> {
        let cert_id = self.build_cert_id(cert, issuer)?;

        if let Some(cached) = self.get_cached_response(&cert_id).await? {
            if cached.is_valid() {
                return Ok(cached.cert_status);
            }
        }

        let request = OcspRequest {
            cert_ids: vec![cert_id.clone()],
            nonce: Some(self.generate_nonce()),
            requestor_name: Some("SMF".to_string()),
        };

        let response = self.send_request(&request, responder_url).await?;

        if response.response_status != OcspResponseStatus::Successful {
            return Err(anyhow!("OCSP request failed: {:?}", response.response_status));
        }

        let response_bytes = response.response_bytes
            .ok_or_else(|| anyhow!("No response bytes in OCSP response"))?;

        let basic_response = OcspCodec::decode_basic_response(&response_bytes.response)?;

        let single_response = basic_response.tbs_response_data.responses
            .iter()
            .find(|r| r.cert_id == cert_id)
            .ok_or_else(|| anyhow!("Certificate not found in OCSP response"))?;

        let cache_entry = OcspCacheEntry::new(
            cert_id,
            single_response.cert_status.clone(),
            single_response.this_update,
            single_response.next_update,
            basic_response.tbs_response_data.produced_at,
            responder_url.to_string(),
        );

        self.cache_response(&cache_entry).await?;

        Ok(single_response.cert_status.clone())
    }

    pub async fn check_certificate_batch(
        &self,
        certs_with_issuers: &[(Certificate, Certificate)],
        responder_url: &str,
    ) -> Result<Vec<(String, CertStatus)>> {
        let mut cert_ids = Vec::new();
        let mut cert_names = Vec::new();

        for (cert, issuer) in certs_with_issuers {
            let cert_id = self.build_cert_id(cert, issuer)?;
            cert_ids.push(cert_id);
            cert_names.push(cert.name.clone());
        }

        let request = OcspRequest {
            cert_ids: cert_ids.clone(),
            nonce: Some(self.generate_nonce()),
            requestor_name: Some("SMF".to_string()),
        };

        let response = self.send_request(&request, responder_url).await?;

        if response.response_status != OcspResponseStatus::Successful {
            return Err(anyhow!("OCSP request failed: {:?}", response.response_status));
        }

        let response_bytes = response.response_bytes
            .ok_or_else(|| anyhow!("No response bytes in OCSP response"))?;

        let basic_response = OcspCodec::decode_basic_response(&response_bytes.response)?;

        let mut results = Vec::new();

        for (i, cert_id) in cert_ids.iter().enumerate() {
            if let Some(single_response) = basic_response.tbs_response_data.responses
                .iter()
                .find(|r| &r.cert_id == cert_id)
            {
                let cache_entry = OcspCacheEntry::new(
                    cert_id.clone(),
                    single_response.cert_status.clone(),
                    single_response.this_update,
                    single_response.next_update,
                    basic_response.tbs_response_data.produced_at,
                    responder_url.to_string(),
                );

                let _ = self.cache_response(&cache_entry).await;

                results.push((cert_names[i].clone(), single_response.cert_status.clone()));
            } else {
                results.push((cert_names[i].clone(), CertStatus::Unknown));
            }
        }

        Ok(results)
    }

    async fn send_request(&self, request: &OcspRequest, responder_url: &str) -> Result<OcspResponse> {
        let request_der = OcspCodec::encode_request(request)?;

        let response = self.http_client
            .post(responder_url)
            .header("Content-Type", "application/ocsp-request")
            .body(request_der)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(anyhow!("OCSP responder returned HTTP {}", response.status()));
        }

        let response_der = response.bytes().await?.to_vec();

        OcspCodec::decode_response(&response_der)
    }

    fn build_cert_id(&self, cert: &Certificate, issuer: &Certificate) -> Result<CertId> {
        let cert_pem = cert.certificate_pem.as_bytes();
        let issuer_pem = issuer.certificate_pem.as_bytes();

        let parsed_cert = Self::parse_pem_certificate(cert_pem)?;
        let parsed_issuer = Self::parse_pem_certificate(issuer_pem)?;

        use x509_cert::der::Encode;
        let issuer_name_der = parsed_issuer.tbs_certificate.subject.to_der()?;
        let issuer_key_der = parsed_issuer.tbs_certificate.subject_public_key_info
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| anyhow!("Invalid issuer public key"))?;

        let mut hasher = Sha256::new();
        hasher.update(&issuer_name_der);
        let issuer_name_hash = hasher.finalize().to_vec();

        let mut hasher = Sha256::new();
        hasher.update(issuer_key_der);
        let issuer_key_hash = hasher.finalize().to_vec();

        let serial_number = parsed_cert.tbs_certificate.serial_number.as_bytes().to_vec();

        Ok(CertId {
            hash_algorithm: crate::types::ocsp::HashAlgorithm::Sha256,
            issuer_name_hash,
            issuer_key_hash,
            serial_number,
        })
    }

    fn parse_pem_certificate(pem_data: &[u8]) -> Result<X509Certificate> {
        let pem_str = std::str::from_utf8(pem_data)?;
        let pem_lines: Vec<&str> = pem_str.lines().collect();

        let mut cert_lines = Vec::new();
        let mut in_cert = false;

        for line in pem_lines {
            if line.contains("BEGIN CERTIFICATE") {
                in_cert = true;
                continue;
            }
            if line.contains("END CERTIFICATE") {
                break;
            }
            if in_cert {
                cert_lines.push(line);
            }
        }

        let cert_base64 = cert_lines.join("");
        let cert_der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &cert_base64)?;

        X509Certificate::from_der(&cert_der).map_err(|e| anyhow!("Failed to parse certificate: {}", e))
    }

    fn generate_nonce(&self) -> Vec<u8> {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
        hasher.update(uuid::Uuid::new_v4().as_bytes());
        hasher.finalize()[0..16].to_vec()
    }

    async fn get_cached_response(&self, cert_id: &CertId) -> Result<Option<OcspCacheEntry>> {
        let collection = self.db.collection::<OcspCacheEntry>("ocsp_cache");

        let filter = doc! {
            "cert_id.hash_algorithm": bson::to_bson(&cert_id.hash_algorithm)?,
            "cert_id.issuer_name_hash": bson::Binary {
                subtype: bson::spec::BinarySubtype::Generic,
                bytes: cert_id.issuer_name_hash.clone(),
            },
            "cert_id.issuer_key_hash": bson::Binary {
                subtype: bson::spec::BinarySubtype::Generic,
                bytes: cert_id.issuer_key_hash.clone(),
            },
            "cert_id.serial_number": bson::Binary {
                subtype: bson::spec::BinarySubtype::Generic,
                bytes: cert_id.serial_number.clone(),
            },
        };

        let result = collection.find_one(filter).await?;

        Ok(result)
    }

    async fn cache_response(&self, entry: &OcspCacheEntry) -> Result<()> {
        let collection = self.db.collection::<OcspCacheEntry>("ocsp_cache");

        let filter = doc! {
            "cert_id.hash_algorithm": bson::to_bson(&entry.cert_id.hash_algorithm)?,
            "cert_id.issuer_name_hash": bson::Binary {
                subtype: bson::spec::BinarySubtype::Generic,
                bytes: entry.cert_id.issuer_name_hash.clone(),
            },
            "cert_id.issuer_key_hash": bson::Binary {
                subtype: bson::spec::BinarySubtype::Generic,
                bytes: entry.cert_id.issuer_key_hash.clone(),
            },
            "cert_id.serial_number": bson::Binary {
                subtype: bson::spec::BinarySubtype::Generic,
                bytes: entry.cert_id.serial_number.clone(),
            },
        };

        if let Some(existing) = collection.find_one(filter.clone()).await? {
            collection.replace_one(doc! { "_id": existing.id }, entry).await?;
        } else {
            collection.insert_one(entry).await?;
        }

        Ok(())
    }

    pub async fn get_cached_status(&self, cert_id: &CertId) -> Result<Option<CertStatus>> {
        let cached = self.get_cached_response(cert_id).await?;

        Ok(cached.and_then(|entry| {
            if entry.is_valid() {
                Some(entry.cert_status)
            } else {
                None
            }
        }))
    }

    pub async fn list_cached_responses(&self) -> Result<Vec<OcspCacheEntry>> {
        let collection = self.db.collection::<OcspCacheEntry>("ocsp_cache");

        let cursor = collection.find(doc! {}).await?;
        use futures::TryStreamExt;
        let results = cursor.try_collect().await?;

        Ok(results)
    }

    pub async fn list_expired_cache_entries(&self) -> Result<Vec<OcspCacheEntry>> {
        let collection = self.db.collection::<OcspCacheEntry>("ocsp_cache");

        let now = Utc::now();
        let filter = doc! {
            "next_update": { "$lt": bson::DateTime::from_millis(now.timestamp_millis()) }
        };

        let cursor = collection.find(filter).await?;
        use futures::TryStreamExt;
        let results = cursor.try_collect().await?;

        Ok(results)
    }

    pub async fn delete_expired_cache_entries(&self) -> Result<u64> {
        let collection = self.db.collection::<OcspCacheEntry>("ocsp_cache");

        let now = Utc::now();
        let filter = doc! {
            "next_update": { "$lt": bson::DateTime::from_millis(now.timestamp_millis()) }
        };

        let result = collection.delete_many(filter).await?;

        Ok(result.deleted_count)
    }

    pub async fn delete_cache_entry(&self, id: &str) -> Result<bool> {
        let collection = self.db.collection::<OcspCacheEntry>("ocsp_cache");

        let filter = doc! { "_id": id };

        let result = collection.delete_one(filter).await?;

        Ok(result.deleted_count > 0)
    }

    pub async fn clear_cache(&self) -> Result<u64> {
        let collection = self.db.collection::<OcspCacheEntry>("ocsp_cache");

        let result = collection.delete_many(doc! {}).await?;

        Ok(result.deleted_count)
    }
}
