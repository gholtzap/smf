use crate::types::ocsp::{
    OcspRequest, OcspResponse, OcspResponseStatus, OcspResponseBytes,
    BasicOcspResponse, ResponseData, ResponderId, SingleResponse,
    CertId, CertStatus, Extension, HashAlgorithm,
};
use anyhow::{anyhow, Result};
use chrono::{DateTime, TimeZone, Utc};
use x509_cert::der::{Decode, Encode};

const OCSP_REQUEST_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
const OCSP_BASIC_RESPONSE_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

pub struct OcspCodec;

impl OcspCodec {
    pub fn encode_request(request: &OcspRequest) -> Result<Vec<u8>> {
        let mut der = Vec::new();

        der.push(0x30);
        let mut content = Vec::new();

        let mut tbs_request = Vec::new();
        tbs_request.push(0x30);
        let mut tbs_content = Vec::new();

        tbs_content.push(0x30);
        let mut request_list = Vec::new();

        for cert_id in &request.cert_ids {
            let mut req_item = Vec::new();
            req_item.push(0x30);
            let mut req_content = Vec::new();

            let cert_id_der = Self::encode_cert_id(cert_id)?;
            req_content.extend_from_slice(&cert_id_der);

            req_item.extend_from_slice(&Self::encode_length(req_content.len())?);
            req_item.extend_from_slice(&req_content);

            request_list.extend_from_slice(&req_item);
        }

        tbs_content.extend_from_slice(&Self::encode_length(request_list.len())?);
        tbs_content.extend_from_slice(&request_list);

        if let Some(nonce) = &request.nonce {
            let mut exts = Vec::new();
            exts.push(0xA2);
            let mut exts_content = Vec::new();

            exts_content.push(0x30);
            let mut ext_seq = Vec::new();

            ext_seq.push(0x30);
            let mut ext_content = Vec::new();

            ext_content.push(0x06);
            let nonce_oid = vec![0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x02];
            ext_content.push(nonce_oid.len() as u8);
            ext_content.extend_from_slice(&nonce_oid);

            ext_content.push(0x04);
            let mut octet_string = Vec::new();
            octet_string.push(0x04);
            octet_string.push(nonce.len() as u8);
            octet_string.extend_from_slice(nonce);
            ext_content.push(octet_string.len() as u8);
            ext_content.extend_from_slice(&octet_string);

            ext_seq.extend_from_slice(&Self::encode_length(ext_content.len())?);
            ext_seq.extend_from_slice(&ext_content);

            exts_content.extend_from_slice(&Self::encode_length(ext_seq.len())?);
            exts_content.extend_from_slice(&ext_seq);

            exts.extend_from_slice(&Self::encode_length(exts_content.len())?);
            exts.extend_from_slice(&exts_content);

            tbs_content.extend_from_slice(&exts);
        }

        tbs_request.extend_from_slice(&Self::encode_length(tbs_content.len())?);
        tbs_request.extend_from_slice(&tbs_content);

        content.extend_from_slice(&tbs_request);

        der.extend_from_slice(&Self::encode_length(content.len())?);
        der.extend_from_slice(&content);

        Ok(der)
    }

    fn encode_cert_id(cert_id: &CertId) -> Result<Vec<u8>> {
        let mut der = Vec::new();
        der.push(0x30);
        let mut content = Vec::new();

        content.push(0x30);
        let hash_alg_oid = cert_id.hash_algorithm.oid();
        let mut alg_id = Vec::new();
        alg_id.push(0x06);
        alg_id.push(hash_alg_oid.len() as u8);
        alg_id.extend_from_slice(hash_alg_oid);
        alg_id.push(0x05);
        alg_id.push(0x00);
        content.extend_from_slice(&Self::encode_length(alg_id.len())?);
        content.extend_from_slice(&alg_id);

        content.push(0x04);
        content.push(cert_id.issuer_name_hash.len() as u8);
        content.extend_from_slice(&cert_id.issuer_name_hash);

        content.push(0x04);
        content.push(cert_id.issuer_key_hash.len() as u8);
        content.extend_from_slice(&cert_id.issuer_key_hash);

        content.push(0x02);
        content.extend_from_slice(&Self::encode_length(cert_id.serial_number.len())?);
        content.extend_from_slice(&cert_id.serial_number);

        der.extend_from_slice(&Self::encode_length(content.len())?);
        der.extend_from_slice(&content);

        Ok(der)
    }

    fn encode_length(length: usize) -> Result<Vec<u8>> {
        if length < 128 {
            Ok(vec![length as u8])
        } else if length <= 255 {
            Ok(vec![0x81, length as u8])
        } else if length <= 65535 {
            Ok(vec![0x82, (length >> 8) as u8, (length & 0xFF) as u8])
        } else {
            Err(anyhow!("Length too large: {}", length))
        }
    }

    pub fn decode_response(der: &[u8]) -> Result<OcspResponse> {
        let mut reader = DerReader::new(der);

        let response_status = reader.read_enum()? as u8;
        let response_status = OcspResponseStatus::from_u8(response_status)
            .ok_or_else(|| anyhow!("Invalid response status: {}", response_status))?;

        let response_bytes = if reader.has_more() {
            reader.expect_tag(0xA0)?;
            let _ = reader.read_length()?;
            Some(Self::decode_response_bytes(&mut reader)?)
        } else {
            None
        };

        Ok(OcspResponse {
            response_status,
            response_bytes,
        })
    }

    fn decode_response_bytes(reader: &mut DerReader) -> Result<OcspResponseBytes> {
        reader.expect_tag(0x30)?;
        let _ = reader.read_length()?;

        reader.expect_tag(0x06)?;
        let oid_len = reader.read_length()?;
        let oid = reader.read_bytes(oid_len)?;

        if oid != OCSP_BASIC_RESPONSE_OID {
            return Err(anyhow!("Unsupported response type OID"));
        }

        reader.expect_tag(0x04)?;
        let response_len = reader.read_length()?;
        let response = reader.read_bytes(response_len)?;

        Ok(OcspResponseBytes {
            response_type: "id-pkix-ocsp-basic".to_string(),
            response,
        })
    }

    pub fn decode_basic_response(der: &[u8]) -> Result<BasicOcspResponse> {
        let mut reader = DerReader::new(der);

        reader.expect_tag(0x30)?;
        let _ = reader.read_length()?;

        let tbs_response_data = Self::decode_response_data(&mut reader)?;

        reader.expect_tag(0x30)?;
        let alg_len = reader.read_length()?;
        let alg_bytes = reader.read_bytes(alg_len)?;
        let signature_algorithm = Self::parse_algorithm_identifier(&alg_bytes)?;

        reader.expect_tag(0x03)?;
        let sig_len = reader.read_length()?;
        let _unused_bits = reader.read_byte()?;
        let signature = reader.read_bytes(sig_len - 1)?;

        let certs = if reader.has_more() && reader.peek_tag() == Some(0xA0) {
            reader.expect_tag(0xA0)?;
            let _ = reader.read_length()?;
            Some(Self::decode_certificates(&mut reader)?)
        } else {
            None
        };

        Ok(BasicOcspResponse {
            tbs_response_data,
            signature_algorithm,
            signature,
            certs,
        })
    }

    fn decode_response_data(reader: &mut DerReader) -> Result<ResponseData> {
        reader.expect_tag(0x30)?;
        let _ = reader.read_length()?;

        let version = if reader.peek_tag() == Some(0xA0) {
            reader.expect_tag(0xA0)?;
            let _ = reader.read_length()?;
            reader.read_integer()? as u8
        } else {
            0
        };

        let responder_id = Self::decode_responder_id(reader)?;

        reader.expect_tag(0x18)?;
        let time_len = reader.read_length()?;
        let time_bytes = reader.read_bytes(time_len)?;
        let produced_at = Self::parse_generalized_time(&time_bytes)?;

        reader.expect_tag(0x30)?;
        let responses_len = reader.read_length()?;
        let responses_bytes = reader.read_bytes(responses_len)?;
        let mut responses_reader = DerReader::new(&responses_bytes);
        let mut responses = Vec::new();

        while responses_reader.has_more() {
            responses.push(Self::decode_single_response(&mut responses_reader)?);
        }

        let response_extensions = if reader.has_more() && reader.peek_tag() == Some(0xA1) {
            reader.expect_tag(0xA1)?;
            let _ = reader.read_length()?;
            Some(Self::decode_extensions(reader)?)
        } else {
            None
        };

        Ok(ResponseData {
            version,
            responder_id,
            produced_at,
            responses,
            response_extensions,
        })
    }

    fn decode_responder_id(reader: &mut DerReader) -> Result<ResponderId> {
        let tag = reader.read_byte()?;
        match tag {
            0xA1 => {
                let len = reader.read_length()?;
                let name_bytes = reader.read_bytes(len)?;
                Ok(ResponderId::ByName {
                    name: format!("{:?}", name_bytes),
                })
            }
            0xA2 => {
                let _ = reader.read_length()?;
                reader.expect_tag(0x04)?;
                let hash_len = reader.read_length()?;
                let key_hash = reader.read_bytes(hash_len)?;
                Ok(ResponderId::ByKey { key_hash })
            }
            _ => Err(anyhow!("Invalid responder ID tag: {}", tag)),
        }
    }

    fn decode_single_response(reader: &mut DerReader) -> Result<SingleResponse> {
        reader.expect_tag(0x30)?;
        let _ = reader.read_length()?;

        let cert_id = Self::decode_cert_id(reader)?;

        let cert_status = Self::decode_cert_status(reader)?;

        reader.expect_tag(0x18)?;
        let time_len = reader.read_length()?;
        let time_bytes = reader.read_bytes(time_len)?;
        let this_update = Self::parse_generalized_time(&time_bytes)?;

        let next_update = if reader.peek_tag() == Some(0xA0) {
            reader.expect_tag(0xA0)?;
            let _ = reader.read_length()?;
            reader.expect_tag(0x18)?;
            let time_len = reader.read_length()?;
            let time_bytes = reader.read_bytes(time_len)?;
            Some(Self::parse_generalized_time(&time_bytes)?)
        } else {
            None
        };

        let single_extensions = if reader.peek_tag() == Some(0xA1) {
            reader.expect_tag(0xA1)?;
            let _ = reader.read_length()?;
            Some(Self::decode_extensions(reader)?)
        } else {
            None
        };

        Ok(SingleResponse {
            cert_id,
            cert_status,
            this_update,
            next_update,
            single_extensions,
        })
    }

    fn decode_cert_id(reader: &mut DerReader) -> Result<CertId> {
        reader.expect_tag(0x30)?;
        let _ = reader.read_length()?;

        reader.expect_tag(0x30)?;
        let alg_len = reader.read_length()?;
        let alg_bytes = reader.read_bytes(alg_len)?;
        let hash_algorithm = Self::parse_hash_algorithm(&alg_bytes)?;

        reader.expect_tag(0x04)?;
        let issuer_name_hash_len = reader.read_length()?;
        let issuer_name_hash = reader.read_bytes(issuer_name_hash_len)?;

        reader.expect_tag(0x04)?;
        let issuer_key_hash_len = reader.read_length()?;
        let issuer_key_hash = reader.read_bytes(issuer_key_hash_len)?;

        reader.expect_tag(0x02)?;
        let serial_len = reader.read_length()?;
        let serial_number = reader.read_bytes(serial_len)?;

        Ok(CertId {
            hash_algorithm,
            issuer_name_hash,
            issuer_key_hash,
            serial_number,
        })
    }

    fn decode_cert_status(reader: &mut DerReader) -> Result<CertStatus> {
        let tag = reader.read_byte()?;
        match tag {
            0x80 => {
                let len = reader.read_length()?;
                if len > 0 {
                    let _ = reader.read_bytes(len)?;
                }
                Ok(CertStatus::Good)
            }
            0xA1 => {
                let _ = reader.read_length()?;

                reader.expect_tag(0x18)?;
                let time_len = reader.read_length()?;
                let time_bytes = reader.read_bytes(time_len)?;
                let revocation_time = Self::parse_generalized_time(&time_bytes)?;

                let revocation_reason = if reader.peek_tag() == Some(0xA0) {
                    reader.expect_tag(0xA0)?;
                    let _ = reader.read_length()?;
                    Some(reader.read_enum()? as u8)
                } else {
                    None
                };

                Ok(CertStatus::Revoked {
                    revocation_time: revocation_time.timestamp(),
                    revocation_reason,
                })
            }
            0x82 => {
                let len = reader.read_length()?;
                if len > 0 {
                    let _ = reader.read_bytes(len)?;
                }
                Ok(CertStatus::Unknown)
            }
            _ => Err(anyhow!("Invalid cert status tag: {}", tag)),
        }
    }

    fn decode_extensions(reader: &mut DerReader) -> Result<Vec<Extension>> {
        reader.expect_tag(0x30)?;
        let exts_len = reader.read_length()?;
        let exts_bytes = reader.read_bytes(exts_len)?;
        let mut ext_reader = DerReader::new(&exts_bytes);
        let mut extensions = Vec::new();

        while ext_reader.has_more() {
            ext_reader.expect_tag(0x30)?;
            let _ = ext_reader.read_length()?;

            ext_reader.expect_tag(0x06)?;
            let oid_len = ext_reader.read_length()?;
            let extn_id = ext_reader.read_bytes(oid_len)?;

            let critical = if ext_reader.peek_tag() == Some(0x01) {
                ext_reader.expect_tag(0x01)?;
                let _ = ext_reader.read_length()?;
                ext_reader.read_byte()? != 0
            } else {
                false
            };

            ext_reader.expect_tag(0x04)?;
            let value_len = ext_reader.read_length()?;
            let extn_value = ext_reader.read_bytes(value_len)?;

            extensions.push(Extension {
                extn_id,
                critical,
                extn_value,
            });
        }

        Ok(extensions)
    }

    fn decode_certificates(reader: &mut DerReader) -> Result<Vec<Vec<u8>>> {
        reader.expect_tag(0x30)?;
        let certs_len = reader.read_length()?;
        let certs_bytes = reader.read_bytes(certs_len)?;
        let mut cert_reader = DerReader::new(&certs_bytes);
        let mut certificates = Vec::new();

        while cert_reader.has_more() {
            cert_reader.expect_tag(0x30)?;
            let cert_len = cert_reader.read_length()?;
            let cert_der = cert_reader.read_bytes(cert_len)?;
            certificates.push(cert_der);
        }

        Ok(certificates)
    }

    fn parse_hash_algorithm(der: &[u8]) -> Result<HashAlgorithm> {
        let mut reader = DerReader::new(der);
        reader.expect_tag(0x06)?;
        let oid_len = reader.read_length()?;
        let oid = reader.read_bytes(oid_len)?;

        match oid.as_slice() {
            &[0x2B, 0x0E, 0x03, 0x02, 0x1A] => Ok(HashAlgorithm::Sha1),
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] => Ok(HashAlgorithm::Sha256),
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02] => Ok(HashAlgorithm::Sha384),
            &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03] => Ok(HashAlgorithm::Sha512),
            _ => Err(anyhow!("Unsupported hash algorithm OID")),
        }
    }

    fn parse_algorithm_identifier(der: &[u8]) -> Result<String> {
        let mut reader = DerReader::new(der);
        reader.expect_tag(0x06)?;
        let oid_len = reader.read_length()?;
        let oid = reader.read_bytes(oid_len)?;
        Ok(format!("{:?}", oid))
    }

    fn parse_generalized_time(bytes: &[u8]) -> Result<DateTime<Utc>> {
        let time_str = std::str::from_utf8(bytes)?;

        if time_str.len() < 14 {
            return Err(anyhow!("Invalid generalized time format"));
        }

        let year: i32 = time_str[0..4].parse()?;
        let month: u32 = time_str[4..6].parse()?;
        let day: u32 = time_str[6..8].parse()?;
        let hour: u32 = time_str[8..10].parse()?;
        let minute: u32 = time_str[10..12].parse()?;
        let second: u32 = time_str[12..14].parse()?;

        Utc.with_ymd_and_hms(year, month, day, hour, minute, second)
            .single()
            .ok_or_else(|| anyhow!("Invalid datetime"))
    }
}

struct DerReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.position >= self.data.len() {
            return Err(anyhow!("Unexpected end of data"));
        }
        let byte = self.data[self.position];
        self.position += 1;
        Ok(byte)
    }

    fn read_bytes(&mut self, count: usize) -> Result<Vec<u8>> {
        if self.position + count > self.data.len() {
            return Err(anyhow!("Unexpected end of data"));
        }
        let bytes = self.data[self.position..self.position + count].to_vec();
        self.position += count;
        Ok(bytes)
    }

    fn read_length(&mut self) -> Result<usize> {
        let first = self.read_byte()?;
        if first < 0x80 {
            Ok(first as usize)
        } else if first == 0x81 {
            Ok(self.read_byte()? as usize)
        } else if first == 0x82 {
            let b1 = self.read_byte()? as usize;
            let b2 = self.read_byte()? as usize;
            Ok((b1 << 8) | b2)
        } else {
            Err(anyhow!("Unsupported length encoding"))
        }
    }

    fn expect_tag(&mut self, expected: u8) -> Result<()> {
        let tag = self.read_byte()?;
        if tag != expected {
            return Err(anyhow!("Expected tag 0x{:02X}, got 0x{:02X}", expected, tag));
        }
        Ok(())
    }

    fn peek_tag(&self) -> Option<u8> {
        if self.position < self.data.len() {
            Some(self.data[self.position])
        } else {
            None
        }
    }

    fn has_more(&self) -> bool {
        self.position < self.data.len()
    }

    fn read_integer(&mut self) -> Result<i64> {
        self.expect_tag(0x02)?;
        let len = self.read_length()?;
        let bytes = self.read_bytes(len)?;

        let mut value: i64 = 0;
        for byte in bytes {
            value = (value << 8) | (byte as i64);
        }
        Ok(value)
    }

    fn read_enum(&mut self) -> Result<i64> {
        self.expect_tag(0x0A)?;
        let len = self.read_length()?;
        let bytes = self.read_bytes(len)?;

        let mut value: i64 = 0;
        for byte in bytes {
            value = (value << 8) | (byte as i64);
        }
        Ok(value)
    }
}
