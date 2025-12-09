use serde::{Deserialize, Serialize};
use crate::types::up_security::{CipheringAlgorithm, IntegrityAlgorithm, UeSecurityCapabilities};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NasMessageType {
    PduSessionEstablishmentRequest = 0xC1,
    PduSessionEstablishmentAccept = 0xC2,
    PduSessionEstablishmentReject = 0xC3,
    PduSessionModificationRequest = 0xC9,
    PduSessionModificationReject = 0xCA,
    PduSessionModificationCommand = 0xCB,
    PduSessionModificationComplete = 0xCC,
    PduSessionModificationCommandReject = 0xCD,
    PduSessionReleaseRequest = 0xD1,
    PduSessionReleaseReject = 0xD2,
    PduSessionReleaseCommand = 0xD3,
    Unknown = 0xFF,
}

impl From<u8> for NasMessageType {
    fn from(value: u8) -> Self {
        match value {
            0xC1 => NasMessageType::PduSessionEstablishmentRequest,
            0xC2 => NasMessageType::PduSessionEstablishmentAccept,
            0xC3 => NasMessageType::PduSessionEstablishmentReject,
            0xC9 => NasMessageType::PduSessionModificationRequest,
            0xCA => NasMessageType::PduSessionModificationReject,
            0xCB => NasMessageType::PduSessionModificationCommand,
            0xCC => NasMessageType::PduSessionModificationComplete,
            0xCD => NasMessageType::PduSessionModificationCommandReject,
            0xD1 => NasMessageType::PduSessionReleaseRequest,
            0xD2 => NasMessageType::PduSessionReleaseReject,
            0xD3 => NasMessageType::PduSessionReleaseCommand,
            _ => NasMessageType::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InformationElementType {
    UeSecurityCapability = 0x2E,
    MaximumDataRatePerUeForUserPlaneIntegrityProtection = 0x2F,
    AlwaysOnPduSessionRequested = 0x01,
    SmPduDnRequestContainer = 0x39,
    ExtendedProtocolConfigurationOptions = 0x7B,
    Unknown = 0xFF,
}

impl From<u8> for InformationElementType {
    fn from(value: u8) -> Self {
        match value {
            0x2E => InformationElementType::UeSecurityCapability,
            0x2F => InformationElementType::MaximumDataRatePerUeForUserPlaneIntegrityProtection,
            0x01 => InformationElementType::AlwaysOnPduSessionRequested,
            0x39 => InformationElementType::SmPduDnRequestContainer,
            0x7B => InformationElementType::ExtendedProtocolConfigurationOptions,
            _ => InformationElementType::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NasPduSessionEstablishmentRequest {
    pub integrity_protection_max_data_rate: Option<MaxDataRatePerUe>,
    pub pdu_session_type: Option<u8>,
    pub ssc_mode: Option<u8>,
    pub ue_security_capabilities: Option<UeSecurityCapabilities>,
    pub always_on_pdu_session_requested: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaxDataRatePerUe {
    Bitrate64kbps,
    MaximumUeRate,
    Bitrate128kbps,
    Bitrate256kbps,
    Bitrate512kbps,
    Bitrate1024kbps,
}

impl From<u8> for MaxDataRatePerUe {
    fn from(value: u8) -> Self {
        match value {
            0x00 => MaxDataRatePerUe::Bitrate64kbps,
            0x01 => MaxDataRatePerUe::MaximumUeRate,
            0x02 => MaxDataRatePerUe::Bitrate128kbps,
            0x03 => MaxDataRatePerUe::Bitrate256kbps,
            0x04 => MaxDataRatePerUe::Bitrate512kbps,
            0x05 => MaxDataRatePerUe::Bitrate1024kbps,
            _ => MaxDataRatePerUe::MaximumUeRate,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NasPduSessionEstablishmentAccept {
    pub selected_pdu_session_type: u8,
    pub selected_ssc_mode: u8,
    pub qos_rules: Vec<u8>,
    pub session_ambr: Vec<u8>,
    pub up_security_policy: Option<UpSecurityPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpSecurityPolicy {
    pub integrity_protection_required: bool,
    pub confidentiality_protection_required: bool,
}

pub struct NasParser;

impl NasParser {
    pub fn parse_pdu_session_establishment_request(data: &[u8]) -> Result<NasPduSessionEstablishmentRequest, String> {
        if data.is_empty() {
            return Err("Empty NAS message data".to_string());
        }

        let extended_protocol_discriminator = data[0];
        if extended_protocol_discriminator != 0x2E {
            return Err(format!("Invalid extended protocol discriminator: {:#x}", extended_protocol_discriminator));
        }

        if data.len() < 3 {
            return Err("NAS message too short".to_string());
        }

        let pdu_session_identity = data[1];
        tracing::debug!("NAS PDU Session Identity: {}", pdu_session_identity);

        let procedure_transaction_identity = data[2];
        tracing::debug!("NAS Procedure Transaction Identity: {}", procedure_transaction_identity);

        if data.len() < 4 {
            return Err("NAS message missing message type".to_string());
        }

        let message_type = NasMessageType::from(data[3]);
        if message_type != NasMessageType::PduSessionEstablishmentRequest {
            return Err(format!("Unexpected NAS message type: {:?}", message_type));
        }

        let mut request = NasPduSessionEstablishmentRequest {
            integrity_protection_max_data_rate: None,
            pdu_session_type: None,
            ssc_mode: None,
            ue_security_capabilities: None,
            always_on_pdu_session_requested: None,
        };

        let mut pos = 4;
        while pos < data.len() {
            if pos + 1 > data.len() {
                break;
            }

            let ie_type = data[pos];
            let ie_type_enum = InformationElementType::from(ie_type);

            match ie_type_enum {
                InformationElementType::UeSecurityCapability => {
                    if let Some(caps) = Self::parse_ue_security_capabilities(&data[pos..]) {
                        request.ue_security_capabilities = Some(caps.0);
                        pos += caps.1;
                        tracing::info!("Parsed UE security capabilities from N1 message");
                    } else {
                        tracing::warn!("Failed to parse UE security capabilities IE");
                        pos += 1;
                    }
                }
                InformationElementType::MaximumDataRatePerUeForUserPlaneIntegrityProtection => {
                    if pos + 2 <= data.len() {
                        let ie_length = data[pos + 1] as usize;
                        if pos + 2 + ie_length <= data.len() && ie_length >= 1 {
                            let max_rate_value = data[pos + 2];
                            request.integrity_protection_max_data_rate = Some(MaxDataRatePerUe::from(max_rate_value));
                            tracing::debug!("Parsed max data rate for UP integrity protection: {:?}", request.integrity_protection_max_data_rate);
                            pos += 2 + ie_length;
                        } else {
                            pos += 1;
                        }
                    } else {
                        pos += 1;
                    }
                }
                InformationElementType::AlwaysOnPduSessionRequested => {
                    request.always_on_pdu_session_requested = Some(true);
                    tracing::debug!("Always-on PDU session requested");
                    pos += 1;
                }
                _ => {
                    if pos + 1 < data.len() {
                        let ie_length = data[pos + 1] as usize;
                        if pos + 2 + ie_length <= data.len() {
                            pos += 2 + ie_length;
                        } else {
                            pos += 1;
                        }
                    } else {
                        pos += 1;
                    }
                }
            }
        }

        Ok(request)
    }

    fn parse_ue_security_capabilities(data: &[u8]) -> Option<(UeSecurityCapabilities, usize)> {
        if data.len() < 2 {
            return None;
        }

        let ie_type = data[0];
        if ie_type != 0x2E {
            return None;
        }

        let ie_length = data[1] as usize;
        if data.len() < 2 + ie_length || ie_length < 2 {
            return None;
        }

        let nr_enc_algorithms_byte = data[2];
        let nr_int_algorithms_byte = data[3];

        let nr_encryption_algorithms = Self::parse_algorithm_bitmap::<CipheringAlgorithm>(nr_enc_algorithms_byte);
        let nr_integrity_algorithms = Self::parse_algorithm_bitmap::<IntegrityAlgorithm>(nr_int_algorithms_byte);

        let (eutra_encryption_algorithms, eutra_integrity_algorithms) = if ie_length >= 4 {
            let eutra_enc = if data.len() >= 6 {
                Some(Self::parse_algorithm_bitmap::<CipheringAlgorithm>(data[4]))
            } else {
                None
            };
            let eutra_int = if data.len() >= 7 {
                Some(Self::parse_algorithm_bitmap::<IntegrityAlgorithm>(data[5]))
            } else {
                None
            };
            (eutra_enc, eutra_int)
        } else {
            (None, None)
        };

        let capabilities = UeSecurityCapabilities {
            nr_encryption_algorithms,
            nr_integrity_algorithms,
            eutra_encryption_algorithms,
            eutra_integrity_algorithms,
        };

        Some((capabilities, 2 + ie_length))
    }

    fn parse_algorithm_bitmap<T>(byte: u8) -> Vec<T>
    where
        T: From<u8> + Copy,
    {
        let mut algorithms = Vec::new();
        for bit in 0..8 {
            if (byte >> bit) & 0x01 == 1 {
                algorithms.push(T::from(bit));
            }
        }
        algorithms
    }

    pub fn build_pdu_session_establishment_accept(
        pdu_session_id: u8,
        procedure_transaction_id: u8,
        selected_pdu_session_type: u8,
        selected_ssc_mode: u8,
        integrity_protection_required: bool,
        confidentiality_protection_required: bool,
    ) -> Vec<u8> {
        let mut message = Vec::new();

        message.push(0x2E);
        message.push(pdu_session_id);
        message.push(procedure_transaction_id);
        message.push(NasMessageType::PduSessionEstablishmentAccept as u8);

        message.push(selected_pdu_session_type | (selected_ssc_mode << 4));

        let up_security_policy_byte =
            ((integrity_protection_required as u8) << 1) |
            (confidentiality_protection_required as u8);

        message.push(InformationElementType::UeSecurityCapability as u8);
        message.push(1);
        message.push(up_security_policy_byte);

        message
    }
}

impl From<u8> for CipheringAlgorithm {
    fn from(value: u8) -> Self {
        match value {
            0 => CipheringAlgorithm::Nea0,
            1 => CipheringAlgorithm::Nea1,
            2 => CipheringAlgorithm::Nea2,
            3 => CipheringAlgorithm::Nea3,
            _ => CipheringAlgorithm::Nea0,
        }
    }
}

impl From<u8> for IntegrityAlgorithm {
    fn from(value: u8) -> Self {
        match value {
            0 => IntegrityAlgorithm::Nia0,
            1 => IntegrityAlgorithm::Nia1,
            2 => IntegrityAlgorithm::Nia2,
            3 => IntegrityAlgorithm::Nia3,
            _ => IntegrityAlgorithm::Nia0,
        }
    }
}
