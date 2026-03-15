use serde::{Deserialize, Serialize};
use crate::types::packet_filter::PacketFilterDirection;
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
    PduSessionReleaseComplete = 0xD4,
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
            0xD4 => NasMessageType::PduSessionReleaseComplete,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GsmCause {
    OperatorDeterminedBarring,
    InsufficientResources,
    MissingOrUnknownDnn,
    UnknownPduSessionType,
    UserAuthenticationFailed,
    RequestRejectedUnspecified,
    ServiceOptionNotSupported,
    RequestedServiceOptionNotSubscribed,
    PtiAlreadyInUse,
    RegularDeactivation,
    NetworkFailure,
    ReactivationRequested,
    SemanticErrorInTft,
    SyntacticalErrorInTft,
    InvalidPduSessionIdentity,
    SemanticErrorsInPacketFilters,
    SyntacticalErrorInPacketFilters,
    OutOfLadnServiceArea,
    PtiMismatch,
    PduSessionTypeIpv4OnlyAllowed,
    PduSessionTypeIpv6OnlyAllowed,
    PduSessionDoesNotExist,
    InsufficientResourcesForSliceAndDnn,
    NotSupportedSscMode,
    InsufficientResourcesForSlice,
    MissingOrUnknownDnnInSlice,
    InvalidPtiValue,
    MaxDataRateForIntegrityProtectionTooLow,
    SemanticErrorInQosOperation,
    SyntacticalErrorInQosOperation,
    InvalidMappedEpsBearerIdentity,
    SemanticallyIncorrectMessage,
    InvalidMandatoryInformation,
    MessageTypeNonExistent,
    MessageTypeNotCompatible,
    InformationElementNonExistent,
    ProtocolErrorUnspecified,
}

impl GsmCause {
    pub fn as_u8(self) -> u8 {
        match self {
            GsmCause::OperatorDeterminedBarring => 8,
            GsmCause::InsufficientResources => 26,
            GsmCause::MissingOrUnknownDnn => 27,
            GsmCause::UnknownPduSessionType => 28,
            GsmCause::UserAuthenticationFailed => 29,
            GsmCause::RequestRejectedUnspecified => 31,
            GsmCause::ServiceOptionNotSupported => 32,
            GsmCause::RequestedServiceOptionNotSubscribed => 33,
            GsmCause::PtiAlreadyInUse => 35,
            GsmCause::RegularDeactivation => 36,
            GsmCause::NetworkFailure => 38,
            GsmCause::ReactivationRequested => 39,
            GsmCause::SemanticErrorInTft => 41,
            GsmCause::SyntacticalErrorInTft => 42,
            GsmCause::InvalidPduSessionIdentity => 43,
            GsmCause::SemanticErrorsInPacketFilters => 44,
            GsmCause::SyntacticalErrorInPacketFilters => 45,
            GsmCause::OutOfLadnServiceArea => 46,
            GsmCause::PtiMismatch => 47,
            GsmCause::PduSessionTypeIpv4OnlyAllowed => 50,
            GsmCause::PduSessionTypeIpv6OnlyAllowed => 51,
            GsmCause::PduSessionDoesNotExist => 54,
            GsmCause::InsufficientResourcesForSliceAndDnn => 67,
            GsmCause::NotSupportedSscMode => 68,
            GsmCause::InsufficientResourcesForSlice => 69,
            GsmCause::MissingOrUnknownDnnInSlice => 70,
            GsmCause::InvalidPtiValue => 81,
            GsmCause::MaxDataRateForIntegrityProtectionTooLow => 82,
            GsmCause::SemanticErrorInQosOperation => 83,
            GsmCause::SyntacticalErrorInQosOperation => 84,
            GsmCause::InvalidMappedEpsBearerIdentity => 85,
            GsmCause::SemanticallyIncorrectMessage => 95,
            GsmCause::InvalidMandatoryInformation => 96,
            GsmCause::MessageTypeNonExistent => 97,
            GsmCause::MessageTypeNotCompatible => 98,
            GsmCause::InformationElementNonExistent => 99,
            GsmCause::ProtocolErrorUnspecified => 111,
        }
    }
}

impl From<u8> for GsmCause {
    fn from(value: u8) -> Self {
        match value {
            8 => GsmCause::OperatorDeterminedBarring,
            26 => GsmCause::InsufficientResources,
            27 => GsmCause::MissingOrUnknownDnn,
            28 => GsmCause::UnknownPduSessionType,
            29 => GsmCause::UserAuthenticationFailed,
            31 => GsmCause::RequestRejectedUnspecified,
            32 => GsmCause::ServiceOptionNotSupported,
            33 => GsmCause::RequestedServiceOptionNotSubscribed,
            35 => GsmCause::PtiAlreadyInUse,
            36 => GsmCause::RegularDeactivation,
            38 => GsmCause::NetworkFailure,
            39 => GsmCause::ReactivationRequested,
            41 => GsmCause::SemanticErrorInTft,
            42 => GsmCause::SyntacticalErrorInTft,
            43 => GsmCause::InvalidPduSessionIdentity,
            44 => GsmCause::SemanticErrorsInPacketFilters,
            45 => GsmCause::SyntacticalErrorInPacketFilters,
            46 => GsmCause::OutOfLadnServiceArea,
            47 => GsmCause::PtiMismatch,
            50 => GsmCause::PduSessionTypeIpv4OnlyAllowed,
            51 => GsmCause::PduSessionTypeIpv6OnlyAllowed,
            54 => GsmCause::PduSessionDoesNotExist,
            67 => GsmCause::InsufficientResourcesForSliceAndDnn,
            68 => GsmCause::NotSupportedSscMode,
            69 => GsmCause::InsufficientResourcesForSlice,
            70 => GsmCause::MissingOrUnknownDnnInSlice,
            81 => GsmCause::InvalidPtiValue,
            82 => GsmCause::MaxDataRateForIntegrityProtectionTooLow,
            83 => GsmCause::SemanticErrorInQosOperation,
            84 => GsmCause::SyntacticalErrorInQosOperation,
            85 => GsmCause::InvalidMappedEpsBearerIdentity,
            95 => GsmCause::SemanticallyIncorrectMessage,
            96 => GsmCause::InvalidMandatoryInformation,
            97 => GsmCause::MessageTypeNonExistent,
            98 => GsmCause::MessageTypeNotCompatible,
            99 => GsmCause::InformationElementNonExistent,
            _ => GsmCause::ProtocolErrorUnspecified,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NasSmHeader {
    pub pdu_session_id: u8,
    pub pti: u8,
    pub message_type: NasMessageType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QosRuleOperationCode {
    CreateNewQosRule,
    DeleteExistingQosRule,
    ModifyAndAddPacketFilters,
    ModifyAndReplaceAllPacketFilters,
    ModifyAndDeletePacketFilters,
    ModifyWithoutChangingPacketFilters,
}

impl QosRuleOperationCode {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::CreateNewQosRule => 1,
            Self::DeleteExistingQosRule => 2,
            Self::ModifyAndAddPacketFilters => 3,
            Self::ModifyAndReplaceAllPacketFilters => 4,
            Self::ModifyAndDeletePacketFilters => 5,
            Self::ModifyWithoutChangingPacketFilters => 6,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::CreateNewQosRule),
            2 => Some(Self::DeleteExistingQosRule),
            3 => Some(Self::ModifyAndAddPacketFilters),
            4 => Some(Self::ModifyAndReplaceAllPacketFilters),
            5 => Some(Self::ModifyAndDeletePacketFilters),
            6 => Some(Self::ModifyWithoutChangingPacketFilters),
            _ => None,
        }
    }

    pub fn has_packet_filters(self) -> bool {
        !matches!(
            self,
            Self::DeleteExistingQosRule | Self::ModifyWithoutChangingPacketFilters
        )
    }

    pub fn has_precedence_and_qfi(self) -> bool {
        !matches!(self, Self::DeleteExistingQosRule)
    }
}

#[derive(Debug, Clone)]
pub struct NasPacketFilter {
    pub direction: PacketFilterDirection,
    pub identifier: u8,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NasQosRule {
    pub rule_id: u8,
    pub operation_code: QosRuleOperationCode,
    pub dqr: bool,
    pub packet_filters: Vec<NasPacketFilter>,
    pub precedence: u8,
    pub qfi: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QosFlowOperationCode {
    CreateNew,
    Delete,
    Modify,
}

impl QosFlowOperationCode {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::CreateNew => 1,
            Self::Delete => 2,
            Self::Modify => 3,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::CreateNew),
            2 => Some(Self::Delete),
            3 => Some(Self::Modify),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NasQosFlowParameter {
    pub id: u8,
    pub value: Vec<u8>,
}

impl NasQosFlowParameter {
    pub const ID_5QI: u8 = 0x01;
    pub const ID_GFBR: u8 = 0x02;
    pub const ID_MFBR: u8 = 0x03;
    pub const ID_AVERAGING_WINDOW: u8 = 0x04;
    pub const ID_EPS_BEARER_ID: u8 = 0x05;

    pub fn five_qi(value: u8) -> Self {
        Self { id: Self::ID_5QI, value: vec![value] }
    }

    pub fn gfbr(dl_unit: u8, dl_value: u16, ul_unit: u8, ul_value: u16) -> Self {
        let mut v = Vec::with_capacity(6);
        v.push(dl_unit);
        v.extend_from_slice(&dl_value.to_be_bytes());
        v.push(ul_unit);
        v.extend_from_slice(&ul_value.to_be_bytes());
        Self { id: Self::ID_GFBR, value: v }
    }

    pub fn mfbr(dl_unit: u8, dl_value: u16, ul_unit: u8, ul_value: u16) -> Self {
        let mut v = Vec::with_capacity(6);
        v.push(dl_unit);
        v.extend_from_slice(&dl_value.to_be_bytes());
        v.push(ul_unit);
        v.extend_from_slice(&ul_value.to_be_bytes());
        Self { id: Self::ID_MFBR, value: v }
    }

    pub fn get_five_qi(&self) -> Option<u8> {
        if self.id == Self::ID_5QI && !self.value.is_empty() {
            Some(self.value[0])
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct NasQosFlowDescription {
    pub qfi: u8,
    pub operation_code: QosFlowOperationCode,
    pub e_bit: bool,
    pub parameters: Vec<NasQosFlowParameter>,
}

#[derive(Debug, Clone)]
pub struct NasPduSessionModificationRequest {
    pub pdu_session_id: u8,
    pub pti: u8,
    pub cause: Option<GsmCause>,
    pub requested_qos_rules: Vec<NasQosRule>,
    pub requested_qos_flow_descriptions: Vec<NasQosFlowDescription>,
    pub always_on_pdu_session_requested: bool,
    pub integrity_protection_max_data_rate: Option<(u8, u8)>,
}

#[derive(Debug, Clone)]
pub struct NasPduSessionReleaseRequest {
    pub pdu_session_id: u8,
    pub pti: u8,
    pub cause: Option<GsmCause>,
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

        if data.len() < 6 {
            return Err("NAS message missing mandatory integrity protection max data rate".to_string());
        }

        let integrity_max_rate_ul = MaxDataRatePerUe::from(data[4]);
        let integrity_max_rate_dl = MaxDataRatePerUe::from(data[5]);
        tracing::debug!(
            "Mandatory integrity protection max data rate: UL={:?}, DL={:?}",
            integrity_max_rate_ul,
            integrity_max_rate_dl
        );

        let mut request = NasPduSessionEstablishmentRequest {
            integrity_protection_max_data_rate: Some(integrity_max_rate_ul),
            pdu_session_type: None,
            ssc_mode: None,
            ue_security_capabilities: None,
            always_on_pdu_session_requested: None,
        };

        let mut pos = 6;
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
        _integrity_protection_required: bool,
        _confidentiality_protection_required: bool,
        ipv4_address: Option<&str>,
        ipv6_address: Option<&str>,
        session_ambr_dl_kbps: u64,
        session_ambr_ul_kbps: u64,
        qfi: u8,
    ) -> Vec<u8> {
        let mut message = Vec::new();

        message.push(0x2E);
        message.push(pdu_session_id);
        message.push(procedure_transaction_id);
        message.push(NasMessageType::PduSessionEstablishmentAccept as u8);

        message.push(selected_pdu_session_type | (selected_ssc_mode << 4));

        let qos_rules = Self::encode_default_qos_rule(qfi);
        message.extend_from_slice(&[
            ((qos_rules.len() >> 8) & 0xFF) as u8,
            (qos_rules.len() & 0xFF) as u8,
        ]);
        message.extend_from_slice(&qos_rules);

        let (dl_unit, dl_value) = Self::encode_ambr_value(session_ambr_dl_kbps);
        let (ul_unit, ul_value) = Self::encode_ambr_value(session_ambr_ul_kbps);
        message.push(6);
        message.push(dl_unit);
        message.push(((dl_value >> 8) & 0xFF) as u8);
        message.push((dl_value & 0xFF) as u8);
        message.push(ul_unit);
        message.push(((ul_value >> 8) & 0xFF) as u8);
        message.push((ul_value & 0xFF) as u8);

        match (ipv4_address, ipv6_address) {
            (Some(ipv4), Some(ipv6)) => {
                let ipv4_ok = ipv4.parse::<std::net::Ipv4Addr>().ok();
                let ipv6_ok = ipv6.split('/').next()
                    .and_then(|s| s.parse::<std::net::Ipv6Addr>().ok());
                if let (Some(v4), Some(v6)) = (ipv4_ok, ipv6_ok) {
                    let octets = v6.octets();
                    message.push(0x29);
                    message.push(13);
                    message.push(3);
                    message.extend_from_slice(&octets[8..16]);
                    message.extend_from_slice(&v4.octets());
                }
            }
            (Some(ipv4), None) => {
                if let Ok(addr) = ipv4.parse::<std::net::Ipv4Addr>() {
                    message.push(0x29);
                    message.push(5);
                    message.push(1);
                    message.extend_from_slice(&addr.octets());
                }
            }
            (None, Some(ipv6)) => {
                let ipv6_str = ipv6.split('/').next().unwrap_or(ipv6);
                if let Ok(addr) = ipv6_str.parse::<std::net::Ipv6Addr>() {
                    let octets = addr.octets();
                    message.push(0x29);
                    message.push(9);
                    message.push(2);
                    message.extend_from_slice(&octets[8..16]);
                }
            }
            (None, None) => {}
        }

        message
    }

    fn encode_ambr_value(kbps: u64) -> (u8, u16) {
        if kbps == 0 {
            return (0x01, 0);
        }
        if kbps <= 65535 {
            return (0x01, kbps as u16);
        }
        let mbps = kbps / 1000;
        if mbps <= 65535 {
            return (0x06, mbps as u16);
        }
        let gbps = kbps / 1_000_000;
        if gbps <= 65535 {
            return (0x0B, gbps as u16);
        }
        (0x0B, 65535)
    }

    fn encode_default_qos_rule(qfi: u8) -> Vec<u8> {
        tracing::debug!("UPDATED CODE: Encoding QoS rule with QFI {} using fixed implementation", qfi);
        let mut rule = Vec::new();

        rule.push(1);

        let rule_content_len = 3u16;
        rule.push(((rule_content_len >> 8) & 0xFF) as u8);
        rule.push((rule_content_len & 0xFF) as u8);

        rule.push(0x30);

        rule.push(255);

        rule.push(qfi);

        tracing::debug!("UPDATED CODE: Generated QoS rule with {} bytes: {:?}", rule.len(), rule);
        rule
    }
}

const IEI_GSM_CAPABILITY: u8 = 0x28;
const IEI_GSM_CAUSE: u8 = 0x59;
const IEI_MAX_PACKET_FILTERS: u8 = 0x55;
const IEI_ALWAYS_ON_REQUESTED: u8 = 0xB0;
const IEI_INTEGRITY_PROT_MAX_RATE: u8 = 0x13;
const IEI_QOS_RULES: u8 = 0x7A;
const IEI_QOS_FLOW_DESCRIPTIONS: u8 = 0x79;
const IEI_MAPPED_EPS_BEARER_CONTEXTS: u8 = 0x75;
const IEI_EPCO: u8 = 0x7B;
const IEI_SESSION_AMBR: u8 = 0x2A;

impl NasParser {
    pub fn parse_sm_header(data: &[u8]) -> Result<NasSmHeader, String> {
        if data.len() < 4 {
            return Err("NAS SM message too short for header".to_string());
        }
        if data[0] != 0x2E {
            return Err(format!(
                "Invalid extended protocol discriminator: {:#x}, expected 0x2E",
                data[0]
            ));
        }
        Ok(NasSmHeader {
            pdu_session_id: data[1],
            pti: data[2],
            message_type: NasMessageType::from(data[3]),
        })
    }

    pub fn parse_pdu_session_modification_request(
        data: &[u8],
    ) -> Result<NasPduSessionModificationRequest, String> {
        let header = Self::parse_sm_header(data)?;
        if header.message_type != NasMessageType::PduSessionModificationRequest {
            return Err(format!(
                "Expected PDU Session Modification Request (0xC9), got {:?}",
                header.message_type
            ));
        }

        let mut result = NasPduSessionModificationRequest {
            pdu_session_id: header.pdu_session_id,
            pti: header.pti,
            cause: None,
            requested_qos_rules: Vec::new(),
            requested_qos_flow_descriptions: Vec::new(),
            always_on_pdu_session_requested: false,
            integrity_protection_max_data_rate: None,
        };

        let mut pos = 4;
        while pos < data.len() {
            let iei = data[pos];

            if iei & 0xF0 == IEI_ALWAYS_ON_REQUESTED & 0xF0 {
                result.always_on_pdu_session_requested = (iei & 0x01) != 0;
                pos += 1;
                continue;
            }

            match iei {
                IEI_GSM_CAUSE => {
                    if pos + 2 < data.len() {
                        let len = data[pos + 1] as usize;
                        if len >= 1 && pos + 2 + len <= data.len() {
                            result.cause = Some(GsmCause::from(data[pos + 2]));
                        }
                        pos += 2 + len;
                    } else {
                        pos += 1;
                    }
                }
                IEI_INTEGRITY_PROT_MAX_RATE => {
                    if pos + 2 < data.len() {
                        let len = data[pos + 1] as usize;
                        if len >= 2 && pos + 2 + len <= data.len() {
                            result.integrity_protection_max_data_rate =
                                Some((data[pos + 2], data[pos + 3]));
                        }
                        pos += 2 + len;
                    } else {
                        pos += 1;
                    }
                }
                IEI_QOS_RULES => {
                    if pos + 3 <= data.len() {
                        let len =
                            ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
                        if pos + 3 + len <= data.len() {
                            result.requested_qos_rules =
                                Self::parse_qos_rules(&data[pos + 3..pos + 3 + len]);
                        }
                        pos += 3 + len;
                    } else {
                        pos += 1;
                    }
                }
                IEI_QOS_FLOW_DESCRIPTIONS => {
                    if pos + 3 <= data.len() {
                        let len =
                            ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
                        if pos + 3 + len <= data.len() {
                            result.requested_qos_flow_descriptions =
                                Self::parse_qos_flow_descriptions(
                                    &data[pos + 3..pos + 3 + len],
                                );
                        }
                        pos += 3 + len;
                    } else {
                        pos += 1;
                    }
                }
                _ => {
                    pos = Self::skip_unknown_ie(data, pos);
                }
            }
        }

        Ok(result)
    }

    pub fn parse_pdu_session_release_request(
        data: &[u8],
    ) -> Result<NasPduSessionReleaseRequest, String> {
        let header = Self::parse_sm_header(data)?;
        if header.message_type != NasMessageType::PduSessionReleaseRequest {
            return Err(format!(
                "Expected PDU Session Release Request (0xD1), got {:?}",
                header.message_type
            ));
        }

        let mut result = NasPduSessionReleaseRequest {
            pdu_session_id: header.pdu_session_id,
            pti: header.pti,
            cause: None,
        };

        let mut pos = 4;
        while pos < data.len() {
            let iei = data[pos];
            match iei {
                IEI_GSM_CAUSE => {
                    if pos + 2 < data.len() {
                        let len = data[pos + 1] as usize;
                        if len >= 1 && pos + 2 + len <= data.len() {
                            result.cause = Some(GsmCause::from(data[pos + 2]));
                        }
                        pos += 2 + len;
                    } else {
                        pos += 1;
                    }
                }
                _ => {
                    pos = Self::skip_unknown_ie(data, pos);
                }
            }
        }

        Ok(result)
    }

    pub fn build_pdu_session_modification_command(
        pdu_session_id: u8,
        pti: u8,
        cause: Option<GsmCause>,
        session_ambr_dl_kbps: Option<u64>,
        session_ambr_ul_kbps: Option<u64>,
        qos_rules: Option<&[NasQosRule]>,
        qos_flow_descriptions: Option<&[NasQosFlowDescription]>,
    ) -> Vec<u8> {
        let mut msg = Vec::new();

        msg.push(0x2E);
        msg.push(pdu_session_id);
        msg.push(pti);
        msg.push(NasMessageType::PduSessionModificationCommand as u8);

        if let Some(c) = cause {
            msg.push(IEI_GSM_CAUSE);
            msg.push(1);
            msg.push(c.as_u8());
        }

        if let (Some(dl), Some(ul)) = (session_ambr_dl_kbps, session_ambr_ul_kbps) {
            msg.push(IEI_SESSION_AMBR);
            msg.push(6);
            let (dl_unit, dl_value) = Self::encode_ambr_value(dl);
            let (ul_unit, ul_value) = Self::encode_ambr_value(ul);
            msg.push(dl_unit);
            msg.extend_from_slice(&dl_value.to_be_bytes());
            msg.push(ul_unit);
            msg.extend_from_slice(&ul_value.to_be_bytes());
        }

        if let Some(rules) = qos_rules {
            if !rules.is_empty() {
                let encoded = Self::encode_qos_rules(rules);
                msg.push(IEI_QOS_RULES);
                msg.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
                msg.extend_from_slice(&encoded);
            }
        }

        if let Some(descs) = qos_flow_descriptions {
            if !descs.is_empty() {
                let encoded = Self::encode_qos_flow_descriptions(descs);
                msg.push(IEI_QOS_FLOW_DESCRIPTIONS);
                msg.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
                msg.extend_from_slice(&encoded);
            }
        }

        msg
    }

    pub fn build_pdu_session_modification_reject(
        pdu_session_id: u8,
        pti: u8,
        cause: GsmCause,
    ) -> Vec<u8> {
        vec![
            0x2E,
            pdu_session_id,
            pti,
            NasMessageType::PduSessionModificationReject as u8,
            cause.as_u8(),
        ]
    }

    pub fn build_pdu_session_release_command(
        pdu_session_id: u8,
        pti: u8,
        cause: GsmCause,
    ) -> Vec<u8> {
        vec![
            0x2E,
            pdu_session_id,
            pti,
            NasMessageType::PduSessionReleaseCommand as u8,
            cause.as_u8(),
        ]
    }

    pub fn build_pdu_session_release_reject(
        pdu_session_id: u8,
        pti: u8,
        cause: GsmCause,
    ) -> Vec<u8> {
        vec![
            0x2E,
            pdu_session_id,
            pti,
            NasMessageType::PduSessionReleaseReject as u8,
            cause.as_u8(),
        ]
    }

    pub fn build_pdu_session_establishment_reject(
        pdu_session_id: u8,
        pti: u8,
        cause: GsmCause,
    ) -> Vec<u8> {
        vec![
            0x2E,
            pdu_session_id,
            pti,
            NasMessageType::PduSessionEstablishmentReject as u8,
            cause.as_u8(),
        ]
    }

    fn parse_qos_rules(data: &[u8]) -> Vec<NasQosRule> {
        let mut rules = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            if pos + 3 > data.len() {
                break;
            }

            let rule_id = data[pos];
            let rule_len =
                ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
            pos += 3;

            if rule_len == 0 || pos + rule_len > data.len() {
                break;
            }

            let rule_end = pos + rule_len;
            let flags = data[pos];
            let code_raw = (flags >> 5) & 0x07;
            let dqr = (flags >> 4) & 0x01 != 0;
            let num_pf = (flags & 0x0F) as usize;
            pos += 1;

            let operation_code = match QosRuleOperationCode::from_u8(code_raw) {
                Some(c) => c,
                None => {
                    pos = rule_end;
                    continue;
                }
            };

            let mut packet_filters = Vec::new();
            if operation_code.has_packet_filters() {
                for _ in 0..num_pf {
                    if pos >= rule_end {
                        break;
                    }
                    let pf_flags = data[pos];
                    let direction = PacketFilterDirection::from_u8((pf_flags >> 4) & 0x03);
                    let pf_id = pf_flags & 0x0F;
                    pos += 1;

                    if pos >= rule_end {
                        break;
                    }
                    let content_len = data[pos] as usize;
                    pos += 1;

                    let content = if pos + content_len <= rule_end {
                        let c = data[pos..pos + content_len].to_vec();
                        pos += content_len;
                        c
                    } else {
                        pos = rule_end;
                        break;
                    };

                    packet_filters.push(NasPacketFilter {
                        direction,
                        identifier: pf_id,
                        content,
                    });
                }
            }

            let mut precedence = 0u8;
            let mut qfi = 0u8;

            if operation_code.has_precedence_and_qfi() && pos < rule_end {
                precedence = data[pos];
                pos += 1;
                if pos < rule_end {
                    qfi = data[pos] & 0x3F;
                    pos += 1;
                }
            }

            rules.push(NasQosRule {
                rule_id,
                operation_code,
                dqr,
                packet_filters,
                precedence,
                qfi,
            });

            pos = rule_end;
        }

        rules
    }

    fn encode_qos_rules(rules: &[NasQosRule]) -> Vec<u8> {
        let mut out = Vec::new();

        for rule in rules {
            let mut body = Vec::new();

            let num_pf = if rule.operation_code.has_packet_filters() {
                rule.packet_filters.len() as u8
            } else {
                0
            };
            let flags =
                (rule.operation_code.as_u8() << 5)
                | (if rule.dqr { 1 } else { 0 } << 4)
                | (num_pf & 0x0F);
            body.push(flags);

            if rule.operation_code.has_packet_filters() {
                for pf in &rule.packet_filters {
                    let pf_flags = ((pf.direction.as_u8() & 0x03) << 4) | (pf.identifier & 0x0F);
                    body.push(pf_flags);
                    body.push(pf.content.len() as u8);
                    body.extend_from_slice(&pf.content);
                }
            }

            if rule.operation_code.has_precedence_and_qfi() {
                body.push(rule.precedence);
                body.push(rule.qfi & 0x3F);
            }

            out.push(rule.rule_id);
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
            out.extend_from_slice(&body);
        }

        out
    }

    fn parse_qos_flow_descriptions(data: &[u8]) -> Vec<NasQosFlowDescription> {
        let mut descs = Vec::new();
        let mut pos = 0;

        while pos + 3 <= data.len() {
            let qfi = data[pos] & 0x3F;
            let code_raw = (data[pos + 1] >> 5) & 0x07;
            let e_bit = (data[pos + 2] >> 6) & 0x01 != 0;
            let num_params = (data[pos + 2] & 0x3F) as usize;
            pos += 3;

            let operation_code = match QosFlowOperationCode::from_u8(code_raw) {
                Some(c) => c,
                None => continue,
            };

            let mut parameters = Vec::new();
            if e_bit {
                for _ in 0..num_params {
                    if pos + 2 > data.len() {
                        break;
                    }
                    let param_id = data[pos];
                    let param_len = data[pos + 1] as usize;
                    pos += 2;

                    if pos + param_len > data.len() {
                        break;
                    }
                    let value = data[pos..pos + param_len].to_vec();
                    pos += param_len;

                    parameters.push(NasQosFlowParameter {
                        id: param_id,
                        value,
                    });
                }
            }

            descs.push(NasQosFlowDescription {
                qfi,
                operation_code,
                e_bit,
                parameters,
            });
        }

        descs
    }

    fn encode_qos_flow_descriptions(descs: &[NasQosFlowDescription]) -> Vec<u8> {
        let mut out = Vec::new();

        for desc in descs {
            out.push(desc.qfi & 0x3F);
            out.push((desc.operation_code.as_u8() & 0x07) << 5);

            let num_params = desc.parameters.len() as u8;
            let e_bit: u8 = if !desc.parameters.is_empty() { 1 } else { 0 };
            out.push((e_bit << 6) | (num_params & 0x3F));

            for param in &desc.parameters {
                out.push(param.id);
                out.push(param.value.len() as u8);
                out.extend_from_slice(&param.value);
            }
        }

        out
    }

    fn skip_unknown_ie(data: &[u8], pos: usize) -> usize {
        if pos >= data.len() {
            return data.len();
        }
        let iei = data[pos];

        if iei >= 0x80 {
            return pos + 1;
        }

        if (0x70..=0x7F).contains(&iei) {
            if pos + 3 <= data.len() {
                let len = ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
                return pos + 3 + len;
            }
            return data.len();
        }

        if pos + 2 <= data.len() {
            let len = data[pos + 1] as usize;
            return pos + 2 + len;
        }
        data.len()
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
