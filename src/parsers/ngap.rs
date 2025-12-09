use anyhow::{anyhow, Result};
use bytes::Bytes;
use crate::types::ngap::{
    AssociatedQosFlowItem, ConfidentialityProtectionResult, GtpTunnel,
    IntegrityProtectionResult, PduSessionResourceSetupResponseTransfer, QosFlowMappingIndication,
    QosFlowPerTnlInformation, QosFlowWithCauseItem, SecurityResult, NgapCause, RadioNetworkCause,
    TransportCause, NasCause, ProtocolCause, MiscCause, PathSwitchRequestTransfer,
    DlNguTnlInformationReused, UserPlaneSecurityInformation, SecurityIndication,
    IntegrityProtectionIndication, ConfidentialityProtectionIndication,
    MaximumIntegrityProtectedDataRate, QosFlowAcceptedItem, QosFlowLevelQosParameters,
    QosCharacteristics, NonDynamic5qiDescriptor, Dynamic5qiDescriptor, PacketErrorRate,
    AllocationAndRetentionPriority, PreEmptionCapability, PreEmptionVulnerability,
    GbrQosFlowInformation, NotificationControl, ReflectiveQosAttribute,
    AdditionalQosFlowInformation,
};

pub struct PerDecoder {
    data: Vec<u8>,
    byte_pos: usize,
    bit_pos: u8,
}

impl PerDecoder {
    pub fn new(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    pub fn read_bits(&mut self, num_bits: usize) -> Result<u64> {
        if num_bits == 0 || num_bits > 64 {
            return Err(anyhow!("Invalid number of bits: {}", num_bits));
        }

        let mut result: u64 = 0;
        let mut bits_remaining = num_bits;

        while bits_remaining > 0 {
            if self.byte_pos >= self.data.len() {
                return Err(anyhow!("Unexpected end of data"));
            }

            let bits_available_in_byte = 8 - self.bit_pos;
            let bits_to_read = bits_remaining.min(bits_available_in_byte as usize);

            let mask = ((1u16 << bits_to_read) - 1) as u8;
            let shift = bits_available_in_byte - bits_to_read as u8;
            let bits = (self.data[self.byte_pos] >> shift) & mask;

            result = (result << bits_to_read) | bits as u64;

            self.bit_pos += bits_to_read as u8;
            if self.bit_pos >= 8 {
                self.bit_pos = 0;
                self.byte_pos += 1;
            }

            bits_remaining -= bits_to_read;
        }

        Ok(result)
    }

    pub fn align_to_byte(&mut self) {
        if self.bit_pos != 0 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
    }

    pub fn read_bytes(&mut self, num_bytes: usize) -> Result<Vec<u8>> {
        self.align_to_byte();

        if self.byte_pos + num_bytes > self.data.len() {
            return Err(anyhow!("Not enough data: requested {} bytes, {} available",
                num_bytes, self.data.len() - self.byte_pos));
        }

        let bytes = self.data[self.byte_pos..self.byte_pos + num_bytes].to_vec();
        self.byte_pos += num_bytes;

        Ok(bytes)
    }

    pub fn read_length_determinant(&mut self) -> Result<usize> {
        let first_bit = self.read_bits(1)?;

        if first_bit == 0 {
            return Ok(self.read_bits(7)? as usize);
        }

        let second_bit = self.read_bits(1)?;

        if second_bit == 0 {
            return Ok(self.read_bits(14)? as usize);
        }

        let length_of_length = self.read_bits(6)? as usize;
        if length_of_length == 0 {
            return Err(anyhow!("Invalid length determinant"));
        }

        self.align_to_byte();
        let mut length = 0usize;
        for _ in 0..length_of_length {
            length = (length << 8) | self.read_bits(8)? as usize;
        }

        Ok(length)
    }

    pub fn read_constrained_integer(&mut self, min: i64, max: i64) -> Result<i64> {
        if min > max {
            return Err(anyhow!("Invalid constraint: min > max"));
        }

        let range = (max - min) as u64;

        if range == 0 {
            return Ok(min);
        }

        let bits_needed = (range as f64).log2().ceil() as usize;
        let bits_needed = bits_needed.max(1);

        let value = self.read_bits(bits_needed)?;
        Ok(min + value as i64)
    }

    pub fn read_unconstrained_integer(&mut self) -> Result<i64> {
        let length = self.read_length_determinant()?;
        self.align_to_byte();

        let bytes = self.read_bytes(length)?;

        if bytes.is_empty() {
            return Ok(0);
        }

        let mut result: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };

        for &byte in &bytes {
            result = (result << 8) | byte as i64;
        }

        Ok(result)
    }

    pub fn read_enumerated(&mut self, max_value: u64) -> Result<u64> {
        if max_value == 0 {
            return Ok(0);
        }

        let bits_needed = (max_value as f64).log2().ceil() as usize;
        let bits_needed = bits_needed.max(1);

        self.read_bits(bits_needed)
    }

    pub fn read_octet_string(&mut self) -> Result<Vec<u8>> {
        let length = self.read_length_determinant()?;
        self.align_to_byte();
        self.read_bytes(length)
    }

    pub fn read_bit_string(&mut self) -> Result<Vec<u8>> {
        let num_bits = self.read_length_determinant()?;

        let num_bytes = (num_bits + 7) / 8;
        let mut result = Vec::with_capacity(num_bytes);

        for _ in 0..num_bytes {
            let bits_to_read = num_bits.min(8);
            let byte = self.read_bits(bits_to_read)? as u8;
            result.push(byte);
        }

        Ok(result)
    }

    pub fn peek_bits(&self, num_bits: usize) -> Result<u64> {
        let mut temp_decoder = Self {
            data: self.data.clone(),
            byte_pos: self.byte_pos,
            bit_pos: self.bit_pos,
        };
        temp_decoder.read_bits(num_bits)
    }

    pub fn remaining_bytes(&self) -> usize {
        if self.byte_pos < self.data.len() {
            self.data.len() - self.byte_pos
        } else {
            0
        }
    }
}

pub struct NgapParser;

impl NgapParser {
    pub fn new() -> Self {
        Self
    }

    pub fn decode_per(data: &[u8]) -> Result<NgapPdu> {
        if data.is_empty() {
            return Err(anyhow!("NGAP data is empty"));
        }

        tracing::debug!("Decoding NGAP PDU from {} bytes", data.len());

        let mut decoder = PerDecoder::new(data);

        let pdu_type = decoder.read_constrained_integer(0, 2)?;
        tracing::debug!("NGAP PDU type: {}", pdu_type);

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("Extension present: {}", extension_present);

        let procedure_code = decoder.read_constrained_integer(0, 255)?;
        tracing::debug!("Procedure code: {}", procedure_code);

        let criticality = decoder.read_enumerated(2)?;
        tracing::debug!("Criticality: {}", criticality);

        decoder.align_to_byte();

        let value_length = decoder.read_length_determinant()?;
        tracing::debug!("Value length: {} bytes", value_length);

        let value_data = decoder.read_bytes(value_length)?;

        let mut value_decoder = PerDecoder::new(&value_data);

        let extension_flag = value_decoder.read_bits(1)? == 1;
        tracing::debug!("IE list extension flag: {}", extension_flag);

        let ie_count = value_decoder.read_constrained_integer(0, 65535)? as usize;
        tracing::debug!("IE count: {}", ie_count);

        let mut information_elements = Vec::new();

        for i in 0..ie_count {
            tracing::debug!("Parsing IE {}/{}", i + 1, ie_count);

            let ie_extension = value_decoder.read_bits(1)? == 1;
            tracing::debug!("  IE extension: {}", ie_extension);

            let ie_id = value_decoder.read_constrained_integer(0, 65535)? as u32;
            tracing::debug!("  IE ID: {}", ie_id);

            let ie_criticality = value_decoder.read_enumerated(2)?;
            tracing::debug!("  IE criticality: {}", ie_criticality);

            value_decoder.align_to_byte();

            let ie_value_length = value_decoder.read_length_determinant()?;
            tracing::debug!("  IE value length: {} bytes", ie_value_length);

            let ie_value_data = value_decoder.read_bytes(ie_value_length)?;

            information_elements.push(InformationElement {
                id: ie_id,
                criticality: match ie_criticality {
                    0 => IeCriticality::Reject,
                    1 => IeCriticality::Ignore,
                    2 => IeCriticality::Notify,
                    _ => return Err(anyhow!("Invalid IE criticality: {}", ie_criticality)),
                },
                value: Bytes::copy_from_slice(&ie_value_data),
            });
        }

        Ok(NgapPdu {
            raw_data: Bytes::copy_from_slice(data),
            pdu_type: match pdu_type {
                0 => PduType::InitiatingMessage,
                1 => PduType::SuccessfulOutcome,
                2 => PduType::UnsuccessfulOutcome,
                _ => return Err(anyhow!("Invalid PDU type: {}", pdu_type)),
            },
            procedure_code: procedure_code as u8,
            criticality: match criticality {
                0 => IeCriticality::Reject,
                1 => IeCriticality::Ignore,
                2 => IeCriticality::Notify,
                _ => return Err(anyhow!("Invalid criticality: {}", criticality)),
            },
            information_elements,
        })
    }

    pub fn extract_ie(&self, pdu: &NgapPdu, ie_id: u32) -> Result<Option<InformationElement>> {
        tracing::debug!(
            "Extracting IE with id {} from NGAP PDU ({} IEs)",
            ie_id,
            pdu.information_elements.len()
        );

        Ok(pdu.information_elements.iter()
            .find(|ie| ie.id == ie_id)
            .cloned())
    }

    pub fn extract_all_ies(&self, pdu: &NgapPdu) -> Vec<InformationElement> {
        pdu.information_elements.clone()
    }

    pub fn extract_gtp_tunnel(&self, pdu: &NgapPdu) -> Result<Option<GtpTunnel>> {
        let ie = self.extract_ie(pdu, ie_ids::GTP_TUNNEL)?;

        if let Some(ie) = ie {
            tracing::debug!("Decoding GTP Tunnel IE ({} bytes)", ie.value.len());

            let mut decoder = PerDecoder::new(&ie.value);

            let extension_present = decoder.read_bits(1)? == 1;
            tracing::debug!("GTP Tunnel extension present: {}", extension_present);

            let transport_layer_address = decoder.read_bit_string()?;
            tracing::debug!("Transport layer address: {} bytes", transport_layer_address.len());

            let gtp_teid = decoder.read_octet_string()?;
            tracing::debug!("GTP TEID: {} bytes", gtp_teid.len());

            if gtp_teid.len() != 4 {
                return Err(anyhow!("Invalid GTP TEID length: expected 4 bytes, got {}", gtp_teid.len()));
            }

            Ok(Some(GtpTunnel {
                transport_layer_address,
                gtp_teid,
            }))
        } else {
            tracing::debug!("GTP Tunnel IE not found in PDU");
            Ok(None)
        }
    }

    pub fn decode_gtp_tunnel(&self, data: &[u8]) -> Result<GtpTunnel> {
        let mut decoder = PerDecoder::new(data);

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("GTP Tunnel extension present: {}", extension_present);

        let transport_layer_address = decoder.read_bit_string()?;
        tracing::debug!("Transport layer address: {} bytes", transport_layer_address.len());

        let gtp_teid = decoder.read_octet_string()?;
        tracing::debug!("GTP TEID: {} bytes", gtp_teid.len());

        if gtp_teid.len() != 4 {
            return Err(anyhow!("Invalid GTP TEID length: expected 4 bytes, got {}", gtp_teid.len()));
        }

        Ok(GtpTunnel {
            transport_layer_address,
            gtp_teid,
        })
    }

    pub fn decode_security_result(&self, data: &[u8]) -> Result<SecurityResult> {
        let mut decoder = PerDecoder::new(data);

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("SecurityResult extension present: {}", extension_present);

        let integrity_protection_result = decoder.read_enumerated(1)?;
        let confidentiality_protection_result = decoder.read_enumerated(1)?;

        Ok(SecurityResult {
            integrity_protection_result: match integrity_protection_result {
                0 => IntegrityProtectionResult::Performed,
                1 => IntegrityProtectionResult::NotPerformed,
                _ => return Err(anyhow!("Invalid integrity protection result: {}", integrity_protection_result)),
            },
            confidentiality_protection_result: match confidentiality_protection_result {
                0 => ConfidentialityProtectionResult::Performed,
                1 => ConfidentialityProtectionResult::NotPerformed,
                _ => return Err(anyhow!("Invalid confidentiality protection result: {}", confidentiality_protection_result)),
            },
        })
    }

    pub fn decode_ngap_cause(&self, data: &[u8]) -> Result<NgapCause> {
        let mut decoder = PerDecoder::new(data);

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("NgapCause extension present: {}", extension_present);

        let cause_type = decoder.read_enumerated(4)?;

        match cause_type {
            0 => {
                let radio_network_cause = decoder.read_enumerated(45)?;
                Ok(NgapCause::RadioNetwork(match radio_network_cause {
                    0 => RadioNetworkCause::UnspecifiedRadioNetworkCause,
                    1 => RadioNetworkCause::TxnrelocoverallExpiry,
                    2 => RadioNetworkCause::SuccessfulHandover,
                    3 => RadioNetworkCause::ReleaseDueToNgranGeneratedReason,
                    4 => RadioNetworkCause::ReleaseDueToFiveGcGeneratedReason,
                    5 => RadioNetworkCause::HandoverCancelled,
                    6 => RadioNetworkCause::PartialHandover,
                    7 => RadioNetworkCause::HoFailureInTarget5GCNgranNode,
                    8 => RadioNetworkCause::HoTargetNotAllowed,
                    9 => RadioNetworkCause::TngrelocoverallExpiry,
                    10 => RadioNetworkCause::TngrelocprepExpiry,
                    11 => RadioNetworkCause::CellNotAvailable,
                    12 => RadioNetworkCause::UnknownTargetId,
                    13 => RadioNetworkCause::NoRadioResourcesAvailableInTargetCell,
                    14 => RadioNetworkCause::UnknownLocalUeNgapId,
                    15 => RadioNetworkCause::InconsistentRemoteUeNgapId,
                    16 => RadioNetworkCause::HandoverDesirableForRadioReason,
                    17 => RadioNetworkCause::TimeCriticalHandover,
                    18 => RadioNetworkCause::ResourceOptimisationHandover,
                    19 => RadioNetworkCause::ReduceLoadInServingCell,
                    20 => RadioNetworkCause::UserInactivity,
                    21 => RadioNetworkCause::RadioConnectionWithUeLost,
                    22 => RadioNetworkCause::RadioResourcesNotAvailable,
                    23 => RadioNetworkCause::InvalidQosCombination,
                    24 => RadioNetworkCause::FailureInRadioInterfaceProcedure,
                    25 => RadioNetworkCause::InteractionWithOtherProcedure,
                    26 => RadioNetworkCause::UnknownPduSessionId,
                    27 => RadioNetworkCause::UeRrcConnectionReestablishmentFailure,
                    28 => RadioNetworkCause::MultipleSessionsNotSupported,
                    29 => RadioNetworkCause::UeContextReestFailure,
                    30 => RadioNetworkCause::NgIntraSystemHandoverTriggered,
                    31 => RadioNetworkCause::NgInterSystemHandoverTriggered,
                    32 => RadioNetworkCause::XnHandoverTriggered,
                    33 => RadioNetworkCause::NotSupported5qiValue,
                    _ => RadioNetworkCause::UnspecifiedRadioNetworkCause,
                }))
            }
            1 => {
                let transport_cause = decoder.read_enumerated(1)?;
                Ok(NgapCause::Transport(match transport_cause {
                    0 => TransportCause::TransportResourceUnavailable,
                    1 => TransportCause::UnspecifiedTransportCause,
                    _ => TransportCause::UnspecifiedTransportCause,
                }))
            }
            2 => {
                let nas_cause = decoder.read_enumerated(3)?;
                Ok(NgapCause::Nas(match nas_cause {
                    0 => NasCause::NormalRelease,
                    1 => NasCause::AuthenticationFailure,
                    2 => NasCause::Deregister,
                    3 => NasCause::UnspecifiedNasCause,
                    _ => NasCause::UnspecifiedNasCause,
                }))
            }
            3 => {
                let protocol_cause = decoder.read_enumerated(6)?;
                Ok(NgapCause::Protocol(match protocol_cause {
                    0 => ProtocolCause::TransferSyntaxError,
                    1 => ProtocolCause::AbstractSyntaxErrorReject,
                    2 => ProtocolCause::AbstractSyntaxErrorIgnoreAndNotify,
                    3 => ProtocolCause::MessageNotCompatibleWithReceiverState,
                    4 => ProtocolCause::SemanticError,
                    5 => ProtocolCause::AbstractSyntaxErrorFalselyConstructedMessage,
                    6 => ProtocolCause::UnspecifiedProtocolCause,
                    _ => ProtocolCause::UnspecifiedProtocolCause,
                }))
            }
            4 => {
                let misc_cause = decoder.read_enumerated(5)?;
                Ok(NgapCause::Misc(match misc_cause {
                    0 => MiscCause::ControlProcessingOverload,
                    1 => MiscCause::NotEnoughUserPlaneProcessingResources,
                    2 => MiscCause::HardwareFailure,
                    3 => MiscCause::OmIntervention,
                    4 => MiscCause::UnknownPlmn,
                    5 => MiscCause::UnspecifiedMiscCause,
                    _ => MiscCause::UnspecifiedMiscCause,
                }))
            }
            _ => Err(anyhow!("Invalid NGAP cause type: {}", cause_type)),
        }
    }

    pub fn decode_qos_flow_with_cause_item(&self, data: &[u8]) -> Result<QosFlowWithCauseItem> {
        let mut decoder = PerDecoder::new(data);

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("QosFlowWithCauseItem extension present: {}", extension_present);

        let ie_count = decoder.read_constrained_integer(0, 65535)? as usize;
        tracing::debug!("QosFlowWithCauseItem IE count: {}", ie_count);

        let mut qos_flow_identifier = None;
        let mut cause = None;

        for _ in 0..ie_count {
            let ie_extension = decoder.read_bits(1)? == 1;
            let ie_id = decoder.read_constrained_integer(0, 65535)? as u32;
            let _ie_criticality = decoder.read_enumerated(2)?;
            decoder.align_to_byte();
            let ie_value_length = decoder.read_length_determinant()?;
            let ie_value_data = decoder.read_bytes(ie_value_length)?;

            match ie_id {
                0 => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    qos_flow_identifier = Some(ie_decoder.read_constrained_integer(0, 63)? as u8);
                }
                1 => {
                    cause = Some(self.decode_ngap_cause(&ie_value_data)?);
                }
                _ => {
                    tracing::debug!("Unknown IE in QosFlowWithCauseItem: {}", ie_id);
                }
            }
        }

        Ok(QosFlowWithCauseItem {
            qos_flow_identifier: qos_flow_identifier.ok_or_else(|| anyhow!("Missing QoS flow identifier"))?,
            cause: cause.ok_or_else(|| anyhow!("Missing cause"))?,
        })
    }

    pub fn decode_associated_qos_flow_item(&self, data: &[u8]) -> Result<AssociatedQosFlowItem> {
        let mut decoder = PerDecoder::new(data);

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("AssociatedQosFlowItem extension present: {}", extension_present);

        let optional_fields_bitmap = decoder.read_bits(1)?;
        let qos_flow_mapping_indication_present = optional_fields_bitmap == 1;

        let ie_count = decoder.read_constrained_integer(0, 65535)? as usize;
        tracing::debug!("AssociatedQosFlowItem IE count: {}", ie_count);

        let mut qos_flow_identifier = None;
        let mut qos_flow_mapping_indication = None;

        for _ in 0..ie_count {
            let ie_extension = decoder.read_bits(1)? == 1;
            let ie_id = decoder.read_constrained_integer(0, 65535)? as u32;
            let _ie_criticality = decoder.read_enumerated(2)?;
            decoder.align_to_byte();
            let ie_value_length = decoder.read_length_determinant()?;
            let ie_value_data = decoder.read_bytes(ie_value_length)?;

            match ie_id {
                0 => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    qos_flow_identifier = Some(ie_decoder.read_constrained_integer(0, 63)? as u8);
                }
                1 if qos_flow_mapping_indication_present => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    let mapping = ie_decoder.read_enumerated(1)?;
                    qos_flow_mapping_indication = Some(match mapping {
                        0 => QosFlowMappingIndication::Ul,
                        1 => QosFlowMappingIndication::Dl,
                        _ => return Err(anyhow!("Invalid QoS flow mapping indication: {}", mapping)),
                    });
                }
                _ => {
                    tracing::debug!("Unknown IE in AssociatedQosFlowItem: {}", ie_id);
                }
            }
        }

        Ok(AssociatedQosFlowItem {
            qos_flow_identifier: qos_flow_identifier.ok_or_else(|| anyhow!("Missing QoS flow identifier"))?,
            qos_flow_mapping_indication,
        })
    }

    pub fn decode_qos_flow_per_tnl_information(&self, data: &[u8]) -> Result<QosFlowPerTnlInformation> {
        let mut decoder = PerDecoder::new(data);

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("QosFlowPerTnlInformation extension present: {}", extension_present);

        let ie_count = decoder.read_constrained_integer(0, 65535)? as usize;
        tracing::debug!("QosFlowPerTnlInformation IE count: {}", ie_count);

        let mut up_transport_layer_information = None;
        let mut associated_qos_flow_list = Vec::new();

        for _ in 0..ie_count {
            let ie_extension = decoder.read_bits(1)? == 1;
            let ie_id = decoder.read_constrained_integer(0, 65535)? as u32;
            let _ie_criticality = decoder.read_enumerated(2)?;
            decoder.align_to_byte();
            let ie_value_length = decoder.read_length_determinant()?;
            let ie_value_data = decoder.read_bytes(ie_value_length)?;

            match ie_id {
                0 => {
                    up_transport_layer_information = Some(self.decode_gtp_tunnel(&ie_value_data)?);
                }
                1 => {
                    let mut list_decoder = PerDecoder::new(&ie_value_data);
                    let list_extension = list_decoder.read_bits(1)? == 1;
                    let list_count = list_decoder.read_constrained_integer(1, 64)? as usize;

                    for _ in 0..list_count {
                        list_decoder.align_to_byte();
                        let item_length = list_decoder.read_length_determinant()?;
                        let item_data = list_decoder.read_bytes(item_length)?;
                        associated_qos_flow_list.push(self.decode_associated_qos_flow_item(&item_data)?);
                    }
                }
                _ => {
                    tracing::debug!("Unknown IE in QosFlowPerTnlInformation: {}", ie_id);
                }
            }
        }

        Ok(QosFlowPerTnlInformation {
            up_transport_layer_information: up_transport_layer_information
                .ok_or_else(|| anyhow!("Missing UP transport layer information"))?,
            associated_qos_flow_list,
        })
    }

    pub fn decode_pdu_session_resource_setup_response_transfer(&self, data: &[u8]) -> Result<PduSessionResourceSetupResponseTransfer> {
        let mut decoder = PerDecoder::new(data);

        tracing::debug!("Decoding PDU Session Resource Setup Response Transfer ({} bytes)", data.len());

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("Extension present: {}", extension_present);

        let optional_fields_bitmap = decoder.read_bits(3)?;
        let additional_dl_qos_flow_per_tnl_information_present = (optional_fields_bitmap & 0x4) != 0;
        let security_result_present = (optional_fields_bitmap & 0x2) != 0;
        let qos_flow_failed_to_setup_list_present = (optional_fields_bitmap & 0x1) != 0;

        tracing::debug!("Optional fields - additional_dl: {}, security: {}, failed: {}",
            additional_dl_qos_flow_per_tnl_information_present,
            security_result_present,
            qos_flow_failed_to_setup_list_present);

        let ie_count = decoder.read_constrained_integer(0, 65535)? as usize;
        tracing::debug!("IE count: {}", ie_count);

        let mut dl_qos_flow_per_tnl_information = None;
        let mut additional_dl_qos_flow_per_tnl_information = None;
        let mut security_result = None;
        let mut qos_flow_failed_to_setup_list = None;

        for i in 0..ie_count {
            tracing::debug!("Parsing IE {}/{}", i + 1, ie_count);

            let ie_extension = decoder.read_bits(1)? == 1;
            let ie_id = decoder.read_constrained_integer(0, 65535)? as u32;
            let _ie_criticality = decoder.read_enumerated(2)?;
            decoder.align_to_byte();
            let ie_value_length = decoder.read_length_determinant()?;
            let ie_value_data = decoder.read_bytes(ie_value_length)?;

            tracing::debug!("  IE ID: {}, length: {} bytes", ie_id, ie_value_length);

            match ie_id {
                0 => {
                    dl_qos_flow_per_tnl_information = Some(self.decode_qos_flow_per_tnl_information(&ie_value_data)?);
                }
                1 if additional_dl_qos_flow_per_tnl_information_present => {
                    let mut list_decoder = PerDecoder::new(&ie_value_data);
                    let list_extension = list_decoder.read_bits(1)? == 1;
                    let list_count = list_decoder.read_constrained_integer(1, 3)? as usize;

                    let mut additional_list = Vec::new();
                    for _ in 0..list_count {
                        list_decoder.align_to_byte();
                        let item_length = list_decoder.read_length_determinant()?;
                        let item_data = list_decoder.read_bytes(item_length)?;
                        additional_list.push(self.decode_qos_flow_per_tnl_information(&item_data)?);
                    }
                    additional_dl_qos_flow_per_tnl_information = Some(additional_list);
                }
                2 if security_result_present => {
                    security_result = Some(self.decode_security_result(&ie_value_data)?);
                }
                3 if qos_flow_failed_to_setup_list_present => {
                    let mut list_decoder = PerDecoder::new(&ie_value_data);
                    let list_extension = list_decoder.read_bits(1)? == 1;
                    let list_count = list_decoder.read_constrained_integer(1, 64)? as usize;

                    let mut failed_list = Vec::new();
                    for _ in 0..list_count {
                        list_decoder.align_to_byte();
                        let item_length = list_decoder.read_length_determinant()?;
                        let item_data = list_decoder.read_bytes(item_length)?;
                        failed_list.push(self.decode_qos_flow_with_cause_item(&item_data)?);
                    }
                    qos_flow_failed_to_setup_list = Some(failed_list);
                }
                _ => {
                    tracing::debug!("Unknown IE in PduSessionResourceSetupResponseTransfer: {}", ie_id);
                }
            }
        }

        Ok(PduSessionResourceSetupResponseTransfer {
            dl_qos_flow_per_tnl_information: dl_qos_flow_per_tnl_information
                .ok_or_else(|| anyhow!("Missing DL QoS flow per TNL information"))?,
            additional_dl_qos_flow_per_tnl_information,
            security_result,
            qos_flow_failed_to_setup_list,
        })
    }

    pub fn extract_pdu_session_resource_setup_response_transfer(&self, ie_value: &[u8]) -> Result<PduSessionResourceSetupResponseTransfer> {
        self.decode_pdu_session_resource_setup_response_transfer(ie_value)
    }

    pub fn decode_qos_flow_accepted_item(&self, data: &[u8]) -> Result<QosFlowAcceptedItem> {
        let mut decoder = PerDecoder::new(data);

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("QosFlowAcceptedItem extension present: {}", extension_present);

        let ie_count = decoder.read_constrained_integer(0, 65535)? as usize;
        tracing::debug!("QosFlowAcceptedItem IE count: {}", ie_count);

        let mut qos_flow_identifier = None;

        for _ in 0..ie_count {
            let ie_extension = decoder.read_bits(1)? == 1;
            let ie_id = decoder.read_constrained_integer(0, 65535)? as u32;
            let _ie_criticality = decoder.read_enumerated(2)?;
            decoder.align_to_byte();
            let ie_value_length = decoder.read_length_determinant()?;
            let ie_value_data = decoder.read_bytes(ie_value_length)?;

            match ie_id {
                0 => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    qos_flow_identifier = Some(ie_decoder.read_constrained_integer(0, 63)? as u8);
                }
                _ => {
                    tracing::debug!("Unknown IE in QosFlowAcceptedItem: {}", ie_id);
                }
            }
        }

        Ok(QosFlowAcceptedItem {
            qos_flow_identifier: qos_flow_identifier.ok_or_else(|| anyhow!("Missing QoS flow identifier"))?,
        })
    }

    pub fn decode_security_indication(&self, data: &[u8]) -> Result<SecurityIndication> {
        let mut decoder = PerDecoder::new(data);

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("SecurityIndication extension present: {}", extension_present);

        let optional_fields_bitmap = decoder.read_bits(2)?;
        let max_integrity_protected_data_rate_ul_present = (optional_fields_bitmap & 0x2) != 0;
        let max_integrity_protected_data_rate_dl_present = (optional_fields_bitmap & 0x1) != 0;

        let ie_count = decoder.read_constrained_integer(0, 65535)? as usize;
        tracing::debug!("SecurityIndication IE count: {}", ie_count);

        let mut integrity_protection_indication = None;
        let mut confidentiality_protection_indication = None;
        let mut maximum_integrity_protected_data_rate_ul = None;
        let mut maximum_integrity_protected_data_rate_dl = None;

        for _ in 0..ie_count {
            let ie_extension = decoder.read_bits(1)? == 1;
            let ie_id = decoder.read_constrained_integer(0, 65535)? as u32;
            let _ie_criticality = decoder.read_enumerated(2)?;
            decoder.align_to_byte();
            let ie_value_length = decoder.read_length_determinant()?;
            let ie_value_data = decoder.read_bytes(ie_value_length)?;

            match ie_id {
                0 => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    let indication = ie_decoder.read_enumerated(2)?;
                    integrity_protection_indication = Some(match indication {
                        0 => IntegrityProtectionIndication::Required,
                        1 => IntegrityProtectionIndication::Preferred,
                        2 => IntegrityProtectionIndication::NotNeeded,
                        _ => return Err(anyhow!("Invalid integrity protection indication: {}", indication)),
                    });
                }
                1 => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    let indication = ie_decoder.read_enumerated(2)?;
                    confidentiality_protection_indication = Some(match indication {
                        0 => ConfidentialityProtectionIndication::Required,
                        1 => ConfidentialityProtectionIndication::Preferred,
                        2 => ConfidentialityProtectionIndication::NotNeeded,
                        _ => return Err(anyhow!("Invalid confidentiality protection indication: {}", indication)),
                    });
                }
                2 if max_integrity_protected_data_rate_ul_present => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    let rate = ie_decoder.read_enumerated(1)?;
                    maximum_integrity_protected_data_rate_ul = Some(match rate {
                        0 => MaximumIntegrityProtectedDataRate::Bitrate64kbs,
                        1 => MaximumIntegrityProtectedDataRate::MaximumUeRate,
                        _ => return Err(anyhow!("Invalid max integrity protected data rate UL: {}", rate)),
                    });
                }
                3 if max_integrity_protected_data_rate_dl_present => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    let rate = ie_decoder.read_enumerated(1)?;
                    maximum_integrity_protected_data_rate_dl = Some(match rate {
                        0 => MaximumIntegrityProtectedDataRate::Bitrate64kbs,
                        1 => MaximumIntegrityProtectedDataRate::MaximumUeRate,
                        _ => return Err(anyhow!("Invalid max integrity protected data rate DL: {}", rate)),
                    });
                }
                _ => {
                    tracing::debug!("Unknown IE in SecurityIndication: {}", ie_id);
                }
            }
        }

        Ok(SecurityIndication {
            integrity_protection_indication: integrity_protection_indication
                .ok_or_else(|| anyhow!("Missing integrity protection indication"))?,
            confidentiality_protection_indication: confidentiality_protection_indication
                .ok_or_else(|| anyhow!("Missing confidentiality protection indication"))?,
            maximum_integrity_protected_data_rate_ul,
            maximum_integrity_protected_data_rate_dl,
        })
    }

    pub fn decode_user_plane_security_information(&self, data: &[u8]) -> Result<UserPlaneSecurityInformation> {
        let mut decoder = PerDecoder::new(data);

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("UserPlaneSecurityInformation extension present: {}", extension_present);

        let ie_count = decoder.read_constrained_integer(0, 65535)? as usize;
        tracing::debug!("UserPlaneSecurityInformation IE count: {}", ie_count);

        let mut security_result = None;
        let mut security_indication = None;

        for _ in 0..ie_count {
            let ie_extension = decoder.read_bits(1)? == 1;
            let ie_id = decoder.read_constrained_integer(0, 65535)? as u32;
            let _ie_criticality = decoder.read_enumerated(2)?;
            decoder.align_to_byte();
            let ie_value_length = decoder.read_length_determinant()?;
            let ie_value_data = decoder.read_bytes(ie_value_length)?;

            match ie_id {
                0 => {
                    security_result = Some(self.decode_security_result(&ie_value_data)?);
                }
                1 => {
                    security_indication = Some(self.decode_security_indication(&ie_value_data)?);
                }
                _ => {
                    tracing::debug!("Unknown IE in UserPlaneSecurityInformation: {}", ie_id);
                }
            }
        }

        Ok(UserPlaneSecurityInformation {
            security_result: security_result.ok_or_else(|| anyhow!("Missing security result"))?,
            security_indication: security_indication.ok_or_else(|| anyhow!("Missing security indication"))?,
        })
    }

    pub fn decode_path_switch_request_transfer(&self, data: &[u8]) -> Result<PathSwitchRequestTransfer> {
        let mut decoder = PerDecoder::new(data);

        tracing::debug!("Decoding Path Switch Request Transfer ({} bytes)", data.len());

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("Extension present: {}", extension_present);

        let optional_fields_bitmap = decoder.read_bits(3)?;
        let dl_ngu_tnl_information_reused_present = (optional_fields_bitmap & 0x4) != 0;
        let user_plane_security_information_present = (optional_fields_bitmap & 0x2) != 0;
        let qos_flow_accepted_list_present = (optional_fields_bitmap & 0x1) != 0;

        tracing::debug!("Optional fields - tnl_reused: {}, security: {}, qos_accepted: {}",
            dl_ngu_tnl_information_reused_present,
            user_plane_security_information_present,
            qos_flow_accepted_list_present);

        let ie_count = decoder.read_constrained_integer(0, 65535)? as usize;
        tracing::debug!("IE count: {}", ie_count);

        let mut dl_ngu_up_tnl_information = None;
        let mut dl_ngu_tnl_information_reused = None;
        let mut user_plane_security_information = None;
        let mut qos_flow_accepted_list = None;

        for i in 0..ie_count {
            tracing::debug!("Parsing IE {}/{}", i + 1, ie_count);

            let ie_extension = decoder.read_bits(1)? == 1;
            let ie_id = decoder.read_constrained_integer(0, 65535)? as u32;
            let _ie_criticality = decoder.read_enumerated(2)?;
            decoder.align_to_byte();
            let ie_value_length = decoder.read_length_determinant()?;
            let ie_value_data = decoder.read_bytes(ie_value_length)?;

            tracing::debug!("  IE ID: {}, length: {} bytes", ie_id, ie_value_length);

            match ie_id {
                0 => {
                    dl_ngu_up_tnl_information = Some(self.decode_gtp_tunnel(&ie_value_data)?);
                }
                1 if dl_ngu_tnl_information_reused_present => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    let reused = ie_decoder.read_enumerated(0)?;
                    dl_ngu_tnl_information_reused = Some(match reused {
                        0 => DlNguTnlInformationReused::True,
                        _ => return Err(anyhow!("Invalid DL NGU TNL information reused value: {}", reused)),
                    });
                }
                2 if user_plane_security_information_present => {
                    user_plane_security_information = Some(self.decode_user_plane_security_information(&ie_value_data)?);
                }
                3 if qos_flow_accepted_list_present => {
                    let mut list_decoder = PerDecoder::new(&ie_value_data);
                    let list_extension = list_decoder.read_bits(1)? == 1;
                    let list_count = list_decoder.read_constrained_integer(1, 64)? as usize;

                    let mut accepted_list = Vec::new();
                    for _ in 0..list_count {
                        list_decoder.align_to_byte();
                        let item_length = list_decoder.read_length_determinant()?;
                        let item_data = list_decoder.read_bytes(item_length)?;
                        accepted_list.push(self.decode_qos_flow_accepted_item(&item_data)?);
                    }
                    qos_flow_accepted_list = Some(accepted_list);
                }
                _ => {
                    tracing::debug!("Unknown IE in PathSwitchRequestTransfer: {}", ie_id);
                }
            }
        }

        Ok(PathSwitchRequestTransfer {
            dl_ngu_up_tnl_information: dl_ngu_up_tnl_information
                .ok_or_else(|| anyhow!("Missing DL NGU UP TNL information"))?,
            dl_ngu_tnl_information_reused,
            user_plane_security_information,
            qos_flow_accepted_list,
        })
    }

    pub fn extract_path_switch_request_transfer(&self, ie_value: &[u8]) -> Result<PathSwitchRequestTransfer> {
        self.decode_path_switch_request_transfer(ie_value)
    }

    pub fn decode_packet_error_rate(&self, data: &[u8]) -> Result<PacketErrorRate> {
        let mut decoder = PerDecoder::new(data);

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("PacketErrorRate extension present: {}", extension_present);

        let ie_count = decoder.read_constrained_integer(0, 65535)? as usize;
        tracing::debug!("PacketErrorRate IE count: {}", ie_count);

        let mut per_scalar = None;
        let mut per_exponent = None;

        for _ in 0..ie_count {
            let _ie_extension = decoder.read_bits(1)? == 1;
            let ie_id = decoder.read_constrained_integer(0, 65535)? as u32;
            let _ie_criticality = decoder.read_enumerated(2)?;
            decoder.align_to_byte();
            let ie_value_length = decoder.read_length_determinant()?;
            let ie_value_data = decoder.read_bytes(ie_value_length)?;

            match ie_id {
                0 => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    per_scalar = Some(ie_decoder.read_constrained_integer(0, 9)? as u8);
                }
                1 => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    per_exponent = Some(ie_decoder.read_constrained_integer(0, 9)? as u8);
                }
                _ => {
                    tracing::debug!("Unknown IE in PacketErrorRate: {}", ie_id);
                }
            }
        }

        Ok(PacketErrorRate {
            per_scalar: per_scalar.ok_or_else(|| anyhow!("Missing PER scalar"))?,
            per_exponent: per_exponent.ok_or_else(|| anyhow!("Missing PER exponent"))?,
        })
    }

    pub fn decode_non_dynamic_5qi_descriptor(&self, data: &[u8]) -> Result<NonDynamic5qiDescriptor> {
        let mut decoder = PerDecoder::new(data);

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("NonDynamic5qiDescriptor extension present: {}", extension_present);

        let optional_fields_bitmap = decoder.read_bits(3)?;
        let priority_level_present = (optional_fields_bitmap & 0x4) != 0;
        let averaging_window_present = (optional_fields_bitmap & 0x2) != 0;
        let maximum_data_burst_volume_present = (optional_fields_bitmap & 0x1) != 0;

        let ie_count = decoder.read_constrained_integer(0, 65535)? as usize;
        tracing::debug!("NonDynamic5qiDescriptor IE count: {}", ie_count);

        let mut five_qi = None;
        let mut priority_level = None;
        let mut averaging_window = None;
        let mut maximum_data_burst_volume = None;

        for _ in 0..ie_count {
            let _ie_extension = decoder.read_bits(1)? == 1;
            let ie_id = decoder.read_constrained_integer(0, 65535)? as u32;
            let _ie_criticality = decoder.read_enumerated(2)?;
            decoder.align_to_byte();
            let ie_value_length = decoder.read_length_determinant()?;
            let ie_value_data = decoder.read_bytes(ie_value_length)?;

            match ie_id {
                0 => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    five_qi = Some(ie_decoder.read_constrained_integer(0, 255)? as u8);
                }
                1 if priority_level_present => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    priority_level = Some(ie_decoder.read_constrained_integer(1, 127)? as u8);
                }
                2 if averaging_window_present => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    averaging_window = Some(ie_decoder.read_constrained_integer(0, 4095)? as u32);
                }
                3 if maximum_data_burst_volume_present => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    maximum_data_burst_volume = Some(ie_decoder.read_constrained_integer(0, 4095)? as u32);
                }
                _ => {
                    tracing::debug!("Unknown IE in NonDynamic5qiDescriptor: {}", ie_id);
                }
            }
        }

        Ok(NonDynamic5qiDescriptor {
            five_qi: five_qi.ok_or_else(|| anyhow!("Missing 5QI"))?,
            priority_level,
            averaging_window,
            maximum_data_burst_volume,
        })
    }

    pub fn decode_dynamic_5qi_descriptor(&self, data: &[u8]) -> Result<Dynamic5qiDescriptor> {
        let mut decoder = PerDecoder::new(data);

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("Dynamic5qiDescriptor extension present: {}", extension_present);

        let optional_fields_bitmap = decoder.read_bits(2)?;
        let averaging_window_present = (optional_fields_bitmap & 0x2) != 0;
        let maximum_data_burst_volume_present = (optional_fields_bitmap & 0x1) != 0;

        let ie_count = decoder.read_constrained_integer(0, 65535)? as usize;
        tracing::debug!("Dynamic5qiDescriptor IE count: {}", ie_count);

        let mut priority_level = None;
        let mut packet_delay_budget = None;
        let mut packet_error_rate = None;
        let mut averaging_window = None;
        let mut maximum_data_burst_volume = None;

        for _ in 0..ie_count {
            let _ie_extension = decoder.read_bits(1)? == 1;
            let ie_id = decoder.read_constrained_integer(0, 65535)? as u32;
            let _ie_criticality = decoder.read_enumerated(2)?;
            decoder.align_to_byte();
            let ie_value_length = decoder.read_length_determinant()?;
            let ie_value_data = decoder.read_bytes(ie_value_length)?;

            match ie_id {
                0 => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    priority_level = Some(ie_decoder.read_constrained_integer(1, 127)? as u8);
                }
                1 => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    packet_delay_budget = Some(ie_decoder.read_constrained_integer(0, 1023)? as u32);
                }
                2 => {
                    packet_error_rate = Some(self.decode_packet_error_rate(&ie_value_data)?);
                }
                3 if averaging_window_present => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    averaging_window = Some(ie_decoder.read_constrained_integer(0, 4095)? as u32);
                }
                4 if maximum_data_burst_volume_present => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    maximum_data_burst_volume = Some(ie_decoder.read_constrained_integer(0, 4095)? as u32);
                }
                _ => {
                    tracing::debug!("Unknown IE in Dynamic5qiDescriptor: {}", ie_id);
                }
            }
        }

        Ok(Dynamic5qiDescriptor {
            priority_level: priority_level.ok_or_else(|| anyhow!("Missing priority level"))?,
            packet_delay_budget: packet_delay_budget.ok_or_else(|| anyhow!("Missing packet delay budget"))?,
            packet_error_rate: packet_error_rate.ok_or_else(|| anyhow!("Missing packet error rate"))?,
            averaging_window,
            maximum_data_burst_volume,
        })
    }

    pub fn decode_qos_characteristics(&self, data: &[u8]) -> Result<QosCharacteristics> {
        let mut decoder = PerDecoder::new(data);

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("QosCharacteristics extension present: {}", extension_present);

        let choice = decoder.read_enumerated(1)?;
        tracing::debug!("QosCharacteristics choice: {}", choice);

        decoder.align_to_byte();
        let value_length = decoder.read_length_determinant()?;
        let value_data = decoder.read_bytes(value_length)?;

        match choice {
            0 => {
                let descriptor = self.decode_non_dynamic_5qi_descriptor(&value_data)?;
                Ok(QosCharacteristics::NonDynamic5qi(descriptor))
            }
            1 => {
                let descriptor = self.decode_dynamic_5qi_descriptor(&value_data)?;
                Ok(QosCharacteristics::Dynamic5qi(descriptor))
            }
            _ => Err(anyhow!("Invalid QoS characteristics choice: {}", choice)),
        }
    }

    pub fn decode_allocation_and_retention_priority(&self, data: &[u8]) -> Result<AllocationAndRetentionPriority> {
        let mut decoder = PerDecoder::new(data);

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("AllocationAndRetentionPriority extension present: {}", extension_present);

        let ie_count = decoder.read_constrained_integer(0, 65535)? as usize;
        tracing::debug!("AllocationAndRetentionPriority IE count: {}", ie_count);

        let mut priority_level = None;
        let mut pre_emption_capability = None;
        let mut pre_emption_vulnerability = None;

        for _ in 0..ie_count {
            let _ie_extension = decoder.read_bits(1)? == 1;
            let ie_id = decoder.read_constrained_integer(0, 65535)? as u32;
            let _ie_criticality = decoder.read_enumerated(2)?;
            decoder.align_to_byte();
            let ie_value_length = decoder.read_length_determinant()?;
            let ie_value_data = decoder.read_bytes(ie_value_length)?;

            match ie_id {
                0 => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    priority_level = Some(ie_decoder.read_constrained_integer(1, 15)? as u8);
                }
                1 => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    let capability = ie_decoder.read_enumerated(1)?;
                    pre_emption_capability = Some(match capability {
                        0 => PreEmptionCapability::ShallNotTriggerPreEmption,
                        1 => PreEmptionCapability::MayTriggerPreEmption,
                        _ => return Err(anyhow!("Invalid pre-emption capability: {}", capability)),
                    });
                }
                2 => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    let vulnerability = ie_decoder.read_enumerated(1)?;
                    pre_emption_vulnerability = Some(match vulnerability {
                        0 => PreEmptionVulnerability::NotPreEmptable,
                        1 => PreEmptionVulnerability::PreEmptable,
                        _ => return Err(anyhow!("Invalid pre-emption vulnerability: {}", vulnerability)),
                    });
                }
                _ => {
                    tracing::debug!("Unknown IE in AllocationAndRetentionPriority: {}", ie_id);
                }
            }
        }

        Ok(AllocationAndRetentionPriority {
            priority_level: priority_level.ok_or_else(|| anyhow!("Missing priority level"))?,
            pre_emption_capability: pre_emption_capability.ok_or_else(|| anyhow!("Missing pre-emption capability"))?,
            pre_emption_vulnerability: pre_emption_vulnerability.ok_or_else(|| anyhow!("Missing pre-emption vulnerability"))?,
        })
    }

    pub fn decode_gbr_qos_flow_information(&self, data: &[u8]) -> Result<GbrQosFlowInformation> {
        let mut decoder = PerDecoder::new(data);

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("GbrQosFlowInformation extension present: {}", extension_present);

        let optional_fields_bitmap = decoder.read_bits(3)?;
        let notification_control_present = (optional_fields_bitmap & 0x4) != 0;
        let maximum_packet_loss_rate_dl_present = (optional_fields_bitmap & 0x2) != 0;
        let maximum_packet_loss_rate_ul_present = (optional_fields_bitmap & 0x1) != 0;

        let ie_count = decoder.read_constrained_integer(0, 65535)? as usize;
        tracing::debug!("GbrQosFlowInformation IE count: {}", ie_count);

        let mut maximum_flow_bit_rate_dl = None;
        let mut maximum_flow_bit_rate_ul = None;
        let mut guaranteed_flow_bit_rate_dl = None;
        let mut guaranteed_flow_bit_rate_ul = None;
        let mut notification_control = None;
        let mut maximum_packet_loss_rate_dl = None;
        let mut maximum_packet_loss_rate_ul = None;

        for _ in 0..ie_count {
            let _ie_extension = decoder.read_bits(1)? == 1;
            let ie_id = decoder.read_constrained_integer(0, 65535)? as u32;
            let _ie_criticality = decoder.read_enumerated(2)?;
            decoder.align_to_byte();
            let ie_value_length = decoder.read_length_determinant()?;
            let ie_value_data = decoder.read_bytes(ie_value_length)?;

            match ie_id {
                0 => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    maximum_flow_bit_rate_dl = Some(ie_decoder.read_constrained_integer(0, 4000000000000)? as u64);
                }
                1 => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    maximum_flow_bit_rate_ul = Some(ie_decoder.read_constrained_integer(0, 4000000000000)? as u64);
                }
                2 => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    guaranteed_flow_bit_rate_dl = Some(ie_decoder.read_constrained_integer(0, 4000000000000)? as u64);
                }
                3 => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    guaranteed_flow_bit_rate_ul = Some(ie_decoder.read_constrained_integer(0, 4000000000000)? as u64);
                }
                4 if notification_control_present => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    let control = ie_decoder.read_enumerated(0)?;
                    notification_control = Some(match control {
                        0 => NotificationControl::NotificationRequested,
                        _ => return Err(anyhow!("Invalid notification control: {}", control)),
                    });
                }
                5 if maximum_packet_loss_rate_dl_present => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    maximum_packet_loss_rate_dl = Some(ie_decoder.read_constrained_integer(0, 1000)? as u16);
                }
                6 if maximum_packet_loss_rate_ul_present => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    maximum_packet_loss_rate_ul = Some(ie_decoder.read_constrained_integer(0, 1000)? as u16);
                }
                _ => {
                    tracing::debug!("Unknown IE in GbrQosFlowInformation: {}", ie_id);
                }
            }
        }

        Ok(GbrQosFlowInformation {
            maximum_flow_bit_rate_dl: maximum_flow_bit_rate_dl.ok_or_else(|| anyhow!("Missing maximum flow bit rate DL"))?,
            maximum_flow_bit_rate_ul: maximum_flow_bit_rate_ul.ok_or_else(|| anyhow!("Missing maximum flow bit rate UL"))?,
            guaranteed_flow_bit_rate_dl: guaranteed_flow_bit_rate_dl.ok_or_else(|| anyhow!("Missing guaranteed flow bit rate DL"))?,
            guaranteed_flow_bit_rate_ul: guaranteed_flow_bit_rate_ul.ok_or_else(|| anyhow!("Missing guaranteed flow bit rate UL"))?,
            notification_control,
            maximum_packet_loss_rate_dl,
            maximum_packet_loss_rate_ul,
        })
    }

    pub fn decode_qos_flow_level_qos_parameters(&self, data: &[u8]) -> Result<QosFlowLevelQosParameters> {
        let mut decoder = PerDecoder::new(data);

        tracing::debug!("Decoding QoS Flow Level QoS Parameters ({} bytes)", data.len());

        let extension_present = decoder.read_bits(1)? == 1;
        tracing::debug!("Extension present: {}", extension_present);

        let optional_fields_bitmap = decoder.read_bits(3)?;
        let gbr_qos_flow_information_present = (optional_fields_bitmap & 0x4) != 0;
        let reflective_qos_attribute_present = (optional_fields_bitmap & 0x2) != 0;
        let additional_qos_flow_information_present = (optional_fields_bitmap & 0x1) != 0;

        tracing::debug!("Optional fields - gbr: {}, reflective: {}, additional: {}",
            gbr_qos_flow_information_present,
            reflective_qos_attribute_present,
            additional_qos_flow_information_present);

        let ie_count = decoder.read_constrained_integer(0, 65535)? as usize;
        tracing::debug!("IE count: {}", ie_count);

        let mut qos_characteristics = None;
        let mut allocation_and_retention_priority = None;
        let mut gbr_qos_flow_information = None;
        let mut reflective_qos_attribute = None;
        let mut additional_qos_flow_information = None;

        for i in 0..ie_count {
            tracing::debug!("Parsing IE {}/{}", i + 1, ie_count);

            let _ie_extension = decoder.read_bits(1)? == 1;
            let ie_id = decoder.read_constrained_integer(0, 65535)? as u32;
            let _ie_criticality = decoder.read_enumerated(2)?;
            decoder.align_to_byte();
            let ie_value_length = decoder.read_length_determinant()?;
            let ie_value_data = decoder.read_bytes(ie_value_length)?;

            tracing::debug!("  IE ID: {}, length: {} bytes", ie_id, ie_value_length);

            match ie_id {
                0 => {
                    qos_characteristics = Some(self.decode_qos_characteristics(&ie_value_data)?);
                }
                1 => {
                    allocation_and_retention_priority = Some(self.decode_allocation_and_retention_priority(&ie_value_data)?);
                }
                2 if gbr_qos_flow_information_present => {
                    gbr_qos_flow_information = Some(self.decode_gbr_qos_flow_information(&ie_value_data)?);
                }
                3 if reflective_qos_attribute_present => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    let attribute = ie_decoder.read_enumerated(0)?;
                    reflective_qos_attribute = Some(match attribute {
                        0 => ReflectiveQosAttribute::SubjectTo,
                        _ => return Err(anyhow!("Invalid reflective QoS attribute: {}", attribute)),
                    });
                }
                4 if additional_qos_flow_information_present => {
                    let mut ie_decoder = PerDecoder::new(&ie_value_data);
                    let info = ie_decoder.read_enumerated(0)?;
                    additional_qos_flow_information = Some(match info {
                        0 => AdditionalQosFlowInformation::MoreLikely,
                        _ => return Err(anyhow!("Invalid additional QoS flow information: {}", info)),
                    });
                }
                _ => {
                    tracing::debug!("Unknown IE in QosFlowLevelQosParameters: {}", ie_id);
                }
            }
        }

        Ok(QosFlowLevelQosParameters {
            qos_characteristics: qos_characteristics.ok_or_else(|| anyhow!("Missing QoS characteristics"))?,
            allocation_and_retention_priority: allocation_and_retention_priority.ok_or_else(|| anyhow!("Missing allocation and retention priority"))?,
            gbr_qos_flow_information,
            reflective_qos_attribute,
            additional_qos_flow_information,
        })
    }

    pub fn extract_qos_flow_level_qos_parameters(&self, pdu: &NgapPdu) -> Result<Option<QosFlowLevelQosParameters>> {
        let ie = self.extract_ie(pdu, ie_ids::QOS_FLOW_LEVEL_QOS_PARAMETERS)?;

        if let Some(ie) = ie {
            tracing::debug!("Decoding QoS Flow Level QoS Parameters IE ({} bytes)", ie.value.len());
            Ok(Some(self.decode_qos_flow_level_qos_parameters(&ie.value)?))
        } else {
            tracing::debug!("QoS Flow Level QoS Parameters IE not found in PDU");
            Ok(None)
        }
    }
}

impl Default for NgapParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduType {
    InitiatingMessage,
    SuccessfulOutcome,
    UnsuccessfulOutcome,
}

#[derive(Debug, Clone)]
pub struct NgapPdu {
    pub raw_data: Bytes,
    pub pdu_type: PduType,
    pub procedure_code: u8,
    pub criticality: IeCriticality,
    pub information_elements: Vec<InformationElement>,
}

impl NgapPdu {
    pub fn len(&self) -> usize {
        self.raw_data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.raw_data.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.raw_data
    }

    pub fn get_ie(&self, ie_id: u32) -> Option<&InformationElement> {
        self.information_elements.iter().find(|ie| ie.id == ie_id)
    }

    pub fn has_ie(&self, ie_id: u32) -> bool {
        self.information_elements.iter().any(|ie| ie.id == ie_id)
    }
}

#[derive(Debug, Clone)]
pub struct InformationElement {
    pub id: u32,
    pub criticality: IeCriticality,
    pub value: Bytes,
}

impl InformationElement {
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }

    pub fn decode_integer(&self, min: i64, max: i64) -> Result<i64> {
        let mut decoder = PerDecoder::new(&self.value);
        decoder.read_constrained_integer(min, max)
    }

    pub fn decode_octet_string(&self) -> Result<Vec<u8>> {
        let mut decoder = PerDecoder::new(&self.value);
        decoder.read_octet_string()
    }

    pub fn decode_bit_string(&self) -> Result<Vec<u8>> {
        let mut decoder = PerDecoder::new(&self.value);
        decoder.read_bit_string()
    }

    pub fn decode_enumerated(&self, max_value: u64) -> Result<u64> {
        let mut decoder = PerDecoder::new(&self.value);
        decoder.read_enumerated(max_value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IeCriticality {
    Reject,
    Ignore,
    Notify,
}

pub mod ie_ids {
    pub const AMF_UE_NGAP_ID: u32 = 10;
    pub const RAN_UE_NGAP_ID: u32 = 85;
    pub const PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ: u32 = 74;
    pub const PDU_SESSION_RESOURCE_SETUP_LIST_SU_RES: u32 = 75;
    pub const PDU_SESSION_RESOURCE_FAILED_TO_SETUP_LIST_SU_RES: u32 = 76;
    pub const PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_REQ: u32 = 77;
    pub const PDU_SESSION_RESOURCE_MODIFY_LIST_MOD_RES: u32 = 78;
    pub const PDU_SESSION_RESOURCE_FAILED_TO_MODIFY_LIST_MOD_RES: u32 = 79;
    pub const PDU_SESSION_RESOURCE_RELEASE_COMMAND_TRANSFER: u32 = 80;
    pub const PDU_SESSION_RESOURCE_RELEASE_RESPONSE_TRANSFER: u32 = 81;
    pub const PATH_SWITCH_REQUEST_TRANSFER: u32 = 82;
    pub const PATH_SWITCH_REQUEST_ACK_TRANSFER: u32 = 83;
    pub const USER_LOCATION_INFORMATION: u32 = 121;
    pub const GTP_TUNNEL: u32 = 122;
    pub const QOS_FLOW_SETUP_REQUEST_LIST: u32 = 136;
    pub const QOS_FLOW_SETUP_RESPONSE_LIST: u32 = 137;
    pub const QOS_FLOW_LEVEL_QOS_PARAMETERS: u32 = 135;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_per_decoder_read_bits() {
        let data = vec![0b11010110, 0b10101100];
        let mut decoder = PerDecoder::new(&data);

        assert_eq!(decoder.read_bits(1).unwrap(), 1);
        assert_eq!(decoder.read_bits(2).unwrap(), 0b10);
        assert_eq!(decoder.read_bits(3).unwrap(), 0b101);
        assert_eq!(decoder.read_bits(4).unwrap(), 0b1010);
    }

    #[test]
    fn test_per_decoder_read_bytes() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let mut decoder = PerDecoder::new(&data);

        let bytes = decoder.read_bytes(2).unwrap();
        assert_eq!(bytes, vec![0x01, 0x02]);

        let bytes = decoder.read_bytes(2).unwrap();
        assert_eq!(bytes, vec![0x03, 0x04]);
    }

    #[test]
    fn test_per_decoder_align_to_byte() {
        let data = vec![0xFF, 0xFF];
        let mut decoder = PerDecoder::new(&data);

        decoder.read_bits(3).unwrap();
        assert_eq!(decoder.bit_pos, 3);

        decoder.align_to_byte();
        assert_eq!(decoder.bit_pos, 0);
        assert_eq!(decoder.byte_pos, 1);
    }

    #[test]
    fn test_per_decoder_length_determinant_short() {
        let data = vec![0b00001010, 0xFF];
        let mut decoder = PerDecoder::new(&data);

        let length = decoder.read_length_determinant().unwrap();
        assert_eq!(length, 10);
    }

    #[test]
    fn test_per_decoder_length_determinant_medium() {
        let data = vec![0b10000000, 0b01000000, 0xFF];
        let mut decoder = PerDecoder::new(&data);

        let length = decoder.read_length_determinant().unwrap();
        assert_eq!(length, 64);
    }

    #[test]
    fn test_per_decoder_constrained_integer() {
        let data = vec![0b11100000];
        let mut decoder = PerDecoder::new(&data);

        let value = decoder.read_constrained_integer(0, 7).unwrap();
        assert_eq!(value, 7);
    }

    #[test]
    fn test_per_decoder_constrained_integer_single_value() {
        let data = vec![0x00];
        let mut decoder = PerDecoder::new(&data);

        let value = decoder.read_constrained_integer(5, 5).unwrap();
        assert_eq!(value, 5);
    }

    #[test]
    fn test_per_decoder_enumerated() {
        let data = vec![0b11000000];
        let mut decoder = PerDecoder::new(&data);

        let value = decoder.read_enumerated(3).unwrap();
        assert_eq!(value, 3);
    }

    #[test]
    fn test_per_decoder_octet_string() {
        let data = vec![0b00000100, 0x01, 0x02, 0x03, 0x04];
        let mut decoder = PerDecoder::new(&data);

        let octets = decoder.read_octet_string().unwrap();
        assert_eq!(octets, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_per_decoder_remaining_bytes() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let mut decoder = PerDecoder::new(&data);

        assert_eq!(decoder.remaining_bytes(), 4);

        decoder.read_bytes(2).unwrap();
        assert_eq!(decoder.remaining_bytes(), 2);
    }

    #[test]
    fn test_per_decoder_peek_bits() {
        let data = vec![0b11010110];
        let decoder = PerDecoder::new(&data);

        assert_eq!(decoder.peek_bits(4).unwrap(), 0b1101);
        assert_eq!(decoder.byte_pos, 0);
        assert_eq!(decoder.bit_pos, 0);
    }

    #[test]
    fn test_ngap_parser_creation() {
        let _parser = NgapParser::new();
    }

    #[test]
    fn test_ngap_pdu_decode_empty() {
        let result = NgapParser::decode_per(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_ngap_pdu_decode_minimal() {
        let mut data = vec![0x00];
        data.push(0x00);
        data.push(0x00);
        data.push(0x00);
        data.push(0x00);
        data.push(0x01);
        data.push(0x00);
        data.push(0x00);

        let result = NgapParser::decode_per(&data);
        if let Ok(pdu) = result {
            assert_eq!(pdu.pdu_type, PduType::InitiatingMessage);
            assert!(!pdu.is_empty());
        }
    }

    #[test]
    fn test_ngap_pdu_get_ie() {
        let pdu = NgapPdu {
            raw_data: Bytes::from_static(&[0x00, 0x01, 0x02]),
            pdu_type: PduType::InitiatingMessage,
            procedure_code: 0,
            criticality: IeCriticality::Reject,
            information_elements: vec![
                InformationElement {
                    id: 10,
                    criticality: IeCriticality::Reject,
                    value: Bytes::from_static(&[0x01, 0x02]),
                },
                InformationElement {
                    id: 85,
                    criticality: IeCriticality::Ignore,
                    value: Bytes::from_static(&[0x03, 0x04]),
                },
            ],
        };

        assert!(pdu.has_ie(10));
        assert!(pdu.has_ie(85));
        assert!(!pdu.has_ie(99));

        let ie = pdu.get_ie(10);
        assert!(ie.is_some());
        assert_eq!(ie.unwrap().id, 10);
    }

    #[test]
    fn test_ngap_ie_decode_methods() {
        let ie = InformationElement {
            id: 10,
            criticality: IeCriticality::Reject,
            value: Bytes::from_static(&[0b00000100, 0x01, 0x02, 0x03, 0x04]),
        };

        let octets = ie.decode_octet_string();
        assert!(octets.is_ok());
        assert_eq!(octets.unwrap(), vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_ngap_parser_extract_ie() {
        let parser = NgapParser::new();
        let pdu = NgapPdu {
            raw_data: Bytes::from_static(&[0x00, 0x01, 0x02]),
            pdu_type: PduType::SuccessfulOutcome,
            procedure_code: 1,
            criticality: IeCriticality::Ignore,
            information_elements: vec![
                InformationElement {
                    id: 121,
                    criticality: IeCriticality::Reject,
                    value: Bytes::from_static(&[0x01, 0x02]),
                },
            ],
        };

        let ie = parser.extract_ie(&pdu, 121).unwrap();
        assert!(ie.is_some());
        assert_eq!(ie.unwrap().id, 121);

        let ie_missing = parser.extract_ie(&pdu, 999).unwrap();
        assert!(ie_missing.is_none());
    }

    #[test]
    fn test_ngap_parser_extract_all_ies() {
        let parser = NgapParser::new();
        let pdu = NgapPdu {
            raw_data: Bytes::from_static(&[0x00, 0x01, 0x02]),
            pdu_type: PduType::UnsuccessfulOutcome,
            procedure_code: 2,
            criticality: IeCriticality::Notify,
            information_elements: vec![
                InformationElement {
                    id: 10,
                    criticality: IeCriticality::Reject,
                    value: Bytes::from_static(&[0x01]),
                },
                InformationElement {
                    id: 85,
                    criticality: IeCriticality::Ignore,
                    value: Bytes::from_static(&[0x02]),
                },
            ],
        };

        let all_ies = parser.extract_all_ies(&pdu);
        assert_eq!(all_ies.len(), 2);
        assert_eq!(all_ies[0].id, 10);
        assert_eq!(all_ies[1].id, 85);
    }

    #[test]
    fn test_extract_gtp_tunnel_ipv4() {
        let parser = NgapParser::new();

        let mut gtp_tunnel_data = Vec::new();
        gtp_tunnel_data.push(0x10);
        gtp_tunnel_data.push(0x60);
        gtp_tunnel_data.push(0x54);
        gtp_tunnel_data.push(0x00);
        gtp_tunnel_data.push(0x85);
        gtp_tunnel_data.push(0x02);
        gtp_tunnel_data.push(0x00);

        gtp_tunnel_data.push(0x12);
        gtp_tunnel_data.push(0x34);
        gtp_tunnel_data.push(0x56);
        gtp_tunnel_data.push(0x78);

        let pdu = NgapPdu {
            raw_data: Bytes::from_static(&[0x00]),
            pdu_type: PduType::SuccessfulOutcome,
            procedure_code: 1,
            criticality: IeCriticality::Reject,
            information_elements: vec![
                InformationElement {
                    id: ie_ids::GTP_TUNNEL,
                    criticality: IeCriticality::Reject,
                    value: Bytes::from(gtp_tunnel_data),
                },
            ],
        };

        let result = parser.extract_gtp_tunnel(&pdu);
        if let Err(e) = &result {
            eprintln!("Error: {:?}", e);
        }
        assert!(result.is_ok());

        let gtp_tunnel = result.unwrap();
        assert!(gtp_tunnel.is_some());

        let tunnel = gtp_tunnel.unwrap();
        assert_eq!(tunnel.transport_layer_address.len(), 4);
        assert_eq!(tunnel.gtp_teid.len(), 4);

        let ip = tunnel.get_ip_address();
        assert!(ip.is_some());
        assert_eq!(ip.unwrap(), "192.168.1.10");

        let teid = tunnel.get_teid();
        assert!(teid.is_some());
        assert_eq!(teid.unwrap(), 0x12345678);
    }

    #[test]
    fn test_extract_gtp_tunnel_not_found() {
        let parser = NgapParser::new();
        let pdu = NgapPdu {
            raw_data: Bytes::from_static(&[0x00]),
            pdu_type: PduType::InitiatingMessage,
            procedure_code: 0,
            criticality: IeCriticality::Reject,
            information_elements: vec![],
        };

        let result = parser.extract_gtp_tunnel(&pdu);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_extract_gtp_tunnel_invalid_teid_length() {
        let parser = NgapParser::new();

        let mut gtp_tunnel_data = Vec::new();
        gtp_tunnel_data.push(0x10);
        gtp_tunnel_data.push(0x60);
        gtp_tunnel_data.push(0x54);
        gtp_tunnel_data.push(0x00);
        gtp_tunnel_data.push(0x85);
        gtp_tunnel_data.push(0x01);
        gtp_tunnel_data.push(0x80);

        gtp_tunnel_data.push(0x12);
        gtp_tunnel_data.push(0x34);
        gtp_tunnel_data.push(0x56);

        let pdu = NgapPdu {
            raw_data: Bytes::from_static(&[0x00]),
            pdu_type: PduType::SuccessfulOutcome,
            procedure_code: 1,
            criticality: IeCriticality::Reject,
            information_elements: vec![
                InformationElement {
                    id: ie_ids::GTP_TUNNEL,
                    criticality: IeCriticality::Reject,
                    value: Bytes::from(gtp_tunnel_data),
                },
            ],
        };

        let result = parser.extract_gtp_tunnel(&pdu);
        assert!(result.is_err());
    }

}
