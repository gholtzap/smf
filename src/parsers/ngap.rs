use anyhow::{anyhow, Result};
use bytes::Bytes;

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

        Ok(NgapPdu {
            raw_data: Bytes::copy_from_slice(data),
        })
    }

    pub fn extract_ie(&self, pdu: &NgapPdu, ie_id: u32) -> Result<Option<InformationElement>> {
        tracing::debug!(
            "Extracting IE with id {} from NGAP PDU ({} bytes)",
            ie_id,
            pdu.raw_data.len()
        );

        Ok(None)
    }
}

impl Default for NgapParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct NgapPdu {
    pub raw_data: Bytes,
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
}

#[derive(Debug, Clone)]
pub struct InformationElement {
    pub id: u32,
    pub criticality: IeCriticality,
    pub value: Bytes,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ngap_parser_creation() {
        let parser = NgapParser::new();
        assert!(parser.extract_ie(&NgapPdu { raw_data: Bytes::new() }, 0).is_ok());
    }

    #[test]
    fn test_ngap_pdu_decode_empty() {
        let result = NgapParser::decode_per(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_ngap_pdu_decode_with_data() {
        let data = vec![0x00, 0x01, 0x02, 0x03];
        let result = NgapParser::decode_per(&data);
        assert!(result.is_ok());
        let pdu = result.unwrap();
        assert_eq!(pdu.len(), 4);
        assert!(!pdu.is_empty());
    }
}
