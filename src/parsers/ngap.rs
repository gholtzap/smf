use anyhow::{anyhow, Result};
use bytes::Bytes;

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
