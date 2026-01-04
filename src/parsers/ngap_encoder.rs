use anyhow::{anyhow, Result};
use std::net::Ipv4Addr;

pub struct NgapEncoder {
    buf: Vec<u8>,
    bit_pos: u8,
}

impl NgapEncoder {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            bit_pos: 0,
        }
    }

    pub fn finish(mut self) -> Vec<u8> {
        if self.bit_pos > 0 {
            self.buf.push(0);
        }
        self.buf
    }

    fn write_bit(&mut self, bit: bool) {
        if self.bit_pos == 0 {
            self.buf.push(0);
        }
        let byte_idx = self.buf.len() - 1;
        if bit {
            self.buf[byte_idx] |= 1 << (7 - self.bit_pos);
        }
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
        }
    }

    fn write_bits(&mut self, value: u64, num_bits: usize) {
        for i in (0..num_bits).rev() {
            let bit = ((value >> i) & 1) == 1;
            self.write_bit(bit);
        }
    }

    fn align_to_byte(&mut self) {
        if self.bit_pos > 0 {
            self.bit_pos = 0;
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.align_to_byte();
        self.buf.extend_from_slice(bytes);
    }

    fn write_length(&mut self, length: usize) {
        if length < 128 {
            self.write_bits(0, 1);
            self.write_bits(length as u64, 7);
        } else if length < 16384 {
            self.write_bits(1, 1);
            self.write_bits(0, 1);
            self.write_bits(length as u64, 14);
        } else {
            self.write_bits(1, 1);
            self.write_bits(1, 1);
            let num_fragments = (length + 16383) / 16384;
            self.write_bits(num_fragments as u64, 6);
        }
    }

    fn write_integer(&mut self, value: i64, min: i64, max: i64) -> Result<()> {
        if value < min || value > max {
            return Err(anyhow!("Value {} out of range [{}, {}]", value, min, max));
        }
        let range = (max - min + 1) as u64;
        let normalized = (value - min) as u64;

        let bits_needed = if range <= 1 {
            0
        } else {
            64 - (range - 1).leading_zeros() as usize
        };

        if bits_needed > 0 {
            self.write_bits(normalized, bits_needed);
        }
        Ok(())
    }

    fn write_octet_string(&mut self, data: &[u8]) {
        self.write_length(data.len());
        self.write_bytes(data);
    }

    fn write_protocol_ie(&mut self, ie_id: u16, criticality: u8, value: &[u8]) {
        self.write_bits(ie_id as u64, 16);
        self.write_bits(criticality as u64, 2);
        self.align_to_byte();
        self.write_length(value.len());
        self.write_bytes(value);
    }
}

pub fn encode_pdu_session_resource_setup_request_transfer(
    session_ambr_dl: u64,
    session_ambr_ul: u64,
    upf_teid: u32,
    upf_ipv4: Ipv4Addr,
    qfi: u8,
) -> Result<Vec<u8>> {
    let mut encoder = NgapEncoder::new();

    encoder.write_bit(false);

    let num_ies = 3;
    encoder.write_integer(num_ies - 1, 0, 65535)?;

    let mut session_ambr_encoder = NgapEncoder::new();
    session_ambr_encoder.write_octet_string(&session_ambr_dl.to_be_bytes());
    session_ambr_encoder.write_octet_string(&session_ambr_ul.to_be_bytes());
    let session_ambr_value = session_ambr_encoder.finish();
    encoder.write_protocol_ie(132, 0, &session_ambr_value);

    let mut tunnel_encoder = NgapEncoder::new();
    tunnel_encoder.write_bit(false);
    tunnel_encoder.align_to_byte();
    let mut tunnel_data = Vec::new();
    tunnel_data.push(0x01);
    tunnel_data.extend_from_slice(&upf_teid.to_be_bytes());
    tunnel_data.extend_from_slice(&upf_ipv4.octets());
    tunnel_encoder.write_octet_string(&tunnel_data);
    let tunnel_value = tunnel_encoder.finish();
    encoder.write_protocol_ie(133, 1, &tunnel_value);

    let mut qos_flow_encoder = NgapEncoder::new();
    qos_flow_encoder.write_integer(0, 0, 65535)?;

    let mut flow_item_encoder = NgapEncoder::new();
    flow_item_encoder.write_bit(false);

    let num_flow_ies = 1;
    flow_item_encoder.write_integer(num_flow_ies - 1, 0, 65535)?;

    let mut qfi_encoder = NgapEncoder::new();
    qfi_encoder.write_integer(qfi as i64, 0, 63)?;
    let qfi_value = qfi_encoder.finish();
    flow_item_encoder.write_protocol_ie(36, 1, &qfi_value);

    let flow_item_value = flow_item_encoder.finish();
    qos_flow_encoder.write_octet_string(&flow_item_value);

    let qos_flow_value = qos_flow_encoder.finish();
    encoder.write_protocol_ie(134, 1, &qos_flow_value);

    Ok(encoder.finish())
}
