use crate::types::pfcp::*;
use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

const MAX_PFCP_MESSAGE_SIZE: usize = 8192;

pub type PfcpClient = Arc<PfcpClientInner>;

pub struct PfcpClientInner {
    socket: Arc<UdpSocket>,
    upf_addr: SocketAddr,
    sequence_number: Mutex<u32>,
}

#[derive(Debug, Clone)]
pub struct PfcpMessage {
    pub version: u8,
    pub message_type: PfcpMessageType,
    pub seid: Option<u64>,
    pub sequence_number: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PfcpMessageType {
    HeartbeatRequest = 1,
    HeartbeatResponse = 2,
    PfdManagementRequest = 3,
    PfdManagementResponse = 4,
    AssociationSetupRequest = 5,
    AssociationSetupResponse = 6,
    AssociationUpdateRequest = 7,
    AssociationUpdateResponse = 8,
    AssociationReleaseRequest = 9,
    AssociationReleaseResponse = 10,
    NodeReportRequest = 12,
    NodeReportResponse = 13,
    SessionSetEstablishmentRequest = 50,
    SessionSetEstablishmentResponse = 51,
    SessionEstablishmentRequest = 52,
    SessionEstablishmentResponse = 53,
    SessionModificationRequest = 54,
    SessionModificationResponse = 55,
    SessionDeletionRequest = 56,
    SessionDeletionResponse = 57,
    SessionReportRequest = 58,
    SessionReportResponse = 59,
}

impl PfcpMessageType {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::HeartbeatRequest),
            2 => Ok(Self::HeartbeatResponse),
            3 => Ok(Self::PfdManagementRequest),
            4 => Ok(Self::PfdManagementResponse),
            5 => Ok(Self::AssociationSetupRequest),
            6 => Ok(Self::AssociationSetupResponse),
            7 => Ok(Self::AssociationUpdateRequest),
            8 => Ok(Self::AssociationUpdateResponse),
            9 => Ok(Self::AssociationReleaseRequest),
            10 => Ok(Self::AssociationReleaseResponse),
            12 => Ok(Self::NodeReportRequest),
            13 => Ok(Self::NodeReportResponse),
            50 => Ok(Self::SessionSetEstablishmentRequest),
            51 => Ok(Self::SessionSetEstablishmentResponse),
            52 => Ok(Self::SessionEstablishmentRequest),
            53 => Ok(Self::SessionEstablishmentResponse),
            54 => Ok(Self::SessionModificationRequest),
            55 => Ok(Self::SessionModificationResponse),
            56 => Ok(Self::SessionDeletionRequest),
            57 => Ok(Self::SessionDeletionResponse),
            58 => Ok(Self::SessionReportRequest),
            59 => Ok(Self::SessionReportResponse),
            _ => Err(anyhow!("Unknown PFCP message type: {}", value)),
        }
    }
}

impl PfcpClientInner {
    pub async fn new(upf_host: String, upf_port: u16, local_addr: SocketAddr) -> Result<PfcpClient> {
        let upf_addr = format!("{}:{}", upf_host, upf_port)
            .parse::<SocketAddr>()
            .map_err(|e| anyhow!("Invalid UPF address: {}", e))?;

        let socket = UdpSocket::bind(local_addr).await?;
        info!("PFCP client bound to {}", local_addr);
        info!("PFCP client configured to communicate with UPF at {}", upf_addr);

        Ok(Arc::new(Self {
            socket: Arc::new(socket),
            upf_addr,
            sequence_number: Mutex::new(1),
        }))
    }

    async fn next_sequence_number(&self) -> u32 {
        let mut seq = self.sequence_number.lock().await;
        let current = *seq;
        *seq = seq.wrapping_add(1);
        current
    }

    pub async fn send_heartbeat_request(&self) -> Result<()> {
        let seq = self.next_sequence_number().await;
        let message = PfcpMessage {
            version: 1,
            message_type: PfcpMessageType::HeartbeatRequest,
            seid: None,
            sequence_number: seq,
            payload: vec![],
        };

        self.send_message(&message).await?;
        debug!("Sent PFCP Heartbeat Request (seq: {})", seq);
        Ok(())
    }

    pub async fn send_association_setup_request(&self, node_id: NodeId) -> Result<()> {
        let seq = self.next_sequence_number().await;

        let payload = serde_json::to_vec(&node_id)?;

        let message = PfcpMessage {
            version: 1,
            message_type: PfcpMessageType::AssociationSetupRequest,
            seid: None,
            sequence_number: seq,
            payload,
        };

        self.send_message(&message).await?;
        debug!("Sent PFCP Association Setup Request (seq: {})", seq);
        Ok(())
    }

    pub async fn send_session_establishment_request(
        &self,
        seid: u64,
        request: &PfcpSessionEstablishmentRequest,
    ) -> Result<()> {
        let seq = self.next_sequence_number().await;

        let payload = serde_json::to_vec(request)?;

        let message = PfcpMessage {
            version: 1,
            message_type: PfcpMessageType::SessionEstablishmentRequest,
            seid: Some(seid),
            sequence_number: seq,
            payload,
        };

        self.send_message(&message).await?;
        debug!("Sent PFCP Session Establishment Request (seq: {}, seid: {})", seq, seid);
        Ok(())
    }

    pub async fn send_session_modification_request(
        &self,
        seid: u64,
        request: &PfcpSessionModificationRequest,
    ) -> Result<()> {
        let seq = self.next_sequence_number().await;

        let payload = serde_json::to_vec(request)?;

        let message = PfcpMessage {
            version: 1,
            message_type: PfcpMessageType::SessionModificationRequest,
            seid: Some(seid),
            sequence_number: seq,
            payload,
        };

        self.send_message(&message).await?;
        debug!("Sent PFCP Session Modification Request (seq: {}, seid: {})", seq, seid);
        Ok(())
    }

    pub async fn send_session_deletion_request(
        &self,
        seid: u64,
        request: &PfcpSessionDeletionRequest,
    ) -> Result<()> {
        let seq = self.next_sequence_number().await;

        let payload = serde_json::to_vec(request)?;

        let message = PfcpMessage {
            version: 1,
            message_type: PfcpMessageType::SessionDeletionRequest,
            seid: Some(seid),
            sequence_number: seq,
            payload,
        };

        self.send_message(&message).await?;
        debug!("Sent PFCP Session Deletion Request (seq: {}, seid: {})", seq, seid);
        Ok(())
    }

    async fn send_message(&self, message: &PfcpMessage) -> Result<()> {
        let encoded = Self::encode_message(message)?;

        let sent = self.socket.send_to(&encoded, self.upf_addr).await?;

        if sent != encoded.len() {
            warn!("Sent {} bytes but message was {} bytes", sent, encoded.len());
        }

        Ok(())
    }

    pub async fn receive_message(&self) -> Result<PfcpMessage> {
        let mut buf = vec![0u8; MAX_PFCP_MESSAGE_SIZE];

        let (len, addr) = self.socket.recv_from(&mut buf).await?;

        if addr != self.upf_addr {
            warn!("Received PFCP message from unexpected address: {}", addr);
        }

        buf.truncate(len);
        Self::decode_message(&buf)
    }

    pub async fn receive_message_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<PfcpMessage> {
        tokio::time::timeout(timeout, self.receive_message())
            .await
            .map_err(|_| anyhow!("PFCP receive timeout"))?
    }

    fn encode_message(message: &PfcpMessage) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        let flags = if message.seid.is_some() {
            (message.version << 5) | 0x01
        } else {
            message.version << 5
        };
        buf.push(flags);

        buf.push(message.message_type as u8);

        let mut length = message.payload.len() + 4;
        if message.seid.is_some() {
            length += 8;
        }
        buf.extend_from_slice(&(length as u16).to_be_bytes());

        if let Some(seid) = message.seid {
            buf.extend_from_slice(&seid.to_be_bytes());
        }

        let seq_bytes = message.sequence_number.to_be_bytes();
        buf.extend_from_slice(&seq_bytes[1..4]);
        buf.push(0);

        buf.extend_from_slice(&message.payload);

        Ok(buf)
    }

    fn decode_message(data: &[u8]) -> Result<PfcpMessage> {
        if data.len() < 8 {
            return Err(anyhow!("PFCP message too short"));
        }

        let flags = data[0];
        let version = flags >> 5;
        let has_seid = (flags & 0x01) != 0;

        let message_type = PfcpMessageType::from_u8(data[1])?;

        let _length = u16::from_be_bytes([data[2], data[3]]) as usize;

        let mut offset = 4;
        let seid = if has_seid {
            let seid_bytes = &data[offset..offset + 8];
            offset += 8;
            Some(u64::from_be_bytes(seid_bytes.try_into()?))
        } else {
            None
        };

        let mut seq_bytes = [0u8; 4];
        seq_bytes[1..4].copy_from_slice(&data[offset..offset + 3]);
        let sequence_number = u32::from_be_bytes(seq_bytes);
        offset += 4;

        let payload = data[offset..].to_vec();

        Ok(PfcpMessage {
            version,
            message_type,
            seid,
            sequence_number,
            payload,
        })
    }

    pub fn decode_session_establishment_response(
        payload: &[u8],
    ) -> Result<PfcpSessionEstablishmentResponse> {
        serde_json::from_slice(payload)
            .map_err(|e| anyhow!("Failed to decode session establishment response: {}", e))
    }

    pub fn decode_session_modification_response(
        payload: &[u8],
    ) -> Result<PfcpSessionModificationResponse> {
        serde_json::from_slice(payload)
            .map_err(|e| anyhow!("Failed to decode session modification response: {}", e))
    }

    pub fn decode_session_deletion_response(
        payload: &[u8],
    ) -> Result<PfcpSessionDeletionResponse> {
        serde_json::from_slice(payload)
            .map_err(|e| anyhow!("Failed to decode session deletion response: {}", e))
    }

    pub fn upf_address(&self) -> SocketAddr {
        self.upf_addr
    }

    pub fn local_address(&self) -> Result<SocketAddr> {
        self.socket.local_addr().map_err(|e| anyhow!("Failed to get local address: {}", e))
    }
}
