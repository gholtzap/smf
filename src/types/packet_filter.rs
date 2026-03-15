use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketFilter {
    pub packet_filter_id: u8,
    pub direction: PacketFilterDirection,
    pub precedence: u8,
    pub components: Vec<PacketFilterComponent>,
    pub qfi: Option<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketFilterDirection {
    Downlink,
    Uplink,
    Bidirectional,
}

impl PacketFilterDirection {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Downlink => 1,
            Self::Uplink => 2,
            Self::Bidirectional => 3,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Downlink,
            2 => Self::Uplink,
            _ => Self::Bidirectional,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PacketFilterComponent {
    MatchAll,
    ProtocolIdentifier(u8),
    SingleLocalPort(u16),
    LocalPortRange { low: u16, high: u16 },
    SingleRemotePort(u16),
    RemotePortRange { low: u16, high: u16 },
    LocalIpv4Address { address: Ipv4Addr, mask: Ipv4Addr },
    RemoteIpv4Address { address: Ipv4Addr, mask: Ipv4Addr },
    LocalIpv6Address { address: Ipv6Addr, prefix_length: u8 },
    RemoteIpv6Address { address: Ipv6Addr, prefix_length: u8 },
    SecurityParameterIndex(u32),
    TypeOfService { tos: u8, mask: u8 },
    FlowLabel(u32),
}

const NAS_PF_MATCH_ALL: u8 = 0x01;
const NAS_PF_IPV4_REMOTE: u8 = 0x10;
const NAS_PF_IPV4_LOCAL: u8 = 0x11;
const NAS_PF_IPV6_REMOTE: u8 = 0x20;
const NAS_PF_IPV6_REMOTE_PREFIX: u8 = 0x21;
const NAS_PF_IPV6_LOCAL: u8 = 0x23;
const NAS_PF_PROTOCOL_ID: u8 = 0x30;
const NAS_PF_SINGLE_LOCAL_PORT: u8 = 0x40;
const NAS_PF_LOCAL_PORT_RANGE: u8 = 0x41;
const NAS_PF_SINGLE_REMOTE_PORT: u8 = 0x50;
const NAS_PF_REMOTE_PORT_RANGE: u8 = 0x51;
const NAS_PF_SPI: u8 = 0x60;
const NAS_PF_TOS: u8 = 0x70;
const NAS_PF_FLOW_LABEL: u8 = 0x80;

impl PacketFilterComponent {
    pub fn parse_nas_content(content: &[u8]) -> Result<Vec<PacketFilterComponent>, String> {
        let mut components = Vec::new();
        let mut pos = 0;
        while pos < content.len() {
            let component_type = content[pos];
            pos += 1;
            match component_type {
                NAS_PF_MATCH_ALL => {
                    components.push(PacketFilterComponent::MatchAll);
                }
                NAS_PF_IPV4_REMOTE => {
                    if pos + 8 > content.len() {
                        return Err("IPv4 remote address truncated".to_string());
                    }
                    let addr = Ipv4Addr::new(content[pos], content[pos + 1], content[pos + 2], content[pos + 3]);
                    let mask = Ipv4Addr::new(content[pos + 4], content[pos + 5], content[pos + 6], content[pos + 7]);
                    components.push(PacketFilterComponent::RemoteIpv4Address { address: addr, mask });
                    pos += 8;
                }
                NAS_PF_IPV4_LOCAL => {
                    if pos + 8 > content.len() {
                        return Err("IPv4 local address truncated".to_string());
                    }
                    let addr = Ipv4Addr::new(content[pos], content[pos + 1], content[pos + 2], content[pos + 3]);
                    let mask = Ipv4Addr::new(content[pos + 4], content[pos + 5], content[pos + 6], content[pos + 7]);
                    components.push(PacketFilterComponent::LocalIpv4Address { address: addr, mask });
                    pos += 8;
                }
                NAS_PF_IPV6_REMOTE | NAS_PF_IPV6_REMOTE_PREFIX => {
                    if pos + 17 > content.len() {
                        return Err("IPv6 remote address truncated".to_string());
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&content[pos..pos + 16]);
                    let addr = Ipv6Addr::from(octets);
                    let prefix_length = content[pos + 16];
                    components.push(PacketFilterComponent::RemoteIpv6Address { address: addr, prefix_length });
                    pos += 17;
                }
                NAS_PF_IPV6_LOCAL => {
                    if pos + 17 > content.len() {
                        return Err("IPv6 local address truncated".to_string());
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&content[pos..pos + 16]);
                    let addr = Ipv6Addr::from(octets);
                    let prefix_length = content[pos + 16];
                    components.push(PacketFilterComponent::LocalIpv6Address { address: addr, prefix_length });
                    pos += 17;
                }
                NAS_PF_PROTOCOL_ID => {
                    if pos >= content.len() {
                        return Err("Protocol identifier truncated".to_string());
                    }
                    components.push(PacketFilterComponent::ProtocolIdentifier(content[pos]));
                    pos += 1;
                }
                NAS_PF_SINGLE_LOCAL_PORT => {
                    if pos + 2 > content.len() {
                        return Err("Single local port truncated".to_string());
                    }
                    let port = u16::from_be_bytes([content[pos], content[pos + 1]]);
                    components.push(PacketFilterComponent::SingleLocalPort(port));
                    pos += 2;
                }
                NAS_PF_LOCAL_PORT_RANGE => {
                    if pos + 4 > content.len() {
                        return Err("Local port range truncated".to_string());
                    }
                    let low = u16::from_be_bytes([content[pos], content[pos + 1]]);
                    let high = u16::from_be_bytes([content[pos + 2], content[pos + 3]]);
                    components.push(PacketFilterComponent::LocalPortRange { low, high });
                    pos += 4;
                }
                NAS_PF_SINGLE_REMOTE_PORT => {
                    if pos + 2 > content.len() {
                        return Err("Single remote port truncated".to_string());
                    }
                    let port = u16::from_be_bytes([content[pos], content[pos + 1]]);
                    components.push(PacketFilterComponent::SingleRemotePort(port));
                    pos += 2;
                }
                NAS_PF_REMOTE_PORT_RANGE => {
                    if pos + 4 > content.len() {
                        return Err("Remote port range truncated".to_string());
                    }
                    let low = u16::from_be_bytes([content[pos], content[pos + 1]]);
                    let high = u16::from_be_bytes([content[pos + 2], content[pos + 3]]);
                    components.push(PacketFilterComponent::RemotePortRange { low, high });
                    pos += 4;
                }
                NAS_PF_SPI => {
                    if pos + 4 > content.len() {
                        return Err("SPI truncated".to_string());
                    }
                    let spi = u32::from_be_bytes([content[pos], content[pos + 1], content[pos + 2], content[pos + 3]]);
                    components.push(PacketFilterComponent::SecurityParameterIndex(spi));
                    pos += 4;
                }
                NAS_PF_TOS => {
                    if pos + 2 > content.len() {
                        return Err("ToS truncated".to_string());
                    }
                    components.push(PacketFilterComponent::TypeOfService { tos: content[pos], mask: content[pos + 1] });
                    pos += 2;
                }
                NAS_PF_FLOW_LABEL => {
                    if pos + 3 > content.len() {
                        return Err("Flow label truncated".to_string());
                    }
                    let label = ((content[pos] as u32 & 0x0F) << 16)
                        | ((content[pos + 1] as u32) << 8)
                        | (content[pos + 2] as u32);
                    components.push(PacketFilterComponent::FlowLabel(label));
                    pos += 3;
                }
                _ => {
                    return Err(format!("Unknown packet filter component type: {:#x}", component_type));
                }
            }
        }
        Ok(components)
    }

    pub fn encode_nas_content(components: &[PacketFilterComponent]) -> Vec<u8> {
        let mut out = Vec::new();
        for component in components {
            match component {
                PacketFilterComponent::MatchAll => {
                    out.push(NAS_PF_MATCH_ALL);
                }
                PacketFilterComponent::ProtocolIdentifier(proto) => {
                    out.push(NAS_PF_PROTOCOL_ID);
                    out.push(*proto);
                }
                PacketFilterComponent::RemoteIpv4Address { address, mask } => {
                    out.push(NAS_PF_IPV4_REMOTE);
                    out.extend_from_slice(&address.octets());
                    out.extend_from_slice(&mask.octets());
                }
                PacketFilterComponent::LocalIpv4Address { address, mask } => {
                    out.push(NAS_PF_IPV4_LOCAL);
                    out.extend_from_slice(&address.octets());
                    out.extend_from_slice(&mask.octets());
                }
                PacketFilterComponent::RemoteIpv6Address { address, prefix_length } => {
                    out.push(NAS_PF_IPV6_REMOTE_PREFIX);
                    out.extend_from_slice(&address.octets());
                    out.push(*prefix_length);
                }
                PacketFilterComponent::LocalIpv6Address { address, prefix_length } => {
                    out.push(NAS_PF_IPV6_LOCAL);
                    out.extend_from_slice(&address.octets());
                    out.push(*prefix_length);
                }
                PacketFilterComponent::SingleLocalPort(port) => {
                    out.push(NAS_PF_SINGLE_LOCAL_PORT);
                    out.extend_from_slice(&port.to_be_bytes());
                }
                PacketFilterComponent::LocalPortRange { low, high } => {
                    out.push(NAS_PF_LOCAL_PORT_RANGE);
                    out.extend_from_slice(&low.to_be_bytes());
                    out.extend_from_slice(&high.to_be_bytes());
                }
                PacketFilterComponent::SingleRemotePort(port) => {
                    out.push(NAS_PF_SINGLE_REMOTE_PORT);
                    out.extend_from_slice(&port.to_be_bytes());
                }
                PacketFilterComponent::RemotePortRange { low, high } => {
                    out.push(NAS_PF_REMOTE_PORT_RANGE);
                    out.extend_from_slice(&low.to_be_bytes());
                    out.extend_from_slice(&high.to_be_bytes());
                }
                PacketFilterComponent::SecurityParameterIndex(spi) => {
                    out.push(NAS_PF_SPI);
                    out.extend_from_slice(&spi.to_be_bytes());
                }
                PacketFilterComponent::TypeOfService { tos, mask } => {
                    out.push(NAS_PF_TOS);
                    out.push(*tos);
                    out.push(*mask);
                }
                PacketFilterComponent::FlowLabel(label) => {
                    out.push(NAS_PF_FLOW_LABEL);
                    out.push(((label >> 16) & 0x0F) as u8);
                    out.push(((label >> 8) & 0xFF) as u8);
                    out.push((label & 0xFF) as u8);
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowDescription {
    pub action: FlowAction,
    pub direction: FlowDirection,
    pub protocol: Option<u8>,
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<PortRange>,
    pub destination_ip: Option<IpAddr>,
    pub destination_port: Option<PortRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowAction {
    Permit,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowDirection {
    In,
    Out,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortRange {
    Single(u16),
    Range { low: u16, high: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdfTemplate {
    pub flow_description: String,
    pub tos_traffic_class: Option<String>,
    pub security_parameter_index: Option<String>,
    pub flow_label: Option<String>,
}

impl PacketFilter {
    pub fn new(
        packet_filter_id: u8,
        direction: PacketFilterDirection,
        precedence: u8,
        components: Vec<PacketFilterComponent>,
        qfi: Option<u8>,
    ) -> Self {
        PacketFilter {
            packet_filter_id,
            direction,
            precedence,
            components,
            qfi,
        }
    }

    pub fn from_flow_description(
        packet_filter_id: u8,
        precedence: u8,
        flow_desc: &FlowDescription,
        qfi: Option<u8>,
    ) -> Self {
        let mut components = Vec::new();
        let direction = match flow_desc.direction {
            FlowDirection::In => PacketFilterDirection::Downlink,
            FlowDirection::Out => PacketFilterDirection::Uplink,
        };

        if let Some(protocol) = flow_desc.protocol {
            components.push(PacketFilterComponent::ProtocolIdentifier(protocol));
        }

        match (&flow_desc.source_ip, flow_desc.direction) {
            (Some(IpAddr::V4(addr)), FlowDirection::Out) => {
                components.push(PacketFilterComponent::LocalIpv4Address {
                    address: *addr,
                    mask: Ipv4Addr::new(255, 255, 255, 255),
                });
            }
            (Some(IpAddr::V4(addr)), FlowDirection::In) => {
                components.push(PacketFilterComponent::RemoteIpv4Address {
                    address: *addr,
                    mask: Ipv4Addr::new(255, 255, 255, 255),
                });
            }
            (Some(IpAddr::V6(addr)), FlowDirection::Out) => {
                components.push(PacketFilterComponent::LocalIpv6Address {
                    address: *addr,
                    prefix_length: 128,
                });
            }
            (Some(IpAddr::V6(addr)), FlowDirection::In) => {
                components.push(PacketFilterComponent::RemoteIpv6Address {
                    address: *addr,
                    prefix_length: 128,
                });
            }
            _ => {}
        }

        match (&flow_desc.destination_ip, flow_desc.direction) {
            (Some(IpAddr::V4(addr)), FlowDirection::Out) => {
                components.push(PacketFilterComponent::RemoteIpv4Address {
                    address: *addr,
                    mask: Ipv4Addr::new(255, 255, 255, 255),
                });
            }
            (Some(IpAddr::V4(addr)), FlowDirection::In) => {
                components.push(PacketFilterComponent::LocalIpv4Address {
                    address: *addr,
                    mask: Ipv4Addr::new(255, 255, 255, 255),
                });
            }
            (Some(IpAddr::V6(addr)), FlowDirection::Out) => {
                components.push(PacketFilterComponent::RemoteIpv6Address {
                    address: *addr,
                    prefix_length: 128,
                });
            }
            (Some(IpAddr::V6(addr)), FlowDirection::In) => {
                components.push(PacketFilterComponent::LocalIpv6Address {
                    address: *addr,
                    prefix_length: 128,
                });
            }
            _ => {}
        }

        match (&flow_desc.source_port, flow_desc.direction) {
            (Some(PortRange::Single(port)), FlowDirection::Out) => {
                components.push(PacketFilterComponent::SingleLocalPort(*port));
            }
            (Some(PortRange::Range { low, high }), FlowDirection::Out) => {
                components.push(PacketFilterComponent::LocalPortRange {
                    low: *low,
                    high: *high,
                });
            }
            (Some(PortRange::Single(port)), FlowDirection::In) => {
                components.push(PacketFilterComponent::SingleRemotePort(*port));
            }
            (Some(PortRange::Range { low, high }), FlowDirection::In) => {
                components.push(PacketFilterComponent::RemotePortRange {
                    low: *low,
                    high: *high,
                });
            }
            _ => {}
        }

        match (&flow_desc.destination_port, flow_desc.direction) {
            (Some(PortRange::Single(port)), FlowDirection::Out) => {
                components.push(PacketFilterComponent::SingleRemotePort(*port));
            }
            (Some(PortRange::Range { low, high }), FlowDirection::Out) => {
                components.push(PacketFilterComponent::RemotePortRange {
                    low: *low,
                    high: *high,
                });
            }
            (Some(PortRange::Single(port)), FlowDirection::In) => {
                components.push(PacketFilterComponent::SingleLocalPort(*port));
            }
            (Some(PortRange::Range { low, high }), FlowDirection::In) => {
                components.push(PacketFilterComponent::LocalPortRange {
                    low: *low,
                    high: *high,
                });
            }
            _ => {}
        }

        PacketFilter {
            packet_filter_id,
            direction,
            precedence,
            components,
            qfi,
        }
    }

    pub fn matches(&self, packet: &PacketInfo) -> bool {
        if !self.direction_matches(packet.direction) {
            return false;
        }

        for component in &self.components {
            if !self.component_matches(component, packet) {
                return false;
            }
        }

        true
    }

    fn direction_matches(&self, packet_direction: PacketFilterDirection) -> bool {
        match self.direction {
            PacketFilterDirection::Bidirectional => true,
            dir => dir == packet_direction,
        }
    }

    fn component_matches(&self, component: &PacketFilterComponent, packet: &PacketInfo) -> bool {
        match component {
            PacketFilterComponent::MatchAll => true,
            PacketFilterComponent::ProtocolIdentifier(proto) => {
                packet.protocol.map_or(false, |p| p == *proto)
            }
            PacketFilterComponent::SingleLocalPort(port) => {
                packet.local_port.map_or(false, |p| p == *port)
            }
            PacketFilterComponent::LocalPortRange { low, high } => packet
                .local_port
                .map_or(false, |p| p >= *low && p <= *high),
            PacketFilterComponent::SingleRemotePort(port) => {
                packet.remote_port.map_or(false, |p| p == *port)
            }
            PacketFilterComponent::RemotePortRange { low, high } => packet
                .remote_port
                .map_or(false, |p| p >= *low && p <= *high),
            PacketFilterComponent::LocalIpv4Address { address, mask } => {
                if let Some(IpAddr::V4(local_ip)) = packet.local_ip {
                    let addr_bytes = address.octets();
                    let mask_bytes = mask.octets();
                    let ip_bytes = local_ip.octets();
                    (0..4).all(|i| (addr_bytes[i] & mask_bytes[i]) == (ip_bytes[i] & mask_bytes[i]))
                } else {
                    false
                }
            }
            PacketFilterComponent::RemoteIpv4Address { address, mask } => {
                if let Some(IpAddr::V4(remote_ip)) = packet.remote_ip {
                    let addr_bytes = address.octets();
                    let mask_bytes = mask.octets();
                    let ip_bytes = remote_ip.octets();
                    (0..4).all(|i| (addr_bytes[i] & mask_bytes[i]) == (ip_bytes[i] & mask_bytes[i]))
                } else {
                    false
                }
            }
            PacketFilterComponent::LocalIpv6Address {
                address,
                prefix_length,
            } => {
                if let Some(IpAddr::V6(local_ip)) = packet.local_ip {
                    let addr_bytes = address.octets();
                    let ip_bytes = local_ip.octets();
                    let _prefix_bytes = (*prefix_length as usize + 7) / 8;
                    let full_bytes = *prefix_length as usize / 8;
                    let remaining_bits = *prefix_length as usize % 8;

                    for i in 0..full_bytes {
                        if addr_bytes[i] != ip_bytes[i] {
                            return false;
                        }
                    }

                    if remaining_bits > 0 && full_bytes < 16 {
                        let mask = 0xFF << (8 - remaining_bits);
                        if (addr_bytes[full_bytes] & mask) != (ip_bytes[full_bytes] & mask) {
                            return false;
                        }
                    }

                    true
                } else {
                    false
                }
            }
            PacketFilterComponent::RemoteIpv6Address {
                address,
                prefix_length,
            } => {
                if let Some(IpAddr::V6(remote_ip)) = packet.remote_ip {
                    let addr_bytes = address.octets();
                    let ip_bytes = remote_ip.octets();
                    let full_bytes = *prefix_length as usize / 8;
                    let remaining_bits = *prefix_length as usize % 8;

                    for i in 0..full_bytes {
                        if addr_bytes[i] != ip_bytes[i] {
                            return false;
                        }
                    }

                    if remaining_bits > 0 && full_bytes < 16 {
                        let mask = 0xFF << (8 - remaining_bits);
                        if (addr_bytes[full_bytes] & mask) != (ip_bytes[full_bytes] & mask) {
                            return false;
                        }
                    }

                    true
                } else {
                    false
                }
            }
            PacketFilterComponent::SecurityParameterIndex(spi) => {
                packet.spi.map_or(false, |s| s == *spi)
            }
            PacketFilterComponent::TypeOfService { tos, mask } => packet
                .tos
                .map_or(false, |t| (t & mask) == (tos & mask)),
            PacketFilterComponent::FlowLabel(label) => {
                packet.flow_label.map_or(false, |l| l == *label)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub direction: PacketFilterDirection,
    pub protocol: Option<u8>,
    pub local_ip: Option<IpAddr>,
    pub local_port: Option<u16>,
    pub remote_ip: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub spi: Option<u32>,
    pub tos: Option<u8>,
    pub flow_label: Option<u32>,
}
