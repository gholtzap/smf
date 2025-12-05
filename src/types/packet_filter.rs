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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PacketFilterComponent {
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
                    let prefix_bytes = (*prefix_length as usize + 7) / 8;
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
