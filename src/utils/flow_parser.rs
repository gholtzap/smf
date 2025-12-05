use crate::types::{FlowAction, FlowDescription, FlowDirection, PortRange};
use std::net::IpAddr;

#[derive(Debug)]
pub enum ParseError {
    InvalidFormat(String),
    InvalidAction(String),
    InvalidDirection(String),
    InvalidProtocol(String),
    InvalidAddress(String),
    InvalidPort(String),
    MissingField(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::InvalidFormat(msg) => write!(f, "Invalid format: {}", msg),
            ParseError::InvalidAction(msg) => write!(f, "Invalid action: {}", msg),
            ParseError::InvalidDirection(msg) => write!(f, "Invalid direction: {}", msg),
            ParseError::InvalidProtocol(msg) => write!(f, "Invalid protocol: {}", msg),
            ParseError::InvalidAddress(msg) => write!(f, "Invalid address: {}", msg),
            ParseError::InvalidPort(msg) => write!(f, "Invalid port: {}", msg),
            ParseError::MissingField(msg) => write!(f, "Missing field: {}", msg),
        }
    }
}

impl std::error::Error for ParseError {}

pub fn parse_flow_description(flow_desc: &str) -> Result<FlowDescription, ParseError> {
    let tokens: Vec<&str> = flow_desc.split_whitespace().collect();

    if tokens.len() < 8 {
        return Err(ParseError::InvalidFormat(
            "Flow description too short".to_string(),
        ));
    }

    let action = parse_action(tokens[0])?;
    let direction = parse_direction(tokens[1])?;
    let protocol = parse_protocol(tokens[2])?;

    if tokens[3] != "from" {
        return Err(ParseError::InvalidFormat(
            "Expected 'from' keyword".to_string(),
        ));
    }

    let (source_ip, source_port, to_idx) = parse_address_port(&tokens[4..])?;

    if to_idx + 4 >= tokens.len() || tokens[to_idx + 4] != "to" {
        return Err(ParseError::InvalidFormat(
            "Expected 'to' keyword".to_string(),
        ));
    }

    let (destination_ip, destination_port, _) = parse_address_port(&tokens[to_idx + 5..])?;

    Ok(FlowDescription {
        action,
        direction,
        protocol,
        source_ip,
        source_port,
        destination_ip,
        destination_port,
    })
}

fn parse_action(action_str: &str) -> Result<FlowAction, ParseError> {
    match action_str.to_lowercase().as_str() {
        "permit" => Ok(FlowAction::Permit),
        "deny" => Ok(FlowAction::Deny),
        _ => Err(ParseError::InvalidAction(action_str.to_string())),
    }
}

fn parse_direction(dir_str: &str) -> Result<FlowDirection, ParseError> {
    match dir_str.to_lowercase().as_str() {
        "in" => Ok(FlowDirection::In),
        "out" => Ok(FlowDirection::Out),
        _ => Err(ParseError::InvalidDirection(dir_str.to_string())),
    }
}

fn parse_protocol(proto_str: &str) -> Result<Option<u8>, ParseError> {
    match proto_str.to_lowercase().as_str() {
        "ip" => Ok(None),
        "tcp" => Ok(Some(6)),
        "udp" => Ok(Some(17)),
        "icmp" => Ok(Some(1)),
        "icmpv6" => Ok(Some(58)),
        "esp" => Ok(Some(50)),
        "ah" => Ok(Some(51)),
        _ => {
            if let Ok(num) = proto_str.parse::<u8>() {
                Ok(Some(num))
            } else {
                Err(ParseError::InvalidProtocol(proto_str.to_string()))
            }
        }
    }
}

fn parse_address_port(tokens: &[&str]) -> Result<(Option<IpAddr>, Option<PortRange>, usize), ParseError> {
    if tokens.is_empty() {
        return Err(ParseError::MissingField("address".to_string()));
    }

    let mut idx = 0;
    let ip = if tokens[0] == "any" {
        idx += 1;
        None
    } else if tokens[0].contains('/') {
        let parts: Vec<&str> = tokens[0].split('/').collect();
        if parts.len() != 2 {
            return Err(ParseError::InvalidAddress(tokens[0].to_string()));
        }
        let addr = parts[0]
            .parse::<IpAddr>()
            .map_err(|_| ParseError::InvalidAddress(tokens[0].to_string()))?;
        idx += 1;
        Some(addr)
    } else {
        let addr = tokens[0]
            .parse::<IpAddr>()
            .map_err(|_| ParseError::InvalidAddress(tokens[0].to_string()))?;
        idx += 1;
        Some(addr)
    };

    let port = if idx < tokens.len() && tokens[idx] != "to" && tokens[idx] != "from" {
        let port_range = parse_port_range(tokens[idx])?;
        idx += 1;
        Some(port_range)
    } else {
        None
    };

    Ok((ip, port, idx))
}

fn parse_port_range(port_str: &str) -> Result<PortRange, ParseError> {
    if port_str.contains('-') {
        let parts: Vec<&str> = port_str.split('-').collect();
        if parts.len() != 2 {
            return Err(ParseError::InvalidPort(port_str.to_string()));
        }
        let low = parts[0]
            .parse::<u16>()
            .map_err(|_| ParseError::InvalidPort(port_str.to_string()))?;
        let high = parts[1]
            .parse::<u16>()
            .map_err(|_| ParseError::InvalidPort(port_str.to_string()))?;
        Ok(PortRange::Range { low, high })
    } else {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| ParseError::InvalidPort(port_str.to_string()))?;
        Ok(PortRange::Single(port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_tcp_flow() {
        let desc = "permit out tcp from any to 192.168.1.1 80";
        let result = parse_flow_description(desc);
        assert!(result.is_ok());
        let flow = result.unwrap();
        assert_eq!(flow.action, FlowAction::Permit);
        assert_eq!(flow.direction, FlowDirection::Out);
        assert_eq!(flow.protocol, Some(6));
        assert!(flow.source_ip.is_none());
        assert!(flow.destination_ip.is_some());
    }

    #[test]
    fn test_parse_udp_with_port_range() {
        let desc = "deny in udp from 10.0.0.1 to any 8000-9000";
        let result = parse_flow_description(desc);
        assert!(result.is_ok());
        let flow = result.unwrap();
        assert_eq!(flow.action, FlowAction::Deny);
        assert_eq!(flow.direction, FlowDirection::In);
        assert_eq!(flow.protocol, Some(17));
    }

    #[test]
    fn test_parse_any_to_any() {
        let desc = "permit out ip from any to any";
        let result = parse_flow_description(desc);
        assert!(result.is_ok());
        let flow = result.unwrap();
        assert!(flow.source_ip.is_none());
        assert!(flow.destination_ip.is_none());
    }
}
