use crate::types::{PacketFilter, PacketInfo, SdfTemplate};
use crate::utils::flow_parser::parse_flow_description;

pub fn create_packet_filter_from_sdf(
    packet_filter_id: u8,
    precedence: u8,
    sdf: &SdfTemplate,
    qfi: Option<u8>,
) -> Result<PacketFilter, String> {
    let flow_desc = parse_flow_description(&sdf.flow_description)
        .map_err(|e| format!("Failed to parse flow description: {}", e))?;

    Ok(PacketFilter::from_flow_description(
        packet_filter_id,
        precedence,
        &flow_desc,
        qfi,
    ))
}

pub fn match_packet_to_filters<'a>(
    packet: &PacketInfo,
    filters: &'a [PacketFilter],
) -> Option<&'a PacketFilter> {
    let mut matching_filters: Vec<&PacketFilter> = filters
        .iter()
        .filter(|f| f.matches(packet))
        .collect();

    matching_filters.sort_by(|a, b| a.precedence.cmp(&b.precedence));

    matching_filters.first().copied()
}

pub fn validate_sdf_template(sdf: &SdfTemplate) -> Result<(), String> {
    parse_flow_description(&sdf.flow_description)
        .map_err(|e| format!("Invalid flow description: {}", e))?;

    if let Some(ref tos) = sdf.tos_traffic_class {
        if !tos.is_empty() && tos.len() > 255 {
            return Err("Invalid TOS/Traffic class".to_string());
        }
    }

    if let Some(ref spi) = sdf.security_parameter_index {
        if spi.parse::<u32>().is_err() {
            return Err("Invalid Security Parameter Index".to_string());
        }
    }

    if let Some(ref flow_label) = sdf.flow_label {
        if let Ok(label) = flow_label.parse::<u32>() {
            if label > 0xFFFFF {
                return Err("Flow label exceeds maximum value (0xFFFFF)".to_string());
            }
        } else {
            return Err("Invalid flow label format".to_string());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PacketFilterDirection};
    use std::net::IpAddr;

    #[test]
    fn test_create_packet_filter_from_sdf() {
        let sdf = SdfTemplate {
            flow_description: "permit out tcp from any to 192.168.1.1 80".to_string(),
            tos_traffic_class: None,
            security_parameter_index: None,
            flow_label: None,
        };

        let result = create_packet_filter_from_sdf(1, 10, &sdf, Some(5));
        assert!(result.is_ok());
        let filter = result.unwrap();
        assert_eq!(filter.packet_filter_id, 1);
        assert_eq!(filter.precedence, 10);
        assert_eq!(filter.qfi, Some(5));
    }

    #[test]
    fn test_match_packet_to_filters() {
        let sdf1 = SdfTemplate {
            flow_description: "permit out tcp from any to 192.168.1.1 80".to_string(),
            tos_traffic_class: None,
            security_parameter_index: None,
            flow_label: None,
        };

        let sdf2 = SdfTemplate {
            flow_description: "permit out tcp from any to any 443".to_string(),
            tos_traffic_class: None,
            security_parameter_index: None,
            flow_label: None,
        };

        let filter1 = create_packet_filter_from_sdf(1, 20, &sdf1, Some(5)).unwrap();
        let filter2 = create_packet_filter_from_sdf(2, 10, &sdf2, Some(9)).unwrap();

        let filters = vec![filter1, filter2];

        let packet = PacketInfo {
            direction: PacketFilterDirection::Uplink,
            protocol: Some(6),
            local_ip: None,
            local_port: Some(12345),
            remote_ip: Some("192.168.1.1".parse::<IpAddr>().unwrap()),
            remote_port: Some(80),
            spi: None,
            tos: None,
            flow_label: None,
        };

        let matched = match_packet_to_filters(&packet, &filters);
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().precedence, 20);
    }

    #[test]
    fn test_validate_sdf_template() {
        let valid_sdf = SdfTemplate {
            flow_description: "permit out tcp from any to 192.168.1.1 80".to_string(),
            tos_traffic_class: None,
            security_parameter_index: None,
            flow_label: None,
        };

        assert!(validate_sdf_template(&valid_sdf).is_ok());

        let invalid_sdf = SdfTemplate {
            flow_description: "invalid flow description".to_string(),
            tos_traffic_class: None,
            security_parameter_index: None,
            flow_label: None,
        };

        assert!(validate_sdf_template(&invalid_sdf).is_err());
    }
}
