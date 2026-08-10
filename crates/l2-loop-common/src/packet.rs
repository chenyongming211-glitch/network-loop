use crate::traffic_class;

pub const ETHERNET_HEADER_LEN: usize = 14;
pub const SINGLE_VLAN_HEADER_LEN: usize = 18;

const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88a8;
const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedL2 {
    pub traffic_class: u8,
    pub outer_vlan_id: Option<u16>,
    pub nested_vlan: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TruncatedEthernet,
    TruncatedVlan,
}

pub fn parse_l2(frame: &[u8]) -> Result<ParsedL2, ParseError> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return Err(ParseError::TruncatedEthernet);
    }

    let destination = [frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]];
    let outer_ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let (ether_type, outer_vlan_id, nested_vlan) = if is_vlan_tpid(outer_ether_type) {
        if frame.len() < SINGLE_VLAN_HEADER_LEN {
            return Err(ParseError::TruncatedVlan);
        }

        let tci = u16::from_be_bytes([frame[14], frame[15]]);
        let inner_ether_type = u16::from_be_bytes([frame[16], frame[17]]);
        (
            inner_ether_type,
            Some(tci & 0x0fff),
            is_vlan_tpid(inner_ether_type),
        )
    } else {
        (outer_ether_type, None, false)
    };

    Ok(ParsedL2 {
        traffic_class: classify(destination, ether_type, nested_vlan),
        outer_vlan_id,
        nested_vlan,
    })
}

fn is_vlan_tpid(ether_type: u16) -> bool {
    matches!(ether_type, ETH_P_8021Q | ETH_P_8021AD)
}

fn classify(destination: [u8; 6], ether_type: u16, nested_vlan: bool) -> u8 {
    if destination == [0xff; 6] {
        traffic_class::L2_BROADCAST
    } else if is_link_local_control(destination) {
        traffic_class::LINK_LOCAL_CONTROL
    } else if nested_vlan {
        multicast_or_unclassified(destination)
    } else if ether_type == ETH_P_IPV4 && is_ipv4_multicast(destination) {
        traffic_class::IPV4_MULTICAST
    } else if ether_type == ETH_P_IPV6 && is_ipv6_multicast(destination) {
        traffic_class::IPV6_MULTICAST
    } else {
        multicast_or_unclassified(destination)
    }
}

fn is_link_local_control(destination: [u8; 6]) -> bool {
    destination[0] == 0x01
        && destination[1] == 0x80
        && destination[2] == 0xc2
        && destination[3] == 0
        && destination[4] == 0
        && destination[5] <= 0x0f
}

fn is_ipv4_multicast(destination: [u8; 6]) -> bool {
    destination[0] == 0x01
        && destination[1] == 0
        && destination[2] == 0x5e
        && destination[3] & 0x80 == 0
}

fn is_ipv6_multicast(destination: [u8; 6]) -> bool {
    destination[0] == 0x33 && destination[1] == 0x33
}

fn multicast_or_unclassified(destination: [u8; 6]) -> u8 {
    if destination[0] & 1 == 1 {
        traffic_class::OTHER_L2_MULTICAST
    } else {
        traffic_class::UNICAST_OR_UNCLASSIFIED
    }
}
