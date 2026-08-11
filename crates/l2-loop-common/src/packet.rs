use crate::{NO_VLAN, traffic_class};

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
#[repr(transparent)]
pub struct ParsedL2Word(u64);

impl ParsedL2Word {
    const VLAN_SHIFT: u32 = 8;
    const NESTED_SHIFT: u32 = 24;
    const ERROR_SHIFT: u32 = 25;
    const ERROR_MASK: u64 = 0x03;
    const TRUNCATED_ETHERNET: u64 = 1;
    const TRUNCATED_VLAN: u64 = 2;

    const fn success(traffic_class: u8, outer_vlan_id: u16, nested_vlan: bool) -> Self {
        Self(
            traffic_class as u64
                | ((outer_vlan_id as u64) << Self::VLAN_SHIFT)
                | ((nested_vlan as u64) << Self::NESTED_SHIFT),
        )
    }

    const fn failure(error: u64) -> Self {
        Self(error << Self::ERROR_SHIFT)
    }

    pub const fn truncated_ethernet() -> Self {
        Self::failure(Self::TRUNCATED_ETHERNET)
    }

    pub const fn truncated_vlan() -> Self {
        Self::failure(Self::TRUNCATED_VLAN)
    }

    pub const fn traffic_class(self) -> u8 {
        self.0 as u8
    }

    pub const fn outer_vlan_id(self) -> u16 {
        (self.0 >> Self::VLAN_SHIFT) as u16
    }

    pub const fn has_outer_vlan(self) -> bool {
        self.outer_vlan_id() != NO_VLAN
    }

    pub const fn nested_vlan(self) -> bool {
        ((self.0 >> Self::NESTED_SHIFT) & 1) != 0
    }

    pub const fn is_error(self) -> bool {
        self.error_code() != 0
    }

    pub const fn into_raw(self) -> u64 {
        self.0
    }

    const fn error_code(self) -> u64 {
        (self.0 >> Self::ERROR_SHIFT) & Self::ERROR_MASK
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    TruncatedEthernet,
    TruncatedVlan,
}

pub fn parse_l2(frame: &[u8]) -> Result<ParsedL2, ParseError> {
    let parsed = parse_l2_word(frame);
    match parsed.error_code() {
        ParsedL2Word::TRUNCATED_ETHERNET => return Err(ParseError::TruncatedEthernet),
        ParsedL2Word::TRUNCATED_VLAN => return Err(ParseError::TruncatedVlan),
        _ => {}
    }
    Ok(ParsedL2 {
        traffic_class: parsed.traffic_class(),
        outer_vlan_id: parsed.has_outer_vlan().then_some(parsed.outer_vlan_id()),
        nested_vlan: parsed.nested_vlan(),
    })
}

pub fn parse_l2_word(frame: &[u8]) -> ParsedL2Word {
    if frame.len() < ETHERNET_HEADER_LEN {
        return ParsedL2Word::truncated_ethernet();
    }

    let destination = [frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]];
    let outer_ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let (ether_type, outer_vlan_id, nested_vlan) = if is_vlan_tpid(outer_ether_type) {
        if frame.len() < SINGLE_VLAN_HEADER_LEN {
            return ParsedL2Word::truncated_vlan();
        }

        let tci = u16::from_be_bytes([frame[14], frame[15]]);
        let inner_ether_type = u16::from_be_bytes([frame[16], frame[17]]);
        (
            inner_ether_type,
            tci & 0x0fff,
            is_vlan_tpid(inner_ether_type),
        )
    } else {
        (outer_ether_type, NO_VLAN, false)
    };

    ParsedL2Word::success(
        classify(destination, ether_type, nested_vlan),
        outer_vlan_id,
        nested_vlan,
    )
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
