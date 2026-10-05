//! Flow keying.
//!
//! A flow is identified by the pair of endpoints it connects. Traffic in the two directions
//! belongs to the same connection, so the key is **normalized**: endpoints are ordered
//! canonically at construction time. Without that, every connection would appear as two
//! half-connections and byte totals would be split in half.
//!
//! Endpoints are ordered by (address, port). Ordering by address first is deliberate: it
//! keeps the key stable regardless of which side happens to be observed first, and it
//! makes the key's `Ord` implementation meaningful for sorting the UI.

use std::net::IpAddr;

use sentinel_common::packet::TransportProtocol;
use serde::{Deserialize, Serialize};

/// One side of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    /// IP address of this side.
    pub addr: IpAddr,
    /// Transport port, or `None` for protocols without ports (ICMP and friends).
    pub port: Option<u16>,
}

impl Endpoint {
    /// Creates an endpoint.
    #[must_use]
    pub const fn new(addr: IpAddr, port: Option<u16>) -> Self {
        Self { addr, port }
    }

    /// Compact display form: `192.168.1.10:52341`, `[2606:4700::1]:443`, or `10.0.0.1`.
    ///
    /// IPv6 addresses with a port are bracketed. Without brackets, `2606:4700::1:443` is a
    /// legal but different IPv6 address, which would make stored endpoints ambiguous.
    #[must_use]
    pub fn display(&self) -> String {
        match self.port {
            Some(port) if self.addr.is_ipv6() => format!("[{}]:{port}", self.addr),
            Some(port) => format!("{}:{}", self.addr, port),
            None => self.addr.to_string(),
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.display())
    }
}

/// A normalized bidirectional flow identifier.
///
/// The two endpoints are stored in canonical order, so a packet and its reply always
/// produce the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowKey {
    /// Transport protocol.
    pub protocol: TransportProtocol,
    /// Lexicographically lower endpoint.
    pub endpoint_a: Endpoint,
    /// Lexicographically higher endpoint.
    pub endpoint_b: Endpoint,
}

impl FlowKey {
    /// Builds a key, ordering the two endpoints canonically.
    ///
    /// Pass the endpoints in either order; the result is identical.
    #[must_use]
    pub fn new(protocol: TransportProtocol, first: Endpoint, second: Endpoint) -> Self {
        if first <= second {
            Self {
                protocol,
                endpoint_a: first,
                endpoint_b: second,
            }
        } else {
            Self {
                protocol,
                endpoint_a: second,
                endpoint_b: first,
            }
        }
    }

    /// Builds a key from a packet's source and destination.
    ///
    /// Returns `None` for non-IP frames, which have no flow identity.
    #[must_use]
    pub fn from_packet(packet: &sentinel_common::packet::NormalizedPacket) -> Option<Self> {
        let protocol = packet.transport_protocol();
        let first = Endpoint::new(packet.src_ip()?, packet.src_port());
        let second = Endpoint::new(packet.dst_ip()?, packet.dst_port());
        Some(Self::new(protocol, first, second))
    }

    /// Which side of the key an address sits on.
    ///
    /// Returns `None` when the address belongs to neither endpoint.
    #[must_use]
    pub fn side_of(&self, addr: IpAddr) -> Option<FlowSide> {
        if self.endpoint_a.addr == addr {
            Some(FlowSide::A)
        } else if self.endpoint_b.addr == addr {
            Some(FlowSide::B)
        } else {
            None
        }
    }

    /// The side that initiated the connection, derived from the well-known port when one
    /// side is a service port, otherwise `None`.
    ///
    /// This is used for display ("Chrome talking to example.com") and is deliberately
    /// conservative: it prefers evidence over guessing.
    #[must_use]
    pub fn likely_initiator(&self) -> Option<FlowSide> {
        match (self.endpoint_a.port, self.endpoint_b.port) {
            (Some(a), Some(b)) => {
                let a_well_known = is_well_known_port(a) && !is_ephemeral(a);
                let b_well_known = is_well_known_port(b) && !is_ephemeral(b);
                match (a_well_known, b_well_known) {
                    // Exactly one side is a service port: that side is the server.
                    (true, false) => Some(FlowSide::B),
                    (false, true) => Some(FlowSide::A),
                    // Both or neither: no basis for a claim.
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// The endpoint most likely to be the server, when identifiable.
    #[must_use]
    pub fn server_endpoint(&self) -> Option<Endpoint> {
        match self.likely_initiator()? {
            FlowSide::A => Some(self.endpoint_b),
            FlowSide::B => Some(self.endpoint_a),
        }
    }

    /// True when both endpoints are private addresses of the same address family as `local`.
    ///
    /// LAN-to-LAN traffic matters for device inventory and ARP checks, so the flow engine
    /// needs to distinguish it from internet-bound traffic without consulting a routing
    /// table. All three addresses must share a family: a v4-to-v6 pair is not "internal" in
    /// any sense a user would recognise.
    #[must_use]
    pub fn is_internal(&self, local: IpAddr) -> bool {
        sentinel_common::net::is_private_addr(self.endpoint_a.addr)
            && sentinel_common::net::is_private_addr(self.endpoint_b.addr)
            && same_address_family(local, self.endpoint_a.addr)
            && same_address_family(local, self.endpoint_b.addr)
    }
}

/// Which canonical side of a [`FlowKey`] an address belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FlowSide {
    /// The lower-ordered endpoint.
    A,
    /// The higher-ordered endpoint.
    B,
}

impl FlowSide {
    /// The other side.
    #[must_use]
    pub const fn opposite(self) -> Self {
        match self {
            FlowSide::A => FlowSide::B,
            FlowSide::B => FlowSide::A,
        }
    }
}

impl std::fmt::Display for FlowSide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowSide::A => f.write_str("a"),
            FlowSide::B => f.write_str("b"),
        }
    }
}

/// True when two addresses are the same IP version.
fn same_address_family(a: IpAddr, b: IpAddr) -> bool {
    matches!(
        (a, b),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

/// True for ports in the well-known and registered range (not ephemeral).
fn is_well_known_port(port: u16) -> bool {
    port > 0 && port < 49_152
}

/// True for the Linux/macOS ephemeral range that clients normally use.
fn is_ephemeral(port: u16) -> bool {
    (49_152..=65_535).contains(&port)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use sentinel_common::packet::{NormalizedPacket, TransportProtocol};

    fn endpoint(addr: &str, port: u16) -> Endpoint {
        Endpoint::new(addr.parse().expect("valid address"), Some(port))
    }

    fn flow_key(a: Endpoint, b: Endpoint) -> FlowKey {
        FlowKey::new(TransportProtocol::Tcp, a, b)
    }

    #[test]
    fn key_ordering_does_not_depend_on_packet_direction() {
        let client = endpoint("192.168.1.10", 52_341);
        let server = endpoint("93.184.216.34", 443);

        let forward = flow_key(client, server);
        let reverse = flow_key(server, client);

        assert_eq!(forward, reverse, "a reply must land in the same flow");
        assert_eq!(
            forward.endpoint_a, server,
            "lower address becomes endpoint_a"
        );
        assert_eq!(forward.endpoint_b, client);
    }

    #[test]
    fn different_protocols_produce_different_keys() {
        let tcp = flow_key(endpoint("10.0.0.1", 443), endpoint("10.0.0.2", 55_000));
        let udp = FlowKey::new(TransportProtocol::Udp, tcp.endpoint_a, tcp.endpoint_b);
        assert_ne!(tcp, udp);
    }

    #[test]
    fn portless_protocols_still_key() {
        let a = Endpoint::new("10.0.0.1".parse().expect("valid"), None);
        let b = Endpoint::new("10.0.0.2".parse().expect("valid"), None);
        let key = FlowKey::new(TransportProtocol::Icmp, a, b);
        assert_eq!(key, FlowKey::new(TransportProtocol::Icmp, b, a));
        assert_eq!(key.server_endpoint(), None, "no port means no server claim");
    }

    /// A connection from an ephemeral client port to a service port. The service port marks
    /// the server, so the other side is the initiator.
    #[test]
    fn initiator_is_identified_from_a_service_port() {
        let key = flow_key(
            endpoint("192.168.1.10", 52_341),
            endpoint("93.184.216.34", 443),
        );

        // Canonical ordering puts the numerically lower address first: the server
        // (93.184.216.34:443) is side A, the client (192.168.1.10:52341) is side B.
        assert_eq!(key.endpoint_a, endpoint("93.184.216.34", 443));
        assert_eq!(key.endpoint_b, endpoint("192.168.1.10", 52_341));

        assert_eq!(
            key.likely_initiator(),
            Some(FlowSide::B),
            "the client is the initiator"
        );
        assert_eq!(key.server_endpoint(), Some(endpoint("93.184.216.34", 443)));

        // Symmetric ports give no basis for a claim.
        let ambiguous = flow_key(
            endpoint("192.168.1.10", 40_000),
            endpoint("93.184.216.34", 40_001),
        );
        assert_eq!(ambiguous.likely_initiator(), None);
        assert_eq!(ambiguous.server_endpoint(), None);
    }

    #[test]
    fn side_lookup_and_opposite() {
        let key = flow_key(endpoint("10.0.0.1", 1), endpoint("10.0.0.2", 2));
        let side = key
            .side_of("10.0.0.1".parse().expect("valid"))
            .expect("side");
        assert_eq!(side.opposite(), FlowSide::B);
        assert_eq!(
            key.side_of("10.0.0.2".parse().expect("valid")),
            Some(FlowSide::B)
        );
        assert_eq!(key.side_of("10.0.0.3".parse().expect("valid")), None);
    }

    #[test]
    fn endpoint_display_includes_port_when_present() {
        assert_eq!(
            endpoint("192.168.1.10", 443).to_string(),
            "192.168.1.10:443"
        );

        let portless = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), None);
        assert_eq!(portless.to_string(), "10.0.0.1");
    }

    /// IPv6 with a port must be bracketed, because an unbracketed form is ambiguous:
    /// `2606:4700::1:443` is itself a valid IPv6 address meaning something else entirely.
    #[test]
    fn ipv6_endpoints_with_ports_are_bracketed() {
        let v6 = Endpoint::new("2606:4700::1".parse().expect("valid"), Some(443));
        assert_eq!(v6.display(), "[2606:4700::1]:443");

        let v6_no_port = Endpoint::new("2606:4700::1".parse().expect("valid"), None);
        assert_eq!(v6_no_port.display(), "2606:4700::1");
    }

    #[test]
    fn internal_detection_uses_private_ranges_and_family() {
        let local: IpAddr = "192.168.1.10".parse().expect("valid");

        let lan = flow_key(
            endpoint("192.168.1.20", 40_000),
            endpoint("192.168.1.1", 445),
        );
        assert!(lan.is_internal(local));

        let internet = flow_key(
            endpoint("192.168.1.20", 52_341),
            endpoint("93.184.216.34", 443),
        );
        assert!(!internet.is_internal(local));

        // Mixed address families are not treated as internal.
        let mixed = FlowKey::new(
            TransportProtocol::Tcp,
            endpoint("192.168.1.20", 40_000),
            Endpoint::new("fd00::1".parse().expect("valid"), Some(40_001)),
        );
        assert!(!mixed.is_internal(local));
    }

    #[test]
    fn keys_are_derived_from_packets() {
        let packet = NormalizedPacket {
            ip: Some(sentinel_common::packet::IpHeader::V4(
                sentinel_common::packet::Ipv4Header {
                    source: "192.168.1.10".parse().expect("valid"),
                    destination: "93.184.216.34".parse().expect("valid"),
                    protocol: 6,
                    ttl: 64,
                    total_length: 40,
                    dont_fragment: true,
                    more_fragments: false,
                    fragment_offset: 0,
                    checksum: 0,
                },
            )),
            transport: Some(sentinel_common::packet::TransportHeader::Tcp(
                sentinel_common::packet::TcpHeader {
                    source_port: 52_341,
                    destination_port: 443,
                    sequence: 0,
                    acknowledgement: 0,
                    flags: Default::default(),
                    window: 0,
                    header_length: 20,
                    option_count: 0,
                    payload_length: 0,
                },
            )),
            ..NormalizedPacket {
                timestamp_us: 0,
                captured_len: 0,
                original_len: 0,
                ethernet: None,
                vlan: None,
                arp: None,
                ip: None,
                transport: None,
                payload_offset: 0,
                payload_len: 0,
                truncated: false,
                is_fragment: false,
            }
        };

        let key = FlowKey::from_packet(&packet).expect("ip packet yields a key");
        assert_eq!(key.protocol, TransportProtocol::Tcp);
        assert_eq!(key.endpoint_a, endpoint("93.184.216.34", 443));

        // An ARP frame carries no IP layer, so it has no flow identity. This is a distinct
        // case from "a truncated IP packet": ARP is not a flow at all.
        let arp_packet = NormalizedPacket {
            ip: None,
            transport: None,
            arp: Some(sentinel_common::packet::ArpMessage {
                opcode: sentinel_common::packet::ArpOpcode::Request,
                hardware_type: 1,
                protocol_type: 0x0800,
                hardware_len: 6,
                protocol_len: 4,
                sender_mac: Default::default(),
                sender_ip: Ipv4Addr::new(10, 0, 0, 1),
                target_mac: Default::default(),
                target_ip: Ipv4Addr::new(10, 0, 0, 2),
            }),
            ..packet
        };
        assert_eq!(FlowKey::from_packet(&arp_packet), None);
    }
}
