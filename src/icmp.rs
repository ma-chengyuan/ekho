use crate::config::get_config;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::{IcmpCode, IcmpType, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol};
use pnet::util::{MacAddr, ParseMacAddrErr};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, RwLock};
use std::thread;
use std::str::FromStr;

fn is_valid_interface(iface: &NetworkInterface) -> bool {
    (cfg!(windows) || iface.is_up()) && !iface.is_loopback() && iface.mac.is_some()
}

fn get_interface_by_name(name: &str) -> Option<NetworkInterface> {
    if let Some(iface) = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == name)
    {
        if is_valid_interface(&iface) {
            return Some(iface);
        }
    }
    None
}

fn get_interface_ip(iface: &NetworkInterface) -> Option<Ipv4Addr> {
    if let Some(ip) = iface.ips.first() {
        if let IpNetwork::V4(ipv4) = ip {
            return Some(ipv4.ip());
        }
    }
    None
}

pub fn init_and_loop() {
    let iface_name = &get_config().iface_name;
    let result = get_interface_by_name(iface_name);
    if result.is_none() {
        log::error!("cannot find interface with name \"{}\"!", iface_name);
        log::error!("available interfaces: ");
        for iface in datalink::interfaces() {
            if is_valid_interface(&iface) {
                for line in format!("{}", iface).split('\n') {
                    log::error!("{}", line);
                }
            }
        }
        panic!("cannot find interface with name \"{}\"", iface_name);
    }
    let interface = Arc::new(result.unwrap());
    let next_hop = Arc::new(RwLock::new(MacAddr::broadcast()));
    let (tx, rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("unknown channel type!"),
        Err(e) => panic!("error creating channel: {}", e),
    };
    let thread_receive = {
        let iface = interface.clone();
        let next_hop = next_hop.clone();
        thread::spawn(|| receive_loop(iface, next_hop, rx))
    };
    let thread_transmit = thread::spawn(|| send_loop(interface, next_hop, tx));
    thread_receive.join().unwrap();
    thread_transmit.join().unwrap();
}

fn receive_loop(
    interface: Arc<NetworkInterface>,
    next_hop: Arc<RwLock<MacAddr>>,
    mut rx: Box<dyn DataLinkReceiver>,
) {
    let self_mac = interface.mac.expect("interface has no MAC address");
    let dest_ip = get_config().dest_ip;
    loop {
        match rx.next() {
            Ok(packet) => {
                let eth_packet = EthernetPacket::new(packet).unwrap();
                if eth_packet.get_source() == self_mac {
                    continue; // Drop outgoing packets
                }
                if let EtherTypes::Ipv4 = eth_packet.get_ethertype() {
                    if let Some(header) = Ipv4Packet::new(eth_packet.payload()) {
                        if header.get_source() == dest_ip {
                            let mut next = next_hop.write().unwrap();
                            *next = eth_packet.get_source();
                        }
                        if let IpNextHeaderProtocols::Icmp = header.get_next_level_protocol() {
                            if let Some(packet) = IcmpPacket::new(header.payload()) {
                                let dest = header.get_destination();
                                log::info!(
                                    "received icmp packet from {} {:?} {:?}",
                                    dest,
                                    packet.get_icmp_type(),
                                    packet.get_icmp_code()
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => panic!("error receiving packet: {}", e),
        }
    }
}

fn send_loop(
    interface: Arc<NetworkInterface>,
    next_hop: Arc<RwLock<MacAddr>>,
    mut tx: Box<dyn DataLinkSender>,
) {
    let self_mac = interface.mac.expect("interface has no MAC address");
    let self_ip = get_interface_ip(&interface).expect("interface has no ipv4 address");
    let dest_ip = get_config().dest_ip;
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::icmp::{IcmpCode, IcmpType, MutableIcmpPacket};
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::MutablePacket;
    let dest_mac = MacAddr::from_str("e0:ac:cb:97:ae:36").unwrap();
    loop {
        let mut buf = [0u8; 14 + 20 + 8];
        let mut eth_packet = MutableEthernetPacket::new(&mut buf).unwrap();
        eth_packet.set_ethertype(EtherTypes::Ipv4);
        let mut ip_packet = MutableIpv4Packet::new(eth_packet.payload_mut()).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(20 + 8);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        let mut icmp_packet = MutableIcmpPacket::new(ip_packet.payload_mut()).unwrap();
        icmp_packet.set_icmp_type(IcmpType(0));
        icmp_packet.set_icmp_code(IcmpCode(0));
        icmp_packet.set_checksum(pnet::packet::icmp::checksum(&icmp_packet.to_immutable()));
        ip_packet.set_source(self_ip);
        ip_packet.set_destination(dest_ip);
        ip_packet.set_checksum(pnet::packet::ipv4::checksum(&ip_packet.to_immutable()));
        eth_packet.set_source(self_mac);
        eth_packet.set_destination(dest_mac);
        tx.send_to(eth_packet.packet(), None).unwrap().unwrap();
    }
}
