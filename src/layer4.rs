use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, icmp_packet_iter};
use std::thread;
use std::net::{Ipv4Addr, IpAddr};
use std::str::FromStr;

pub fn recv_loop() {
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
    let (mut tx, mut rx) = transport_channel(4096, protocol)
        .expect("error creating transport channel");
    let mut iter = icmp_packet_iter(&mut rx);

    let _ = thread::spawn(move || {
    });

    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                println!("ICMP packet from {:?} type {:?} code {:?} payload {:?}",
                    addr, packet.get_icmp_type(), packet.get_icmp_code(), packet.payload());
            },
            Err(e) => {
                panic!("error: {}", e);
            }
        }
    }
}