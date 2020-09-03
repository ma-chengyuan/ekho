use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, udp_packet_iter};
use std::thread;
use std::net::{Ipv4Addr, IpAddr};
use std::str::FromStr;

pub fn recv_loop() {
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Test1));
    let (mut tx, mut rx) = transport_channel(4096, protocol)
        .expect("error creating transport channel");
    let mut iter = udp_packet_iter(&mut rx);

    let _ = thread::spawn(move || {
        let mut buf = vec![0; 2048];
        let mut packet = MutableUdpPacket::new(&mut buf).unwrap();
        packet.set_source(0u16);
        packet.set_destination(23333u16);
        tx.send_to(packet, IpAddr::V4(Ipv4Addr::from_str("127.0.0.1").unwrap())).unwrap();
    });

    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                let mut vec: Vec<u8> = vec![0; packet.packet().len()];
                let mut new_packet = MutableUdpPacket::new(&mut vec[..]).unwrap();

                new_packet.clone_from(&packet);
                println!("{:?}:{:?}", addr, new_packet);
            },
            Err(e) => {
                panic!("error: {}", e);
            }
        }
    }
}