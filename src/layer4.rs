use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::icmp::{IcmpType, IcmpCode, MutableIcmpPacket};
use pnet::packet::{Packet};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, icmp_packet_iter};
use bytes::{Bytes, Buf, BytesMut, BufMut};
use std::{thread, time};
use std::net::{IpAddr};
use std::sync::{Arc, Mutex};

pub fn recv_loop() {
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
    let (tx, mut rx) = transport_channel(4096, protocol)
        .expect("error creating transport channel");
    let mut iter = icmp_packet_iter(&mut rx);

    let tx = Arc::new(Mutex::new(tx));

    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                if let IcmpType(8) = packet.get_icmp_type() { // Ping request
                    let mut data = Bytes::copy_from_slice(packet.payload());
                    let id = data.get_u16();
                    println!("Received ICMP ping request from {} with id {}", addr, id);
                    let local_tx = tx.clone();
                    thread::spawn(move || {
                        for _ in 1..60 {
                            let mut buf = vec![0; 1024];
                            let mut packet = MutableIcmpPacket::new(&mut buf).unwrap();
                            packet.set_icmp_code(IcmpCode(0));
                            packet.set_icmp_type(IcmpType(0));
                            let mut payload = BytesMut::new();
                            payload.put_u16(id);
                            payload.put_u16(0);
                            packet.set_payload(&payload);
                            packet.set_checksum(pnet::packet::icmp::checksum(&packet.to_immutable()));
                            {
                                let mut tx = local_tx.lock().unwrap();
                                tx.send_to(packet, addr).unwrap();
                            }
                            thread::sleep(time::Duration::from_millis(500));
                        }
                    });
                } else {
                    println!("ICMP packet from {:?} type {:?} code {:?} payload {:?}",
                             addr, packet.get_icmp_type(), packet.get_icmp_code(), packet.payload());
                }
            }
            Err(e) => {
                panic!("error: {}", e);
            }
        }
    }
}