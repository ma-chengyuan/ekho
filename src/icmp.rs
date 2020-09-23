#![allow(clippy::cast_ptr_alignment)]
#![allow(clippy::type_complexity)]

use crate::config::get_config;
use crate::kcp::handle_kcp_packet;
use bytes::Bytes;
use crossbeam_channel::{Receiver, Sender};
use lazy_static::lazy_static;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{
    icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
    TransportReceiver, TransportSender,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr};
use std::num::Wrapping;

const MAGIC: [u8; 3] = [0x4b, 0x43, 0x50];

#[derive(Hash, Eq, PartialEq, Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: Ipv4Addr,
    pub id: u16,
}

pub type PacketInfo = (Endpoint, Bytes);
lazy_static! {
    static ref CHANNEL: (Sender<PacketInfo>, Receiver<PacketInfo>) =
        crossbeam_channel::bounded(get_config().icmp.send_buffer_size);
}

pub fn get_sender() -> Sender<PacketInfo> {
    CHANNEL.0.clone()
}

pub fn init_and_loop() {
    let (mut tx, mut rx) = transport_channel(
        get_config().icmp.recv_buffer_size,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )
    .expect("error creating transport channel");
    platform_specific::prepare_receiver(&rx);
    crossbeam_utils::thread::scope(|s| {
        s.spawn(|_| recv_loop(&mut rx));
        s.spawn(|_| send_loop(&mut tx, CHANNEL.1.clone()));
    })
    .unwrap();
}

fn recv_loop(rx: &mut TransportReceiver) {
    let mut iter = icmp_packet_iter(rx);
    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                if let IpAddr::V4(ipv4) = addr {
                    if platform_specific::filter_local_ip(ipv4) {
                        let payload = packet.payload();
                        if (packet.get_icmp_type() == IcmpTypes::EchoRequest
                            || packet.get_icmp_type() == IcmpTypes::EchoReply)
                            && payload.len() >= 8
                            && payload[4..7] == MAGIC
                        {
                            handle_kcp_packet(
                                &payload[8..],
                                Endpoint {
                                    ip: ipv4,
                                    id: u16::from_be_bytes(payload[..2].try_into().unwrap()),
                                },
                            );
                        }
                    }
                }
            }
            Err(e) => panic!("error receiving ICMP packet: {}", e),
        }
    }
}

fn send_loop(tx: &mut TransportSender, input: Receiver<PacketInfo>) {
    const HEADER: usize = IcmpPacket::minimum_packet_size();
    let mut buf = [0u8; 1500];
    let mut resend_last_packet = false;
    let mut packet_len = 0usize;
    let mut seq: HashMap<Endpoint, u16> = HashMap::new();
    let code = match get_config().remote {
        Some(_) => IcmpTypes::EchoRequest,
        None => IcmpTypes::EchoReply,
    };
    let mut last_endpoint = Endpoint {
        ip: Ipv4Addr::UNSPECIFIED,
        id: 0,
    };
    loop {
        let result = if resend_last_packet {
            tx.send_to(
                IcmpPacket::new(&buf[..packet_len]).unwrap(),
                IpAddr::from(last_endpoint.ip),
            )
        } else {
            let (endpoint, block) = input.recv().expect("error receiving data");
            packet_len = HEADER + 4 /* conv */ + 3 /* magic number */ + 1 /* type */ + block.len();
            let mut packet = MutableIcmpPacket::new(&mut buf[0..packet_len]).unwrap();
            packet.set_icmp_type(code);
            let payload = packet.payload_mut();
            payload[0..2].copy_from_slice(&endpoint.id.to_be_bytes());
            payload[2..4].copy_from_slice(&seq.entry(endpoint).or_insert(0).to_be_bytes());
            payload[4..7].copy_from_slice(&MAGIC);
            payload[7] = 0 /* RESERVED */;
            payload[8..].copy_from_slice(&block);
            packet.set_checksum(pnet::packet::icmp::checksum(&packet.to_immutable()));
            last_endpoint = endpoint;
            tx.send_to(packet.consume_to_immutable(), IpAddr::from(endpoint.ip))
        };
        resend_last_packet = match result {
            Ok(_) => {
                seq.entry(last_endpoint)
                    .and_modify(|s| *s = (Wrapping(*s) + Wrapping(1)).0);
                false
            }
            Err(e) => match e.raw_os_error() {
                Some(105 /*ENOBUFS on Unix*/) if cfg!(unix) => true,
                _ => panic!("error sending ICMP packets: {}", e),
            },
        }
    }
}

/// On windows, ICMP raw sockets will not work if bound to 0.0.0.0 instead of a specific IP, as is
/// the default behavior of libpnet.
/// Moreover, SIO_RCVALL needs to be enabled for the raw socket to receive ICMP traffic.
/// However, if we enable SIO_RCVALL, then we'll also receive outgoing packets, which is not quite
/// what we want.
/// This module
/// 1. Guesses the common network adapter of the system and acquires its IP to bind the socket.
/// 2. Filters out outgoing packets by their source IP.
#[cfg(windows)]
mod platform_specific {
    use lazy_static::lazy_static;
    use parking_lot::RwLock;
    use pnet::transport::TransportReceiver;
    use std::ffi::CString;
    use std::mem;
    use std::net::Ipv4Addr;
    use std::thread;
    use winapi::ctypes::c_int;
    use winapi::shared::ifdef::IF_INDEX;
    use winapi::shared::ipmib::{PMIB_IPADDRTABLE, PMIB_IPFORWARDTABLE};
    use winapi::shared::minwindef::{DWORD, LPDWORD, LPVOID, ULONG};
    use winapi::shared::mstcpip::{RCVALL_IPLEVEL, SIO_RCVALL};
    use winapi::shared::ntdef::PHANDLE;
    use winapi::shared::winerror::NO_ERROR;
    use winapi::shared::ws2def::{ADDRESS_FAMILY, AF_INET, INADDR_ANY, SOCKADDR, SOCKADDR_IN};
    use winapi::um::iphlpapi::{GetIpAddrTable, GetIpForwardTable, NotifyAddrChange};
    use winapi::um::minwinbase::LPOVERLAPPED;
    use winapi::um::winsock2::{bind, inet_addr, ntohs, WSAIoctl, SOCKET, SOCKET_ERROR};

    lazy_static! {
        static ref LOCAL_INTERFACE: Option<IF_INDEX> = unsafe { guess_local_interface() };
        static ref LOCAL_IP: RwLock<Option<Ipv4Addr>> =
            RwLock::new(unsafe { LOCAL_INTERFACE.and_then(|index| get_ip_from_index(index)) });
    }

    unsafe fn get_ip_from_index(index: IF_INDEX) -> Option<Ipv4Addr> {
        const BUFFER_SIZE: usize = 1 << 14;
        static mut BUFFER: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
        let ptr = BUFFER.as_mut_ptr() as PMIB_IPADDRTABLE;
        let mut size = BUFFER_SIZE as ULONG;
        if GetIpAddrTable(ptr, &mut size, 0) == NO_ERROR {
            for i in 0..(*ptr).dwNumEntries {
                let row = (*ptr).table.get_unchecked(i as usize);
                if row.dwIndex == index {
                    let octets = row.dwAddr.to_be_bytes();
                    return Some(Ipv4Addr::new(octets[3], octets[2], octets[1], octets[0]));
                }
            }
        }
        None
    }

    unsafe fn guess_local_interface() -> Option<IF_INDEX> {
        const BUFFER_SIZE: usize = 1 << 14;
        static mut BUFFER: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
        let ptr = BUFFER.as_mut_ptr() as PMIB_IPFORWARDTABLE;
        let mut size = BUFFER_SIZE as ULONG;
        if GetIpForwardTable(ptr, &mut size, 0) == NO_ERROR {
            for i in 0..(*ptr).dwNumEntries {
                let row = (*ptr).table.get_unchecked(i as usize);
                if row.dwForwardDest == INADDR_ANY
                    && row.dwForwardMask == INADDR_ANY
                    && row.dwForwardMetric1 != 0
                // Exclude virtual TUN/TAP adapters
                {
                    return Some(row.dwForwardIfIndex);
                }
            }
        }
        None
    }

    pub fn prepare_receiver(tx: &TransportReceiver) {
        unsafe {
            let socket = tx.socket.fd as SOCKET;
            let mut addr: SOCKADDR_IN = mem::zeroed();
            addr.sin_family = AF_INET as ADDRESS_FAMILY;
            addr.sin_port = ntohs(0);
            let ip = LOCAL_IP.read().expect("cannot guess the local ip");
            log::info!("raw socket bound to ip {}", ip);
            let ip_str = CString::new(format!("{}", ip)).unwrap();
            *addr.sin_addr.S_un.S_addr_mut() = inet_addr(ip_str.as_ptr());
            let error = bind(
                socket,
                &addr as *const SOCKADDR_IN as *const SOCKADDR,
                mem::size_of::<SOCKADDR_IN>() as c_int,
            );
            if error == SOCKET_ERROR {
                panic!(
                    "error binding the socket: {}",
                    std::io::Error::last_os_error()
                );
            }
            // This step is necessary for ICMP raw socket as well
            let in_opt = RCVALL_IPLEVEL.to_le_bytes();
            let out_opt = 0u32.to_le_bytes();
            let returned = [0 as DWORD; 0];
            let error = WSAIoctl(
                socket,
                SIO_RCVALL,
                in_opt.as_ptr() as LPVOID,
                in_opt.len() as DWORD,
                out_opt.as_ptr() as LPVOID,
                out_opt.len() as DWORD,
                &returned as *const DWORD as LPDWORD,
                std::ptr::null_mut(),
                None,
            );
            if error == SOCKET_ERROR {
                panic!(
                    "error setting io control: {}",
                    std::io::Error::last_os_error()
                );
            }
            thread::spawn(|| loop {
                NotifyAddrChange(0 as PHANDLE, 0 as LPOVERLAPPED);
                *LOCAL_IP.write() = LOCAL_INTERFACE.and_then(|index| get_ip_from_index(index));
                log::info!("Local IP changed to {:?}", LOCAL_IP.read());
            });
        }
    }

    pub fn filter_local_ip(addr: Ipv4Addr) -> bool {
        LOCAL_IP.read().map(|local| local != addr).unwrap_or(true)
    }
}

#[cfg(not(windows))]
mod platform_specific {
    use pnet::transport::TransportReceiver;
    use std::net::Ipv4Addr;

    pub fn prepare_receiver(_tx: &TransportReceiver) {}

    pub fn filter_local_ip(_addr: Ipv4Addr) -> bool {
        true
    }
}