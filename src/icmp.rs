#![allow(clippy::cast_ptr_alignment)]
#![allow(clippy::type_complexity)]

use crate::config::get_config;
use crossbeam_channel::{Receiver, Sender};
use lazy_static::lazy_static;
use pnet_packet::icmp::{IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::{MutablePacket, Packet};
use pnet_transport::{
    icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
    TransportReceiver, TransportSender,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr};
use std::num::Wrapping;
use std::thread;
use std::thread_local;

#[derive(Hash, Eq, PartialEq, Copy, Clone, Debug, Deserialize)]
pub struct IcmpEndpoint {
    pub ip: Ipv4Addr,
    pub id: u16,
}

pub type PacketWithEndpoint = (IcmpEndpoint, Vec<u8>);
lazy_static! {
    static ref CHANNEL: (Sender<PacketWithEndpoint>, Receiver<PacketWithEndpoint>) =
        // crossbeam_channel::bounded(get_config().icmp.send_buffer_size);
        crossbeam_channel::unbounded();
}

pub fn send_packet(to: IcmpEndpoint, packet: Vec<u8>) {
    thread_local!(static LOCAL_SENDER: Sender<PacketWithEndpoint> = CHANNEL.0.clone());
    LOCAL_SENDER.with(|sender| sender.send((to, packet)).unwrap());
}

pub fn init_send_recv_loop() {
    let (mut tx, mut rx) = transport_channel(
        8192,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )
    .expect("error creating transport channel");
    platform_impl::prepare_receiver(&rx);
    thread::spawn(move || recv_loop(&mut rx));
    thread::spawn(move || send_loop(&mut tx, CHANNEL.1.clone()));
}

fn recv_loop(rx: &mut TransportReceiver) {
    let mut iter = icmp_packet_iter(rx);
    loop {
        let (packet, addr) = iter.next().expect("error receiving ICMP packet");
        if let IpAddr::V4(ipv4) = addr {
            if platform_impl::filter_local_ip(ipv4) {
                let payload = packet.payload();
                if (packet.get_icmp_type() == IcmpTypes::EchoRequest
                    || packet.get_icmp_type() == IcmpTypes::EchoReply)
                    && payload.len() >= 4
                {
                    let endpoint = IcmpEndpoint {
                        ip: ipv4,
                        id: u16::from_be_bytes(payload[..2].try_into().unwrap()),
                    };
                    crate::kcp::on_recv_packet(&payload[4..], endpoint);
                }
            }
        }
    }
}

fn send_loop(tx: &mut TransportSender, input: Receiver<PacketWithEndpoint>) {
    let mut buf = [0u8; 1500 /* typical Ethernet MTU */];
    let mut resend = false;
    let mut len = 0usize;
    let mut seq: HashMap<IcmpEndpoint, u16> = HashMap::new();
    let code = match get_config().remote {
        Some(_) => IcmpTypes::EchoRequest,
        None => IcmpTypes::EchoReply,
    };
    let mut last_dst = IcmpEndpoint {
        ip: Ipv4Addr::UNSPECIFIED,
        id: 0,
    };
    loop {
        let result = if resend {
            tx.send_to(
                IcmpPacket::new(&buf[..len]).unwrap(),
                IpAddr::from(last_dst.ip),
            )
        } else {
            let (dst, data) = input.recv().expect("error receiving data");
            len = IcmpPacket::minimum_packet_size() + 4 + data.len();
            let mut packet = MutableIcmpPacket::new(&mut buf[0..len]).unwrap();
            packet.set_icmp_type(code);
            let payload = packet.payload_mut();
            payload[0..2].copy_from_slice(&dst.id.to_be_bytes());
            payload[2..4].copy_from_slice(&seq.entry(dst).or_insert(0).to_be_bytes());
            payload[4..].copy_from_slice(&data);
            packet.set_checksum(pnet_packet::icmp::checksum(&packet.to_immutable()));
            last_dst = dst;
            tx.send_to(packet.consume_to_immutable(), IpAddr::from(dst.ip))
        };
        resend = match result {
            Ok(_) => {
                // Increment the seq. number
                seq.entry(last_dst)
                    .and_modify(|s| *s = (Wrapping(*s) + Wrapping(1)).0);
                false
            }
            Err(e) => match e.raw_os_error() {
                // Sometimes attempting to send packets too fast will trigger a ENOBUF error
                // (perhaps a driver-dependent issue). In this case we shall just attempt to resend
                // that packet.
                Some(105 /* ENOBUFS */) if cfg!(unix) => true,
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
mod platform_impl {
    use lazy_static::lazy_static;
    use parking_lot::RwLock;
    use pnet_transport::TransportReceiver;
    use std::ffi::CString;
    use std::mem::{size_of, zeroed};
    use std::net::Ipv4Addr;
    use std::thread;
    use winapi::ctypes::c_int;
    use winapi::shared::ifdef::IF_INDEX;
    use winapi::shared::ipmib::{
        MIB_IPADDRTABLE, MIB_IPFORWARDTABLE, PMIB_IPADDRTABLE, PMIB_IPFORWARDTABLE,
    };
    use winapi::shared::minwindef::{DWORD, LPDWORD, LPVOID};
    use winapi::shared::mstcpip::{RCVALL_IPLEVEL, SIO_RCVALL};
    use winapi::shared::ntdef::PHANDLE;
    use winapi::shared::winerror::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use winapi::shared::ws2def::{ADDRESS_FAMILY, AF_INET, INADDR_ANY, SOCKADDR, SOCKADDR_IN};
    use winapi::um::heapapi::{GetProcessHeap, HeapAlloc, HeapFree};
    use winapi::um::iphlpapi::{GetIpAddrTable, GetIpForwardTable, NotifyAddrChange};
    use winapi::um::minwinbase::LPOVERLAPPED;
    use winapi::um::winsock2::{bind, inet_addr, ntohs, WSAIoctl, SOCKET, SOCKET_ERROR};

    lazy_static! {
        static ref LOCAL_INTERFACE: Option<IF_INDEX> = unsafe { guess_local_interface() };
        static ref LOCAL_IP: RwLock<Option<Ipv4Addr>> =
            RwLock::new(unsafe { LOCAL_INTERFACE.and_then(|index| get_ip_from_index(index)) });
    }

    unsafe fn alloc(size: usize) -> LPVOID {
        HeapAlloc(GetProcessHeap(), 0, size)
    }

    unsafe fn free(ptr: LPVOID) {
        HeapFree(GetProcessHeap(), 0, ptr);
    }

    unsafe fn get_ip_from_index(index: IF_INDEX) -> Option<Ipv4Addr> {
        let mut ptr = alloc(size_of::<MIB_IPADDRTABLE>()) as PMIB_IPADDRTABLE;
        let mut size = 0;
        if GetIpAddrTable(ptr, &mut size, 0) == ERROR_INSUFFICIENT_BUFFER {
            free(ptr as LPVOID);
            ptr = alloc(size as usize) as PMIB_IPADDRTABLE;
        }
        if GetIpAddrTable(ptr, &mut size, 0) == NO_ERROR {
            for i in 0..(*ptr).dwNumEntries {
                let row = (*ptr).table.get_unchecked(i as usize);
                if row.dwIndex == index {
                    let octets = row.dwAddr.to_le_bytes();
                    free(ptr as LPVOID);
                    return Some(Ipv4Addr::from(octets));
                }
            }
        }
        free(ptr as LPVOID);
        None
    }

    unsafe fn guess_local_interface() -> Option<IF_INDEX> {
        let mut ptr = alloc(size_of::<MIB_IPFORWARDTABLE>()) as PMIB_IPFORWARDTABLE;
        let mut size = 0;
        if GetIpForwardTable(ptr, &mut size, 0) == ERROR_INSUFFICIENT_BUFFER {
            free(ptr as LPVOID);
            ptr = alloc(size as usize) as PMIB_IPFORWARDTABLE;
        }
        if GetIpForwardTable(ptr, &mut size, 0) == NO_ERROR {
            for i in 0..(*ptr).dwNumEntries {
                let row = (*ptr).table.get_unchecked(i as usize);
                if row.dwForwardDest == INADDR_ANY
                    && row.dwForwardMask == INADDR_ANY
                    && row.dwForwardMetric1 != 0
                // dwForwardMetric 1 != 0 to exclude virtual TUN/TAP adapters
                {
                    let ret = Some(row.dwForwardIfIndex);
                    free(ptr as LPVOID);
                    return ret;
                }
            }
        }
        free(ptr as LPVOID);
        None
    }

    pub fn prepare_receiver(tx: &TransportReceiver) {
        unsafe {
            let socket = tx.socket.fd as SOCKET;
            let ip = LOCAL_IP.read().expect("cannot guess the local ip");
            log::info!("raw socket bound to ip {}", ip);
            let ip_str = CString::new(ip.to_string()).unwrap();

            let mut addr: SOCKADDR_IN = zeroed();
            addr.sin_family = AF_INET as ADDRESS_FAMILY;
            addr.sin_port = ntohs(0);
            *addr.sin_addr.S_un.S_addr_mut() = inet_addr(ip_str.as_ptr());

            let error = bind(
                socket,
                &addr as *const SOCKADDR_IN as *const SOCKADDR,
                size_of::<SOCKADDR_IN>() as c_int,
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
                // Luckily, we do not need to re-bind the socket, because when we bind the IP to the
                // raw socket Windows actually binds that socket to the network adaptor. As long as
                // the network adaptor does not change the change of local IP does not invalidate
                // the socket.
                log::info!("Local IP changed to {:?}", LOCAL_IP.read());
            });
        }
    }

    pub fn filter_local_ip(addr: Ipv4Addr) -> bool {
        LOCAL_IP.read().map(|local| local != addr).unwrap_or(true)
    }
}

#[cfg(not(windows))]
mod platform_impl {
    use pnet_transport::TransportReceiver;
    use std::net::Ipv4Addr;

    pub fn prepare_receiver(_tx: &TransportReceiver) {}

    pub fn filter_local_ip(_addr: Ipv4Addr) -> bool {
        true
    }
}
