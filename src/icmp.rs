#![allow(clippy::cast_ptr_alignment)]

use crate::config::get_config;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use crossbeam_channel::{Receiver, Sender};
use lazy_static::lazy_static;
use once_cell::sync::OnceCell;
use pnet::packet::icmp::{IcmpCode, IcmpPacket, IcmpType, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::MutablePacket;
use pnet::transport::{
    icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
    TransportReceiver, TransportSender,
};
use std::net::IpAddr;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

const MAGIC: [u8; 3] = [0x4b, 0x43, 0x50];
lazy_static! {
    static ref CHANNEL: (Sender<Bytes>, Receiver<Bytes>) = crossbeam_channel::bounded(10);
}

pub fn get_sender() -> Sender<Bytes> {
    CHANNEL.0.clone()
}

pub fn init_and_loop() {
    let (mut tx, mut rx) = transport_channel(
        get_config().layer4_buffer,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )
    .expect("error creating transport channel");
    win_fix::fix_windows_error(&rx);
    crossbeam_utils::thread::scope(|s| {
        // TODO: Make both threads adapt to change of IP
        s.spawn(|_| rx_loop(&mut rx));
        s.spawn(|_| tx_loop(&mut tx, CHANNEL.1.clone()));
    })
    .unwrap();
}

fn rx_loop(rx: &mut TransportReceiver) {
    let dest_ip = get_config().dest_ip;
    let mut iter = icmp_packet_iter(rx);
    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                if let IpAddr::V4(ipv4) = addr {
                    if true {
                        log::info!(
                            "ICMP packet from {:?} {:?} {:?}",
                            addr,
                            packet.get_icmp_type(),
                            packet.get_icmp_code()
                        )
                    }
                }
            }
            Err(e) => panic!("error receiving ICMP packet: {}", e),
        }
    }
}

fn tx_loop(tx: &mut TransportSender, input: Receiver<Bytes>) {
    const HEADER: usize = IcmpPacket::minimum_packet_size();
    let dest_ip = IpAddr::V4(get_config().dest_ip);
    let mut buf = [0u8; 1500];
    let mut resend_last_packet = false;
    let mut packet_len = 0usize;
    loop {
        let result = if resend_last_packet {
            tx.send_to(IcmpPacket::new(&buf[..packet_len]).unwrap(), dest_ip)
        } else {
            let block = input.recv().expect("error receiving data");
            packet_len = HEADER + 4 /* conv */ + 3 /* magic number */ + 1 /* type */ + block.len();
            let mut packet = MutableIcmpPacket::new(&mut buf[0..packet_len]).unwrap();
            packet.set_icmp_type(IcmpType(0));
            packet.set_icmp_code(IcmpCode(0));
            let payload = packet.payload_mut();
            payload[..4].copy_from_slice(&44353u32.to_be_bytes());
            payload[4..4 + 3].copy_from_slice(&MAGIC);
            payload[4 + 3] = 0 /* RESERVED */;
            payload[4 + 3 + 1..].copy_from_slice(&block);
            tx.send_to(packet.consume_to_immutable(), dest_ip)
        };
        resend_last_packet = match result {
            Ok(_) => false,
            Err(e) => match e.raw_os_error() {
                Some(105 /*ENOBUFS on Unix*/) if cfg!(unix) => true,
                _ => panic!("error sending ICMP packets: {}", e),
            },
        }
    }
}

#[cfg(windows)]
mod win_fix {
    use pnet::datalink;
    use pnet::ipnetwork::IpNetwork;
    use pnet::transport::TransportReceiver;
    use std::ffi::{CStr, CString};
    use std::mem;
    use std::net::Ipv4Addr;
    use std::time::Instant;
    use winapi::ctypes::c_int;
    use winapi::shared::ifdef::IF_INDEX;
    use winapi::shared::ipmib::{MIB_IPFORWARDTABLE, PMIB_IPFORWARDTABLE};
    use winapi::shared::minwindef::{DWORD, LPDWORD, LPVOID, ULONG};
    use winapi::shared::mstcpip::{RCVALL_ON, SIO_RCVALL};
    use winapi::shared::ntdef::PVOID;
    use winapi::shared::winerror::{ERROR_BUFFER_OVERFLOW, ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use winapi::shared::ws2def::{ADDRESS_FAMILY, AF_INET, INADDR_ANY, SOCKADDR, SOCKADDR_IN};
    use winapi::um::heapapi::{GetProcessHeap, HeapAlloc, HeapFree};
    use winapi::um::iphlpapi::{GetAdaptersAddresses, GetIpForwardTable};
    use winapi::um::iptypes::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_FRIENDLY_NAME,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES, PIP_ADAPTER_ADDRESSES,
    };
    use winapi::um::winsock2;
    use winapi::um::winsock2::{bind, inet_addr, inet_ntoa, WSAIoctl, SOCKET, SOCKET_ERROR};

    unsafe fn get_ip_from_index(index: IF_INDEX) -> Option<Ipv4Addr> {
        const BUFFER_SIZE: usize = 32768;
        static mut BUFFER: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
        let ptr = BUFFER.as_mut_ptr() as PIP_ADAPTER_ADDRESSES;
        let mut size: ULONG = BUFFER_SIZE as ULONG;
        let flags = GAA_FLAG_SKIP_MULTICAST
            | GAA_FLAG_SKIP_ANYCAST
            | GAA_FLAG_SKIP_FRIENDLY_NAME
            | GAA_FLAG_SKIP_DNS_SERVER;
        if GetAdaptersAddresses(AF_INET as ULONG, flags, 0 as PVOID, ptr, &mut size) == NO_ERROR {
            let mut current = ptr;
            while !current.is_null() {
                if (*current).u.s().IfIndex == index {
                    let addr = (*current).FirstUnicastAddress;
                    if !addr.is_null()
                        && (*(*addr).Address.lpSockaddr).sa_family == AF_INET as ADDRESS_FAMILY
                    {
                        let sockaddr = (*addr).Address.lpSockaddr as *mut SOCKADDR_IN;
                        let s = (*sockaddr).sin_addr.S_un.S_un_b();
                        let ret = Ipv4Addr::new(s.s_b1, s.s_b2, s.s_b3, s.s_b4);
                        return Some(ret);
                    }
                }
                current = (*current).Next;
            }
        }
        None
    }

    unsafe fn guess_local_ip() -> Option<Ipv4Addr> {
        let mut ptr = HeapAlloc(GetProcessHeap(), 0, mem::size_of::<MIB_IPFORWARDTABLE>())
            as PMIB_IPFORWARDTABLE;
        let mut size: ULONG = 0;
        if GetIpForwardTable(ptr, &mut size, 0) == ERROR_INSUFFICIENT_BUFFER {
            HeapFree(GetProcessHeap(), 0, ptr as LPVOID);
            ptr = HeapAlloc(GetProcessHeap(), 0, size as usize) as PMIB_IPFORWARDTABLE;
        }
        if GetIpForwardTable(ptr, &mut size, 0) == NO_ERROR {
            for i in 0..(*ptr).dwNumEntries {
                let row = &(*ptr).table[i as usize];
                if row.dwForwardDest == INADDR_ANY
                    && row.dwForwardMask == INADDR_ANY
                    && row.dwForwardMetric1 != 0
                // Exclude virtual TUN/TAP adapters
                {
                    return get_ip_from_index(row.dwForwardIfIndex);
                }
            }
        }
        HeapFree(GetProcessHeap(), 0, ptr as LPVOID);
        None
    }

    pub fn fix_windows_error(tx: &TransportReceiver) {
        let mut test = None;
        let start = Instant::now();
        for _ in 0..1000 {
            test = unsafe { guess_local_ip() };
        }
        println!("{:?}", start.elapsed());
        unsafe {
            let socket = tx.socket.fd as SOCKET;
            let mut addr: SOCKADDR_IN = mem::zeroed();
            addr.sin_family = AF_INET as ADDRESS_FAMILY;
            addr.sin_port = winsock2::ntohs(0);
            let ip = guess_local_ip().expect("cannot guess the local ip");
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
            let in_opt = RCVALL_ON.to_le_bytes();
            let out_opt = 0u32.to_le_bytes();
            let returned = [0 as DWORD; 0];
            let error = WSAIoctl(
                socket,
                SIO_RCVALL,
                &in_opt as *const u8 as LPVOID,
                in_opt.len() as DWORD,
                &out_opt as *const u8 as LPVOID,
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
        }
    }
}

#[cfg(not(windows))]
mod win_fix {
    use pnet::transport::TransportReceiver;

    pub fn fix_windows_error(_tx: &TransportReceiver) {}
}
