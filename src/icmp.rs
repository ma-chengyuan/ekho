use crate::config::get_config;
use pnet::datalink;
use pnet::datalink::{DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::{IcmpCode, IcmpType, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::transport::{
    icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
};
use pnet::util::{MacAddr, ParseMacAddrErr};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, RwLock};
use std::thread;

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
    let (mut tx, mut rx) = transport_channel(
        8192,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )
    .expect("error creating transport channel");
    let dest_ip = get_config().dest_ip;
    if cfg!(windows) {
        win_fix::fix_windows_error(&rx);
    }
    loop {
        let mut packet = MutableIcmpPacket::owned(vec![0u8; 8]).unwrap();
        packet.set_icmp_type(IcmpType(0));
        packet.set_icmp_code(IcmpCode(0));
        packet.set_checksum(pnet::packet::icmp::checksum(&packet.to_immutable()));
        tx.send_to(packet.consume_to_immutable(), IpAddr::V4(dest_ip))
            .unwrap();
    }
    let mut iter = icmp_packet_iter(&mut rx);
    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                if let IpAddr::V4(ipv4) = addr {
                    if ipv4 == dest_ip {
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

#[cfg(windows)]
mod win_fix {
    use pnet::datalink;
    use pnet::ipnetwork::IpNetwork;
    use pnet::transport::TransportReceiver;
    use std::ffi::CString;
    use std::mem;
    use std::net::Ipv4Addr;
    use winapi::ctypes::c_int;
    use winapi::shared::ipmib::{MIB_IPFORWARDTABLE, PMIB_IPFORWARDTABLE};
    use winapi::shared::minwindef::{DWORD, LPDWORD, LPVOID, ULONG};
    use winapi::shared::mstcpip::{RCVALL_ON, SIO_RCVALL};
    use winapi::shared::winerror::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use winapi::shared::ws2def::{ADDRESS_FAMILY, AF_INET, INADDR_ANY, SOCKADDR, SOCKADDR_IN};
    use winapi::um::heapapi::{GetProcessHeap, HeapAlloc, HeapFree};
    use winapi::um::iphlpapi::GetIpForwardTable;
    use winapi::um::winsock2;
    use winapi::um::winsock2::{bind, inet_addr, WSAIoctl, SOCKET, SOCKET_ERROR};

    fn guess_local_ip() -> Option<Ipv4Addr> {
        unsafe {
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
                    // Exclude virtual TUN/TAP adaptors
                    {
                        if let Some(iface) = datalink::interfaces()
                            .into_iter()
                            .find(|iface| iface.index == row.dwForwardIfIndex)
                        {
                            if let Some(IpNetwork::V4(ip)) = iface.ips.first() {
                                HeapFree(GetProcessHeap(), 0, ptr as LPVOID);
                                return Some(ip.ip());
                            }
                        }
                    }
                }
            }
            HeapFree(GetProcessHeap(), 0, ptr as LPVOID);
            None
        }
    }

    pub fn fix_windows_error(tx: &TransportReceiver) {
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
