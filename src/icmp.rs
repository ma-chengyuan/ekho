/*
Copyright 2021 Chengyuan Ma

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute, sub-
-license, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-
-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#![allow(clippy::cast_ptr_alignment)]
#![allow(clippy::type_complexity)]
#![allow(clippy::if_same_then_else)]

use crate::config::config;
use anyhow::{Context, Result};
use lazy_static::lazy_static;
use parking_lot::Mutex as SyncMutex;
use pnet_packet::icmp::{IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::{MutablePacket, Packet};
use pnet_transport::{
    icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
    TransportReceiver, TransportSender,
};
use rustc_hash::FxHashMap;
use serde::Deserialize;
use std::convert::TryInto;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::num::Wrapping;
use std::thread;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::Mutex;
use tracing::{debug_span, instrument};

#[derive(Hash, Eq, PartialEq, Copy, Clone, Debug, Deserialize)]
pub struct IcmpEndpoint {
    pub ip: Ipv4Addr,
    pub id: u16,
}

impl fmt::Display for IcmpEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip, self.id)
    }
}

type Sender = UnboundedSender<(IcmpEndpoint, Vec<u8>)>;
type Receiver = UnboundedReceiver<(IcmpEndpoint, Vec<u8>)>;

lazy_static! {
    static ref TX_CHANNEL: (Mutex<Sender>, SyncMutex<Receiver>) = {
        let (tx, rx) = unbounded_channel();
        (Mutex::new(tx), SyncMutex::new(rx))
    };
    static ref RX_CHANNEL: (SyncMutex<Sender>, Mutex<Receiver>) = {
        let (tx, rx) = unbounded_channel();
        (SyncMutex::new(tx), Mutex::new(rx))
    };
}

pub async fn clone_sender() -> Sender {
    TX_CHANNEL.0.lock().await.clone()
}

pub async fn receive_packet() -> (IcmpEndpoint, Vec<u8>) {
    RX_CHANNEL.1.lock().await.recv().await.unwrap()
}

pub async fn init_send_recv_loop() -> Result<()> {
    let (tx, rx) = transport_channel(
        8192,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )
    .with_context(|| {
        format!(
            "failed to create ICMP socket ({})",
            if cfg!(target_os = "linux") {
                "Ekho needs to be run either as root or with NET_CAP_RAW"
            } else if cfg!(windows) {
                "Ekho needs to be run with administrator privilege"
            } else {
                "Ekho needs to be run with a higher privilege to be able to set up ICMP socket"
            }
        )
    })?;
    platform_impl::prepare_receiver(&rx)?;
    thread::spawn(move || recv_loop(rx));
    thread::spawn(move || send_loop(tx));
    Ok(())
}

#[instrument(skip(rx))]
fn recv_loop(mut rx: TransportReceiver) {
    let mut iter = icmp_packet_iter(&mut rx);
    let sender = RX_CHANNEL.0.lock();
    loop {
        let (packet, addr) = {
            let span = debug_span!("recv_icmp_packet");
            let _enter = span.enter();
            iter.next().expect("error receiving ICMP packet")
        };
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
                    sender.send((endpoint, Vec::from(&payload[4..]))).unwrap();
                }
            }
        }
    }
}

/*
#[instrument(skip(tx))]
fn send_loop(mut tx: TransportSender) {
    let mut buf = [0u8; 1500 /* typical Ethernet MTU */];
    let mut resend = false;
    let mut len = 0usize;
    let mut seq: FxHashMap<IcmpEndpoint, u16> = FxHashMap::default();
    let code = match config().remote {
        Some(_) => IcmpTypes::EchoRequest,
        None => IcmpTypes::EchoReply,
    };
    let mut last_dst = IcmpEndpoint {
        ip: Ipv4Addr::UNSPECIFIED,
        id: 0,
    };
    let mut receiver = TX_CHANNEL.1.lock();
    loop {
        let result = if resend {
            let span = debug_span!("resend_icmp");
            let _enter = span.enter();
            tx.send_to(
                IcmpPacket::new(&buf[..len]).unwrap(),
                IpAddr::from(last_dst.ip),
            )
        } else {
            let (dst, data) = {
                let span = debug_span!("recv_payload");
                let _enter = span.enter();
                receiver.blocking_recv().unwrap()
            };
            let span = debug_span!("send_icmp");
            let _enter = span.enter();
            len = IcmpPacket::minimum_packet_size() + 4 + data.len();
            let mut packet = MutableIcmpPacket::new(&mut buf[0..len]).unwrap();
            packet.set_icmp_type(code);
            let payload = packet.payload_mut();
            payload[..2].copy_from_slice(&dst.id.to_be_bytes());
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
 */

#[instrument(skip(tx))]
fn send_loop(mut tx: TransportSender) {
    let mut buf = vec![0u8; IcmpPacket::minimum_packet_size() + 4 + config().kcp.mtu as usize];
    let mut seq: FxHashMap<IcmpEndpoint, u16> = FxHashMap::default();
    let code = match config().remote {
        Some(_) => IcmpTypes::EchoRequest,
        None => IcmpTypes::EchoReply,
    };
    let mut receiver = TX_CHANNEL.1.lock();
    loop {
        let (dst, data) = {
            let span = debug_span!("recv_payload");
            let _enter = span.enter();
            receiver.blocking_recv().unwrap()
        };
        let span = debug_span!("send_icmp", ?dst);
        let _enter = span.enter();
        let len = IcmpPacket::minimum_packet_size() + 4 + data.len();
        let mut packet = MutableIcmpPacket::new(&mut buf[0..len]).unwrap();
        packet.set_icmp_type(code);
        let payload = packet.payload_mut();
        payload[..2].copy_from_slice(&dst.id.to_be_bytes());
        payload[2..4].copy_from_slice(&seq.entry(dst).or_insert(0).to_be_bytes());
        payload[4..].copy_from_slice(&data);
        packet.set_checksum(pnet_packet::icmp::checksum(&packet.to_immutable()));
        match tx.send_to(packet.consume_to_immutable(), IpAddr::from(dst.ip)) {
            Ok(_) => {
                // Increment the seq. number
                seq.entry(dst)
                    .and_modify(|s| *s = (Wrapping(*s) + Wrapping(1)).0);
            }
            Err(e) => match e.raw_os_error() {
                // Silently drop the packet if we are sending too fast
                Some(105 /* ENOBUFS */) if cfg!(unix) => continue,
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
    use anyhow::{Context, Result};
    use lazy_static::lazy_static;
    use parking_lot::RwLock;
    use pnet_transport::TransportReceiver;
    use std::ffi::CString;
    use std::mem::{size_of, zeroed};
    use std::net::Ipv4Addr;
    use std::thread;
    use tracing::debug;
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

    pub fn prepare_receiver(tx: &TransportReceiver) -> Result<()> {
        unsafe {
            let socket = tx.socket.fd as SOCKET;
            let ip = LOCAL_IP.read().context("cannot guess the local ip")?;
            debug!("raw socket bound to ip {}", ip);
            let ip_str = CString::new(ip.to_string())?;

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
                return Err(std::io::Error::last_os_error().into());
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
                return Err(std::io::Error::last_os_error().into());
            }
            thread::spawn(|| loop {
                NotifyAddrChange(0 as PHANDLE, 0 as LPOVERLAPPED);
                *LOCAL_IP.write() = LOCAL_INTERFACE.and_then(|index| get_ip_from_index(index));
                // Luckily, we do not need to re-bind the socket, because when we bind the IP to the
                // raw socket Windows actually binds that socket to the network adapter. As long as
                // the network adapter does not change the change of local IP does not invalidate
                // the socket.
                debug!("local IP changed to {:?}", LOCAL_IP.read());
            });
            Ok(())
        }
    }

    pub fn filter_local_ip(addr: Ipv4Addr) -> bool {
        LOCAL_IP.read().map(|local| local != addr).unwrap_or(true)
    }
}

#[cfg(not(windows))]
mod platform_impl {
    use anyhow::{bail, Result};
    use pnet_transport::TransportReceiver;
    use std::net::Ipv4Addr;

    pub fn prepare_receiver(_tx: &TransportReceiver) -> Result<()> {
        if let Ok(status) = std::fs::read_to_string("/proc/sys/net/ipv4/icmp_echo_ignore_all") {
            if status.trim().parse::<i32>()? != 1 {
                bail!("sysctl net.ipv4.icmp_echo_ignore_all should be 1 for Ekho to run properly");
            }
        }
        Ok(())
    }

    pub fn filter_local_ip(_addr: Ipv4Addr) -> bool {
        true
    }
}
